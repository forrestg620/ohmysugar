#!/usr/bin/env python3
"""
Dexcom G7 Dashboard Server
Multi-user: each user logs in with their own Dexcom credentials via the browser.
Credentials are never stored. Dexcom session IDs are kept in HMAC-signed cookies
so sessions survive server restarts (Render free tier spin-down).
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import urllib.request
import urllib.error
from http.server import HTTPServer, SimpleHTTPRequestHandler
from http.cookies import SimpleCookie
from datetime import datetime, timezone

# Dexcom Share API configuration
DEXCOM_BASE_URL = "https://share2.dexcom.com/ShareWebServices/Services"
DEXCOM_APP_ID = "d89443d2-327c-4a6f-89e5-496bbb0317db"

# Signing key for cookies — set SECRET_KEY env var in production
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# In-memory cache per dexcom session ID (readings only, not auth)
_readings_cache = {}  # dexcom_sid -> { readings, time }
CACHE_TTL_SECONDS = 300  # 5 minutes
COOKIE_MAX_AGE = 7 * 24 * 3600  # 7 days


def sign_value(value):
    """Create an HMAC-signed cookie value: value.signature"""
    sig = hmac.new(SECRET_KEY.encode(), value.encode(), hashlib.sha256).hexdigest()
    return f"{value}.{sig}"


def verify_signed_value(signed):
    """Verify and extract value from signed cookie. Returns value or None."""
    if not signed or "." not in signed:
        return None
    value, sig = signed.rsplit(".", 1)
    expected = hmac.new(SECRET_KEY.encode(), value.encode(), hashlib.sha256).hexdigest()
    if hmac.compare_digest(sig, expected):
        return value
    return None


def dexcom_request(endpoint, payload):
    """Make a POST request to the Dexcom Share API."""
    url = f"{DEXCOM_BASE_URL}/{endpoint}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Dexcom Share/3.0.2.11",
        },
    )
    with urllib.request.urlopen(req) as resp:
        raw = resp.read().decode("utf-8")
        if not raw:
            return []
        return json.loads(raw)


def dexcom_login(username, password):
    """Authenticate with Dexcom Share. Returns dexcom_session_id."""
    account_id = dexcom_request(
        "General/AuthenticatePublisherAccount",
        {
            "accountName": username,
            "password": password,
            "applicationId": DEXCOM_APP_ID,
        },
    )

    session_id = dexcom_request(
        "General/LoginPublisherAccountById",
        {
            "accountId": account_id,
            "password": password,
            "applicationId": DEXCOM_APP_ID,
        },
    )

    if session_id == "00000000-0000-0000-0000-000000000000":
        raise RuntimeError(
            "Dexcom Share is not active. Enable Share in your Dexcom G7 app "
            "(Settings → Share) and add at least one follower."
        )

    return session_id


def fetch_readings(dexcom_sid, minutes=43200, max_count=50000):
    """Fetch glucose readings, with per-session caching."""
    now = datetime.now(timezone.utc)
    cached = _readings_cache.get(dexcom_sid)
    if cached:
        elapsed = (now - cached["time"]).total_seconds()
        if elapsed < CACHE_TTL_SECONDS:
            return cached["readings"]

    readings = dexcom_request(
        "Publisher/ReadPublisherLatestGlucoseValues",
        {
            "sessionId": dexcom_sid,
            "minutes": minutes,
            "maxCount": max_count,
        },
    )

    _readings_cache[dexcom_sid] = {"readings": readings, "time": now}
    return readings


def get_dexcom_sid(handler):
    """Extract and verify the Dexcom session ID from signed cookie."""
    cookie_header = handler.headers.get("Cookie", "")
    cookie = SimpleCookie()
    cookie.load(cookie_header)
    if "session" in cookie:
        return verify_signed_value(cookie["session"].value)
    return None


class DashboardHandler(SimpleHTTPRequestHandler):
    """Serves the dashboard, login page, and API endpoints."""

    def do_GET(self):
        if self.path == "/api/readings":
            self.handle_api_readings()
        elif self.path == "/api/status":
            self.handle_api_status()
        elif self.path == "/" or self.path == "/index.html":
            self.path = "/index.html"
            super().do_GET()
        elif self.path == "/login":
            self.path = "/login.html"
            super().do_GET()
        else:
            super().do_GET()

    def do_POST(self):
        if self.path == "/api/login":
            self.handle_api_login()
        elif self.path == "/api/logout":
            self.handle_api_logout()
        else:
            self.send_response(404)
            self.end_headers()

    def handle_api_login(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            username = body.get("username", "").strip()
            password = body.get("password", "")

            if not username or not password:
                self.send_json(400, {"error": "Username and password are required."})
                return

            # If it looks like a phone number (no @), normalize to digits only
            if "@" not in username:
                username = re.sub(r"[^\d+]", "", username)

            # Authenticate with Dexcom — credentials used here only, never stored
            dexcom_sid = dexcom_login(username, password)

            # Store Dexcom session ID in a signed cookie — no server-side session needed
            signed = sign_value(dexcom_sid)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header(
                "Set-Cookie",
                f"session={signed}; Path=/; HttpOnly; SameSite=Strict; Max-Age={COOKIE_MAX_AGE}",
            )
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True}).encode("utf-8"))

        except RuntimeError as e:
            self.send_json(401, {"error": str(e)})
        except urllib.error.HTTPError:
            self.send_json(401, {"error": "Invalid Dexcom username or password."})
        except Exception as e:
            self.send_json(500, {"error": f"Login failed: {e}"})

    def handle_api_logout(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header(
            "Set-Cookie",
            "session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
        )
        self.end_headers()
        self.wfile.write(json.dumps({"ok": True}).encode("utf-8"))

    def handle_api_status(self):
        dexcom_sid = get_dexcom_sid(self)
        self.send_json(200, {"authenticated": dexcom_sid is not None})

    def handle_api_readings(self):
        dexcom_sid = get_dexcom_sid(self)
        if not dexcom_sid:
            self.send_json(401, {"error": "Not logged in"})
            return

        try:
            readings = fetch_readings(dexcom_sid)
            self.send_json(200, readings)
        except urllib.error.HTTPError as e:
            if e.code == 500:
                # Dexcom session expired — clear cookie, user needs to re-login
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.send_header(
                    "Set-Cookie",
                    "session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
                )
                self.end_headers()
                self.wfile.write(
                    json.dumps({"error": "Dexcom session expired. Please log in again."}).encode("utf-8")
                )
            else:
                self.send_json(500, {"error": f"Dexcom API error: {e.code}"})
        except Exception as e:
            self.send_json(500, {"error": str(e)})

    def send_json(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def log_message(self, format, *args):
        path = str(args[0]) if args else ""
        if "/api/" in path:
            super().log_message(format, *args)


def main():
    port = int(os.environ.get("PORT", 8050))
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    print("=" * 60)
    print("  Oh My Sugar")
    print("=" * 60)
    print()
    print("  Users log in with their own Dexcom credentials")
    print("  via the browser. No credentials stored on disk.")
    print("  Sessions persist in signed cookies (7-day expiry).")
    print()

    if os.environ.get("SECRET_KEY"):
        print("  SECRET_KEY: loaded from environment")
    else:
        print("  SECRET_KEY: auto-generated (set SECRET_KEY env var for persistence)")
    print()

    server = HTTPServer(("0.0.0.0", port), DashboardHandler)
    print(f"Dashboard running at http://localhost:{port}")
    print("Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
