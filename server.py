#!/usr/bin/env python3
"""
Dexcom G7 Dashboard Server
Multi-user: each user logs in with their own Dexcom credentials via the browser.
Credentials are held only in server memory, per-session, and never logged or stored to disk.
"""

import json
import os
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

# In-memory session store: token -> { dexcom_session_id, cache, cache_time }
# No credentials are stored after initial auth
sessions = {}
SESSION_TTL_SECONDS = 3600  # 1 hour
CACHE_TTL_SECONDS = 300  # 5 minutes


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


def fetch_readings_for_session(session_data, minutes=43200, max_count=50000):
    """Fetch glucose readings using a session's Dexcom session ID."""
    now = datetime.now(timezone.utc)
    cache = session_data.get("cache")
    cache_time = session_data.get("cache_time")
    if cache and cache_time:
        elapsed = (now - cache_time).total_seconds()
        if elapsed < CACHE_TTL_SECONDS:
            return cache

    dexcom_sid = session_data["dexcom_session_id"]
    readings = dexcom_request(
        "Publisher/ReadPublisherLatestGlucoseValues",
        {
            "sessionId": dexcom_sid,
            "minutes": minutes,
            "maxCount": max_count,
        },
    )

    session_data["cache"] = readings
    session_data["cache_time"] = now
    return readings


def cleanup_sessions():
    """Remove expired sessions."""
    now = datetime.now(timezone.utc)
    expired = [
        token
        for token, data in sessions.items()
        if (now - data["created"]).total_seconds() > SESSION_TTL_SECONDS
    ]
    for token in expired:
        del sessions[token]


def get_session_token(handler):
    """Extract session token from cookie."""
    cookie_header = handler.headers.get("Cookie", "")
    cookie = SimpleCookie()
    cookie.load(cookie_header)
    if "session" in cookie:
        return cookie["session"].value
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

            # Authenticate with Dexcom — credentials are used here only, not stored
            dexcom_sid = dexcom_login(username, password)

            # Create app session — store only the Dexcom session ID, not credentials
            cleanup_sessions()
            token = secrets.token_urlsafe(32)
            sessions[token] = {
                "dexcom_session_id": dexcom_sid,
                "created": datetime.now(timezone.utc),
                "cache": None,
                "cache_time": None,
            }

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header(
                "Set-Cookie",
                f"session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL_SECONDS}",
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
        token = get_session_token(self)
        if token and token in sessions:
            del sessions[token]
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header(
            "Set-Cookie",
            "session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
        )
        self.end_headers()
        self.wfile.write(json.dumps({"ok": True}).encode("utf-8"))

    def handle_api_status(self):
        token = get_session_token(self)
        if token and token in sessions:
            self.send_json(200, {"authenticated": True})
        else:
            self.send_json(200, {"authenticated": False})

    def handle_api_readings(self):
        token = get_session_token(self)
        if not token or token not in sessions:
            self.send_json(401, {"error": "Not logged in"})
            return

        try:
            readings = fetch_readings_for_session(sessions[token])
            self.send_json(200, readings)
        except urllib.error.HTTPError as e:
            if e.code == 500:
                # Dexcom session expired — user needs to re-login
                del sessions[token]
                self.send_json(401, {"error": "Dexcom session expired. Please log in again."})
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
        # Only log API calls, skip static files
        if "/api/" in path:
            # Never log credentials
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
