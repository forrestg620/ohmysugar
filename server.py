#!/usr/bin/env python3
"""
Dexcom G7 Dashboard Server
Multi-user: each user logs in with their own Dexcom credentials via the browser.
Credentials are stored in encrypted, HttpOnly cookies — never on disk.
When a Dexcom session expires, the server auto-re-authenticates transparently.
"""

import base64
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

# Signing/encryption key for cookies — set SECRET_KEY env var in production
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# In-memory cache per user
_readings_cache = {}  # username_hash -> { readings, time }
CACHE_TTL_SECONDS = 300  # 5 minutes
COOKIE_MAX_AGE = 30 * 24 * 3600  # 30 days

# Data accumulation directory
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def _derive_key():
    """Derive a 32-byte key from SECRET_KEY for XOR encryption."""
    return hashlib.sha256(SECRET_KEY.encode()).digest()


def encrypt_value(plaintext):
    """Encrypt + HMAC sign a string. Returns base64 string."""
    key = _derive_key()
    plainbytes = plaintext.encode("utf-8")
    # XOR encrypt with repeating key
    encrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(plainbytes))
    payload = base64.urlsafe_b64encode(encrypted).decode()
    sig = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def decrypt_value(token):
    """Verify HMAC and decrypt. Returns plaintext or None."""
    if not token or "." not in token:
        return None
    payload, sig = token.rsplit(".", 1)
    key = _derive_key()
    expected = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        encrypted = base64.urlsafe_b64decode(payload)
        plainbytes = bytes(b ^ key[i % len(key)] for i, b in enumerate(encrypted))
        return plainbytes.decode("utf-8")
    except Exception:
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


def _user_hash(username):
    """Hash username for use as filename — no PII on disk."""
    return hashlib.sha256(username.encode()).hexdigest()[:16]


def _user_data_path(username):
    """Path to a user's accumulated readings file."""
    return os.path.join(DATA_DIR, f"{_user_hash(username)}.json")


def load_stored_readings(username):
    """Load previously accumulated readings from disk."""
    path = _user_data_path(username)
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return []


def save_readings(username, readings):
    """Save accumulated readings to disk."""
    os.makedirs(DATA_DIR, exist_ok=True)
    path = _user_data_path(username)
    with open(path, "w") as f:
        json.dump(readings, f)


def merge_readings(stored, fresh):
    """Merge fresh API readings into stored history, deduplicating by timestamp."""
    # Build set of existing timestamps for fast lookup
    existing = set()
    for r in stored:
        existing.add(r.get("WT", ""))

    merged = list(stored)
    for r in fresh:
        if r.get("WT", "") not in existing:
            merged.append(r)
            existing.add(r.get("WT", ""))

    # Sort by timestamp (newest first, matching Dexcom API order)
    def sort_key(r):
        wt = r.get("WT", "Date(0)")
        try:
            return -int(wt.split("(")[1].split(")")[0].split("-")[0].split("+")[0])
        except (IndexError, ValueError):
            return 0

    merged.sort(key=sort_key)

    # Trim to 90 days max (~26000 readings at 5-min intervals)
    max_readings = 26000
    if len(merged) > max_readings:
        merged = merged[:max_readings]

    return merged


def fetch_readings(dexcom_sid, username, minutes=43200, max_count=50000):
    """Fetch glucose readings, merge with stored history, and cache."""
    cache_key = _user_hash(username)
    now = datetime.now(timezone.utc)
    cached = _readings_cache.get(cache_key)
    if cached:
        elapsed = (now - cached["time"]).total_seconds()
        if elapsed < CACHE_TTL_SECONDS:
            return cached["readings"]

    # Fetch fresh 24h from Dexcom Share API
    fresh = dexcom_request(
        "Publisher/ReadPublisherLatestGlucoseValues",
        {
            "sessionId": dexcom_sid,
            "minutes": minutes,
            "maxCount": max_count,
        },
    )

    # Load stored history, merge, and save
    stored = load_stored_readings(username)
    merged = merge_readings(stored, fresh)
    save_readings(username, merged)

    _readings_cache[cache_key] = {"readings": merged, "time": now}
    return merged


def get_session_data(handler):
    """Extract and decrypt session data from cookie. Returns dict or None."""
    cookie_header = handler.headers.get("Cookie", "")
    cookie = SimpleCookie()
    cookie.load(cookie_header)
    if "session" not in cookie:
        return None
    plaintext = decrypt_value(cookie["session"].value)
    if not plaintext:
        return None
    try:
        return json.loads(plaintext)
    except (json.JSONDecodeError, ValueError):
        return None


def make_session_cookie(username, password, dexcom_sid):
    """Create an encrypted cookie value containing session data."""
    data = json.dumps({"u": username, "p": password, "sid": dexcom_sid})
    return encrypt_value(data)


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

            # Authenticate with Dexcom
            dexcom_sid = dexcom_login(username, password)

            # Store encrypted credentials + session ID in cookie
            cookie_val = make_session_cookie(username, password, dexcom_sid)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header(
                "Set-Cookie",
                f"session={cookie_val}; Path=/; HttpOnly; SameSite=Strict; Max-Age={COOKIE_MAX_AGE}",
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
        session = get_session_data(self)
        self.send_json(200, {"authenticated": session is not None})

    def handle_api_readings(self):
        session = get_session_data(self)
        if not session:
            self.send_json(401, {"error": "Not logged in"})
            return

        dexcom_sid = session["sid"]
        username = session["u"]
        password = session["p"]

        try:
            readings = fetch_readings(dexcom_sid, username)
            self.send_json(200, readings)
        except urllib.error.HTTPError as e:
            if e.code == 500:
                # Dexcom session expired — auto re-authenticate
                try:
                    new_sid = dexcom_login(username, password)
                    # Clear stale cache
                    _readings_cache.pop(_user_hash(username), None)
                    readings = fetch_readings(new_sid, username)

                    # Update cookie with new session ID
                    cookie_val = make_session_cookie(username, password, new_sid)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header(
                        "Set-Cookie",
                        f"session={cookie_val}; Path=/; HttpOnly; SameSite=Strict; Max-Age={COOKIE_MAX_AGE}",
                    )
                    self.end_headers()
                    self.wfile.write(json.dumps(readings).encode("utf-8"))
                except Exception:
                    # Re-auth failed — credentials may have changed, force re-login
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.send_header(
                        "Set-Cookie",
                        "session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
                    )
                    self.end_headers()
                    self.wfile.write(
                        json.dumps({"error": "Session expired and re-login failed. Please sign in again."}).encode("utf-8")
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
    print("  Auto re-authentication enabled (30-day sessions)")
    print("  Credentials encrypted in HttpOnly cookies")
    print("  Never stored on disk or logged")
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
