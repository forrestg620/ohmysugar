#!/usr/bin/env python3
"""
Dexcom G7 Dashboard Server — OAuth2 Edition
Uses the official Dexcom Developer API for up to 90 days of glucose data.
Users authenticate via Dexcom's OAuth2 consent screen — no passwords on our site.
Tokens are stored in encrypted HttpOnly cookies with auto-refresh.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import urllib.request
import urllib.error
import urllib.parse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from http.cookies import SimpleCookie
from datetime import datetime, timedelta, timezone

# Dexcom Developer API configuration
DEXCOM_CLIENT_ID = os.environ.get(
    "DEXCOM_CLIENT_ID", "9aNNnzsa3ck8D8TPQg9xRRcWJUPm9Ac6"
)
DEXCOM_CLIENT_SECRET = os.environ.get(
    "DEXCOM_CLIENT_SECRET", "u3MDRBRL7rv7VaUW"
)
DEXCOM_API_BASE = "https://api.dexcom.com"
DEXCOM_AUTH_URL = f"{DEXCOM_API_BASE}/v2/oauth2/login"
DEXCOM_TOKEN_URL = f"{DEXCOM_API_BASE}/v2/oauth2/token"

# Determine redirect URI from environment or default
BASE_URL = os.environ.get("BASE_URL", "http://localhost:8050")
REDIRECT_URI = f"{BASE_URL}/oauth/callback"

# Signing/encryption key for cookies
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# In-memory cache
_readings_cache = {}  # access_token hash -> { readings, time }
CACHE_TTL_SECONDS = 300  # 5 minutes
COOKIE_MAX_AGE = 30 * 24 * 3600  # 30 days


def _derive_key():
    """Derive a 32-byte key from SECRET_KEY for encryption."""
    return hashlib.sha256(SECRET_KEY.encode()).digest()


def encrypt_value(plaintext):
    """Encrypt + HMAC sign a string."""
    key = _derive_key()
    plainbytes = plaintext.encode("utf-8")
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


def get_session_data(handler):
    """Extract and decrypt session data from cookie."""
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


def make_session_cookie(access_token, refresh_token, expires_at):
    """Create encrypted cookie with OAuth tokens."""
    data = json.dumps({
        "at": access_token,
        "rt": refresh_token,
        "exp": expires_at,
    })
    return encrypt_value(data)


def exchange_code_for_tokens(code):
    """Exchange OAuth2 authorization code for tokens."""
    data = urllib.parse.urlencode({
        "client_id": DEXCOM_CLIENT_ID,
        "client_secret": DEXCOM_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": REDIRECT_URI,
    }).encode()

    req = urllib.request.Request(
        DEXCOM_TOKEN_URL,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())


def refresh_access_token(refresh_token):
    """Use refresh token to get a new access token."""
    data = urllib.parse.urlencode({
        "client_id": DEXCOM_CLIENT_ID,
        "client_secret": DEXCOM_CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
        "redirect_uri": REDIRECT_URI,
    }).encode()

    req = urllib.request.Request(
        DEXCOM_TOKEN_URL,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())


def dexcom_api_get(endpoint, access_token, params=None):
    """Make an authenticated GET request to the Dexcom API."""
    url = f"{DEXCOM_API_BASE}{endpoint}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())


def fetch_egvs(access_token, days=30):
    """Fetch EGV (estimated glucose values) for the past N days."""
    now = datetime.now(timezone.utc)
    cache_key = hashlib.sha256(access_token.encode()).hexdigest()[:16]
    cached = _readings_cache.get(cache_key)
    if cached:
        elapsed = (now - cached["time"]).total_seconds()
        if elapsed < CACHE_TTL_SECONDS:
            return cached["readings"]

    end = now
    start = end - timedelta(days=days)
    # Dexcom API format: YYYY-MM-DDThh:mm:ss
    start_str = start.strftime("%Y-%m-%dT%H:%M:%S")
    end_str = end.strftime("%Y-%m-%dT%H:%M:%S")

    result = dexcom_api_get("/v3/users/self/egvs", access_token, {
        "startDate": start_str,
        "endDate": end_str,
    })

    # Convert to the same format the frontend expects (Share API format)
    readings = []
    for record in result.get("records", []):
        # systemTime is ISO format like "2026-03-27T10:30:00"
        st = record.get("systemTime", "")
        dt_obj = datetime.fromisoformat(st.replace("Z", "+00:00"))
        epoch_ms = int(dt_obj.timestamp() * 1000)
        readings.append({
            "WT": f"Date({epoch_ms})",
            "ST": f"Date({epoch_ms})",
            "DT": f"Date({epoch_ms})",
            "Value": record.get("value", record.get("smoothedValue", 0)),
            "Trend": record.get("trend", "Flat"),
        })

    _readings_cache[cache_key] = {"readings": readings, "time": now}
    return readings


def ensure_valid_token(session):
    """Check if access token is expired and refresh if needed.
    Returns (access_token, new_session_data_or_None).
    If session data changed (refreshed), returns new session dict to update cookie.
    """
    now = datetime.now(timezone.utc).timestamp()
    # Refresh if within 5 minutes of expiry
    if now < session["exp"] - 300:
        return session["at"], None

    # Token expired or about to expire — refresh
    tokens = refresh_access_token(session["rt"])
    new_session = {
        "at": tokens["access_token"],
        "rt": tokens.get("refresh_token", session["rt"]),
        "exp": now + tokens.get("expires_in", 7200),
    }
    return new_session["at"], new_session


class DashboardHandler(SimpleHTTPRequestHandler):
    """Serves the dashboard, OAuth flow, and API endpoints."""

    def do_GET(self):
        if self.path == "/api/readings":
            self.handle_api_readings()
        elif self.path == "/api/status":
            self.handle_api_status()
        elif self.path.startswith("/oauth/callback"):
            self.handle_oauth_callback()
        elif self.path == "/oauth/login":
            self.handle_oauth_redirect()
        elif self.path == "/" or self.path == "/index.html":
            self.path = "/index.html"
            super().do_GET()
        elif self.path == "/login":
            self.path = "/login.html"
            super().do_GET()
        else:
            super().do_GET()

    def do_POST(self):
        if self.path == "/api/logout":
            self.handle_api_logout()
        else:
            self.send_response(404)
            self.end_headers()

    def handle_oauth_redirect(self):
        """Redirect user to Dexcom's OAuth2 consent screen."""
        state = secrets.token_urlsafe(16)
        params = urllib.parse.urlencode({
            "client_id": DEXCOM_CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "scope": "offline_access",
            "state": state,
        })
        self.send_response(302)
        self.send_header("Location", f"{DEXCOM_AUTH_URL}?{params}")
        # Store state in a short-lived cookie for CSRF protection
        self.send_header(
            "Set-Cookie",
            f"oauth_state={state}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600",
        )
        self.end_headers()

    def handle_oauth_callback(self):
        """Handle OAuth2 callback from Dexcom."""
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        error = params.get("error", [None])[0]
        if error:
            self.send_response(302)
            self.send_header("Location", f"/login?error={error}")
            self.end_headers()
            return

        code = params.get("code", [None])[0]
        if not code:
            self.send_response(302)
            self.send_header("Location", "/login?error=no_code")
            self.end_headers()
            return

        try:
            tokens = exchange_code_for_tokens(code)
            now = datetime.now(timezone.utc).timestamp()
            session = {
                "at": tokens["access_token"],
                "rt": tokens.get("refresh_token", ""),
                "exp": now + tokens.get("expires_in", 7200),
            }
            cookie_val = make_session_cookie(
                session["at"], session["rt"], session["exp"]
            )

            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header(
                "Set-Cookie",
                f"session={cookie_val}; Path=/; HttpOnly; SameSite=Strict; Max-Age={COOKIE_MAX_AGE}",
            )
            # Clear oauth_state cookie
            self.send_header(
                "Set-Cookie",
                "oauth_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
            )
            self.end_headers()
        except Exception as e:
            error_msg = urllib.parse.quote(str(e))
            self.send_response(302)
            self.send_header("Location", f"/login?error={error_msg}")
            self.end_headers()

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

        try:
            access_token, new_session = ensure_valid_token(session)

            readings = fetch_egvs(access_token)

            if new_session:
                # Token was refreshed — update cookie
                cookie_val = make_session_cookie(
                    new_session["at"], new_session["rt"], new_session["exp"]
                )
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header(
                    "Set-Cookie",
                    f"session={cookie_val}; Path=/; HttpOnly; SameSite=Strict; Max-Age={COOKIE_MAX_AGE}",
                )
                self.end_headers()
                self.wfile.write(json.dumps(readings).encode("utf-8"))
            else:
                self.send_json(200, readings)

        except urllib.error.HTTPError as e:
            if e.code == 401:
                # Token invalid — try refresh
                try:
                    tokens = refresh_access_token(session["rt"])
                    now = datetime.now(timezone.utc).timestamp()
                    new_session = {
                        "at": tokens["access_token"],
                        "rt": tokens.get("refresh_token", session["rt"]),
                        "exp": now + tokens.get("expires_in", 7200),
                    }
                    readings = fetch_egvs(new_session["at"])
                    cookie_val = make_session_cookie(
                        new_session["at"], new_session["rt"], new_session["exp"]
                    )
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header(
                        "Set-Cookie",
                        f"session={cookie_val}; Path=/; HttpOnly; SameSite=Strict; Max-Age={COOKIE_MAX_AGE}",
                    )
                    self.end_headers()
                    self.wfile.write(json.dumps(readings).encode("utf-8"))
                except Exception:
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.send_header(
                        "Set-Cookie",
                        "session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
                    )
                    self.end_headers()
                    self.wfile.write(
                        json.dumps({"error": "Session expired. Please connect Dexcom again."}).encode("utf-8")
                    )
            else:
                body = e.read().decode()[:200] if hasattr(e, "read") else ""
                self.send_json(500, {"error": f"Dexcom API error {e.code}: {body}"})
        except Exception as e:
            self.send_json(500, {"error": str(e)})

    def send_json(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def log_message(self, format, *args):
        path = str(args[0]) if args else ""
        if "/api/" in path or "/oauth/" in path:
            super().log_message(format, *args)


def main():
    port = int(os.environ.get("PORT", 8050))
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    print("=" * 60)
    print("  Oh My Sugar (OAuth2 Edition)")
    print("=" * 60)
    print()
    print(f"  Dexcom API:    {DEXCOM_API_BASE}")
    print(f"  Redirect URI:  {REDIRECT_URI}")
    print(f"  Client ID:     {DEXCOM_CLIENT_ID[:8]}...")
    print()

    if os.environ.get("SECRET_KEY"):
        print("  SECRET_KEY:    loaded from environment")
    else:
        print("  SECRET_KEY:    auto-generated (set env var for persistence)")
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
