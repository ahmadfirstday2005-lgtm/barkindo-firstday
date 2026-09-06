"""
Barkindo FirstDay - Student Registration Website

Everything uses only the Python standard library (no pip installs):
  - SQLite database (users, sessions) via the built-in sqlite3 module
  - Password hashing via hashlib (never store plain text passwords)
  - Sessions via cookies, stored in the database (survive restarts)

Layout:
    app.py
    templates/   HTML pages served to the browser
    static/      CSS and JavaScript assets
    registration.db   created automatically on first run

Run locally with:
    python app.py
    then open http://localhost:8000

Deployment configuration (environment variables, all optional):
    HOST=0.0.0.0            bind address              (default: localhost)
    PORT=8000               port                      (default: 8000)
    DB_PATH=/abs/path.db    database file location    (default: next to app.py)
    COOKIE_SECURE=1         send Secure cookies       (use behind HTTPS)
"""

import hashlib
import json
import os
import re
import secrets
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "registration.db"))

# Defaults safe for a local learning project; overridable for deployment.
# On Render/HOSTING, bind to 0.0.0.0 and use the PORT the platform provides.
HOST = os.environ.get("HOST", "0.0.0.0").strip()
PORT = int(os.environ.get("PORT", "8000"))
COOKIE_FLAGS = "Path=/; HttpOnly; SameSite=Lax"
if os.environ.get("COOKIE_SECURE") == "1":
    COOKIE_FLAGS += "; Secure"

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name     TEXT NOT NULL,
            email         TEXT NOT NULL UNIQUE,
            age           INTEGER NOT NULL,
            salt          TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            token      TEXT PRIMARY KEY,
            email      TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    conn.close()


def password_salt():
    return secrets.token_hex(16)


def hash_password(password, salt):
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000,
    )
    return digest.hex()


def find_user(conn, email):
    row = conn.execute(
        "SELECT * FROM users WHERE email = ?", (email,)
    ).fetchone()
    return row


def validate_registration(fields):
    """Return a list of error strings. Empty list means everything is OK."""
    errors = []

    full_name = str(fields.get("fullName", "")).strip()
    email = str(fields.get("email", "")).strip()
    age = str(fields.get("age", "")).strip()
    password = str(fields.get("password", ""))
    confirm_password = str(fields.get("confirmPassword", ""))

    if not full_name:
        errors.append("Full name is required.")
    if not EMAIL_RE.match(email):
        errors.append("Email address looks invalid.")
    if not age.isdigit() or not (1 <= int(age) <= 120):
        errors.append("Age must be a number between 1 and 120.")
    if not password:
        errors.append("Password is required.")
    elif len(password) < 8:
        errors.append("Password must be at least 8 characters.")
    elif not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one letter and one number.")
    if password != confirm_password:
        errors.append("Passwords do not match.")
    return errors


class RegistrationHandler(BaseHTTPRequestHandler):
    # ----- helpers -----------------------------------------------------

    def _send_bytes(self, data, content_type, status=200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_text(self, text, content_type, status=200):
        self._send_bytes(text.encode("utf-8"), content_type, status)

    def _send_file(self, directory, filename, content_type):
        with open(os.path.join(directory, filename), "rb") as f:
            self._send_bytes(f.read(), content_type)

    def _send_template(self, filename, content_type="text/html"):
        self._send_file(TEMPLATES_DIR, filename, content_type)

    def _send_static(self, filename, content_type):
        self._send_file(STATIC_DIR, filename, content_type)

    def _send_json(self, payload, status=200):
        self._send_text(json.dumps(payload), "application/json", status)

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _session_email(self):
        cookie = self.headers.get("Cookie", "")
        token = None
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("session="):
                token = part[len("session="):]
                break
        if not token:
            return None
        conn = get_db()
        row = conn.execute(
            "SELECT email FROM sessions WHERE token = ?", (token,)
        ).fetchone()
        conn.close()
        return row["email"] if row else None

    def _set_session_cookie(self, token):
        self.send_header(
            "Set-Cookie",
            f"session={token}; {COOKIE_FLAGS}",
        )

    # ----- GET routes --------------------------------------------------

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/index.html":
            self._send_template("index.html")
        elif path == "/static/style.css":
            self._send_static("style.css", "text/css")
        elif path == "/static/script.js":
            self._send_static("script.js", "application/javascript")
        elif path == "/login":
            self._send_template("login.html")
        elif path == "/success":
            self._send_template("success.html")
        elif path == "/dashboard":
            self._dashboard()
        elif path == "/logout":
            self._logout()
        else:
            self._send_text("<h1>404 - Page not found</h1>", "text/html", 404)

    def _dashboard(self):
        email = self._session_email()
        if email is None:
            self._redirect("/login")
            return
        conn = get_db()
        user = find_user(conn, email)
        conn.close()
        if user is None:
            self._redirect("/login")
            return
        with open(os.path.join(TEMPLATES_DIR, "dashboard.html"), "r", encoding="utf-8") as f:
            page = f.read()
        page = page.replace("{{full_name}}", user["full_name"])
        page = page.replace("{{email}}", user["email"])
        page = page.replace("{{age}}", str(user["age"]))
        self._send_text(page, "text/html")

    def _logout(self):
        cookie = self.headers.get("Cookie", "")
        token = None
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("session="):
                token = part[len("session="):]
                break
        if token:
            conn = get_db()
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
            conn.close()
        self.send_response(302)
        self.send_header("Location", "/login")
        # Clear the cookie in the browser too.
        self.send_header("Set-Cookie", "session=; Path=/; Max-Age=0")
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ----- POST routes -------------------------------------------------

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/register":
            self._register()
        elif parsed.path == "/api/login":
            self._login()
        else:
            self._send_json({"ok": False, "errors": ["Unknown endpoint."]}, 404)

    def _read_json_body(self):
        content_length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(content_length)
        return json.loads(raw.decode("utf-8"))

    def _register(self):
        try:
            body = self._read_json_body()
        except (json.JSONDecodeError, ValueError):
            self._send_json({"ok": False, "errors": ["Invalid request."]})
            return

        errors = validate_registration(body)

        conn = get_db()
        if not errors and find_user(conn, body.get("email", "").strip()) is not None:
            errors.append("That email is already registered.")

        if errors:
            conn.close()
            self._send_json({"ok": False, "errors": errors})
            return

        email = body.get("email", "").strip()
        salt = password_salt()
        password_hash = hash_password(body["password"], salt)
        conn.execute(
            """
            INSERT INTO users (full_name, email, age, salt, password_hash)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                body.get("fullName", "").strip(),
                email,
                int(body.get("age", "0")),
                salt,
                password_hash,
            ),
        )
        conn.commit()
        conn.close()

        self._send_json({"ok": True})

    def _login(self):
        try:
            body = self._read_json_body()
        except (json.JSONDecodeError, ValueError):
            self._send_json({"ok": False, "errors": ["Invalid request."]})
            return

        email = body.get("email", "").strip()
        password = body.get("password", "")

        conn = get_db()
        user = find_user(conn, email)
        if user is None or hash_password(password, user["salt"]) != user["password_hash"]:
            conn.close()
            self._send_json({"ok": False, "errors": ["Invalid email or password."]})
            return
        conn.close()

        token = secrets.token_hex(32)
        conn = get_db()
        conn.execute(
            "INSERT INTO sessions (token, email) VALUES (?, ?)",
            (token, user["email"]),
        )
        conn.commit()
        conn.close()
        self.send_response(200)
        self._set_session_cookie(token)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b'{"ok": true}')))
        self.end_headers()
        self.wfile.write(b'{"ok": true}')


def main():
    init_db()
    # ThreadingHTTPServer handles several browsers' requests at once,
    # which matters on a real host (HTML, CSS and JS load in parallel).
    server = ThreadingHTTPServer((HOST, PORT), RegistrationHandler)
    print(f"Server running at http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop.")
    server.serve_forever()


if __name__ == "__main__":
    main()