"""Password protection for the Field Day logger.

Two passwords, both configured through environment variables so they never live
in the database or in an exported log:

  FD_PASSWORD        Access password — required to open the logger at all. Hand
                     this out to everyone allowed to operate or watch the log.
  FD_ADMIN_PASSWORD  Admin / override password — required to edit or delete past
                     contacts and to change station settings. Keep this with the
                     event coordinator only.

Behaviour:
  * If FD_ADMIN_PASSWORD is unset it falls back to FD_PASSWORD, so a single
    password still gates everything (you just won't have a separate override).
  * If FD_PASSWORD is unset, authentication is DISABLED — the logger runs wide
    open exactly as it did before — and a loud warning is printed at startup.

Logging a *new* contact only needs the access password; the admin password is
reserved for changing the past (edits, deletes) and the configuration.
"""
import os
import functools
import secrets

from flask import session, request, jsonify, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

_ACCESS_PW = os.environ.get("FD_PASSWORD", "").strip()
_ADMIN_PW = os.environ.get("FD_ADMIN_PASSWORD", "").strip() or _ACCESS_PW

# Authentication is only active once an access password is configured.
AUTH_ENABLED = bool(_ACCESS_PW)

# Hash immediately so the plaintext passwords aren't kept around in memory.
_ACCESS_HASH = generate_password_hash(_ACCESS_PW) if _ACCESS_PW else None
_ADMIN_HASH = generate_password_hash(_ADMIN_PW) if _ADMIN_PW else None


def secret_key(data_dir):
    """Return a stable Flask secret key, persisted so logins survive restarts."""
    path = os.path.join(data_dir, "secret.key")
    if os.path.exists(path):
        with open(path) as f:
            key = f.read().strip()
            if key:
                return key
    key = secrets.token_hex(32)
    os.makedirs(data_dir, exist_ok=True)
    with open(path, "w") as f:
        f.write(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def startup_banner():
    """One-line summary of the auth state, printed at startup."""
    if not AUTH_ENABLED:
        return (
            "  !! NO PASSWORD SET — the logger is OPEN to anyone on the network.\n"
            "     Set FD_PASSWORD (and optionally FD_ADMIN_PASSWORD) to lock it down."
        )
    sep = "separate admin password set" if _ADMIN_PW != _ACCESS_PW else \
        "admin actions use the same password (set FD_ADMIN_PASSWORD for a separate one)"
    return f"  Password protection: ON — access password required; {sep}."


# --------------------------------------------------------------------------
# Password checks
# --------------------------------------------------------------------------
def check_access(pw):
    return bool(_ACCESS_HASH) and check_password_hash(_ACCESS_HASH, pw or "")


def check_admin(pw):
    return bool(_ADMIN_HASH) and check_password_hash(_ADMIN_HASH, pw or "")


# --------------------------------------------------------------------------
# Session state helpers
# --------------------------------------------------------------------------
def auth_ok():
    """True if the current session may use the logger at all."""
    return (not AUTH_ENABLED) or bool(session.get("authed"))


def admin_ok():
    """True if the current session may change the past / settings."""
    return (not AUTH_ENABLED) or bool(session.get("admin"))


def _wants_json():
    p = request.path
    return p.startswith("/api/") or p.startswith("/export/") or p == "/stream"


def auth_required_response():
    """Response to send when access authentication is missing."""
    if _wants_json():
        return jsonify({"error": "Authentication required.", "auth_required": True}), 401
    return redirect(url_for("login", next=request.path))


def admin_required_response():
    return jsonify({"error": "Admin password required.", "admin_required": True}), 403


# --------------------------------------------------------------------------
# Decorators
# --------------------------------------------------------------------------
def require_auth(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not auth_ok():
            return auth_required_response()
        return fn(*args, **kwargs)
    return wrapper


def require_admin(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not auth_ok():
            return auth_required_response()
        if not admin_ok():
            return admin_required_response()
        return fn(*args, **kwargs)
    return wrapper
