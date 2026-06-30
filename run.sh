#!/usr/bin/env bash
# Start the Field Day Logger. All operators point their browsers at this host.
set -e
cd "$(dirname "$0")"

PORT="${PORT:-8073}"

# --- Passwords --------------------------------------------------------------
# Lock the logger down by setting these before running (or uncomment below):
#   FD_PASSWORD       - required to open the logger at all (give to operators).
#   FD_ADMIN_PASSWORD - required to edit/delete past contacts and change setup
#                       (keep with the coordinator). Falls back to FD_PASSWORD.
# If FD_PASSWORD is unset, the logger runs open with no password.
# export FD_PASSWORD="changeme"
# export FD_ADMIN_PASSWORD="override-me"

# Use a venv if present, otherwise system python3.
PY=python3
if [ -d .venv ]; then PY=.venv/bin/python; fi

# Show the LAN address operators should connect to.
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo "============================================================"
echo "  Field Day Logger starting on port ${PORT}"
[ -n "$IP" ] && echo "  Operators connect to:  http://${IP}:${PORT}/"
echo "  This machine:          http://localhost:${PORT}/"
echo "============================================================"

PORT="$PORT" exec "$PY" app.py
