#!/bin/bash
set -euo pipefail

# GVFS mount for Samba share; run as the desktop user.
# Usage: ./share.sh

SMB_SERVER="${SMB_SERVER:-srv_fs}"
SMB_SHARE="${SMB_SHARE:-share}"
SMB_DOMAIN="${SMB_DOMAIN:-WORKGROUP}"
SMB_USER="${SMB_USER:-$USER}"

# Ensure runtime dir exists in non-systemd sessions (xrdp)
if [ -z "${XDG_RUNTIME_DIR:-}" ]; then
  XDG_RUNTIME_DIR="/run/user/$(id -u)"
fi
# Try system runtime dir; if no permissions, fall back to user-writable path
if ! mkdir -p "$XDG_RUNTIME_DIR" 2>/dev/null; then
  XDG_RUNTIME_DIR="$HOME/.run"
  mkdir -p "$XDG_RUNTIME_DIR"
fi
chmod 700 "$XDG_RUNTIME_DIR" 2>/dev/null || true
export XDG_RUNTIME_DIR

read -r -s -p "Password for ${SMB_DOMAIN}\\${SMB_USER}: " SMB_PASS
echo

printf '%s\n' "$SMB_PASS" | gio mount "smb://${SMB_DOMAIN};${SMB_USER}@${SMB_SERVER}/${SMB_SHARE}/"

echo "Mounted: smb://${SMB_DOMAIN};${SMB_USER}@${SMB_SERVER}/${SMB_SHARE}/"
echo "Path: /run/user/$(id -u)/gvfs/smb-share:domain=${SMB_DOMAIN},server=${SMB_SERVER},share=${SMB_SHARE},user=${SMB_USER}"
