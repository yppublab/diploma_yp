#!/bin/sh
# PAM_EXEC helper: create /run/user/$UID for the logging-in user.
user="${PAM_USER:-}"
uid=""
gid=""
if [ -n "$user" ]; then
  uid="$(id -u "$user" 2>/dev/null || true)"
  gid="$(id -g "$user" 2>/dev/null || true)"
fi
if [ -z "$uid" ]; then
  uid="${PAM_UID:-}"
fi
if [ -z "$gid" ] && [ -n "$uid" ]; then
  gid="$(id -g "$uid" 2>/dev/null || true)"
fi
if [ -z "$uid" ]; then
  uid="$(id -u)"
  gid="$(id -g)"
fi
runtime="/run/user/$uid"
if [ ! -d "$runtime" ]; then
  mkdir -p "$runtime"
  chown "$uid:$gid" "$runtime" 2>/dev/null || true
  chmod 700 "$runtime" 2>/dev/null || true
fi

# Create Desktop shortcut on first login
if [ -n "$user" ]; then
  home="$(getent passwd "$user" 2>/dev/null | cut -d: -f6)"
  if [ -z "$home" ]; then
    home="/home/$user"
  fi
  if [ -d "$home" ]; then
    desktop_dir="$home/Desktop"
    desktop_file="$desktop_dir/Share Mount.desktop"
    if [ ! -f "$desktop_file" ]; then
      mkdir -p "$desktop_dir"
      cat <<'EOF' > "$desktop_file"
[Desktop Entry]
Version=1.0
Type=Application
Name=Share mount
Comment=
Exec=/usr/local/bin/share.sh
Icon=drive-harddisk
Path=/tmp/
Terminal=true
StartupNotify=false
EOF
      chown "$uid:$gid" "$desktop_file" 2>/dev/null || true
      chmod 0755 "$desktop_file" 2>/dev/null || true
    fi
  fi
fi
exit 0
