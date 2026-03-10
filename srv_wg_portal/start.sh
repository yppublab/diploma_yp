#!/bin/bash

ip route del default || true
ip route add default via "$GATEWAY_IP" || true

# Enforce pam_access for group-based login control
if ! grep -q '^account required pam_access.so' /etc/pam.d/common-account; then
    echo 'account required pam_access.so' >> /etc/pam.d/common-account
fi

# Create local admin account if needed
if ! id localadmin >/dev/null 2>&1; then
    useradd -u 6666 -m -s /bin/bash localadmin
fi
echo "localadmin:${LOCALADMIN_PASSWORD}" | chpasswd
usermod -aG sudo localadmin

# Access rules: allow root locally, allow bastion admins/users groups, deny all else
cat <<'EOF' >> /etc/security/access.conf
+:root:LOCAL
+:localadmin:ALL
# Разрешить членам группы ADMINS (имя группы в Linux, не DN!)
+:SG_ADMINS:ALL
# Запретить всем остальным (важно, иначе смысла нет)
-:ALL:ALL
EOF

sed -i "s|SG_ADMINS|$SG_ADMINS|g" /etc/security/access.conf

touch /etc/sudoers.d/ldap-sudo
cat <<'EOF' >> /etc/sudoers.d/ldap-sudo
%SG_ADMINS ALL=(ALL:ALL) ALL
localadmin ALL=(ALL:ALL) ALL
EOF
chown root:root /etc/sudoers.d/ldap-sudo
chmod 0440 /etc/sudoers.d/ldap-sudo
sed -i "s|SG_ADMINS|$SG_ADMINS|g" /etc/sudoers.d/ldap-sudo

# Запуск rsyslog
if [ -f /run/rsyslogd.pid ]; then
  pid="$(cat /run/rsyslogd.pid 2>/dev/null || true)"
  if [ -n "${pid:-}" ] && ! ps -p "$pid" -o comm= 2>/dev/null | grep -qx rsyslogd; then
    rm -f /run/rsyslogd.pid
  fi
fi

pgrep -x rsyslogd >/dev/null 2>&1 || /usr/sbin/rsyslogd -iNONE



# Optional admin user for the container and wg-portal config override
if [ -n "${WG_PORTAL_ADMIN_USERNAME:-}" ] && [ -n "${WG_PORTAL_ADMIN_PASSWORD:-}" ]; then
  if ! id "$WG_PORTAL_ADMIN_USERNAME" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$WG_PORTAL_ADMIN_USERNAME"
  fi
  echo "${WG_PORTAL_ADMIN_USERNAME}:${WG_PORTAL_ADMIN_PASSWORD}" | chpasswd
  usermod -aG sudo "$WG_PORTAL_ADMIN_USERNAME"

  if [ -f /app/config/config.yaml ]; then
    sed -i "s|^  admin_user:.*|  admin_user: ${WG_PORTAL_ADMIN_USERNAME}|" /app/config/config.yaml
    sed -i "s|^  admin_password:.*|  admin_password: ${WG_PORTAL_ADMIN_PASSWORD}|" /app/config/config.yaml
  fi
fi

# SSH
mkdir -p /etc/ssh /run/sshd
chmod 755 /run/sshd
if [ ! -f /etc/ssh/sshd_config ]; then
  cat > /etc/ssh/sshd_config <<'EOF'
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PasswordAuthentication yes
PermitRootLogin no
UsePAM yes
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
fi
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config || true
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || true
ssh-keygen -A >/dev/null 2>&1 || true
if [ -f /run/sshd.pid ]; then
  pid="$(cat /run/sshd.pid 2>/dev/null || true)"
  if [ -n "${pid:-}" ] && ! ps -p "$pid" -o comm= 2>/dev/null | grep -qx sshd; then
    rm -f /run/sshd.pid /var/run/sshd.pid
  fi
fi
pgrep -x sshd >/dev/null 2>&1 || /usr/sbin/sshd

# WAZUH AGENT START
/var/ossec/bin/wazuh-control start

# SSSD execute and test
mkdir -p /etc/sssd
cp /etc/sssd_temp.conf /etc/sssd/sssd.conf
chmod 600 /etc/sssd/sssd.conf
mkdir -p /var/lib/sss/db /var/log/sssd
if [ -f /run/sssd.pid ]; then
  pid="$(cat /run/sssd.pid 2>/dev/null || true)"
  if [ -n "${pid:-}" ] && ! ps -p "$pid" -o comm= 2>/dev/null | grep -qx sssd; then
    rm -f /run/sssd.pid /var/run/sssd.pid
  fi
fi
pgrep -x sssd >/dev/null 2>&1 || /usr/sbin/sssd
echo "Testing LDAP connection via SSSD..."
if getent passwd test >/dev/null 2>&1; then
    echo "LDAP connection OK, NSS cache warmed."
else
    echo "LDAP user 'test' not found via NSS"
fi

# Keep one peer expiration date near current time:
# update to yesterday only when current DB value differs from now by > 1 month.
DB_FILE="/app/data/sqlite.db"
TARGET_USER_IDENTIFIER="${WG_PORTAL_EXPIRES_TARGET_USER_IDENTIFIER:-srv_branch_wg_gate}"
TARGET_INTERFACE_IDENTIFIER="${WG_PORTAL_EXPIRES_TARGET_INTERFACE_IDENTIFIER:-wg0}"
if [ -f "$DB_FILE" ]; then
  DB_FILE="$DB_FILE" \
  TARGET_USER_IDENTIFIER="$TARGET_USER_IDENTIFIER" \
  TARGET_INTERFACE_IDENTIFIER="$TARGET_INTERFACE_IDENTIFIER" \
  python3 - <<'PY'
import os
import sqlite3
from datetime import datetime, timedelta, timezone

db_file = os.environ["DB_FILE"]
target_user = os.environ["TARGET_USER_IDENTIFIER"]
target_iface = os.environ["TARGET_INTERFACE_IDENTIFIER"]

def parse_db_dt(value: str):
    if not value:
        return None
    raw = value.strip().replace(" ", "T", 1)
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt

conn = sqlite3.connect(db_file)
cur = conn.cursor()
cur.execute(
    "SELECT expires_at FROM peers WHERE user_identifier = ? AND interface_identifier = ? LIMIT 1",
    (target_user, target_iface),
)
row = cur.fetchone()
if row is None:
    print(f"[srv_wg_portal] Peer not found for user_identifier={target_user}, interface_identifier={target_iface}")
    conn.close()
    raise SystemExit(0)

current_raw = row[0]
current_dt = parse_db_dt(current_raw)
if current_dt is None:
    print(f"[srv_wg_portal] Skip expires_at update: cannot parse current value '{current_raw}'")
    conn.close()
    raise SystemExit(0)

now_utc = datetime.now(timezone.utc)
delta_seconds = abs((now_utc - current_dt).total_seconds())
month_seconds = 31 * 24 * 60 * 60
if delta_seconds <= month_seconds:
    print(
        f"[srv_wg_portal] Skip expires_at update: difference is <= 1 month "
        f"({delta_seconds/86400:.1f} days)"
    )
    conn.close()
    raise SystemExit(0)

new_dt = (now_utc - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
new_value = new_dt.strftime("%Y-%m-%d %H:%M:%S+00:00")
cur.execute(
    "UPDATE peers SET expires_at = ? WHERE user_identifier = ? AND interface_identifier = ?",
    (new_value, target_user, target_iface),
)
conn.commit()
conn.close()
print(f"[srv_wg_portal] Updated peers.expires_at to {new_value} for {target_user}/{target_iface}")
PY
else
  echo "[srv_wg_portal] sqlite DB not found: $DB_FILE"
fi

cd /app || exit 1
exec /usr/local/bin/wg-portal "$@"
