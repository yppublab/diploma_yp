#!/bin/bash

ip route del default
ip route add default via $GATEWAY_IP || true

# Trust mounted certificates and configure Firefox policies
CERT_FILES=()
[ -f /usr/local/share/ca-certificates/proxy_ca.crt ] && CERT_FILES+=("/usr/local/share/ca-certificates/proxy_ca.crt")
[ -f /usr/local/share/ca-certificates/wazuh.dashboard.pem ] && CERT_FILES+=("/usr/local/share/ca-certificates/wazuh.dashboard.pem")

if [ "${#CERT_FILES[@]}" -gt 0 ]; then
  update-ca-certificates || true

  cert_json_items=""
  for cert in "${CERT_FILES[@]}"; do
    if [ -n "$cert_json_items" ]; then
      cert_json_items="$cert_json_items, "
    fi
    cert_json_items="${cert_json_items}\"${cert}\""
  done

  for policy_dir in /etc/firefox/policies /etc/firefox-esr/policies; do
    mkdir -p "$policy_dir"
    cat > "$policy_dir/policies.json" <<EOF
{
  "policies": {
    "Certificates": {
      "ImportEnterpriseRoots": true,
      "Install": [${cert_json_items}]
    }
  }
}
EOF
  done
fi

# Enforce pam_access for group-based login control
if ! grep -q '^account required pam_access.so' /etc/pam.d/common-account; then
    echo 'account required pam_access.so' >> /etc/pam.d/common-account
fi

# Create local admin account if needed
if ! id localadmin >/dev/null 2>&1; then
    useradd -m -s /bin/bash localadmin
fi
echo "localadmin:${LOCALADMIN_PASSWORD}" | chpasswd
usermod -aG sudo localadmin

# Access rules: allow root locally, allow bastion admins/users groups, deny all else
cat <<'EOF' >> /etc/security/access.conf
+:root:LOCAL
+:localadmin:ALL
# Разрешить членам группы ADMINS (имя группы в Linux, не DN!)
+:SG_ADMINS:ALL
# Разрешить членам группы USERS
+:SG_USERS:ALL
# Запретить всем остальным (важно, иначе смысла нет)
-:ALL:ALL
EOF

sed -i "s|SG_USERS|$SG_USERS|g" /etc/security/access.conf
sed -i "s|SG_ADMINS|$SG_ADMINS|g" /etc/security/access.conf

touch /etc/sudoers.d/ldap-sudo
cat <<'EOF' >> /etc/sudoers.d/ldap-sudo
%SG_ADMINS ALL=(ALL:ALL) ALL
localadmin ALL=(ALL:ALL) ALL
EOF
chown root:root /etc/sudoers.d/ldap-sudo
chmod 0440 /etc/sudoers.d/ldap-sudo
sed -i "s|SG_ADMINS|$SG_ADMINS|g" /etc/sudoers.d/ldap-sudo

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

# Запуск rsyslog
if [ -f /run/rsyslogd.pid ]; then
  pid="$(cat /run/rsyslogd.pid 2>/dev/null || true)"
  if [ -n "${pid:-}" ] && ! ps -p "$pid" -o comm= 2>/dev/null | grep -qx rsyslogd; then
    rm -f /run/rsyslogd.pid
  fi
fi

pgrep -x rsyslogd >/dev/null 2>&1 || /usr/sbin/rsyslogd -iNONE



# Права на домашние директории: владелец по имени каталога, права 0755
# Нужно если подключалось через volumes и права не сохранились при загрузке с гита
for d in /home/users/*; do
  [ -d "$d" ] || continue
  user=$(basename "$d")
  if id "$user" >/dev/null 2>&1; then
    chown -R "$user:root" "$d"
    chmod 0755 "$d"
  fi
done

# Run SSH server
mkdir -p /run/sshd
chmod 755 /run/sshd
if [ -f /run/sshd.pid ]; then
  pid="$(cat /run/sshd.pid 2>/dev/null || true)"
  if [ -n "${pid:-}" ] && ! ps -p "$pid" -o comm= 2>/dev/null | grep -qx sshd; then
    rm -f /run/sshd.pid /var/run/sshd.pid
  fi
fi
pgrep -x sshd >/dev/null 2>&1 || /usr/sbin/sshd

# WAZUH AGENT START
/var/ossec/bin/wazuh-control start

# Передаем управление оригинальному скрипту entrypoint образа scottyhardy
# (В оригинальном образе entrypoint обычно /usr/bin/entrypoint)
exec /usr/bin/entrypoint "$@"


