#!/bin/bash
echo "[srv_ntp] Starting init-script"

ip route del default
ip route add default via $GATEWAY_IP || true

# Ensure Wazuh manager resolves before services start
echo "${IP_SRV_WAZUH_MANAGER} srv_wazuh_manager" >> /etc/hosts

# SSSD execute and test
mkdir -p /etc/sssd
cp /etc/sssd_temp.conf /etc/sssd/sssd.conf
chmod 600 /etc/sssd/sssd.conf
mkdir -p /var/lib/sss/db /var/log/sssd
rm -f /run/sssd.pid /var/run/sssd.pid || true
pgrep -x sssd >/dev/null 2>&1 || /usr/sbin/sssd
echo "Testing LDAP connection via SSSD..."
if getent passwd test >/dev/null 2>&1; then
    echo "LDAP connection OK, NSS cache warmed."
else
    echo "LDAP user 'test' not found via NSS"
fi

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

# Access rules: allow root locally, allow admins/users groups, deny all else
cat <<'EOF' >> /etc/security/access.conf
+:root:LOCAL
+:localadmin:ALL
+:SG_ADMINS:ALL
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

# Start rsyslog
/usr/sbin/rsyslogd -n -iNONE &

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

# Wazuh agent
/var/ossec/bin/wazuh-control start &

# Remove stale chronyd pid file before starting chrony
if [ -f /run/chrony/chronyd.pid ]; then
  rm -f /run/chrony/chronyd.pid
fi

# Run chrony in foreground
exec chronyd -f /etc/chrony/chrony.conf -d