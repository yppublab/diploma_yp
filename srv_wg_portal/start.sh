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
/usr/sbin/rsyslogd

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
/usr/sbin/sshd

# WAZUH AGENT START
/var/ossec/bin/wazuh-control start

# SSSD execute and test
mkdir -p /etc/sssd
cp /etc/sssd_temp.conf /etc/sssd/sssd.conf
chmod 600 /etc/sssd/sssd.conf
mkdir -p /var/lib/sss/db /var/log/sssd
/usr/sbin/sssd
echo "Testing LDAP connection via SSSD..."
if getent passwd test >/dev/null 2>&1; then
    echo "LDAP connection OK, NSS cache warmed."
else
    echo "LDAP user 'test' not found via NSS"
fi

cd /app || exit 1
exec /usr/local/bin/wg-portal "$@"