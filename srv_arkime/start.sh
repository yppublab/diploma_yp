#!/bin/bash

set +e
set -o pipefail

ip route del default
ip route add default via $GATEWAY_IP || true

OPENSEARCH_URL="${ARKIME__elasticsearch:-http://srv_opensearch:9200}"
OPENSEARCH_WAIT_TIMEOUT="${OPENSEARCH_WAIT_TIMEOUT:-300}"
OPENSEARCH_WAIT_INTERVAL="${OPENSEARCH_WAIT_INTERVAL:-2}"

echo "Waiting for OpenSearch at ${OPENSEARCH_URL}..."
SECONDS=0
until curl -sSf "${OPENSEARCH_URL}" >/dev/null 2>&1; do
    if [ "${OPENSEARCH_WAIT_TIMEOUT}" -gt 0 ] && [ "${SECONDS}" -ge "${OPENSEARCH_WAIT_TIMEOUT}" ]; then
        echo "Timed out waiting for OpenSearch after ${OPENSEARCH_WAIT_TIMEOUT}s"
        exit 1
    fi
    sleep "${OPENSEARCH_WAIT_INTERVAL}"
done

echo "OpenSearch is reachable, checking Arkime DB..."

/opt/arkime/db/db.pl "${OPENSEARCH_URL}" init --ifneeded
if [ -n "${ARKIME_ADMIN_PASSWORD}" ]; then
  /opt/arkime/bin/arkime_add_user.sh admin ArkimeAdmin ${ARKIME_ADMIN_PASSWORD} --admin --createOnly
fi

# SSSD execute and test
mkdir -p /etc/sssd
cp /etc/sssd_temp.conf /etc/sssd/sssd.conf
chmod 600 /etc/sssd/sssd.conf
mkdir -p /var/lib/sss/db /var/log/sssd
/usr/sbin/sssd
echo "Testing LDAP connection via SSSD..."
while true; do
    if getent passwd test >/dev/null 2>&1; then
        echo "LDAP connection OK, NSS cache warmed."
        break
    else
        echo "LDAP user 'test' not found via NSS"
    fi
    sleep 2
done

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

# Запуск rsyslog
/usr/sbin/rsyslogd

# SSH
echo "SSH setup..."
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


# Schedule pcap_edit.py to run every 7 minutes.
if [ -f /opt/arkime/etc/pcap_edit.py ]; then
  cat > /etc/cron.d/pcap_edit <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
*/7 * * * * root /opt/arkime/venv/bin/python /opt/arkime/etc/pcap_edit.py >>/proc/1/fd/1 2>>/proc/1/fd/2
EOF
  chmod 0644 /etc/cron.d/pcap_edit
  if command -v cron >/dev/null 2>&1; then
    if ! pgrep -x cron >/dev/null 2>&1; then
      cron -f -L 8 &
    fi
  fi
fi

# Передаем управление оригинальному скрипту
echo "Arkime starting..."
exec /opt/arkime/bin/docker.sh capture-viewer --update-geo "$@"




