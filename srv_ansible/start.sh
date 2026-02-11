#!/usr/bin/env bash
set -euo pipefail

# Default route via firewall
ip route del default || true
ip route add default via "${GATEWAY_IP}" || true

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

: "${SG_USERS:=SG-USERS}"
: "${SG_ADMINS:=SG-ADMINS}"

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
# Разрешить членам группы ADMINS (имя группы в Linux, не DN!)
+:SG_ADMINS:ALL
# Разрешить членам группы USERS
+:SG_USERS:ALL
+:ansible:ALL
# Запретить всем остальным
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


# Start rsyslog
/usr/sbin/rsyslogd

# Create ansible user if needed
if ! id ansible >/dev/null 2>&1; then
  useradd -m -s /bin/bash ansible
fi

ANSIBLE_DIR="${ANSIBLE:-/workspace/ansible}"
ansible_group=$(id -g ansible 2>/dev/null || echo ansible)
install -d -m 700 -o ansible -g "${ansible_group}" /home/ansible
printf "export ANSIBLE=%s\n" "$ANSIBLE_DIR" | tee -a /home/ansible/.bashrc >/dev/null
chown ansible:${ansible_group} /home/ansible/.bashrc
chown -R ansible:${ansible_group} /workspace
chmod 600 /home/ansible/.bashrc
if [ -d "${ANSIBLE_DIR}/inventory" ]; then
  chmod 700 "${ANSIBLE_DIR}/inventory"
fi

RUN_AS="ansible"
ANSIBLE_PLAYBOOK_PATH="${ANSIBLE_PLAYBOOK_PATH:-$(command -v ansible-playbook 2>/dev/null || echo /usr/bin/ansible-playbook)}"
SUDOERS_FILE="/etc/sudoers.d/${ANSIBLE_USERNAME}-ansible-playbook"

sudo -u ansible mkdir -p /home/ansible/.secrets
sudo -u ansible bash -c "echo '${ANSIBLE_PASSWORD}' > /home/ansible/.secrets/ssh_pass.txt"
sudo chmod 600 /home/ansible/.secrets/ssh_pass.txt

printf '%s\n' "${ANSIBLE_USERNAME} ALL=(${RUN_AS}) NOPASSWD: SETENV: ${ANSIBLE_PLAYBOOK_PATH} *" > "${SUDOERS_FILE}"
printf '%s\n' "Defaults:${ANSIBLE_USERNAME} env_keep += \"ANSIBLE\"" >> "${SUDOERS_FILE}"
chown root:root "${SUDOERS_FILE}"
chmod 0440 "${SUDOERS_FILE}"

# Run SSH server
mkdir -p /run/sshd
chmod 755 /run/sshd
ssh-keygen -A >/dev/null 2>&1 || true
/usr/sbin/sshd

# WAZUH AGENT START
/var/ossec/bin/wazuh-control start

# Keep container alive
tail -f /dev/null

