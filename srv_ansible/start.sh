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
if [ -f /run/rsyslogd.pid ]; then
  pid="$(cat /run/rsyslogd.pid 2>/dev/null || true)"
  if [ -n "${pid:-}" ] && ! ps -p "$pid" -o comm= 2>/dev/null | grep -qx rsyslogd; then
    rm -f /run/rsyslogd.pid
  fi
fi
pgrep -x rsyslogd >/dev/null 2>&1 || /usr/sbin/rsyslogd -iNONE

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

# Make ANSIBLE_USERNAME/ANSIBLE_PASSWORD visible for adm_student login shell sessions.
if [ -n "${ANSIBLE_USERNAME:-}" ] && [ -n "${ANSIBLE_PASSWORD:-}" ]; then
  ansible_username_b64="$(printf '%s' "$ANSIBLE_USERNAME" | base64 | tr -d '\n')"
  ansible_password_b64="$(printf '%s' "$ANSIBLE_PASSWORD" | base64 | tr -d '\n')"
  cat > /etc/profile.d/61-adm_student-ansible-creds.sh <<EOF
if [ "\${USER:-}" = "adm_student" ]; then
  export ANSIBLE_USERNAME="\$(printf '%s' '${ansible_username_b64}' | base64 -d)"
  export ANSIBLE_PASSWORD="\$(printf '%s' '${ansible_password_b64}' | base64 -d)"
fi
EOF
  chmod 0644 /etc/profile.d/61-adm_student-ansible-creds.sh
fi

# Run SSH server
mkdir -p /run/sshd
chmod 755 /run/sshd
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

# Keep container alive
tail -f /dev/null
