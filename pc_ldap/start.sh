#!/bin/bash

ip route del default
ip route add default via $GATEWAY_IP || true

# Trust PolarProxy CA if mounted
if [ -f /usr/local/share/ca-certificates/proxy_ca.crt ]; then
  update-ca-certificates || true
  for policy_dir in /etc/firefox/policies /etc/firefox-esr/policies /usr/lib/firefox/distribution /usr/lib/firefox-esr/distribution; do
    mkdir -p "$policy_dir"
    cat <<'EOF' > "$policy_dir/policies.json"
{
  "policies": {
    "Certificates": {
      "ImportEnterpriseRoots": true,
      "Install": ["/usr/local/share/ca-certificates/proxy_ca.crt"]
    },
    "Preferences": {
      "network.http.http2.enabled": {
        "Value": false,
        "Status": "locked"
      }
    }    
  }
}
EOF
  done
fi

# Password policy & logs files conf
chmod 644 /etc/login.defs
chown root:root /etc/login.defs

chmod 644 /etc/security/pwquality.conf
chown root:root /etc/security/pwquality.conf

chmod 644 /etc/security/pwhistory.conf
chown root:root /etc/security/pwhistory.conf

chmod 644 /etc/security/faillock.conf
chown root:root /etc/security/faillock.conf

chmod 644 /etc/pam.d/common-auth
chown root:root /etc/pam.d/common-auth

chmod 644 /etc/rsyslog.d/50-default.conf
chown root:root /etc/rsyslog.d/50-default.conf

chmod 644 /etc/logrotate.conf
chown root:root /etc/logrotate.conf

chmod 644 /etc/logrotate.d/rsyslog
chown root:root /etc/logrotate.d/rsyslog

chmod 644 /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config



# Проверка и добавление pam_pwhistory.so в нужное место
if ! grep -q "^[^#]*pam_pwhistory.so" /etc/pam.d/common-password; then
    # вставляем СРАЗУ ПОСЛЕ pam_pwquality.so
    sed -i '/^[^#]*pam_pwquality.so/a password        required                        pam_pwhistory.so' /etc/pam.d/common-password
    echo "✓ pam_pwhistory.so inserted after pam_pwquality.so"
else
    # Убедимся, что строка в правильном месте (после pwquality, до unix)
    PWQUALITY_LINE=$(grep -n "^[^#]*pam_pwquality.so" /etc/pam.d/common-password | head -1 | cut -d: -f1)
    PHISTORY_LINE=$(grep -n "^[^#]*pam_pwhistory.so" /etc/pam.d/common-password | head -1 | cut -d: -f1)
    PUNIX_LINE=$(grep -n "^[^#]*pam_unix.so" /etc/pam.d/common-password | head -1 | cut -d: -f1)
    
    if [ -n "$PWQUALITY_LINE" ] && [ -n "$PHISTORY_LINE" ] && [ -n "$PUNIX_LINE" ]; then
        if [ "$PHISTORY_LINE" -le "$PWQUALITY_LINE" ] || [ "$PHISTORY_LINE" -ge "$PUNIX_LINE" ]; then
            echo "⚠ pam_pwhistory.so in wrong position — reordering..."
            # Удаляем старую строку и вставляем заново в правильное место
            sed -i '/^[^#]*pam_pwhistory.so/d' /etc/pam.d/common-password
            sed -i '/^[^#]*pam_pwquality.so/a password        required                        pam_pwhistory.so' /etc/pam.d/common-password
        fi
    fi
    echo "✓ pam_pwhistory.so already configured"
fi

# Создаем директорию для faillock и настраиваем права
mkdir -p /var/lib/faillock
chown root:root /var/lib/faillock
chmod 700 /var/lib/faillock
echo "✓ Настройка faillock завершена"


echo "##### CONFIGURING PAM.D/SU #####"
echo "Начинаем настройку /etc/pam.d/su ..."

PAM_FILE="/etc/pam.d/su"
GROUP="sudo"

# Проверяем, есть ли уже активное правило для группы sudo
if grep -qE '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so.*group='"$GROUP" "$PAM_FILE"; then
    echo "✓ Правило для группы '$GROUP' уже активно"
else
    # Удаляем старые закомментированные/неправильные версии правила
    sed -i -E '/^[[:space:]]*#?[[:space:]]*auth[[:space:]]+(required|sufficient)[[:space:]]+pam_wheel\.so/d' "$PAM_FILE"

    # Вставляем правильное правило СРАЗУ ПОСЛЕ pam_rootok.so
    if grep -q 'pam_rootok\.so' "$PAM_FILE"; then
        sed -i "/pam_rootok\.so/a auth       required   pam_wheel.so use_uid group=$GROUP" "$PAM_FILE"
        echo "✓ Добавлено правило: auth required pam_wheel.so use_uid group=$GROUP"
    else
        echo "Ошибка: не найдена строка 'pam_rootok.so' в $PAM_FILE" >&2
    fi
fi
echo "Настройка /etc/pam.d/su завершена"



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

sed -i "s|SG_USERS|$SG_PC_USERS|g" /etc/security/access.conf
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

# Запуск rsyslog
/usr/sbin/rsyslogd

# Принудительная ротация логов при старте
logrotate -f /etc/logrotate.conf  


# Права на домашние директории: владелец по имени каталога, права 0755
# Нужно если подключалось через volumes и права не сохранились при загрузке
for d in /home/*; do
  [ -d "$d" ] || continue
  user=$(basename "$d")
  if id "$user" >/dev/null 2>&1; then
    chown -R "$user:root" "$d"
    chmod 0755 "$d"
  fi
done

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

# Run scenario if present and optionally schedule via cron
#Каждую минуту: * * * * *
#Каждые 5 минут: */5 * * * *
if [ -f /opt/scenario.sh ]; then
    period="${SCENARIO_PERIOD:-5}"
    echo "Adding scenario to cron (every ${period} min)"
    chmod +x /opt/scenario.sh
    # Use Debian cron layout instead of BusyBox crond paths
    echo "*/${period} * * * * root IP_LDAP_SRV=${IP_LDAP_SRV} LDAP_SUFFIX=${LDAP_SUFFIX} /opt/scenario.sh" > /etc/cron.d/scenario
    chmod 0644 /etc/cron.d/scenario
    cron -f -L 8 &
fi

# Schedule web.py to run every 10 minutes if present.
if [ -f /opt/web.py ]; then

    cat > /etc/cron.d/web <<EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
*/10 * * * * root /usr/bin/python3 /opt/web.py >/var/log/web-cron.log 2>&1
EOF
    chmod 0644 /etc/cron.d/web

    if command -v cron >/dev/null 2>&1; then
        if ! pgrep -x cron >/dev/null 2>&1; then
            cron -f -L 8 &
        fi
    fi
fi

/var/ossec/bin/wazuh-control start

# Передаем управление оригинальному скрипту entrypoint образа scottyhardy
# (В оригинальном образе entrypoint обычно /usr/bin/entrypoint)
exec /usr/bin/entrypoint "$@"

