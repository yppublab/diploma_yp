#!/usr/bin/env bash
set -euo pipefail

# Default route via firewall
ip route del default || true
ip route add default via "${GATEWAY_IP}" || true

echo "original entrypoint..."
# Continue with the default OpenLDAP entrypoint from the base image
/container/tool/run &

# Wait for base image startup to finish so it doesn't overwrite our changes
wait_for_base_startup() {
  for _ in {1..60}; do
    if [ -f /container/run/state/startup-done ]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

if ! wait_for_base_startup; then
  echo "Base OpenLDAP startup did not finish in time; continuing anyway."
fi

# Ppolicy + check_password bootstrap (idempotent)
PPOLICY_DIR="/opt/ppolicy"
if [ -d "$PPOLICY_DIR" ]; then
  : "${LDAP_BASE_DN:=dc=local,dc=host}"
  LDAP_ADMIN_DN="cn=admin,${LDAP_BASE_DN}"

  wait_for_ldap() {
    for _ in {1..30}; do
      if ldapwhoami -Y EXTERNAL -H ldapi:/// >/dev/null 2>&1; then
        return 0
      fi
      sleep 1
    done
    return 1
  }

  if wait_for_ldap; then
    if [ -f "$PPOLICY_DIR/check_password.conf" ]; then
      install -m 0644 "$PPOLICY_DIR/check_password.conf" /etc/ldap/check_password.conf
    fi

    if ! ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config "(olcModuleLoad=*ppolicy*)" olcModuleLoad | grep -q ppolicy; then
      if ! ldapmodify -Y EXTERNAL -H ldapi:/// -f "$PPOLICY_DIR/ppolicy-module.ldif"; then
        echo "Failed to load ppolicy module."
      fi
    fi
    if ! ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config "(olcModuleLoad=*check_password*)" olcModuleLoad | grep -q check_password; then
      if ! ldapmodify -Y EXTERNAL -H ldapi:/// -f "$PPOLICY_DIR/check-password-module.ldif"; then
        echo "Failed to load check_password module."
      fi
    fi

    if ! ldapsearch -Y EXTERNAL -H ldapi:/// -b "olcDatabase={1}mdb,cn=config" "(olcOverlay=ppolicy)" dn >/dev/null 2>&1; then
      ldapadd -Y EXTERNAL -H ldapi:/// -f "$PPOLICY_DIR/ppolicy-overlay.ldif"
    fi

    HAS_PWD_POLICY_SUBENTRY=false
    if ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=schema,cn=config "(olcAttributeTypes=*pwdPolicySubentry*)" dn | grep -q "^dn: "; then
      HAS_PWD_POLICY_SUBENTRY=true
    fi

    if [ -n "${LDAP_ADMIN_PASSWORD:-}" ]; then
      if ! ldapsearch -x -H ldap://127.0.0.1 -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -b "ou=Policies,${LDAP_BASE_DN}" -s base "(objectClass=*)" >/dev/null 2>&1; then
        ldapadd -x -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -f "$PPOLICY_DIR/ppolicy-ou.ldif"
      fi

      if ! ldapsearch -x -H ldap://127.0.0.1 -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -b "cn=pwdPolicyUsers,ou=Policies,${LDAP_BASE_DN}" -s base "(objectClass=*)" >/dev/null 2>&1; then
        ldapadd -x -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -f "$PPOLICY_DIR/policy-users.ldif"
      fi

      if ! ldapsearch -x -H ldap://127.0.0.1 -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -b "cn=pwdPolicyService,ou=Policies,${LDAP_BASE_DN}" -s base "(objectClass=*)" >/dev/null 2>&1; then
        ldapadd -x -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -f "$PPOLICY_DIR/policy-service.ldif"
      fi

      if [ "$HAS_PWD_POLICY_SUBENTRY" = true ]; then
        if ldapsearch -x -H ldap://127.0.0.1 -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -b "ou=Users,${LDAP_BASE_DN}" -s base "(objectClass=*)" >/dev/null 2>&1; then
          if ! ldapmodify -x -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -f "$PPOLICY_DIR/apply-policy-users.ldif"; then
            echo "Failed to assign policy for OU Users."
          fi
        else
          echo "OU Users not found, skipping policy assignment for users."
        fi

        if ldapsearch -x -H ldap://127.0.0.1 -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -b "ou=Service Accounts,ou=Users,${LDAP_BASE_DN}" -s base "(objectClass=*)" >/dev/null 2>&1; then
          if ! ldapmodify -x -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -f "$PPOLICY_DIR/apply-policy-service.ldif"; then
            echo "Failed to assign policy for OU Service Accounts."
          fi
        else
          echo "OU Service Accounts not found, skipping policy assignment for service accounts."
        fi

        apply_policy_to_entries() {
          local base_dn="$1"
          local policy_dn="$2"
          ldapsearch -LLL -o ldif-wrap=no -x -H ldap://127.0.0.1 -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" \
            -b "$base_dn" -s one "(uid=*)" dn | while IFS= read -r line; do
              local dn=""
              case "$line" in
                "dn:: "*)
                  dn="$(printf '%s' "${line#dn:: }" | base64 -d)"
                  ;;
                "dn: "*)
                  dn="${line#dn: }"
                  ;;
                *)
                  continue
                  ;;
              esac
              if [ -n "$dn" ]; then
                ldapmodify -x -H ldap://127.0.0.1 -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" <<EOF
dn: $dn
changetype: modify
replace: pwdPolicySubentry
pwdPolicySubentry: $policy_dn
EOF
              fi
            done
        }

        apply_policy_to_entries "ou=Users,${LDAP_BASE_DN}" "cn=pwdPolicyUsers,ou=Policies,${LDAP_BASE_DN}"
        apply_policy_to_entries "ou=Service Accounts,ou=Users,${LDAP_BASE_DN}" "cn=pwdPolicyService,ou=Policies,${LDAP_BASE_DN}"
      else
        echo "pwdPolicySubentry attribute is not available, skipping policy assignment."
      fi
    else
      echo "LDAP_ADMIN_PASSWORD not set, skipping ppolicy policy entries."
    fi
  else
    echo "LDAP not ready, skipping ppolicy setup."
  fi
fi

# Enforce pam_access for group-based login control
if ! grep -q '^account required pam_access.so' /etc/pam.d/common-account; then
  echo 'account required pam_access.so' >> /etc/pam.d/common-account
fi
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
+:ansible:ALL
# Запретить всем остальным
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

# Run SSH server
mkdir -p /run/sshd
chmod 755 /run/sshd
ssh-keygen -A >/dev/null 2>&1 || true
/usr/sbin/sshd

# WAZUH AGENT START
/var/ossec/bin/wazuh-control start

# SSSD execute and test
mkdir -p /etc/sssd
cp /etc/sssd_temp.conf /etc/sssd/sssd.conf
chmod 600 /etc/sssd/sssd.conf
mkdir -p /var/lib/sss/db /var/log/sssd
if [ ! -f /var/run/sssd.pid ]; then
  /usr/sbin/sssd
fi 
echo "Testing LDAP connection via SSSD..."
if getent passwd test >/dev/null 2>&1; then
    echo "LDAP connection OK, NSS cache warmed."
else
    echo "LDAP user 'test' not found via NSS"
fi

# Keep container alive
tail -f /dev/null
