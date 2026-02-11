#!/bin/bash

ip route del default
ip route add default via $GATEWAY_IP || true

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

# Create local admin account if needed
if ! id localadmin >/dev/null 2>&1; then
  useradd -m -s /bin/bash localadmin
  echo "localadmin:${LOCALADMIN_PASSWORD}" | chpasswd
  usermod -aG sudo localadmin

fi

if ! id test >/dev/null 2>&1; then
  useradd -m -s /bin/bash test
  echo "test:Qwerty12" | chpasswd
  usermod -aG sudo test
fi

# Access rules: allow root locally, allow bastion admins/users groups, deny all else
cat <<'EOF' >> /etc/security/access.conf
+:root:LOCAL
+:ALL:ALL
EOF

touch /etc/sudoers.d/ldap-sudo
cat <<'EOF' >> /etc/sudoers.d/ldap-sudo
localadmin ALL=(ALL:ALL) ALL
test ALL=(ALL:ALL) ALL
EOF
chown root:root /etc/sudoers.d/ldap-sudo
chmod 0440 /etc/sudoers.d/ldap-sudo

create_desktop_shortcut() {
  user="$1"
  file="$2"
  name="$3"
  exec_cmd="$4"
  icon="$5"
  terminal="$6"
  desktop_dir="/home/$user/Desktop"

  mkdir -p "$desktop_dir"
  cat > "$desktop_dir/$file" <<EOF
[Desktop Entry]
Type=Application
Name=$name
Exec=$exec_cmd
Icon=$icon
Terminal=$terminal
EOF
  chmod +x "$desktop_dir/$file"
}

create_shortcuts() {
  user="$1"
  create_desktop_shortcut "$user" "SuperTux.desktop" "SuperTux" "supertux2" "supertux" "false"
  create_desktop_shortcut "$user" "OpenTTD.desktop" "OpenTTD" "openttd" "openttd" "false"
  create_desktop_shortcut "$user" "AisleRiot.desktop" "AisleRiot" "sol" "aisleriot" "false"
  create_desktop_shortcut "$user" "GNOME-Mines.desktop" "GNOME Mines" "gnome-mines" "gnome-mines" "false"
  create_desktop_shortcut "$user" "NetHack.desktop" "NetHack" "nethack" "nethack" "true"
}

create_shortcuts test
create_shortcuts localadmin

# Права на домашние директории: владелец по имени каталога, права 0755
# Нужно если подключалось через volumes и права не сохранились при загрузке
for d in /home/*; do
  [ -d "$d" ] || continue
  user=$(basename "$d")
  if id "$user" >/dev/null 2>&1; then
    chown -R "$user:$user" "$d"
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

exec /usr/bin/entrypoint "$@"
