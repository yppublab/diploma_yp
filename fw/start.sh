#!/usr/bin/bash
set -euo pipefail

# Prepare PATH
echo 'export PATH=/usr/sbin:/sbin:$PATH' > /etc/profile.d/00-sbin.sh

echo "[fw] Renaming interfaces by subnet..."
# Default missing subnet vars to avoid set -u failures.
: "${SUBNET_UPLINK:=0.0.0.0}"
: "${SUBNET_DEV:=0.0.0.0}"
: "${SUBNET_USERS:=0.0.0.0}"
: "${SUBNET_DMZ:=0.0.0.0}"
: "${SUBNET_SERVERS:=0.0.0.0}"
: "${SUBNET_ADMIN:=0.0.0.0}"
: "${SUBNET_INFOSEC:=0.0.0.0}"
# Переименовываем все интерфейсы в понятный вид
while read -r line; do
  dev=$(echo "$line" | awk '{print $2}')
  cidr=$(echo "$line" | awk '{print $4}')
  [ "$dev" = "lo" ] && continue
  ip=${cidr%/*}
  # Derive /24 subnet x.y.z.0/24
  subnet=$(echo "$ip" | awk -F. '{printf "%s.%s.%s.0/24\n", $1,$2,$3}')
  new=""
  case "$subnet" in
    $SUBNET_UPLINK.0/24)   new="eth_uplink"  ;;
    $SUBNET_DEV.0/24)   new="eth_dev"  ;;
    $SUBNET_USERS.0/24)  new="eth_users"  ;;
    $SUBNET_DMZ.0/24)  new="eth_dmz" ;;
    $SUBNET_SERVERS.0/24)  new="eth_servers" ;;
    $SUBNET_ADMIN.0/24)  new="eth_admin" ;;
    $SUBNET_INFOSEC.0/24)  new="eth_infosec" ;;
  esac
  [ -z "$new" ] && continue
  [ "$dev" = "$new" ] && continue

  # Skip if target name is already taken
  if ip link show "$new" >/dev/null 2>&1; then
    echo "[fw] Target name '$new' already exists, skipping $dev"
    continue
  fi
  echo "[fw] renaming $dev ($cidr) -> $new"
  ip link set dev "$dev" down || true
  ip link set dev "$dev" name "$new" || true
  ip link set dev "$new" up || true
done < <(ip -o -4 addr show)

# Задаем маршруты
echo "Adding default route via ${GATEWAY_IP} on eth_uplink"
ip route add default via $GATEWAY_IP dev eth_uplink || true
# ip route add 10.11.0.0/16 via $VPN_SRV_IP || true
ip route add $VPN_SUBNET via $VPN_SRV_IP || true

# Load nftables rules
if nft list chain ip nat PREROUTING >/dev/null 2>&1; then
  nft flush chain ip nat PREROUTING || true
fi
if nft list chain ip nat POSTROUTING >/dev/null 2>&1; then
  nft flush chain ip nat POSTROUTING || true
fi
nft -f /etc/nftables.conf

# Enforce pam_access for group-based login control
if ! grep -q '^account required pam_access.so' /etc/pam.d/common-account; then
    echo 'account required pam_access.so' >> /etc/pam.d/common-account
fi

# Create local admin account if needed (Ubuntu)
if ! id localadmin >/dev/null 2>&1; then
    useradd -m -s /bin/bash localadmin
fi
if ! getent group sudo >/dev/null 2>&1; then
    groupadd -r sudo
fi
usermod -aG sudo localadmin || true
echo "localadmin:${LOCALADMIN_PASSWORD}" | chpasswd

# Access rules: allow root locally, allow bastion admins/users groups, deny all else
cat <<'EOF' >> /etc/security/access.conf
+:root:LOCAL
+:localadmin:ALL
# Разрешить членам группы ADMINS (имя группы в Linux, не DN!)
+:SG_ADMINS:ALL
# Запретить всем остальным (важно, иначе смысла нет)
-:ALL:ALL
EOF

sed -i "s|SG_ADMINS|$SG_NET_ADMINS|g" /etc/security/access.conf

touch /etc/sudoers.d/ldap-sudo
cat <<'EOF' >> /etc/sudoers.d/ldap-sudo
%SG_ADMINS ALL=(ALL:ALL) ALL
%sudo ALL=(ALL:ALL) ALL
localadmin ALL=(ALL:ALL) ALL
EOF
chown root:root /etc/sudoers.d/ldap-sudo
chmod 0440 /etc/sudoers.d/ldap-sudo
sed -i "s|SG_ADMINS|$SG_NET_ADMINS|g" /etc/sudoers.d/ldap-sudo

# Запуск rsyslog
/usr/sbin/rsyslogd
echo "[fw] Starting Suricata configuration..."

ALL_SUBNETS=$(env | grep '^SUBNET_' | cut -d= -f2 | sed 's/$/.0\/24/' | paste -sd "," -)

echo "[fw] Detected networks for HOME_NET: $ALL_SUBNETS"

if [ -z "$ALL_SUBNETS" ]; then
    echo "[fw] ERROR: No SUBNET_* variables found! Using 192.168.0.0/16 as fallback."
    ALL_SUBNETS="192.168.0.0/16"
fi

sed "s|\${SURICATA_HOME_NET}|$ALL_SUBNETS|g" /etc/suricata/suricata.yaml.template> /etc/suricata/suricata.yaml

IFACES_CONF=$(mktemp)

for IFACE in eth_uplink eth_dev eth_users eth_dmz eth_servers eth_admin eth_infosec; do
  if ip link show "$IFACE" >/dev/null 2>&1; then
    echo "[fw] Adding $IFACE to Suricata config"
    
    cat <<EOF >> "$IFACES_CONF"
  - interface: $IFACE
    defrag: yes
EOF
    ethtool -K "$IFACE" gro off lro off tso off gso off || true
  fi
done


sed -i '/# INTERFACES_PLACEHOLDER/r '"$IFACES_CONF" /etc/suricata/suricata.yaml

rm "$IFACES_CONF"

if [ ! -f /var/lib/suricata/rules/suricata.rules ]; then
  echo "[fw] Suricata rules not found, running suricata-update..."
  if command -v suricata-update >/dev/null 2>&1; then
    suricata-update || true
  fi
fi

if [ ! -f /var/lib/suricata/rules/suricata.rules ]; then
  echo "[fw] Suricata rules still missing, creating minimal test rule set"
  mkdir -p /var/lib/suricata/rules
  cat <<'EOF' > /var/lib/suricata/rules/suricata.rules
alert icmp any any -> any any (msg:"SURICATA TEST ICMP"; itype:8; sid:1000001; rev:1;)
EOF
fi

suricata -T -c /etc/suricata/suricata.yaml || echo "[fw] Suricata config test failed!"
if [ -f /var/lib/suricata/rules/suricata.rules ]; then
  cp /var/lib/suricata/rules/suricata.rules /etc/suricata/suricata.rules
fi
suricata -c /etc/suricata/suricata.yaml -s /etc/suricata/xmrig.rule -D --af-packet


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

# SSSD execute and test
mkdir -p /etc/sssd
cp /etc/sssd_temp.conf /etc/sssd/sssd.conf
chmod 600 /etc/sssd/sssd.conf
mkdir -p /var/lib/sss/db /var/log/sssd
/usr/sbin/sssd
echo "Testing LDAP connection via SSSD..."
if getent passwd test >/dev/null 2>&1; then
  echo "LDAP connection OK, NSS cache warmed."
  break
else
  echo "LDAP user 'test' not found via NSS"
fi

# Keep container alive
tail -f /dev/null




