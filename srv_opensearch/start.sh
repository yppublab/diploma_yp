#!/bin/bash

ip route del default
ip route add default via $GATEWAY_IP || true

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

# Передаем управление оригинальному скрипту
exec su -s /bin/bash opensearch -c "/usr/share/opensearch/opensearch-docker-entrypoint.sh opensearch"



