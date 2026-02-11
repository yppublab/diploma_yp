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

# Передаем управление оригинальному скрипту
exec su -s /bin/bash opensearch -c "/usr/share/opensearch/opensearch-docker-entrypoint.sh opensearch"




