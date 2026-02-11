#!/bin/sh

echo "Route changing..."
ip route del default || true
ip route add default via $GATEWAY_IP || true

chown -R "wazuh:wazuh" /var/ossec/

# Switch to user 'wazuh' and continue with the standard entrypoint
exec su -s /bin/execlineb -c "/init" root
