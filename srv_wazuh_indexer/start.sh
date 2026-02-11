#!/bin/sh

echo "Route changing..."
ip route del default || true
ip route add default via $GATEWAY_IP || true

chown -R wazuh-indexer:wazuh-indexer /var/lib/wazuh-indexer

# Switch to user 'wazuh' and continue with the standard entrypoint
exec su -s /bin/sh -c "/entrypoint.sh" wazuh-indexer
