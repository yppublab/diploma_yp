FROM wazuh/wazuh-indexer:4.14.1

USER root
RUN dnf install -y iproute util-linux && dnf clean all
COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

ENTRYPOINT ["/usr/local/bin/start.sh"]
