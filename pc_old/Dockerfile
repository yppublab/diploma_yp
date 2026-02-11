FROM scottyhardy/docker-remote-desktop:latest
# Ubuntu

USER root

ENV DEBIAN_FRONTEND=noninteractive TZ=Europe/Moscow
RUN apt-get update
    
# Net tools, ssh, base utils
RUN apt-get install -y --no-install-recommends \
    openssh-server \
    iproute2 \
    sssd \
    sssd-tools \
    sssd-ldap \
    libnss-sss \
    libpam-sss \
    ldap-utils \
    supertux \
    openttd \
    aisleriot \
    gnome-mines \       
    nethack-console
    
RUN rm -rf /var/lib/apt/lists/*

# NSS
RUN sed -i 's/^passwd:.*/passwd:         files sss/' /etc/nsswitch.conf && \
    sed -i 's/^group:.*/group:          files sss/' /etc/nsswitch.conf && \
    sed -i 's/^shadow:.*/shadow:         files sss/' /etc/nsswitch.conf

COPY /start.sh /usr/bin/start.sh
RUN chmod +x /usr/bin/start.sh

ENTRYPOINT ["/usr/bin/start.sh"]
