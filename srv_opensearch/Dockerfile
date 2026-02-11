FROM opensearchproject/opensearch:latest

USER root 

RUN dnf install -y \
    sssd \
    sssd-ldap \
    sssd-tools \
    openldap-clients \
    nano \
    iputils \
    net-tools \
    rsyslog \
    iproute \
    openssh-server \
    sudo \
    && dnf clean all \
    && rm -rf /var/cache/dnf

# NSS
RUN sed -i 's/^passwd:.*/passwd:     files sss/' /etc/nsswitch.conf && \
    sed -i 's/^group:.*/group:      files sss/' /etc/nsswitch.conf && \
    sed -i 's/^shadow:.*/shadow:     files sss/' /etc/nsswitch.conf

COPY start.sh /usr/bin/start.sh
RUN chmod +x /usr/bin/start.sh

ENTRYPOINT ["/usr/bin/start.sh"]
