FROM osixia/phpldapadmin:latest

ENV DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC

# Use Debian archive mirrors, drop obsolete third-party repos, and keep update+install in one layer
RUN rm -f /etc/apt/sources.list.d/*nginx*.list \
 && sed -i '/nginx.org/d; \
            s@deb.debian.org/debian@archive.debian.org/debian@g; \
            s@security.debian.org/debian-security@archive.debian.org/debian-security@g; \
            /buster-backports/d' /etc/apt/sources.list \
 && printf 'Acquire::Check-Valid-Until "false";\n' >/etc/apt/apt.conf.d/99no-check-valid \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
   ca-certificates \
   gnupg \
   nano \
   iputils-ping \
   net-tools \
   dnsutils \
   syslog-ng \
   iproute2 \
   openssh-client \
   openssh-server \
   curl \
   cron \
   sssd \
   sssd-tools \
   sssd-ldap \
   libnss-sss \
   libpam-sss \
   ldap-utils \
   libpam-pwquality \
   cracklib-runtime \
   sudo \
   gawk \
 && rm -rf /var/lib/apt/lists/*

# Wazuh agent repo + install
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && \
    chmod 644 /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main" > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    WAZUH_MANAGER=srv_wazuh_manager apt-get install -y wazuh-agent && \
    rm -rf /var/lib/apt/lists/*


# PAM (mkhomedir)
RUN echo "session required pam_mkhomedir.so skel=/etc/skel umask=0077" >> /etc/pam.d/common-session

# NSS
RUN sed -i 's/^passwd:.*/passwd:         files sss/' /etc/nsswitch.conf && \
    sed -i 's/^group:.*/group:          files sss/' /etc/nsswitch.conf && \
    sed -i 's/^shadow:.*/shadow:         files sss/' /etc/nsswitch.conf

COPY start.sh /usr/bin/start.sh
RUN chmod +x /usr/bin/start.sh

ENTRYPOINT ["/usr/bin/start.sh"]
