FROM scottyhardy/docker-remote-desktop:latest
# Ubuntu

USER root

ENV DEBIAN_FRONTEND=noninteractive TZ=Europe/Moscow
RUN apt-get update

# Net tools, ssh, base utils
RUN apt-get install -y --no-install-recommends \
   ca-certificates \
   gnupg \
   nano \
   iputils-ping \
   net-tools \
   dnsutils \
   rsyslog \
   logrotate \
   iproute2 \
   openssh-client \
   openssh-server \
   curl \
   cron   

# Passwords and politics
RUN apt-get install -y --no-install-recommends \
   sssd \
   sssd-tools \
   sssd-ldap \
   libnss-sss \
   libpam-sss \
   ldap-utils \
   libpam-modules \
   libpam-pwquality \
   cracklib-runtime \
   sudo

 # Wazuh agent repo + install
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && \
    chmod 644 /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main" > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    WAZUH_MANAGER=srv_wazuh_manager apt-get install -y wazuh-agent

RUN apt-get install -y --no-install-recommends \
    remmina \
    remmina-plugin-rdp \
    freerdp2-x11 \
    samba-client \
    gvfs \
    gvfs-backends \
    gvfs-daemons \
    gvfs-fuse
    
RUN rm -rf /var/lib/apt/lists/*

# 2. Настройка PAM (mkhomedir)
RUN echo "session required pam_mkhomedir.so skel=/etc/skel umask=0077" >> /etc/pam.d/common-session



# 4. Настраиваем nsswitch
RUN sed -i 's/^passwd:.*/passwd:         files sss/' /etc/nsswitch.conf && \
    sed -i 's/^group:.*/group:          files sss/' /etc/nsswitch.conf && \
    sed -i 's/^shadow:.*/shadow:         files sss/' /etc/nsswitch.conf

# Ensure XDG_RUNTIME_DIR exists for non-systemd sessions (xrdp)
RUN mkdir -p /etc/X11/Xsession.d && \
    cat <<'EOF' > /etc/X11/Xsession.d/99-xdg-runtime
if [ -z "$XDG_RUNTIME_DIR" ]; then
  export XDG_RUNTIME_DIR=/run/user/$(id -u)
  if [ ! -d "$XDG_RUNTIME_DIR" ]; then
    mkdir -p "$XDG_RUNTIME_DIR"
    chmod 700 "$XDG_RUNTIME_DIR"
    chown "$(id -u):$(id -g)" "$XDG_RUNTIME_DIR" 2>/dev/null || true
  fi
fi
EOF

COPY /start.sh /usr/bin/start.sh
RUN chmod +x /usr/bin/start.sh

RUN mkdir -p /run/user
RUN chmod 0755 /run/user
COPY share.sh /usr/local/bin/share.sh
RUN chmod +x /usr/local/bin/share.sh
RUN chmod 755 /usr/local/bin/share.sh
COPY xdg-runtime.sh /usr/local/libexec/xdg-runtime.sh
RUN chmod 755 /usr/local/libexec/xdg-runtime.sh
RUN if ! grep -q '/usr/local/libexec/xdg-runtime.sh' /etc/pam.d/common-session; then \
    echo 'session optional pam_exec.so /usr/local/libexec/xdg-runtime.sh' >> /etc/pam.d/common-session; \
  fi

ENTRYPOINT ["/usr/bin/start.sh"]
