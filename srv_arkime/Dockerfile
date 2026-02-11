FROM ghcr.io/arkime/arkime/arkime:v5-latest

#Ubuntu 

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
   libpam-pwquality \
   cracklib-runtime \
   sudo
   
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3 \
    python3-pip \
    python3-venv

# Use a venv to avoid PEP 668 restrictions in the system Python.
RUN python3 -m venv /opt/arkime/venv \
    && /opt/arkime/venv/bin/pip install --no-cache-dir scapy

RUN rm -rf /var/lib/apt/lists/*

# 2. Настройка PAM (mkhomedir)
RUN echo "session required pam_mkhomedir.so skel=/etc/skel umask=0077" >> /etc/pam.d/common-session



# 4. Настраиваем nsswitch
RUN sed -i 's/^passwd:.*/passwd:         files sss/' /etc/nsswitch.conf && \
    sed -i 's/^group:.*/group:          files sss/' /etc/nsswitch.conf && \
    sed -i 's/^shadow:.*/shadow:         files sss/' /etc/nsswitch.conf

COPY start.sh /usr/bin/start.sh
RUN chmod +x /usr/bin/start.sh

ENTRYPOINT ["/usr/bin/start.sh"]
