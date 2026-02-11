FROM ubuntu:22.04

# Отключаем интерактивные окна при установке
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    nginx \
    php-fpm \
    php-mysql \
    php-gd \
    php-zip \
    php-curl \
    php-mbstring \
    php-xml \
    php-intl \
    mariadb-client \
    curl \
    unzip

# Копируем архив с сайтом и секрет для api
COPY wp.tar.gz /tmp/wp.tar.gz
COPY secret.txt /tmp/secret.txt 

# Настраиваем папки
RUN mkdir -p /var/www/wordpress /var/www/other /run/php && \
    chown -R www-data:www-data /var/www/other

# Распаковка WP
RUN tar -xzf /tmp/wp.tar.gz -C /var/www/wordpress --strip-components=1 && \
    chown -R www-data:www-data /var/www/wordpress
RUN sed -i "s/define( 'DB_HOST', 'db' );/define( 'DB_HOST', 'srv_web_db' );/" /var/www/wordpress/wp-config.php && \
    sed -i "s/define( 'DB_NAME', 'wp_db' );/define( 'DB_NAME', 'wordpress' );/" /var/www/wordpress/wp-config.php

# Добавляем динамическую настройку WP_HOME и WP_SITEURL
RUN sed -i "/That's all, stop editing!/i \
// Динамическое определение домена для локальной среды\n\
\$protocol = (isset(\$_SERVER['HTTPS']) && \$_SERVER['HTTPS'] === 'on') ? 'https' : 'http';\n\
\$host = \$_SERVER['HTTP_HOST'] ?? 'local.host';\n\
\$allowed = ['127.0.0.1', 'localhost', 'local.host', 'srv_web', '192.168.204.34'];\n\
\n\
if (in_array(\$host, \$allowed)) {\n\
    define('WP_HOME', \"\$protocol://\$host\");\n\
    define('WP_SITEURL', \"\$protocol://\$host\");\n\
} else {\n\
    // Безопасный фолбэк\n\
    define('WP_HOME', \"\$protocol://local.host\");\n\
    define('WP_SITEURL', \"\$protocol://local.host\");\n\
}\n\
" /var/www/wordpress/wp-config.php



# Копируем файлы api для порта 8080
COPY index.html /var/www/other/index.html 
COPY api.php /var/www/other/api.php

# Конфиги
COPY default.conf /etc/nginx/sites-available/default
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

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

 # Wazuh agent repo + install
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && \
    chmod 644 /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main" > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    WAZUH_MANAGER=srv_wazuh_manager apt-get install -y wazuh-agent

RUN rm -rf /var/lib/apt/lists/*

# 2. Настройка PAM (mkhomedir)
RUN echo "session required pam_mkhomedir.so skel=/etc/skel umask=0077" >> /etc/pam.d/common-session

# 4. Настраиваем nsswitch
RUN sed -i 's/^passwd:.*/passwd:         files sss/' /etc/nsswitch.conf && \
    sed -i 's/^group:.*/group:          files sss/' /etc/nsswitch.conf && \
    sed -i 's/^shadow:.*/shadow:         files sss/' /etc/nsswitch.conf


ENTRYPOINT ["entrypoint.sh"]
