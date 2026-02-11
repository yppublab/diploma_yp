#!/bin/bash

# For Ubuntu (!)

# WAZUH AGENT START
# Install GPG/curl, add Wazuh key to a dedicated keyring, add repo, then install the agent.
apt-get update
apt-get install -y curl gnupg ca-certificates && update-ca-certificates
# сохраним исходные значения, чтобы вернуть после установки
ORIG_SSL_CERT_FILE=${SSL_CERT_FILE:-}
ORIG_CURL_CA_BUNDLE=${CURL_CA_BUNDLE:-}
unset SSL_CERT_FILE CURL_CA_BUNDLE
export CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main" > /etc/apt/sources.list.d/wazuh.list
apt-get update
WAZUH_MANAGER=$WAZUH_MANAGER_IP apt-get install -y wazuh-agent
/var/ossec/bin/wazuh-control start
# вернуть переменные CA
if [ -n "$ORIG_SSL_CERT_FILE" ]; then export SSL_CERT_FILE="$ORIG_SSL_CERT_FILE"; else unset SSL_CERT_FILE; fi
if [ -n "$ORIG_CURL_CA_BUNDLE" ]; then export CURL_CA_BUNDLE="$ORIG_CURL_CA_BUNDLE"; else unset CURL_CA_BUNDLE; fi