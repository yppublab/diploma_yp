#!/usr/bin/env bash

ip route del default || true
ip route add default via $GATEWAY_IP || true

cd /opt/
python3 script.py

tail -f /dev/null