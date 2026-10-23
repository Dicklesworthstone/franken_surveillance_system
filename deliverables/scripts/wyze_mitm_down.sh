#!/bin/bash
sudo pkill -f wyze_arp_spoof.py; sudo pkill -f wyze_dns_redirect.py
sudo pkill -f wyze_forge_serve.py; sudo pkill -f wyze_mqtt_mitm.py
sudo sysctl -w net.inet.ip.forwarding=0 >/dev/null
echo "stack down, forwarding off"
