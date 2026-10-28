#!/bin/bash
# Pre-flight for the two-cycle Wyze flash runbook (docs/exploit/FINISH-WYZE.md).
#
# Read-only against the camera: it resolves the unit, judges presence, and verifies every host-side
# artefact the runbook depends on. It never writes to a device and never starts a listener.
#
# Why a script: the runbook's hardcoded addresses went stale (DHCP moved .4.23/.4.24 to .4.39/.4.51
# and the old addresses are now held by other vendors' devices), the redirect address .4.160 was not
# aliased on any interface, and the negative capsule had disappeared from /tmp. Each of those fails
# silently and looks exactly like a device fault.
#
#   CAM_MAC=80:48:2c:4b:cf:0b ./wyze_flash_preflight.sh          # .4.24 (lane owner)
#   CAM_MAC=80:48:2c:52:59:05 ./wyze_flash_preflight.sh          # .4.23
#
# Exit 0 = every gate PASS (or WARN, which is reported but not fatal). Exit 1 = at least one FAIL.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
FW="$HERE/../firmware"
CERTS="$HERE/../certs"
CAP_DIR="${CAP_DIR:-/tmp/fwserve}"
# follow the armed daemon when one is installed: checking a path the responder does not advertise
# passes while the device would 404
CAP_PATH="${CAP_PATH:-$(plutil -extract EnvironmentVariables.CAP_PATH raw \
  /Library/LaunchDaemons/com.jeffreyemanuel.wyze-broker.plist 2>/dev/null || true)}"
CAP_PATH="${CAP_PATH:-wuv2/upgrade/HL_CAM4/firmware/4.52.17.32.tar}"
UP="${UP:-192.168.4.160}"
CAM_MAC="${CAM_MAC:-80:48:2c:4b:cf:0b}"
GW="${GW:-192.168.4.1}"

fails=0
TMPCAP=$(mktemp -d "${TMPDIR:-/tmp}/fss-preflight.XXXXXX")
pass() { printf 'PASS  %s\n' "$*"; }
warn() { printf 'WARN  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; fails=$((fails + 1)); }

# --- 1. resolve the unit by MAC (arp is the authority; the IPs move) ---------------------------
# arp prints octets without leading zeros (80:48:2c:4b:cf:b), so both sides are normalised.
norm_mac() { echo "$1" | tr A-F a-f | awk -F: '{ for (i = 1; i <= NF; i++) $i = $i + 0; print }' OFS=:; }
CAM_IP="${CAM_IP:-}"
if [ -z "$CAM_IP" ]; then
  CAM_IP=$(sudo -n /usr/sbin/arp -an 2>/dev/null | awk -v m="$(norm_mac "$CAM_MAC")" '
    { gsub(/[()]/, "", $2); mac = $4; n = split(mac, o, ":"); out = ""
      for (i = 1; i <= n; i++) out = out (i > 1 ? ":" : "") (o[i] + 0)
      if (out == m) { print $2; exit } }')
fi
if [ -z "$CAM_IP" ]; then
  # the cache ages out (~20 min); a sweep re-populates it and is the only way to find a moved unit
  for i in $(seq 1 254); do (ping -c1 -W 200 "192.168.4.$i" >/dev/null 2>&1) & done
  wait
  CAM_IP=$(sudo -n /usr/sbin/arp -an 2>/dev/null | awk -v m="$(norm_mac "$CAM_MAC")" '
    { gsub(/[()]/, "", $2); mac = $4; n = split(mac, o, ":"); out = ""
      for (i = 1; i <= n; i++) out = out (i > 1 ? ":" : "") (o[i] + 0)
      if (out == m) { print $2; exit } }')
fi
if [ -z "$CAM_IP" ]; then
  fail "camera $CAM_MAC is not in the ARP table (sweep: for i in \$(seq 1 254); do ping -c1 -W200 192.168.4.\$i & done; wait)"
else
  pass "camera $CAM_MAC resolves to $CAM_IP (arp)"
fi

# --- 2. presence = ICMP AND arp ---------------------------------------------------------------
if [ -n "$CAM_IP" ]; then
  if ping -c 3 -W 700 "$CAM_IP" >/dev/null 2>&1; then
    pass "ICMP answers on $CAM_IP"
  else
    warn "no ICMP from $CAM_IP — ARP-present but the app is asleep/wedged; a power cycle is the revival gate"
  fi
fi

# --- 3. interface and redirect address --------------------------------------------------------
IFACE="${IFACE:-$(route -n get "${CAM_IP:-$GW}" 2>/dev/null | awk '/interface:/{print $2}')}"
if [ -z "$IFACE" ]; then
  fail "cannot determine the interface towards ${CAM_IP:-$GW}"
else
  pass "interface $IFACE"
  MASK=$(ifconfig "$IFACE" 2>/dev/null | awk '/inet 192\.168\./{print $4; exit}')
  if ifconfig "$IFACE" 2>/dev/null | grep "inet $UP " | grep -q "netmask ${MASK:-0xffffff00}"; then
    pass "redirect address $UP is local on $IFACE"
  elif [ "${FIX:-0}" = 1 ] && sudo -n ifconfig "$IFACE" alias "$UP" netmask "${MASK:-255.255.255.0}" 2>/dev/null \
       && ifconfig "$IFACE" | grep -q "inet $UP "; then
    pass "redirect address $UP added as an alias on $IFACE (FIX=1)"
  else
    fail "redirect address $UP is NOT on $IFACE — every DNS answer points at a dead address (fix: sudo ifconfig $IFACE alias $UP netmask ${MASK:-255.255.255.0}, or re-run with FIX=1)"
  fi
fi

# --- 4. staged artefacts and their published digests ------------------------------------------
# The negative is deterministic: the 20 ASCII bytes FSS-H4-OTA-NEGATIVE\n (ota-path.md §9.3).
NEG="$CAP_DIR/wuv2/upgrade/HL_CAM4/firmware/4.52.17.30.tar"
NEG_MD5=6909e9ca42b912662c04e6e98d7c5821
if [ ! -s "$NEG" ]; then
  warn "negative capsule missing at $NEG (rebuild: printf 'FSS-H4-OTA-NEGATIVE\n' > $NEG)"
elif [ "$(wc -c <"$NEG" | tr -d ' ')" != 20 ]; then
  fail "negative capsule is $(wc -c <"$NEG" | tr -d ' ') B, must be 20 (a stale real tar under the negative name stops at the MD5 gate only by accident)"
elif [ "$(md5 -q "$NEG")" != "$NEG_MD5" ]; then
  fail "negative capsule md5 $(md5 -q "$NEG") != $NEG_MD5"
else
  pass "negative capsule 20 B md5 $NEG_MD5"
fi

# Every published capsule digest, checked where the file exists. A missing one is a FAIL only for
# the path the runbook will actually serve.
check_md5() { # path expected-md5 label
  if [ ! -s "$1" ]; then warn "$3 missing ($1)"; return; fi
  if [ "$(md5 -q "$1")" = "$2" ]; then pass "$3 md5 $2"; else fail "$3 md5 $(md5 -q "$1") != $2"; fi
}
check_md5 "$CAP_DIR/wuv2/upgrade/HL_CAM4/firmware/4.52.17.31.tar" bf0535f59515f71a04ba00bd2176ffd2 "capsule .31 (published)"
check_md5 "$CAP_DIR/wuv2/upgrade/HL_CAM4/firmware/4.52.17.32.tar" c642a2ca9f80b03c7ee5e05795f5822b "capsule .32 (armed)"
check_md5 "$CAP_DIR/wuv2/upgrade/HL_CAM4/firmware/4.52.17.33.tar" c642a2ca9f80b03c7ee5e05795f5822b "capsule .33 (mirror of .32)"

SERVED="$CAP_DIR/$CAP_PATH"
if [ ! -s "$SERVED" ]; then
  fail "the path the responder advertises is absent: $SERVED"
else
  pass "advertised capsule present: $CAP_PATH ($(wc -c <"$SERVED" | tr -d ' ') B)"
  if tar tf "$SERVED" 2>/dev/null | grep -qx 'Upgrade/upgraderun.sh' \
     && tar tf "$SERVED" 2>/dev/null | grep -qx 'Upgrade/busybox'; then
    pass "capsule members Upgrade/upgraderun.sh + Upgrade/busybox"
  else
    fail "capsule members are not the installer pair (tar tf: $(tar tf "$SERVED" 2>/dev/null | tr '\n' ' '))"
  fi
fi

# --- 5. image on the HTTP plane ---------------------------------------------------------------
IMG="${IMG:-$CAP_DIR/img.bin}"
if [ -s "$IMG" ]; then
  pass "image staged $IMG sha256 $(shasum -a 256 "$IMG" | cut -c1-16)…"
  if [ -e "$CAP_DIR/img/thingino_os04d10.bin" ] || [ -e "$CAP_DIR/img/thingino_gc4653.bin" ]; then
    pass "image name is reachable under $CAP_DIR/img/"
  else
    warn "no thingino image symlink under $CAP_DIR/img/ (the installer fetches by name)"
  fi
else
  warn "no image at $IMG (the installer aborts on its sha256 gate before any write)"
fi

# --- 6. forged chain --------------------------------------------------------------------------
LEAF="$CERTS/emudhra/leaf.pem"
INT="$CERTS/emudhra/ev-ca-aaa-cross.pem"
BUNDLE="${BUNDLE:-$HOME/fss-exploit/fw/root_system/local/cacert.pem}"
if [ -s "$LEAF" ] && [ -s "$INT" ]; then
  if [ -s "$BUNDLE" ]; then
    if openssl verify -CAfile "$BUNDLE" -untrusted "$INT" "$LEAF" >/dev/null 2>&1; then
      pass "forged leaf validates against the device's own bundle"
    else
      fail "forged leaf does NOT validate against $BUNDLE"
    fi
  else
    warn "device CA bundle not found at $BUNDLE"
  fi
  san=$(openssl x509 -in "$LEAF" -noout -ext subjectAltName 2>/dev/null | tr -d ' ')
  for h in s3-us-west-2.amazonaws.com aws-iot.wyzecam.com a24rq1e5m4mtei.iot.us-west-2.amazonaws.com; do
    case "$san" in *"DNS:$h"*) pass "leaf SAN covers $h" ;; *) fail "leaf SAN misses $h" ;; esac
  done
else
  fail "forged leaf/intermediate missing under $CERTS/emudhra/"
fi

# --- 7. listeners (only judged when something is armed) ---------------------------------------
for probe in "udp 53" "tcp 443" "tcp 8443" "tcp 8883" "tcp 8080" "tcp 9101"; do
  set -- $probe
  if [ "$1" = udp ]; then
    n=$(sudo -n lsof -nP -iUDP:"$2" 2>/dev/null | wc -l | tr -d ' ')
  else
    n=$(sudo -n lsof -nP -iTCP:"$2" -sTCP:LISTEN 2>/dev/null | wc -l | tr -d ' ')
  fi
  if [ "$n" -ge 2 ]; then pass "listener $1:$2 up"; else warn "listener $1:$2 DOWN"; fi
done

# --- 7b. the planes end to end, exactly as the device would use them --------------------------
# TLS: the forged chain must satisfy the device's own bundle, and the served bytes must be the
# capsule the responder advertises. This is the check that catches a stale/wrong file under the
# advertised name, which a bare md5 of a different path cannot.
if [ -s "$BUNDLE" ] && [ -s "$SERVED" ]; then
  code=$(curl -sS --max-time 8 --cacert "$BUNDLE" \
    --resolve "s3-us-west-2.amazonaws.com:443:127.0.0.1" -o "$TMPCAP/served.tar" \
    -w '%{http_code}' "https://s3-us-west-2.amazonaws.com/$CAP_PATH" 2>"$TMPCAP/curl.err")
  if [ "$code" = 200 ] && [ "$(md5 -q "$TMPCAP/served.tar")" = "$(md5 -q "$SERVED")" ]; then
    pass "TLS plane serves $CAP_PATH 200 with the staged bytes (chain validated by the device bundle)"
  else
    fail "TLS plane GET $CAP_PATH -> ${code:-no answer} $(head -1 "$TMPCAP/curl.err" 2>/dev/null)"
  fi
fi
# Local checks must not use 127.0.0.1: another pane's mitmdump holds 127.0.0.1:8080 and shadows the
# image/beacon plane for loopback clients (the device is unaffected — it dials the LAN address).
# Stale aliases exist too (192.168.4.200 is configured but no longer routed), so the address is
# chosen by actually connecting, not by position.
HOSTADDR=""
for cand in "$UP" $(ifconfig "$IFACE" 2>/dev/null | awk '/inet 192\.168\./{print $2}'); do
  # a bare TCP connect is not enough: .200 accepts and then never answers
  if [ "$(curl -sS --max-time 3 -o /dev/null -w '%{http_code}' "http://$cand:8080/" 2>/dev/null)" != 000 ]; then
    HOSTADDR="$cand"; break
  fi
done
if [ -z "$HOSTADDR" ]; then
  HOSTADDR=$(ifconfig "$IFACE" 2>/dev/null | awk '/inet 192\.168\./{print $2; exit}')
  warn "no local address answers :8080 (stale aliases? ifconfig $IFACE)"
fi
HOSTADDR="${HOSTADDR:-127.0.0.1}"

# HTTP: the capsule's own upgraderun.sh fetches http://$HOST:8080/img.bin and sha256-gates it, so
# :8080/img.bin is the plane that matters (9101 is the legacy mirror). The digest must equal the
# image the capsule pins, or the installer aborts before any write.
if [ -s "$SERVED" ]; then
  pinned=$(tar xOf "$SERVED" Upgrade/upgraderun.sh 2>/dev/null | awk -F= '/^IMG_SHA=/{print $2; exit}')
  if [ -z "$pinned" ]; then
    fail "capsule has no IMG_SHA line — the installer cannot gate the image"
  elif [ -s "$IMG" ] && [ "$(shasum -a 256 "$IMG" | cut -d' ' -f1)" != "$pinned" ]; then
    fail "staged image $IMG does not match the capsule's pinned sha256 ($(shasum -a 256 "$IMG" | cut -d' ' -f1 | cut -c1-16)… vs ${pinned:0:16}…)"
  else
    if curl -sS --max-time 10 -o "$TMPCAP/img.bin" "http://$HOSTADDR:8080/img.bin" 2>/dev/null \
       && [ "$(shasum -a 256 "$TMPCAP/img.bin" | cut -d' ' -f1)" = "$pinned" ]; then
      pass "HTTP plane serves /img.bin on $HOSTADDR:8080 matching the capsule's pinned sha256"
    else
      fail "HTTP plane does not serve /img.bin on $HOSTADDR:8080 matching the pinned sha256"
    fi
  fi
fi
# Beacon plane: the :8080 log is the execution proof for cycles 4/5.
if curl -sS --max-time 5 -o /dev/null "http://$HOSTADDR:8080/fss-preflight-probe" 2>/dev/null; then
  pass "beacon plane answers on $HOSTADDR:8080"
else
  warn "beacon plane :8080 does not answer (cycles 4/5 have no execution proof without it)"
fi

# --- 8. capsule build dry run ----------------------------------------------------------------
printf '#!/bin/sh\nexit 0\n' > "$TMPCAP/probe.sh"
if python3 "$HERE/build_ota_tar.py" --script "$TMPCAP/probe.sh" --out-dir "$TMPCAP/out" --no-aes >"$TMPCAP/build.log" 2>&1; then
  if tar tf "$TMPCAP/out/Upgrade.tar" 2>/dev/null | grep -qx 'Upgrade/upgraderun.sh'; then
    pass "build_ota_tar.py dry run produces an installer capsule"
  else
    fail "build_ota_tar.py ran but the capsule has no Upgrade/upgraderun.sh"
  fi
else
  fail "build_ota_tar.py dry run failed: $(tail -2 "$TMPCAP/build.log" | tr '\n' ' ')"
fi

# --- 9. sensor variant ------------------------------------------------------------------------
# The vendor ships ONE image for both sensors (both /etc/sensor blobs, runtime i2c probe); thingino
# bakes the choice into /etc/modules.d/30-sensor, so a wrong pick boots blind. The variant is only
# knowable from the unit (i2c 0x29 = gc4653, 0x3c = os04d10 per iCamera's descriptor table).
for v in gc4653 os04d10; do
  f=""
  for d in "$FW" "$HOME/fss-exploit/fw"; do
    [ -s "$d/thingino_$v.bin" ] && f="$d/thingino_$v.bin" && break
  done
  if [ -n "$f" ]; then
    pass "image variant $v present ($f, hdr byte 0x9=$(xxd -s 9 -l 1 -p "$f"), sha256 $(shasum -a 256 "$f" | cut -c1-16)…)"
  else
    warn "image variant $v missing"
  fi
done
warn "sensor variant is NOT decidable host-side — read it from the unit before flashing (i2c 0x29 gc4653 / 0x3c os04d10)"

# --- 10. verdict ------------------------------------------------------------------------------
echo
if [ "$fails" -eq 0 ]; then
  echo "PREFLIGHT PASS (warnings above are operator judgement, not gates)"
  exit 0
fi
echo "PREFLIGHT FAIL: $fails gate(s)"
exit 1
