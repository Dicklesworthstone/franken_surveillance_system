#!/bin/bash
# Wyze power-cycle readiness asserts (OMP review D2) — run BEFORE any power-cycle
# so the first MQTT CONNECT after boot lands on OUR :8883 with accepted-rewrite armed.
# Each assert is a hard gate; failure means the power-cycle would produce defect #6.
set -u
FAIL=0
ok()   { echo "  ✓ $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  ✗ $1"; }

echo "== Wyze power-cycle readiness asserts =="
# A1: broker listening on :8883
if nc -z -G 2 127.0.0.1 8883 2>/dev/null; then ok "A1 broker :8883 listening"; else bad "A1 broker :8883 NOT listening — camera boot would hit real cloud"; fi

# A2: accepted-rewrite armed (REWRITE env in broker plist)
REWRITE=$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:REWRITE' /Library/LaunchDaemons/com.jeffreyemanuel.wyze-broker.plist 2>/dev/null)
[ "$REWRITE" = "1" ] && ok "A2 accepted-rewrite armed (REWRITE=1)" || bad "A2 accepted-rewrite NOT armed (REWRITE=$REWRITE)"

# A3: OTA_MD5 matches live capsule
MD5V=$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:OTA_MD5' /Library/LaunchDaemons/com.jeffreyemanuel.wyze-broker.plist 2>/dev/null)
CAP=$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:CAP_PATH' /Library/LaunchDaemons/com.jeffreyemanuel.wyze-broker.plist 2>/dev/null)
if [ -n "$CAP" ] && [ -n "$MD5V" ]; then
  ACTUAL=$(md5 -q "/tmp/fwserve/$CAP" 2>/dev/null)
  [ "$ACTUAL" = "$MD5V" ] && ok "A3 OTA_MD5 matches capsule ($MD5V)" || bad "A3 OTA_MD5 MISMATCH: env=$MD5V file=${ACTUAL:-missing}"
else
  bad "A3 cannot verify (CAP_PATH or OTA_MD5 missing from plist)"
fi

# A4: pf rdr rules for .39/.51 → :8883 present
PFCOUNT=$(sudo -n pfctl -a fss -s nat 2>/dev/null | grep -c '192.168.4.39.*66.151.242.74.*8883')
[ "$PFCOUNT" -ge 2 ] && ok "A4 pf rdr .39→:8883 armed ($PFCOUNT rules)" || bad "A4 pf rdr .39→:8883 MISSING ($PFCOUNT)"
PFCOUNT51=$(sudo -n pfctl -a fss -s nat 2>/dev/null | grep -c '192.168.4.51.*66.151.242.74.*8883')
[ "$PFCOUNT51" -ge 2 ] && ok "A4b pf rdr .51→:8883 armed ($PFCOUNT51 rules)" || bad "A4b pf rdr .51→:8883 MISSING ($PFCOUNT51)"

# A5: backup receivers listening (444-449)
BK=0; for p in 444 445 446 447 448 449; do nc -z -G 1 127.0.0.1 $p 2>/dev/null && BK=$((BK+1)); done
[ "$BK" -eq 6 ] && ok "A5 backup receivers 444-449 all listening" || bad "A5 backup receivers only $BK/6 — installer step 2 would die"

# A6: bootwatch or chain-watch daemon alive (captures the proof on boot)
CW=$(pgrep -f 'wyze_chain_watch' | head -1)
[ -n "$CW" ] && ok "A6 chain-watch daemon alive (pid $CW)" || bad "A6 chain-watch daemon NOT running — proof would be lost"

# A7: forge serving the exact capsule bytes
FORGE_OK=$(curl -sk https://127.0.0.1:443/wuv2/upgrade/HL_CAM4/firmware/4.52.17.99.tar 2>/dev/null | md5 -q)
[ "$FORGE_OK" = "$MD5V" ] && ok "A7 forge serves capsule byte-verified" || bad "A7 forge capsule md5 mismatch (${FORGE_OK:-no-response})"

echo "== readiness: $FAIL failures =="
exit $FAIL
