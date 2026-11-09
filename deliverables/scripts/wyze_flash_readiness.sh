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

# A3b: the delta URL must be the cert-valid tunnel host, not the forged-cert s3 origin.
# The OTA downloader verifies strictly (VERIFYHOST=2 + own CAINFO) and rejects the
# forged eMudhra chain, so an s3 URL here is a silently dead flash.
URLV=$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:OTA_URL' /Library/LaunchDaemons/com.jeffreyemanuel.wyze-broker.plist 2>/dev/null)
case "$URLV" in
  https://*.trycloudflare.com/*) ok "A3b delta URL is the LE-cert tunnel host" ;;
  *) bad "A3b delta URL is not the tunnel ($URLV) — camera would hit the forged-cert s3 origin" ;;
esac

# A3c: that exact URL must serve the capsule over real TLS end-to-end through cloudflared
if [ -n "$URLV" ]; then
  WANT=$(stat -f %z "/tmp/fwserve/$CAP" 2>/dev/null)
  # HEAD by default: host + verified TLS + the exact Content-Length is what A3c is for, and a
  # download through a quick tunnel can take minutes. FULL=1 pulls the bytes (A7 already md5s
  # them over the forge leg).
  if [ "${FULL:-0}" = 1 ]; then
    E2E=$(curl -sS -A fss-probe/readiness -o /dev/null -w '%{http_code} %{size_download} %{ssl_verify_result}' \
          --max-time 60 "$URLV" 2>/dev/null)
    [ -n "$WANT" ] && [ "$E2E" = "200 $WANT 0" ] \
      && ok "A3c tunnel serves capsule, TLS verified ($WANT bytes, downloaded)" \
      || bad "A3c tunnel end-to-end FAILED (code/size/ssl=$E2E, want '200 ${WANT:-?} 0')"
  else
    HDR=$(curl -sS -I -A fss-probe/readiness -o /dev/null -w '%{http_code} %{size_header} %{ssl_verify_result} %{header_json}' \
          --max-time 15 "$URLV" 2>/dev/null)
    CL=$(printf '%s' "$HDR" | sed -E 's/.*"content-length":\["?([0-9]+).*/\1/')
    [ -n "$WANT" ] && [ "$CL" = "$WANT" ] \
      && ok "A3c tunnel serves capsule, TLS verified (Content-Length $WANT)" \
      || bad "A3c tunnel FAILED (content-length=${CL:-?}, want ${WANT:-?})"
  fi
else
  bad "A3c cannot test (no OTA_URL)"
fi

# A6: bootwatch or chain-watch daemon alive (captures the proof on boot)
CW=$(pgrep -f 'wyze_chain_watch' | head -1)
[ -n "$CW" ] && ok "A6 chain-watch daemon alive (pid $CW)" || bad "A6 chain-watch daemon NOT running — proof would be lost"

# A7: forge serving the exact capsule bytes
FORGE_OK=$(curl -sk -A fss-probe/readiness https://127.0.0.1:443/$CAP 2>/dev/null | md5 -q)
[ "$FORGE_OK" = "$MD5V" ] && ok "A7 forge serves capsule byte-verified" || bad "A7 forge capsule md5 mismatch (${FORGE_OK:-no-response})"

# A8: :9443 is the UA-logging server, and it actually witnesses requests. Without this
# the camera's GET through the tunnel leaves no attributable record and chain-watch
# can never fire (a plain `python -m http.server` fails this).
ACC=/tmp/ota/fwserve_access.jsonl
if nc -z -G 2 127.0.0.1 9443 2>/dev/null; then
  PRE=$(grep -c 'fss-probe/a8' "$ACC" 2>/dev/null)
  curl -sS -A fss-probe/a8 -o /dev/null -I --max-time 10 http://127.0.0.1:9443/$CAP 2>/dev/null
  sleep 1
  POST=$(grep -c 'fss-probe/a8' "$ACC" 2>/dev/null)
  if [ "${POST:-0}" -gt "${PRE:-0}" ]; then
    ok "A8 :9443 access log witnesses requests (probe recorded)"
  else
    bad "A8 :9443 up but access log records nothing — chain-watch is blind"
  fi
else
  bad "A8 :9443 capsule server NOT listening — tunnel would 502 and the flash never starts"
fi

# A9: the capsule's installer must be RENDERED. The served tar was built without
# --render once, so upgraderun.sh still said HOST=@HOST@ / IMG_URL=@IMAGE@ — the
# downloader rejects nothing, the installer just dies at backup step 2 (busybox nc
# cannot resolve "@HOST@"). The image is 16 MiB and must not be a partial serve.
if [ -n "$CAP" ] && [ -f "/tmp/fwserve/$CAP" ]; then
  if tar -xOf "/tmp/fwserve/$CAP" Upgrade/upgraderun.sh 2>/dev/null | grep -qE '@[A-Z_]+@'; then
    LEFT=$(tar -xOf "/tmp/fwserve/$CAP" Upgrade/upgraderun.sh 2>/dev/null | grep -oE '@[A-Z_]+@' | sort -u | tr '\n' ' ')
    bad "A9 capsule has unrendered placeholders ($LEFT) — installer would die"
  else
    ok "A9 capsule installer fully rendered"
  fi
else
  bad "A9 capsule file missing"
fi

# A11: the capsule must carry the static busybox, executable. The installer's very
# first line is `[ -x /tmp/Upgrade/busybox ] || die`; the capsule was rebuilt without
# it once and every other assert stayed green (measured 2026-11-09).
if [ -n "$CAP" ] && [ -f "/tmp/fwserve/$CAP" ]; then
  BBROW=$(tar -tvf "/tmp/fwserve/$CAP" 2>/dev/null | grep -E 'Upgrade/busybox$')
  case "$BBROW" in
    -rwx*Upgrade/busybox) ok "A11 capsule carries executable busybox ($(echo "$BBROW" | awk '{print $5}')B)" ;;
    "") bad "A11 capsule has NO Upgrade/busybox — installer dies on its first line" ;;
    *) bad "A11 busybox present but not executable ($BBROW)" ;;
  esac
else
  bad "A11 capsule file missing"
fi

# A10: the image plane the installer fetches from (IMG_URL is built from the same
# HOST/PORT pair, so a dead :8080 or short image is another silent stall)
IMGCL=$(curl -sS -A fss-probe/a10 -I --max-time 10 http://192.168.4.160:8080/img.bin 2>/dev/null \
        | tr -d '\r' | awk 'tolower($1)=="content-length:"{print $2}')
[ "$IMGCL" = "16777216" ] \
  && ok "A10 image plane serves the 16 MiB image" \
  || bad "A10 image plane broken (content-length=${IMGCL:-none}, want 16777216)"

echo "== readiness: $FAIL failures =="
exit $FAIL
