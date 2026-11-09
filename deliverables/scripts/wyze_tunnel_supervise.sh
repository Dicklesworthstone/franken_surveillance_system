#!/bin/bash
# Keep a cert-valid public URL in front of the capsule server, and keep the
# broker's OTA_URL pointing at it.
#
# The camera's OTA downloader verifies TLS strictly (VERIFYHOST=2 + its own
# CAINFO) and rejects the forged eMudhra chain the s3 origin serves, so the
# tunnel is load-bearing, not a convenience. Quick tunnels mint a NEW hostname
# on every start, which silently invalidates any URL written into the delta
# earlier. This wrapper therefore re-injects the hostname after each start and
# restarts the broker only when the URL actually changed.
#
# launchd KeepAlive supervises this; cloudflared itself is waited on so a
# crash loops back through a fresh URL injection.
set -u
LOG=/tmp/cloudflared_tunnel.log
PLIST=/Library/LaunchDaemons/com.jeffreyemanuel.wyze-broker.plist
CAP=4.52.17.100.tar
CF=/opt/homebrew/bin/cloudflared

log() { echo "$(date '+%H:%M:%S') $*"; }

: > "$LOG"
"$CF" tunnel --no-autoupdate --url http://localhost:9443 >> "$LOG" 2>&1 &
CFPID=$!

URL=""
for _ in $(seq 1 40); do
  URL=$(grep -oE 'https://[a-z-]+\.trycloudflare\.com' "$LOG" 2>/dev/null | tail -1)
  [ -n "$URL" ] && break
  sleep 1
done
if [ -z "$URL" ]; then
  log "FAILED: no hostname minted in 40s"
  kill "$CFPID" 2>/dev/null
  exit 1
fi
log "tunnel up: $URL"

NEW="$URL/$CAP"
CUR=$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:OTA_URL' "$PLIST" 2>/dev/null)
if [ "$NEW" != "$CUR" ]; then
  if /usr/libexec/PlistBuddy -c "Set :EnvironmentVariables:OTA_URL $NEW" "$PLIST"; then
    log "delta URL updated -> broker reload"
    # kickstart alone does NOT re-read the plist: launchd keeps the
    # EnvironmentVariables it parsed at bootstrap, so the proxy would come back
    # holding the previous hostname (measured 2026-11-08). bootout+bootstrap is
    # the only reload that actually applies a plist edit.
    launchctl bootout system/com.jeffreyemanuel.wyze-broker 2>/dev/null
    launchctl bootstrap system "$PLIST"
  else
    log "FAILED: could not write OTA_URL into $PLIST"
  fi
else
  log "delta URL already current, broker untouched"
fi

wait "$CFPID"
log "cloudflared exited, relaunching"
