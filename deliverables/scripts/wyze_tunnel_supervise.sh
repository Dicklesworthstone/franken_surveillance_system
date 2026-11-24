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
LOG="${LOG:-/tmp/cloudflared_tunnel.log}"
PLIST="${PLIST:-/Library/LaunchDaemons/com.jeffreyemanuel.wyze-broker.plist}"
CF="${CF:-/opt/homebrew/bin/cloudflared}"
PLBUDDY="${PLBUDDY:-/usr/libexec/PlistBuddy}"

resolve_cap() {
  # Derive the served capsule filename from the broker plist's CAP_PATH so OTA_URL
  # can never drift onto an obsolete filename (such as 4.52.17.100.tar -> 404).
  if [ -n "${CAP:-}" ]; then
    echo "$CAP"
    return 0
  fi
  local cap_path=""
  if [ -x "$PLBUDDY" ] && [ -f "$PLIST" ]; then
    cap_path=$("$PLBUDDY" -c 'Print :EnvironmentVariables:CAP_PATH' "$PLIST" 2>/dev/null || true)
  elif [ -f "$PLIST" ]; then
    cap_path=$(python3 - "$PLIST" <<'PY' 2>/dev/null || true
import plistlib, sys
with open(sys.argv[1], "rb") as fh:
    doc = plistlib.load(fh)
print(doc.get("EnvironmentVariables", {}).get("CAP_PATH", ""))
PY
)
  fi
  if [ -n "$cap_path" ]; then
    basename "$cap_path"
  else
    echo "4.52.17.106.tar"
  fi
}

CAP="$(resolve_cap)"
if [ "${1:-}" = "--print-cap" ]; then
  echo "$CAP"
  exit 0
fi

log() { echo "$(date '+%H:%M:%S') $*"; }

: > "$LOG"
"$CF" tunnel --no-autoupdate --url http://localhost:9443 >> "$LOG" 2>&1 &
CFPID=$!
trap 'kill "$CFPID" 2>/dev/null || true' EXIT TERM INT

URL=""
for _ in $(seq 1 40); do
  URL=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$LOG" 2>/dev/null | tail -1)
  [ -n "$URL" ] && break
  kill -0 "$CFPID" 2>/dev/null || break
  sleep 1
done
if [ -z "$URL" ]; then
  log "FAILED: no hostname minted in 40s"
  kill "$CFPID" 2>/dev/null || true
  exit 1
fi
log "tunnel up: $URL"

NEW="$URL/$CAP"
CUR=$("$PLBUDDY" -c 'Print :EnvironmentVariables:OTA_URL' "$PLIST" 2>/dev/null || true)
if [ "$NEW" != "$CUR" ]; then
  if "$PLBUDDY" -c "Set :EnvironmentVariables:OTA_URL $NEW" "$PLIST" 2>/dev/null \
     || "$PLBUDDY" -c "Add :EnvironmentVariables:OTA_URL string $NEW" "$PLIST"; then
    log "delta URL updated -> broker reload"
    # kickstart alone does NOT re-read the plist: launchd keeps the
    # EnvironmentVariables it parsed at bootstrap, so the proxy would come back
    # holding the previous hostname (measured 2026-11-08). bootout+bootstrap is
    # the only reload that actually applies a plist edit.
    launchctl bootout system/com.jeffreyemanuel.wyze-broker 2>/dev/null || true
    # launchctl bootout tears down asynchronously on macOS; calling bootstrap
    # immediately races EIO/EBUSY and leaves wyze-broker unloaded. Wait for
    # teardown and retry bootstrap cleanly.
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      launchctl print system/com.jeffreyemanuel.wyze-broker >/dev/null 2>&1 || break
      sleep 0.5
    done
    bootstrapped=0
    for _ in 1 2 3 4 5; do
      if launchctl bootstrap system "$PLIST" 2>/dev/null; then
        bootstrapped=1
        break
      fi
      sleep 1
    done
    if [ "$bootstrapped" != 1 ]; then
      log "FAILED: launchctl bootstrap system $PLIST failed after retries — exiting so launchd KeepAlive retries"
      kill "$CFPID" 2>/dev/null || true
      exit 1
    fi
  else
    log "FAILED: could not write OTA_URL into $PLIST"
  fi
else
  log "delta URL already current, broker untouched"
fi

wait "$CFPID"
log "cloudflared exited, relaunching"
