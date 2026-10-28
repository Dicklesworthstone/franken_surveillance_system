#!/bin/bash
# Sensor-variant probe for the Wyze v4 fleet — reads the image sensor's i2c
# address through the unit's root shell and maps it to the thingino image to
# flash. The variant is NOT decidable host-side (wyze_flash_preflight.sh §9
# WARN refuses to guess): the vendor image ships both /etc/sensor blobs and
# probes at runtime; thingino bakes the choice into /etc/modules.d/30-sensor,
# so a wrong pick boots blind (recoverable by re-serving the other capsule,
# but it burns a power cycle).
#
# Address map (iCamera's descriptor table; same map the preflight warns with):
#   0x29 -> gc4653   (image: thingino_gc4653.bin, chip-header byte @0x9 = 0x40)
#   0x3c -> os04d10  (image: thingino_os04d10.bin, chip-header byte @0x9 = 0x52)
#
# The probe runs over the established root shell on port 4444 (the
# tapo_post.py cmd() pattern: one connection per command, bounded read) —
# it reads, it never writes: no i2cset, no flash, no config change.
#
# Usage:
#   wyze_sensor_probe.sh <camera-ip> [--shell-port 4444] [--json]
#   SHELL_CMD="cat /tmp/fake-console" wyze_sensor_probe.sh - --json   # self-test
#
# Exit 0 = variant decided and printed (last line: VARIANT=<name>).
# Exit 1 = shell unreachable or both probes empty. Exit 2 = usage.
set -u

CAM="${1:--}"
SHELL_PORT="${SHELL_PORT:-4444}"
[ "${2:-}" = "--shell-port" ] && { SHELL_PORT="${3:-4444}"; shift 2; }
JSON=0
for a in "$@"; do [ "$a" = "--json" ] && JSON=1; done

# The i2c read: enumerate the adapter the sensor sits on, then read one byte
# per candidate address. Read-only (`i2cdetect`/`i2cget` never write; a probe
# of an absent address just NACKs). /dev/i2c-0 is the sensor bus on T41NQ
# builds; 1..2 are swept in case the base image maps it differently.
# shellcheck disable=SC2016  # the $(...) must reach the remote shell unexpanded
I2C_PROBE='$
for d in /dev/i2c-0 /dev/i2c-1 /dev/i2c-2; do
  [ -e "$d" ] || continue
  for addr in 0x29 0x3c; do
    v=$(i2cget "${d#*/dev/}" "$addr" 2>/dev/null) && echo "HIT ${d} $addr $v"
  done
done
echo PROBE-DONE'

GC4653_ADDR="0x29"
OS04D10_ADDR="0x3c"

# Run the probe through the root shell. Default: a real TCP shell on 4444
# (tapo_post.py cmd() shape — one connection, bounded read). Override with
# SHELL_CMD for testing: it receives the probe script on stdin and its stdout
# is parsed identically.
run_probe() {
  if [ -n "${SHELL_CMD:-}" ]; then
    printf '%s\n' "$I2C_PROBE" | sh -c "$SHELL_CMD"
    return
  fi
  [ "$CAM" = "-" ] && { echo "usage: wyze_sensor_probe.sh <camera-ip>"; return 2; }
  python3 - "$CAM" "$SHELL_PORT" <<'PY'
import socket, sys, time
host, port = sys.argv[1], int(sys.argv[2])
script = sys.stdin.read()
try:
    s = socket.create_connection((host, port), timeout=5)
    s.settimeout(6)
    s.sendall((script + "\n").encode())
    time.sleep(1.0)
    out = b""
    while True:
        try:
            d = s.recv(4096)
        except socket.timeout:
            break
        if not d:
            break
        out += d
    sys.stdout.write(out.decode("latin1", "replace"))
except OSError as e:
    sys.stderr.write("shell connect failed: %s\n" % e)
    sys.exit(3)
PY
}

OUT=$(run_probe) || { echo "FAIL probe transport"; exit 1; }
echo "$OUT"

GC4653_HIT=$(printf '%s\n' "$OUT" | awk -v a="$GC4653_ADDR" '$1=="HIT" && $3==a {print $2; exit}')
OS04D10_HIT=$(printf '%s\n' "$OUT" | awk -v a="$OS04D10_ADDR" '$1=="HIT" && $3==a {print $2; exit}')
DONE=$(printf '%s\n' "$OUT" | grep -c PROBE-DONE)

if [ "$DONE" -eq 0 ]; then
  echo "FAIL probe script did not complete (no PROBE-DONE)"
  exit 1
fi

VARIANT=""
if [ -n "$GC4653_HIT" ]; then
  VARIANT=gc4653
  BUS="$GC4653_HIT"
elif [ -n "$OS04D10_HIT" ]; then
  VARIANT=os04d10
  BUS="$OS04D10_HIT"
fi

if [ -z "$VARIANT" ]; then
  echo "FAIL neither i2c address answered (unit asleep/wedged, or the sensor bus is mapped elsewhere — read PROBE output above)"
  exit 1
fi

if [ "$JSON" = 1 ]; then
  printf '{"variant":"%s","i2c_addr":"%s","bus":"%s","image":"thingino_%s.bin","chip_header_byte":"%s"}\n' \
    "$VARIANT" \
    "$([ "$VARIANT" = gc4653 ] && echo 0x29 || echo 0x3c)" \
    "$BUS" "$VARIANT" \
    "$([ "$VARIANT" = gc4653 ] && echo 0x40 || echo 0x52)"
else
  echo "sensor on $BUS -> $VARIANT (per-unit mapping: record it in FLASH-DAY-RUNBOOK.md §0.2)"
fi
echo "VARIANT=$VARIANT"
exit 0
