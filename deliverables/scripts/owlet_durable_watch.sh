#!/bin/sh
# Owlet durable watch (launchd KeepAlive): the operator closes the app; everything else
# is automatic. One cycle every 60s:
#   1. relay watcher, one bounded 60s passive capture (3478 keepalives)
#   2. oracle ring, one rolling 90s window on the camera's ports (grant-trace capture)
#   3. a mint->probe->ACK->0x06E3 fire attempt ONLY when the just-finished capture saw a
#      60s-quiet window (the fss-kemuu precondition) — never fire on top of active relay
#      traffic
# Logs: /tmp/owlet_relay_watch.log (watcher), /tmp/owlet_oracle/ (ring + decode).
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
export PATH
CAM=192.168.4.163
HERE=/Users/jemanuel/projects/franken_surveillance_system/deliverables/scripts
ORACLE=/tmp/owlet_oracle
mkdir -p "$ORACLE"

while true; do
  # 1. one bounded passive capture (tcpdump needs root); fire ONLY on an observed
  # zero-window ("RELAY IDLE") — a silent camera (ARP unstable) is NOT evidence the
  # relay slot is free, and firing then would only produce wake-probe noise.
  OUT=$(sudo -n python3 "$HERE/owlet_relay_watch.py" watch --window 60 --attempts 1 2>&1)
  echo "$OUT" | tail -1 >> /tmp/owlet_relay_watch.log
  case "$OUT" in
    *"RELAY IDLE"*) FIRE=1 ;;
    *) FIRE=0 ;;
  esac

  # 2. oracle ring window (passive, full snaplen, bounded)
  timeout 92 tcpdump -n -i en1 -s 0 -U -w "$ORACLE/ring_now.pcapng" \
    "host $CAM and (udp port 63616 or udp port 3478 or udp port 32761)" 2>/dev/null
  if [ -s "$ORACLE/ring_now.pcapng" ]; then
    # decode + flag non-0x0602 camera frames into the watch log
    sudo -n python3 "$HERE/owlet_oracle_watch.py" --minutes 1 >/dev/null 2>&1
  fi

  # 3. root attempt whenever the camera is present (own liveness gate; silent exit if
  #    absent) — this is the priority chain: mint->probe->ACK->0x06E3->avClientStart
  sudo -n "$HERE/owlet_root_attempt.sh" >> /tmp/owlet_relay_watch.log 2>&1

  # 4. the RELAY IDLE gated fire (idle-window precondition lane) unchanged
  if [ "$FIRE" = "1" ]; then
    sudo -n python3 "$HERE/owlet_relay_watch.py" fire --force >> /tmp/owlet_relay_watch.log 2>&1
  fi

  sleep 60
done
