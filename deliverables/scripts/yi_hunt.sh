#!/bin/bash
# yi_hunt.sh — one-pass Yi relocation hunt across the camera subnets (fss lane, 2026-10-28).
#
# What it does, in order, all read-only:
#   1. discovers the LAN interface + our IP on 192.168.4.0/22 (no hardcoded host IP);
#   2. sudo nmap -sn with MAC resolution on 192.168.4-7.0/24, listing every
#      Zowee-OUI (B0:D5:9D) host — the Yi's vendor — plus any host answering
#      the Yi fingerprint ports;
#   3. per subnet, nmap top-40 ports + targeted 23/80/554 TCP sweeps with -Pn
#      (Eero proxy-answers ICMP; -Pn avoids false "host down");
#   4. WS-Discovery directed probe (UDP 3702) to every candidate — the Yi's Y1
#      surface answers with the NetworkVideoTransmitter Scopes block
#      (EV-pack-H-006); a Google Home Mini does not answer 3702 at all, which
#      is exactly the .4.20 discriminator;
#   5. TUTK/TNP probe (UDP 32761, the 2018-era Yi port) to every candidate;
#   6. appends everything to docs/exploit/yi-hunt.log.md (the log IS the
#      deliverable — findings land in yi-runbook.md addenda, committed).
#
# Safety: single pass, no state changes, no device writes. ICMP/TCP/UDP probes only.
# Exit 0 always; the log records what happened.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
LOG="$REPO/docs/exploit/yi-hunt.log.md"
STAMP="$(date '+%Y-%m-%d %H:%M:%S %Z')"

log() { printf '%s\n' "$*" >> "$LOG"; }

# ── interface + host IP discovery (learnings: en0/en1 swap, IP churn) ──
IFACE="$(route -n get 192.168.4.1 2>/dev/null | awk '/interface:/{print $2; exit}')"
GW_NET="$(ipconfig getifaddr "$IFACE" 2>/dev/null | awk -F. '{print $1"."$2"."$3}')"
# host IP: the alias on the gateway's /24 (en0 holds several; ipconfig returns the first, which may be a /22 alias on a different broadcast domain)
MY_IP="$(ifconfig "$IFACE" 2>/dev/null | awk -v net="$GW_NET" '$1=="inet" && index($2, net".") == 1 {print $2; exit}')"

{
  echo
  echo "## Yi hunt — $STAMP (iface ${IFACE:-?}, host ${MY_IP:-?})"
} >> "$LOG"

if [ -z "$IFACE" ] || [ -z "$MY_IP" ]; then
  log "FATAL: could not resolve LAN interface/IP for 192.168.4.1 — not associated?"
  exit 0
fi
log "iface=$IFACE host=$MY_IP"

# ── 1. host discovery + MAC resolution, all four /24s ──
CANDIDATES="/tmp/yi_hunt_candidates.$$"
: > "$CANDIDATES"
for s in 4 5 6 7; do
  log "### subnet sweep 192.168.$s.0/24"
  # seed the kernel ARP cache first: MAC resolution in nmap -sn depends on fresh ARP,
  # and a cold cache silently drops hosts (measured: .4.20 vanished on a cold pass)
  ping -c1 -t1 -i0.2 "192.168.$s.255" >/dev/null 2>&1 || true
  sleep 1
  sudo -n nmap -sn "192.168.$s.0/24" 2>/dev/null \
    | awk '/scan report for/{ip=$5} /MAC Address:/{print ip"|"$3"|"$0}' \
    >> "$CANDIDATES"
  n=$(grep -c "192[.]168[.]$s[.]" "$CANDIDATES" 2>/dev/null || echo 0)
  n="${n%%$'\n'*}"
  log "resolved-mac hosts: $n"
done

# ── 2. Zowee-OUI (B0:D5:9D) hosts are primary candidates ──
log "### Zowee-OUI (B0:D5:9D) candidates"
grep "B0:D5:9D" "$CANDIDATES" | while IFS='|' read -r ip mac line; do
  log "YI-CANDIDATE $ip $mac"
  echo "$ip" >> "$CANDIDATES.zowee"
done
touch "$CANDIDATES.zowee"
log "zowee count: $(wc -l < "$CANDIDATES.zowee" | tr -d ' ')"

# ── 3. port sweeps: top-40 + targeted 23/80/554 on Zowee candidates and
#      on the known former addresses (they may have kept them) ──
TARGETS="$(sort -u "$CANDIDATES.zowee"; echo 192.168.6.156; echo 192.168.4.21)"
TARGETS="$(sort -u <<< "$TARGETS" | grep -v '^$')"
log "### port sweeps (nmap -Pn, top-40 + 23/80/554)"
for ip in $TARGETS; do
  log "-- $ip"
  top="$(sudo -n nmap -Pn --top-ports 40 --open "$ip" 2>/dev/null | grep -E '^[0-9]+/tcp' | tr '\n' '; ')"
  [ -n "$top" ] && log "   top-40 open: $top" || log "   top-40 open: none"
  tgt="$(sudo -n nmap -Pn -p 23,80,554 --open "$ip" 2>/dev/null | grep -E '^[0-9]+/tcp' | tr '\n' '; ')"
  [ -n "$tgt" ] && log "   23/80/554 open: $tgt" || log "   23/80/554 open: none"
done

# ── 4. WS-Discovery directed probe (Y1 discriminator) ──
WSDD_PROBE='<?xml version="1.0" encoding="UTF-8"?><e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dn="http://www.onvif.org/ver10/network/wsdl"><e:Header><wsa:MessageID xmlns:wsa="http://www.w3.org/2005/08/addressing">urn:uuid:fss-yi-hunt-1</wsa:MessageID><wsa:To xmlns:wsa="http://www.w3.org/2005/08/addressing">urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action xmlns:wsa="http://www.w3.org/2005/08/addressing">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action></e:Header><e:Body><d:Probe/></e:Body></e:Envelope>'
log "### WS-Discovery directed probes (UDP 3702, 5 s window each)"
for ip in $TARGETS; do
  reply="$(WSDD_PROBE="$WSDD_PROBE" python3 - "$ip" "$MY_IP" <<'PYEOF'
import socket, sys
ip, host = sys.argv[1], sys.argv[2]
msg = open('/dev/stdin').read() if False else None
import os
probe = os.environ.get('WSDD_PROBE', '')
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
try:
    # seed ARP first: macOS returns Errno 65 on send before ARP completes
    socket.create_connection((ip, 9), timeout=0.4).close()
except OSError:
    pass
try:
    s.sendto(probe.encode(), (ip, 3702))
    d, a = s.recvfrom(4096)
    hit = 'NetworkVideoTransmitter' in d.decode('utf-8', 'replace')
    print(f"REPLY from {a[0]} len={len(d)} nvt={hit}")
except OSError as e:
    print(f"no-reply ({e})")
PYEOF
)"
  log "$ip: $reply"
done

# ── 5. TUTK/TNP probe (UDP 32761, legacy Yi port) ──
log "### TUTK legacy probes (UDP 32761, 4 s window each)"
for ip in $TARGETS; do
  reply="$(python3 - "$ip" <<'PYEOF'
import socket, sys
ip = sys.argv[1]
# Yi 2018-era discovery datagram: p2p header probe (harmless, unauthenticated)
pkt = bytes.fromhex("f1300000")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
try:
    socket.create_connection((ip, 9), timeout=0.4).close()
except OSError:
    pass
try:
    s.sendto(pkt, (ip, 32761))
    d, a = s.recvfrom(2048)
    print(f"REPLY from {a[0]} len={len(d)} head={d[:16].hex()}")
except OSError as e:
    print(f"no-reply ({e})")
PYEOF
)"
  log "$ip: $reply"
done

# ── 6. verdict block ──
log "### verdict"
zowee_ips="$(cat "$CANDIDATES.zowee" 2>/dev/null | sort -u | tr '\n' ' ')"
log "zowee hosts seen: ${zowee_ips:-none}"
nvt_hits="$(grep -c 'nvt=True' "$LOG" || true)"
log "WSDD NetworkVideoTransmitter hits this run: see REPLY lines above"
log "next: any nvt=True host is the Yi — run the §30-second fingerprint from yi-runbook.md"

rm -f "$CANDIDATES" "$CANDIDATES.zowee" 2>/dev/null
echo "hunt complete; log: $LOG"
exit 0
