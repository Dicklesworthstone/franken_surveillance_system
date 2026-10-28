#!/usr/bin/env python3
"""owlet_relay_session_map.py — passive 3478 cadence statistics + quiet-window prediction.

WindyJay wave-3 (bead fss-pb9cj thread): the Owlet relay registration has held the
single-client slot for 4+ h with no observed idle window. The camera refreshes its STUN
registration on a duty cycle (24 B keepalives every ~60 s to 3 peers, plus 4 B
re-checks every ~10 s — the §9.8 baseline pattern). This tool measures that cadence
passively over a bounded window and predicts when a registration GAP is likely — the
moment a minted-credential session can fire into the slot (runbook §9.10).

What it does, purely passive (one wake-pulse LAN probe at start to defeat duty-cycle
silence; that probe is the §9.9.4 liveness primitive and opens no session):

  1. N x WINDOW-second tcpdump windows on the camera's 3478 traffic (default
     10 windows x 60 s = 10 min), each timestamped, packet sizes + peer + direction
     recorded. External `timeout` on tcpdump so a silent camera cannot hang the pass
     (the §9.9.4 lesson).
  2. Inter-arrival statistics: mean/median/p95 of the gap between camera-sourced
     packets; packet-size histogram (24 B = keepalive, 4 B = re-check, other =
     session/AV traffic); per-peer counts.
  3. Cadence classification: the dominant 24 B period and the 4 B period, plus a
     "registration healthy" verdict per window (>= expected keepalives seen).
  4. Quiet-window prediction: a probability-of-quiet curve over the minute-of-hour
     and second-of-period, derived from where the observed gaps cluster relative to
     the keepalive period — the gap between consecutive 24 B keepalives is the only
     structurally quiet moment; anything longer than keepalive_period + margin
     without traffic indicates a lapsed or re-registering unit (PIR wake events
     reset the cycle, so the curve is per-observation, not absolute).
  5. Recommended watcher cadence: the poll interval that maximizes the chance of
     catching a lapsed registration given the measured p95 gap — written to
     docs/exploit/owlet-relay-cadence.md together with the curve data.

Output: human-readable report to stdout AND an append to
docs/exploit/owlet-relay-cadence.md (the committed log IS the deliverable).
Exit 0 always; every failure mode is recorded, never thrown.

Usage:
  sudo python3 owlet_relay_session_map.py [--windows 10] [--window 60] [--iface en0]
      [--host-ip auto] [--out docs/exploit/owlet-relay-cadence.md]
"""
import argparse
import datetime
import os
import re
import select
import statistics
import subprocess
import sys
import time

CAM_IP = "192.168.4.163"
CAM_MAC = "38:01:46:AB:83:8A"
RELAY_PEERS = ("14.1.31.34", "64.74.160.146", "66.23.205.210")
LAN_SEARCH_PORT = 63616
KEEPALIVE_SIZE = 24      # B — STUN binding request (§9.8 baseline)
RECHECK_SIZE = 4         # B — short re-check
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
DEFAULT_OUT = os.path.join(REPO, "docs", "exploit", "owlet-relay-cadence.md")


def ts() -> str:
    return datetime.datetime.now().isoformat(timespec="milliseconds")


def iface_and_ip() -> tuple[str, str]:
    """Resolve the LAN interface + the host IP on the camera's /24 (measured: en0
    holds 3 aliases; ipconfig's first answer can be a /22 alias on another broadcast
    domain — pick the one sharing the camera's /24 prefix)."""
    out = subprocess.run(["route", "-n", "get", CAM_IP], capture_output=True, text=True).stdout
    m = re.search(r"interface:\s+(\S+)", out)
    iface = m.group(1) if m else "en0"
    ip_out = subprocess.run(["ifconfig", iface], capture_output=True, text=True).stdout
    prefix = ".".join(CAM_IP.split(".")[:3])
    for line in ip_out.splitlines():
        f = line.split()
        if f and f[0] == "inet" and f[1].startswith(prefix + "."):
            return iface, f[1]
    return iface, ""


def arp_present() -> str | None:
    out = subprocess.run(["sudo", "-n", "arp", "-an"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if CAM_IP in line and "incomplete" not in line:
            m = re.search(r"at ([0-9a-fA-F:]+)", line)
            return m.group(1) if m else "?"
    return None


def wake_pulse(my_ip: str, iface: str):
    """One LAN-search probe on 63616 — the §9.9.4 liveness primitive. Harmless:
    wakes the LAN-search responder without opening a session. Sends the unencoded
    f1 30 00 00 ping used by the subtype sweep (camera answers from an ephemeral port)."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(bytes.fromhex("f1300000"), (CAM_IP, LAN_SEARCH_PORT))
        s.recvfrom(2048)
        return True
    except OSError:
        return False
    finally:
        s.close()


def capture_window(iface: str, window: float, my_ip: str):
    """One tcpdump window on the camera's 3478 traffic. Returns a list of events:
    (t_rel, size, direction, peer) with t_rel seconds from window start."""
    peers = " or ".join(f"host {p}" for p in RELAY_PEERS)
    filt = f"udp port 3478 and src host {CAM_IP} and ({peers})"
    cmd = ["sudo", "-n", "timeout", str(int(window) + 5),
           "tcpdump", "-n", "-l", "-i", iface, "-e", filt]
    events = []
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    except FileNotFoundError:
        return None
    t0 = time.time()
    fd = p.stdout.fileno()
    try:
        while time.time() - t0 < window:
            ready, _, _ = select.select([fd], [], [], min(0.5, window - (time.time() - t0)))
            if not ready:
                continue
            line = p.stdout.readline()
            if not line:
                if p.poll() is not None:
                    break
                continue
            # -e lines: "<ts> <srcmac> > <dstmac>, ethertype IPv4 (0x0800), length 60: 192.168.4.163.p > peer.3478: UDP, length 4"
            # the LAST "length N" before the colon is the wire frame; the UDP length is
            # the one after "UDP," — we want the UDP payload length (24/4 classification).
            m = re.search(r"UDP, length (\d+)", line)
            if not m:
                continue
            pm = re.search(r"192\.168\.4\.163\.\d+ > (\d+\.\d+\.\d+\.\d+)\.3478", line)
            peer = pm.group(1) if pm else "?"
            events.append((time.time() - t0, int(m.group(1)), "out", peer))
    finally:
        p.terminate()
        try:
            p.wait(2)
        except subprocess.TimeoutExpired:
            p.kill()
    return events


def classify(events, window):
    """Cadence statistics + classification for one window's events."""
    sizes = [e[1] for e in events]
    gaps = [round(events[i][0] - events[i - 1][0], 3) for i in range(1, len(events))]
    gap_kinds = []
    for i in range(1, len(events)):
        s0, s1 = events[i - 1][1], events[i][1]
        if s0 == KEEPALIVE_SIZE or s1 == KEEPALIVE_SIZE:
            gap_kinds.append(("ka", gaps[i - 1]))
        elif s0 == RECHECK_SIZE and s1 == RECHECK_SIZE:
            gap_kinds.append(("rc", gaps[i - 1]))
        else:
            gap_kinds.append(("other", gaps[i - 1]))
    ka = sizes.count(KEEPALIVE_SIZE)
    rc = sizes.count(RECHECK_SIZE)
    other = len(sizes) - ka - rc
    return {
        "n": len(events),
        "ka": ka, "rc": rc, "other": other,
        "gaps": gaps,
        "gap_kinds": gap_kinds,
        "ka_gaps": [g for k, g in gap_kinds if k == "ka"],
        "rc_gaps": [g for k, g in gap_kinds if k == "rc"],
        "gap_mean": round(statistics.mean(gaps), 2) if gaps else None,
        "gap_median": round(statistics.median(gaps), 2) if gaps else None,
        "gap_max": round(max(gaps), 2) if gaps else None,
        "silent": len(events) == 0,
    }


def quiet_probability(all_stats, keepalive_period):
    """Probability-of-quiet curve: for each second-offset into the keepalive period,
    the fraction of observed inter-keepalive gaps that were still open at that offset
    (i.e. no keepalive arrived in [offset, offset+1)). Structural quiet = the tail of
    the gap distribution; the curve is empirical, not parametric."""
    if not all_stats["ka_gaps"]:
        return []
    g = all_stats["ka_gaps"]
    # floor the horizon at max observed gap + 1 s; the 3x-period cap only applies when
    # the period is meaningful (a doublet-dominated median of 0 s must not collapse it)
    horizon = max(int(max(g)) + 1, 5)
    cap = int(keepalive_period * 3) if keepalive_period >= 5 else horizon
    maxg = min(horizon, cap)
    curve = []
    for off in range(0, maxg):
        # P(quiet at offset) = P(a gap covers [off, off+1)) — survivor function
        survivors = sum(1 for x in g if x > off + 1)
        curve.append((off, round(survivors / len(g), 3)))
    return curve


def recommend_cadence(all_stats, keepalive_period):
    """Watcher poll interval: to catch a lapsed registration you must poll at least
    twice inside the smallest structurally quiet interval. With no observed lapse,
    the recommended cadence is keepalive_period / 2 (Nyquist on the refresh)."""
    p95 = (sorted(all_stats["ka_gaps"])[int(0.95 * len(all_stats["ka_gaps"]))]
           if all_stats["ka_gaps"] else keepalive_period)
    return round(keepalive_period / 2, 1), round(p95, 2)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--windows", type=int, default=10)
    ap.add_argument("--window", type=float, default=60)
    ap.add_argument("--iface", default=None)
    ap.add_argument("--out", default=DEFAULT_OUT)
    a = ap.parse_args()

    iface, my_ip = (a.iface, "") if a.iface else iface_and_ip()
    if not my_ip:
        _, my_ip = iface_and_ip()

    lines = []
    lines.append("")
    lines.append(f"## Cadence session — {ts()} (iface {iface}, host {my_ip or '?'})")
    mac = arp_present()
    lines.append(f"ARP at start: {mac or 'ABSENT (will wake-pulse)'}")
    if not mac:
        if wake_pulse(my_ip, iface):
            lines.append("wake-pulse: nO received — responder alive, continuing")
        else:
            lines.append("wake-pulse: no nO — camera likely duty-cycled out; results may be empty")
    else:
        lines.append("wake-pulse: skipped (ARP present; staying fully passive)")

    stats = []
    raw_events = []
    for i in range(a.windows):
        ev = capture_window(iface, a.window, my_ip)
        if ev is None:
            lines.append(f"window {i+1}/{a.windows}: tcpdump missing — aborting pass")
            break
        raw_events.extend(ev)
        c = classify(ev, a.window)
        c["t"] = ts()
        stats.append(c)
        lines.append(
            f"window {i+1}/{a.windows} @ {c['t']}: n={c['n']} ka24={c['ka']} rc4={c['rc']} "
            f"other={c['other']} silent={c['silent']} "
            f"gap mean/med/max = {c['gap_mean']}/{c['gap_median']}/{c['gap_max']}")

    # true keepalive-to-keepalive gaps (either neighbor is a 24 B keepalive) feed the
    # curve; all-gap stats recorded for context.
    all_gaps = [g for c in stats for g in c["gaps"] if g is not None]
    ka_gaps = [g for c in stats for g in c["ka_gaps"]]

    n_total = sum(c["n"] for c in stats)
    ka_total = sum(c["ka"] for c in stats)
    rc_total = sum(c["rc"] for c in stats)
    silent_windows = sum(1 for c in stats if c["silent"])

    # dominant keepalive period: the median of *non-burst* ka gaps (gaps > 1 s — the
    # sub-second gaps are intra-burst doublet spacing, not the cycle). Fallbacks:
    # any-gap median, then the §9.8 nominal 60 s.
    ka_cycle_gaps = [g for g in ka_gaps if g > 1.0]
    period = (round(statistics.median(ka_cycle_gaps), 2) if ka_cycle_gaps
              else round(statistics.median(all_gaps), 2) if all_gaps else 60.0)
    burst_median = round(statistics.median([g for g in ka_gaps if g <= 1.0]), 3) if any(g <= 1.0 for g in ka_gaps) else None
    curve = quiet_probability({"ka_gaps": ka_gaps or all_gaps}, period)
    cadence, p95 = recommend_cadence({"ka_gaps": ka_gaps or all_gaps}, period)

    lines.append("### aggregate")
    lines.append(f"windows={len(stats)}/{a.windows} pkts={n_total} ka24={ka_total} rc4={rc_total} "
                 f"silent_windows={silent_windows}")
    peers = {}
    for _, _, _, peer in raw_events:
        peers[peer] = peers.get(peer, 0) + 1
    if peers:
        lines.append("per-peer pkts: " + ", ".join(f"{p}={n}" for p, n in sorted(peers.items(), key=lambda kv: -kv[1])))
    lines.append(f"dominant keepalive period (median non-burst ka gap): {period}s; "
                 f"intra-burst doublet median: {burst_median if burst_median is not None else 'n/a'}s; "
                 f"p95 gap: {p95}s")
    if silent_windows:
        lines.append(f"NOTE: {silent_windows} window(s) fully silent — registration lapsed at "
                     f"least once during the pass (those timestamps are your quiet windows).")
    lines.append("")
    lines.append("### probability-of-quiet curve (empirical survivor function over gap offsets)")
    lines.append("")
    lines.append("```svg")
    lines.append(f'<svg viewBox="0 0 720 {40 + len(curve) * 0 + 160}" xmlns="http://www.w3.org/2000/svg" font-family="monospace" font-size="12">')
    if curve:
        W, H = 660, 110
        x0, y0 = 40, 20
        maxx = max(o for o, _ in curve) or 1
        pts = " ".join(
            f"{x0 + (o / maxx) * W:.1f},{y0 + (1 - p) * H:.1f}" for o, p in curve
        )
        lines.append(f'  <polyline points="{pts}" fill="none" stroke="var(--accent)" stroke-width="2"/>')
        lines.append(f'  <line x1="{x0}" y1="{y0 + H}" x2="{x0 + W}" y2="{y0 + H}" stroke="var(--border)"/>')
        lines.append(f'  <line x1="{x0}" y1="{y0}" x2="{x0}" y2="{y0 + H}" stroke="var(--border)"/>')
        for frac in (0.0, 0.5, 1.0):
            yy = y0 + frac * H
            lines.append(f'  <line x1="{x0}" y1="{yy:.0f}" x2="{x0 + W}" y2="{yy:.0f}" stroke="var(--border)" stroke-dasharray="2 4"/>')
            lines.append(f'  <text x="4" y="{yy + 4:.0f}" fill="var(--muted)">{1 - frac:.1f}</text>')
        for frac in (0.0, 0.5, 1.0):
            xx = x0 + frac * W
            lines.append(f'  <text x="{xx:.0f}" y="{y0 + H + 16}" fill="var(--muted)">{frac * maxx:.0f}s</text>')
        lines.append(f'  <text x="{x0 + W / 2}" y="{y0 + H + 34}" text-anchor="middle" fill="var(--fg)">offset into keepalive gap (s) → P(quiet)</text>')
    else:
        lines.append('  <text x="40" y="60" fill="var(--muted)">no gaps observed</text>')
    lines.append("</svg>")
    lines.append("```")
    lines.append("")
    lines.append("### recommended watcher cadence")
    lines.append(f"poll every **{cadence}s** (half the dominant {period}s keepalive period — Nyquist "
                 f"on the refresh; catches a lapse within one period). Current p95 gap {p95}s means "
                 f"an idle window longer than that is structurally significant, not noise.")
    lines.append("")
    lines.append(f"(log: this file; tool: deliverables/scripts/owlet_relay_session_map.py)")

    report = "\n".join(lines)
    print(report)
    try:
        with open(a.out, "a") as f:
            f.write(report + "\n")
    except OSError as e:
        print(f"(could not append to {a.out}: {e})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
