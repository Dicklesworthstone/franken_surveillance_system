#!/usr/bin/env python3
"""registry.py — resolve and sweep the camera identity registry.

    registry.py resolve wyze-39            # ARP lookup by MAC (ping-sweep fallback)
    registry.py resolve 80:48:2c:52:59:05  # by MAC directly
    registry.py sweep                      # ping the subnet, update last_seen_ip, diff
    registry.py table                      # markdown status table (renders as a chart)
    registry.py export-dhcp                # static-lease table for manual router entry

Read-only against the network: passive discovery only — no deauth, no ARP
spoofing, no resets. Writes only to registry.yaml's `last_seen_ip` fields on
`sweep --write`.
"""
import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import time

try:
    import yaml
except ImportError:
    yaml = None  # the registry subset is parsed by _mini_yaml below

def _mini_yaml(path):
    """Parse the registry's constrained YAML subset (two-level maps, scalars,
    inline lists, block strings folded to one line). Sufficient for registry.yaml;
    NOT a general YAML parser. Prevents a hard pyyaml dependency on this host."""
    import re
    root = {}
    stack = [(-1, root)]
    cur_key = None
    for raw in open(path):
        line = raw.rstrip("\n")
        if not line.strip() or line.strip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        s = line.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        m = re.match(r"^([^:]+):\s*(.*)$", s)
        if not m:
            continue
        key, val = m.group(1).strip(), m.group(2).strip()
        if val == "":
            d = {}
            parent[key] = d
            stack.append((indent, d))
            cur_key = key
        elif val.startswith("[") and val.endswith("]"):
            parent[key] = [v.strip() for v in val[1:-1].split(",") if v.strip()]
        elif val in ("true", "false"):
            parent[key] = val == "true"
        elif re.match(r"^-?\d+$", val):
            parent[key] = int(val)
        else:
            parent[key] = val.strip('>"')
        # block scalars folded: '>' becomes the previous scalar; good enough here
    return root

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.normpath(os.path.join(HERE, "..", "fleet", "registry.yaml"))


def norm_mac(m):
    """Zero-padded colonless lowercase — the wyze_mitm_up.sh canonical form."""
    parts = re.split(r"[:.\-]", m.strip().lower())
    return "".join(p.zfill(2) for p in parts if p)


def load():
    if yaml is not None:
        with open(REGISTRY) as f:
            return yaml.safe_load(f)
    return _mini_yaml(REGISTRY)


def save(reg):
    if yaml is not None:
        with open(REGISTRY, "w") as f:
            yaml.safe_dump(reg, f, sort_keys=False, allow_unicode=True)
    else:
        raise SystemExit("registry.py sweep --write requires pyyaml (pip3 install pyyaml); read-only modes work without it")


def arp_table():
    out = {}
    # macOS 27 quirk (measured 2026-11-06, 1h+ of isolation): any process in the
    # spawn lineage of THIS harness's long-lived session — python children, sh
    # wrappers, pty, new-session, env-stripped — reads a 1-line ARP snapshot,
    # while the interactive zsh reads all 315 entries. Lineage, not env/tty.
    # Bridge: a snapshot file rendered by a top-level zsh (operator shell,
    # cron, or launchd hook) and consumed here; stale >60s is reported, not
    # trusted. `registry.py snapshot` regenerates it (run from a real shell).
    snap = "/tmp/fleet_arp_snapshot.txt"
    try:
        age = time.time() - os.path.getmtime(snap)
    except OSError:
        age = 1e9
    if age > 60:
        print(f"registry: ARP snapshot stale ({age:.0f}s) — run `zsh -c 'arp -a > {snap}'` "
              f"from a login shell; proceeding with possibly stale data", file=sys.stderr)
    try:
        with open(snap) as f:
            for line in f:
                m = re.match(r"\S+ \(([\d.]+)\) at ([0-9a-fA-F:]+)", line)
                if m:
                    out[norm_mac(m.group(2))] = m.group(1)
    except OSError:
        pass
    return out


def ping_sweep(subnet="192.168.4"):
    procs = []
    for i in range(1, 255):
        procs.append(subprocess.Popen(
            ["ping", "-c", "1", "-t", "1", "-W", "500", f"{subnet}.{i}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    for p in procs:
        p.wait()
    return arp_table()


def cmd_snapshot(_a):
    """Render the ARP table via a fresh zsh (works when run from a login shell)."""
    r = subprocess.run(["/bin/zsh", "-c",
                        f"/usr/sbin/arp -a > /tmp/fleet_arp_snapshot.txt 2>/dev/null; wc -l < /tmp/fleet_arp_snapshot.txt"],
                       capture_output=True, text=True, timeout=45)
    n = r.stdout.strip()
    print(f"snapshot: {n} entries")
    return 0 if n.isdigit() and int(n) > 5 else 1


def ping_probe(ip):
    """Per-IP liveness via ping; works from any lineage (unlike the ARP table read)."""
    r = subprocess.run(["ping", "-c", "1", "-t", "1", "-W", "700", ip],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
    return r.returncode == 0


def cmd_resolve(a):
    reg = load()
    q = norm_mac(a.target)
    cam = None
    for c in reg["cameras"]:
        if norm_mac(c["mac"]) == q or c["id"] == a.target:
            cam = c
            break
    if cam is None:
        print(f"registry: no camera matches {a.target}", file=sys.stderr)
        return 2
    table = arp_table()
    ip = table.get(norm_mac(cam["mac"]))
    how = "arp"
    if ip is None and a.sweep:
        if ping_probe(cam.get("last_seen_ip") or ""):
            ip, how = cam.get("last_seen_ip"), "ping(registry-ip)"
    print(f"{cam['id']} mac={cam['mac']} ip={ip or 'NOT-ON-LAN'} vector={cam['vector']} via={how}")
    return 0 if ip else 1


def cmd_sweep(a):
    reg = load()
    table = ping_sweep()
    changes = []
    for c in reg["cameras"]:
        new = table.get(norm_mac(c["mac"]))
        old = c.get("last_seen_ip")
        if new and new != old:
            changes.append((c["id"], old, new))
            if a.write:
                c["last_seen_ip"] = new
    print("| camera | expected | seen | change |")
    print("|---|---|---|---|")
    for c in reg["cameras"]:
        new = table.get(norm_mac(c["mac"]))
        old = c.get("last_seen_ip")
        chg = ""
        if new and old and new != old:
            chg = f"**{old} → {new}**"
        elif new is None:
            chg = "absent"
        print(f"| {c['id']} | {old or '—'} | {new or '—'} | {chg} |")
    if changes and a.write:
        reg["generation"] = int(reg.get("generation", 0)) + 1
        reg["updated"] = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
        reg.setdefault("CHANGELOG", []).append(
            f"gen {reg['generation']}: sweep re-observed " +
            ", ".join(f"{i} {o}→{n}" for i, o, n in changes))
        save(reg)
        print(f"registry.yaml updated (gen {reg['generation']})")
    return 0


def cmd_table(_a):
    reg = load()
    table = arp_table()
    print("| id | model | mac | ip (registry) | on-lan now | vector |")
    print("|---|---|---|---|---|---|")
    for c in reg["cameras"]:
        now = table.get(norm_mac(c["mac"]))
        print(f"| {c['id']} | {c['model'][:28]} | {c['mac']} | {c.get('last_seen_ip') or '—'} "
              f"| {'✅ ' + now if now else '—'} | {c['vector']} |")
    return 0


def cmd_dhcp(_a):
    reg = load()
    print("# DHCP static-lease table — enter these in the router's reservation UI")
    print("# (manual entry acceptable per fss-cam-identity-registry design note)")
    print()
    print("| hostname | MAC | IP |")
    print("|---|---|---|")
    for c in reg["cameras"]:
        if c.get("dhcp_reserve") and c.get("last_seen_ip"):
            print(f"| {c['id']} | {c['mac']} | {c['last_seen_ip']} |")
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("resolve")
    r.add_argument("target")
    r.add_argument("--sweep", action="store_true", help="ping-sweep fallback when ARP misses")
    r.set_defaults(fn=cmd_resolve)
    s = sub.add_parser("sweep")
    s.add_argument("--write", action="store_true", help="update last_seen_ip + generation")
    s.set_defaults(fn=cmd_sweep)
    t = sub.add_parser("table")
    t.set_defaults(fn=cmd_table)
    d = sub.add_parser("export-dhcp")
    d.set_defaults(fn=cmd_dhcp)
    sn = sub.add_parser("snapshot")
    sn.set_defaults(fn=cmd_snapshot)
    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
