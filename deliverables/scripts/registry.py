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

def _strip_yaml_comment(s: str) -> str:
    """Strip an unquoted `# ...` comment from a YAML scalar line."""
    in_quote = None
    escaped = False
    for idx, ch in enumerate(s):
        if escaped:
            escaped = False
            continue
        if in_quote == '"' and ch == "\\":
            escaped = True
            continue
        if in_quote:
            if ch == in_quote:
                in_quote = None
            continue
        if ch in ('"', "'"):
            in_quote = ch
        elif ch == "#" and (idx == 0 or s[idx - 1].isspace()):
            return s[:idx].rstrip()
    return s.rstrip()


def _parse_yaml_scalar(val: str):
    val = _strip_yaml_comment(val).strip()
    if val in ("", "null", "Null", "NULL", "~"):
        return None
    if val in ("true", "True", "TRUE"):
        return True
    if val in ("false", "False", "FALSE"):
        return False
    if val.startswith("[") and val.endswith("]"):
        inner = val[1:-1].strip()
        if not inner:
            return []
        return [_parse_yaml_scalar(part.strip()) for part in inner.split(",") if part.strip()]
    if val.startswith("{") and val.endswith("}"):
        inner = val[1:-1].strip()
        if not inner:
            return {}
        out = {}
        for part in inner.split(","):
            if ":" in part:
                k, v = part.split(":", 1)
                out[k.strip().strip("\"'")] = _parse_yaml_scalar(v)
        return out
    if (val.startswith('"') and val.endswith('"') and len(val) >= 2):
        # Unescape standard double-quoted YAML escapes
        try:
            return json.loads(val)
        except ValueError:
            return val[1:-1]
    if (val.startswith("'") and val.endswith("'") and len(val) >= 2):
        return val[1:-1].replace("''", "'")
    if re.match(r"^-?\d+$", val):
        return int(val)
    return val


def _mini_yaml(path):
    """Parse the registry's constrained YAML subset (nested maps, block lists of
    strings or maps, inline lists, folded/literal block scalars, multiline quoted
    strings). Matches yaml.safe_load on deliverables/fleet/registry.yaml without
    requiring pyyaml."""
    with open(path, encoding="utf-8") as fh:
        raw_lines = [ln.rstrip("\r\n") for ln in fh]

    def _next_significant(start_idx: int):
        for j in range(start_idx, len(raw_lines)):
            st = raw_lines[j].strip()
            if st and not st.startswith("#"):
                return j, len(raw_lines[j]) - len(raw_lines[j].lstrip()), st
        return None, -1, ""

    def _collect_multiline_double_quoted(first_val: str, start_idx: int):
        buf = first_val[1:]
        i = start_idx + 1
        while i < len(raw_lines):
            chunk = raw_lines[i].strip()
            if chunk.endswith('"') and not chunk.endswith('\\"'):
                end_part = chunk[:-1]
                buf = (buf + " " + end_part) if (buf and end_part) else (buf + end_part)
                try:
                    return json.loads('"' + buf + '"'), i
                except ValueError:
                    return buf, i
            buf = (buf + " " + chunk) if (buf and chunk) else (buf + chunk)
            i += 1
        return buf, i - 1

    def _collect_multiline_single_quoted(first_val: str, start_idx: int):
        # YAML single-quoted multiline scalar: '' is escaped single quote; empty lines become \n.
        lines_buf = [first_val[1:]]
        i = start_idx + 1
        while i < len(raw_lines):
            chunk = raw_lines[i].strip()
            # Count trailing single quotes: odd number means closing quote
            trailing_q = len(chunk) - len(chunk.rstrip("'"))
            if trailing_q % 2 == 1:
                lines_buf.append(chunk[:-1])
                break
            lines_buf.append(chunk)
            i += 1
        # Fold YAML single-quoted lines: non-empty consecutive lines join with space,
        # blank lines become '\n'.
        out_parts = []
        blank_run = 0
        for part in lines_buf:
            if part == "":
                blank_run += 1
            else:
                if out_parts:
                    if blank_run > 0:
                        out_parts.append("\n" * blank_run)
                    else:
                        out_parts.append(" ")
                out_parts.append(part)
                blank_run = 0
        if blank_run > 0:
            out_parts.append("\n" * blank_run)
        return "".join(out_parts).replace("''", "'"), min(i, len(raw_lines) - 1)

    def _collect_multiline_plain(first_val: str, key_indent: int, start_idx: int):
        parts = [first_val]
        i = start_idx + 1
        while i < len(raw_lines):
            raw = raw_lines[i]
            st = raw.strip()
            if not st or st.startswith("#"):
                break
            ind = len(raw) - len(raw.lstrip())
            if ind <= key_indent or st.startswith("- ") or re.match(r'^[^:#][^:]*?:\s', st):
                break
            parts.append(_strip_yaml_comment(st).strip())
            i += 1
        return " ".join(parts), i - 1

    def _collect_block_scalar(mode: str, parent_indent: int, start_idx: int):
        lines_out = []
        i = start_idx + 1
        block_indent = None
        while i < len(raw_lines):
            raw = raw_lines[i]
            if not raw.strip():
                lines_out.append("")
                i += 1
                continue
            ind = len(raw) - len(raw.lstrip())
            if ind <= parent_indent:
                break
            if block_indent is None:
                block_indent = ind
            lines_out.append(raw[min(ind, block_indent):])
            i += 1
        while lines_out and lines_out[-1] == "":
            lines_out.pop()
        if mode.startswith(">"):
            text = " ".join(ln.strip() for ln in lines_out if ln.strip())
        else:
            text = "\n".join(lines_out)
        if not mode.endswith("-"):
            text += "\n"
        return text, i - 1

    def _parse_value(raw_val: str, key_indent: int, idx: int):
        val_nc = _strip_yaml_comment(raw_val).strip()
        if val_nc in (">", ">-", "|", "|-"):
            return _collect_block_scalar(val_nc, key_indent, idx)
        if val_nc.startswith('"') and not (len(val_nc) >= 2 and val_nc.endswith('"') and not val_nc.endswith('\\"')):
            return _collect_multiline_double_quoted(val_nc, idx)
        if val_nc.startswith("'"):
            inner = val_nc[1:]
            trailing_q = len(inner) - len(inner.rstrip("'"))
            if trailing_q % 2 == 0:
                return _collect_multiline_single_quoted(val_nc, idx)
        scalar = _parse_yaml_scalar(raw_val)
        if isinstance(scalar, str) and not (val_nc.startswith('"') or val_nc.startswith("'")):
            return _collect_multiline_plain(scalar, key_indent, idx)
        return scalar, idx

    root = {}
    # stack entries: (indent, kind, container) where kind in ("map", "seq")
    stack = [(-1, "map", root)]
    i = 0
    while i < len(raw_lines):
        line = raw_lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        indent = len(line) - len(line.lstrip())
        is_list_item = stripped.startswith("- ") or stripped == "-"

        if is_list_item:
            while len(stack) > 1 and (
                indent < stack[-1][0]
                or (indent == stack[-1][0] and stack[-1][1] != "seq")
            ):
                stack.pop()
        else:
            while len(stack) > 1 and indent <= stack[-1][0]:
                stack.pop()

        parent = stack[-1][2]

        if is_list_item:
            if not isinstance(parent, list):
                i += 1
                continue
            rest = stripped[2:].strip() if stripped.startswith("- ") else ""
            # Only treat as map item when rest starts with `identifier:` (not quoted string containing `:`)
            kv = None
            if not rest.startswith(("'", '"')):
                kv = re.match(r'^([A-Za-z0-9_.-]+):\s*(.*)$', rest)
            if kv:
                item = {}
                parent.append(item)
                stack.append((indent, "map", item))
                key, raw_val = kv.group(1), kv.group(2)
                val_nc = _strip_yaml_comment(raw_val).strip()
                if val_nc == "":
                    _, next_ind, next_s = _next_significant(i + 1)
                    if next_ind >= indent + 2 and (next_s.startswith("- ") or next_s == "-"):
                        child = []
                        item[key] = child
                        stack.append((indent + 2, "seq", child))
                    elif next_ind > indent + 2:
                        child = {}
                        item[key] = child
                        stack.append((indent + 2, "map", child))
                    else:
                        item[key] = None
                else:
                    item[key], i = _parse_value(raw_val, indent + 2, i)
            else:
                val, i = _parse_value(rest, indent, i)
                parent.append(val)
            i += 1
            continue

        # Mapping entry (`key: val`)
        m = re.match(r'^([^:#][^:]*?):\s*(.*)$', stripped)
        if not m or not isinstance(parent, dict):
            i += 1
            continue
        key = m.group(1).strip().strip("\"'")
        raw_val = m.group(2)
        val_nc = _strip_yaml_comment(raw_val).strip()
        if val_nc == "":
            _, next_ind, next_s = _next_significant(i + 1)
            if next_ind >= indent and (next_s.startswith("- ") or next_s == "-"):
                child = []
                parent[key] = child
                stack.append((next_ind, "seq", child))
            elif next_ind > indent:
                child = {}
                parent[key] = child
                stack.append((indent, "map", child))
            else:
                parent[key] = None
        else:
            parent[key], i = _parse_value(raw_val, indent, i)
        i += 1

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
        reg_ip = cam.get("last_seen_ip")
        if reg_ip and ping_probe(reg_ip):
            ip, how = reg_ip, "ping(registry-ip)"
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
