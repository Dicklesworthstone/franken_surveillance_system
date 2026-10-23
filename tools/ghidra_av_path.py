# Ghidra post-script: decompile the TUTK AV packet path.
# @category FSS
import os

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT = os.environ.get("FSS_GHIDRA_OUT", "/tmp/ghidra-out")
os.makedirs(OUT, exist_ok=True)

TARGETS = [0x688D10, 0x689134, 0x6926DC, 0x67A0D4]

prog = currentProgram
fm = prog.getFunctionManager()
dec = DecompInterface()
dec.openProgram(prog)
mon = ConsoleTaskMonitor()
seen = set()


def emit(addr, tag):
    f = fm.getFunctionAt(toAddr(addr))
    if f is None:
        with open(os.path.join(OUT, "%08x_missing.txt" % addr), "w") as fh:
            fh.write("no function at %08x\n" % addr)
        return None
    name = "%08x_%s" % (addr, tag)
    with open(os.path.join(OUT, name + ".c"), "w") as fh:
        fh.write("// %s @ %s\n" % (f.getName(), f.getEntryPoint()))
        res = dec.decompileFunction(f, 90, mon)
        fh.write(res.getDecompiledFunction().getC() if res.decompileCompleted() else "// decompile failed\n")
    return f


for t in TARGETS:
    f = emit(t, "self")
    if f is None:
        continue
    for ref in f.getReferencesTo(f.getEntryPoint()):
        a = ref.getFromAddress()
        caller = fm.getFunctionContaining(a)
        if caller is None:
            continue
        ca = caller.getEntryPoint().getOffset()
        if ca in seen:
            continue
        seen.add(ca)
        emit(ca, "caller")

# One more hop for the FIFO put path only.
for ca in list(seen):
    f = fm.getFunctionAt(toAddr(ca))
    if f is None:
        continue
    for ref in f.getReferencesTo(f.getEntryPoint()):
        caller = fm.getFunctionContaining(ref.getFromAddress())
        if caller is None:
            continue
        c2 = caller.getEntryPoint().getOffset()
        if c2 in seen:
            continue
        seen.add(c2)
        emit(c2, "caller2")

with open(os.path.join(OUT, "index.txt"), "w") as fh:
    for a in sorted(seen):
        fh.write("%08x\n" % a)
print("done: %d functions" % len(seen))
