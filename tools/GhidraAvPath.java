// Decompile the TUTK AV packet path: self + callers (2 hops).
// @category FSS

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.LinkedHashSet;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.ConsoleTaskMonitor;

public class GhidraAvPath extends GhidraScript {

    private static final long[] TARGETS = { 0x688D10L, 0x689134L, 0x6926DCL, 0x67A0D4L };

    private DecompInterface dec;
    private String outDir;
    private Set<Long> seen = new LinkedHashSet<>();

    private void emit(long addr, String tag) throws Exception {
        Function f = getFunctionAt(toAddr(addr));
        if (f == null) {
            PrintWriter pw = new PrintWriter(new FileWriter(outDir + String.format("/%08x_missing.txt", addr)));
            pw.println("no function at " + Long.toHexString(addr));
            pw.close();
            return;
        }
        String name = String.format("%08x_%s", addr, tag);
        PrintWriter pw = new PrintWriter(new FileWriter(outDir + "/" + name + ".c"));
        pw.println("// " + f.getName() + " @ " + f.getEntryPoint());
        DecompileResults res = dec.decompileFunction(f, 120, new ConsoleTaskMonitor());
        if (res.decompileCompleted()) {
            pw.println(res.getDecompiledFunction().getC());
        } else {
            pw.println("// decompile failed: " + res.getErrorMessage());
        }
        pw.close();
    }

    private void hop(Set<Long> from) throws Exception {
        Set<Long> next = new LinkedHashSet<>();
        for (Long ca : from) {
            Function f = getFunctionAt(toAddr(ca));
            if (f == null) {
                continue;
            }
            for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint())) {
                Function caller = getFunctionContaining(ref.getFromAddress());
                if (caller == null) {
                    continue;
                }
                long c2 = caller.getEntryPoint().getOffset();
                if (seen.add(c2)) {
                    next.add(c2);
                    emit(c2, "caller");
                }
            }
        }
        for (Long n : next) {
            Function f = getFunctionAt(toAddr(n));
            if (f == null) {
                continue;
            }
            for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint())) {
                Function caller = getFunctionContaining(ref.getFromAddress());
                if (caller == null) {
                    continue;
                }
                long c2 = caller.getEntryPoint().getOffset();
                if (seen.add(c2)) {
                    emit(c2, "caller2");
                }
            }
        }
    }

    @Override
    public void run() throws Exception {
        outDir = System.getenv("FSS_GHIDRA_OUT");
        if (outDir == null) {
            outDir = "/tmp/ghidra-out";
        }
        new java.io.File(outDir).mkdirs();
        dec = new DecompInterface();
        dec.openProgram(currentProgram);
        for (long t : TARGETS) {
            Address a = toAddr(t);
            Function f = getFunctionAt(a);
            if (f == null) {
                emit(t, "self");
                continue;
            }
            emit(t, "self");
            for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint())) {
                Function caller = getFunctionContaining(ref.getFromAddress());
                if (caller == null) {
                    continue;
                }
                long ca = caller.getEntryPoint().getOffset();
                if (seen.add(ca)) {
                    emit(ca, "caller");
                }
            }
        }
        hop(seen);
        PrintWriter ix = new PrintWriter(new FileWriter(outDir + "/index.txt"));
        for (Long a : seen) {
            ix.println(Long.toHexString(a));
        }
        ix.close();
        println("done: " + seen.size());
    }
}
