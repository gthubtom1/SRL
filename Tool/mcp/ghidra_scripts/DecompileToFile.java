// DecompileToFile.java -- Ghidra headless decompile helper for seep_decompile_auto
// @category Seep
// Usage: analyzeHeadless ... -postScript DecompileToFile.java <functionNameOrAddress> <outFile>

import java.io.FileWriter;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.task.ConsoleTaskMonitor;

public class DecompileToFile extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        String target = (a != null && a.length > 0) ? a[0] : "auto";
        String outPath = (a != null && a.length > 1) ? a[1] : "decompile_out.c";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();

        FunctionManager fm = currentProgram.getFunctionManager();
        Function targetFunc = null;

        if (target != null && !target.isEmpty() && !target.equals("auto")) {
            for (Function f : fm.getFunctions(true)) {
                if (f.getName().equals(target)) { targetFunc = f; break; }
            }
            if (targetFunc == null && target.startsWith("0x")) {
                try {
                    long addrVal = Long.parseLong(target.substring(2), 16);
                    ghidra.program.model.address.Address addr =
                        currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addrVal);
                    targetFunc = fm.getFunctionContaining(addr);
                } catch (Exception e) { }
            }
        }

        FileWriter fout = new FileWriter(outPath);
        try {
            if (targetFunc != null) {
                DecompileResults res = decomp.decompileFunction(targetFunc, 60, monitor);
                if (res != null && res.decompileCompleted()) {
                    fout.write("// function: " + targetFunc.getName() + " @ " + targetFunc.getEntryPoint() + "\n");
                    fout.write(res.getDecompiledFunction().getC());
                } else {
                    fout.write("// decompile failed for " + target + "\n");
                }
            } else {
                int count = 0;
                for (Function f : fm.getFunctions(true)) {
                    if (f.isThunk()) continue;
                    DecompileResults res = decomp.decompileFunction(f, 30, monitor);
                    if (res != null && res.decompileCompleted()) {
                        fout.write("// ===== " + f.getName() + " @ " + f.getEntryPoint() + " =====\n");
                        String c = res.getDecompiledFunction().getC();
                        fout.write(c.length() > 1500 ? c.substring(0, 1500) : c);
                        fout.write("\n\n");
                        count++;
                    }
                    if (count >= 10) break;
                }
            }
        } finally {
            fout.close();
        }
        println("WROTE:" + outPath);
    }
}
