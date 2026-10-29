import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.FileWriter;
import java.io.File;
import java.io.PrintWriter;

/**
 * Ghidra headless helper: decompiles EVERY function of the imported program
 * to per-function C files plus a _functions.csv manifest.
 *
 * Usage (headless):
 *   analyzeHeadless <projDir> <projName> -import <binary> -overwrite \
 *     -scriptPath tools -postScript ExportDecompiled.java <outputDir>
 */
public class ExportDecompiled extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outDir = args.length > 0 ? args[0] : "decomp";
        new File(outDir).mkdirs();

        DecompInterface di = new DecompInterface();
        di.setOptions(new DecompileOptions());
        di.openProgram(currentProgram);

        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        PrintWriter manifest = new PrintWriter(new FileWriter(new File(outDir, "_functions.csv")));
        manifest.println("name,address,size");

        int ok = 0, fail = 0;
        while (it.hasNext()) {
            Function f = it.next();
            String addr = f.getEntryPoint().toString();
            String name = f.getName().replaceAll("[^A-Za-z0-9_.$-]", "_");
            manifest.println(name + "," + addr + "," + f.getBody().getNumAddresses());

            DecompileResults res;
            try {
                res = di.decompileFunction(f, 90, monitor);
            } catch (Exception e) {
                res = null;
            }
            String c;
            if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                c = res.getDecompiledFunction().getC();
                ok++;
            } else {
                c = "// decompile failed: " + (res == null ? "exception" : res.getErrorMessage());
                fail++;
            }
            PrintWriter pw = new PrintWriter(new FileWriter(new File(outDir, name + "_" + addr + ".c")));
            pw.println("// function: " + f.getName() + " @ " + addr);
            pw.println(c);
            pw.close();
        }
        manifest.close();
        println("ExportDecompiled: " + ok + " decompiled, " + fail + " failed, output=" + outDir);
    }
}
