import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;

import java.awt.Color;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Color the addresses a QEMU/gdb trace actually executed, in the style of
 * AlephSecurity's xnu-qemu-arm64-tools ColorAddress.java.
 *
 * Supported trace line formats:
 *   1) AlephSecurity QEMU trace:  "Trace N: 0xADDR [file/section/offset]"
 *   2) any line containing a bare hex token 0xADDR (gdb batch logs, symtab
 *      dumps, kernel-syms.py output)
 *
 * Usage: run in a Ghidra program whose base matches the trace, pick the
 * trace file; executed addresses are painted pink.
 */
public class TraceColor extends GhidraScript {

    @Override
    protected void run() throws Exception {
        File file = askFile("QEMU/gdb trace file", "Choose trace:");
        Pattern aleph = Pattern.compile("Trace \\d+: 0x([0-9a-fA-F]+) \\[");
        Pattern hex = Pattern.compile("\\b0x([0-9a-fA-F]{6,16})\\b");

        Set<String> tokens = new LinkedHashSet<>();
        try (BufferedReader r = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = r.readLine()) != null) {
                Matcher m = aleph.matcher(line);
                if (m.find()) {
                    tokens.add(m.group(1));
                    continue;
                }
                m = hex.matcher(line);
                if (m.find()) {
                    tokens.add(m.group(1));
                }
            }
        }

        Address min = currentProgram.getMinAddress();
        Address max = currentProgram.getMaxAddress();
        AddressSet set = new AddressSet();
        int inRange = 0;
        for (String h : tokens) {
            try {
                Address a = currentAddress.getAddress("0x" + h);
                if (a != null && a.compareTo(min) >= 0 && a.compareTo(max) <= 0) {
                    set.add(a);
                    inRange++;
                }
            } catch (Exception ignore) {
                // unparsable token — skip
            }
        }
        setBackgroundColor(set, new Color(255, 119, 255));
        println("TraceColor: " + inRange + " addresses colored (parsed " + tokens.size() + " tokens)");
    }
}
