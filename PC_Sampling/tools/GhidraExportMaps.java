// Ghidra headless: export address->meaning maps for ONE core ELF.
// @category RISCV.Coverage
//
// This single script covers BOTH Ghidra phases; the wrapper registers it twice:
//   -preScript  GhidraExportMaps.java pre [nodwarf] [aggressive]     (before analysis)
//   -postScript GhidraExportMaps.java <LABEL> <OUTDIR> [PC_LIST]     (after analysis)
//
// outputs, per core (LABEL is the core name the caller supplies, e.g. H / F / CM / Q):
//   basic_blocks_core<LABEL>.txt  "0xSTART 0xEND"   END is EXCLUSIVE (last byte + 1)
//   functions_core<LABEL>.txt     "0xENTRY <size_dec> <name>"   name is the last field
//   callgraph_core<LABEL>.txt     "0xCALLER 0xCALLEE"   function-entry level, deduped
//   symbols_core<LABEL>.json      per-core fragment (kept, so cores can be exported one by one)
//   symbols.json                  all fragments combined: hash + time + counts + exec ranges
//
// Java rather than Python: Ghidra 12 routes .py to PyGhidra, which needs a CPython package an
// offline host cannot install. Java scripts are compiled by the JDK Ghidra already requires.
//
// Measured lessons baked in:
//   * DWARF is the memory/time hog on a several-hundred-MB firmware ELF and is NOT needed here
//     (names come from the ELF symbol table). Default heap 2G plus DWARF = the run dies.
//   * Ghidra only disassembles code some static reference reaches, so ISR/vector-table and
//     function-pointer targets stay undefined: 28% of executable bytes and 21% of sampled PCs
//     were unmapped. "aggressive" plus PC_LIST seeding brought PC coverage to 98%.
//
// The ELF filename is never recorded - only its hash - so the ELF/core-label mapping stays
// with whoever owns the ELF files.
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import java.util.HashMap;
import java.util.Map;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

public class GhidraExportMaps extends GhidraScript {

    private static final String FRAG_PREFIX = "symbols_core";
    private static final String FRAG_SUFFIX = ".json";

    private static final Comparator<long[]> PAIR = new Comparator<long[]>() {
        public int compare(long[] x, long[] y) {
            int c = Long.compare(x[0], y[0]);
            return c != 0 ? c : Long.compare(x[1], y[1]);
        }
    };

    private static String clean(String s) {
        return s == null ? "" : s.replaceAll("\s+", " ").trim();
    }

    private static String jq(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String hx(long v) {
        return "0x" + Long.toHexString(v).toUpperCase();
    }

    private static String stamp() {
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
    }

    private static PrintWriter open(File dir, String name) throws Exception {
        return new PrintWriter(new BufferedWriter(new FileWriter(new File(dir, name))));
    }

    private static String readAll(File f) throws Exception {
        StringBuilder sb = new StringBuilder();
        BufferedReader br = new BufferedReader(new FileReader(f));
        String line;
        while ((line = br.readLine()) != null) {
            sb.append(line).append("\n");
        }
        br.close();
        return sb.toString();
    }

    // ---------- pre-analysis phase ----------

    private void setAnalyzer(String analyzer, boolean enable) {
        try {
            setAnalysisOption(currentProgram, analyzer, enable ? "true" : "false");
            println("[preopts] " + (enable ? "enabled: " : "disabled: ") + analyzer);
        } catch (Exception e) {
            println("[preopts] could not change " + analyzer + ": " + e.getMessage());
        }
    }

    private void runPrePhase(String[] args) {
        boolean noDwarf = false;
        boolean aggressive = false;
        for (String a : args) {
            if (a.equalsIgnoreCase("nodwarf")) {
                noDwarf = true;
            } else if (a.equalsIgnoreCase("aggressive")) {
                aggressive = true;
            }
        }
        if (noDwarf) {
            setAnalyzer("DWARF", false);
        }
        // Not needed for BB/function/callgraph and expensive.
        setAnalyzer("Decompiler Parameter ID", false);
        // Decompiler Switch Analysis stays ON: it resolves jump tables, which finds more code
        // and more call edges - exactly what this map needs.
        if (aggressive) {
            setAnalyzer("Aggressive Instruction Finder", true);
        }
        println("[preopts] done (nodwarf=" + noDwarf + " aggressive=" + aggressive + ")");
    }

    // ---------- optional: seed disassembly at observed PCs ----------

    private void seedFromPcList(String path) throws Exception {
        File pcf = new File(path);
        if (!pcf.isFile()) {
            println("[export] PC_LIST not found, skipping seed: " + path);
            return;
        }
        long seeded = 0, already = 0, outside = 0, failed = 0;
        BufferedReader br = new BufferedReader(new FileReader(pcf));
        String line;
        while ((line = br.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            String t = line.split("\s+")[0];
            if (t.startsWith("0x") || t.startsWith("0X")) {
                t = t.substring(2);
            }
            long v;
            try {
                v = Long.parseLong(t, 16);
            } catch (NumberFormatException e) {
                continue;
            }
            Address at = toAddr(v);
            if (!currentProgram.getMemory().contains(at)) {
                outside++;
                continue;
            }
            if (getInstructionContaining(at) != null) {
                already++;
                continue;
            }
            // disassemble() follows flow, so one seed can define a whole body. If data is
            // already defined there it refuses; clear that one spot and retry once.
            if (disassemble(at)) {
                seeded++;
            } else {
                try {
                    clearListing(at);
                } catch (Exception e) {
                    // fall through to the retry, which will just fail again
                }
                if (disassemble(at)) {
                    seeded++;
                } else {
                    failed++;
                }
            }
        }
        br.close();
        println("[export] PC seed: " + seeded + " disassembled, " + already + " already defined, "
                + outside + " outside memory, " + failed + " failed");
    }

    // ---------- symbols.json: combine per-core fragments (no JSON parsing needed) ----------

    private void writeSymbolsJson(File od) throws Exception {
        File[] frags = od.listFiles(new FilenameFilter() {
            public boolean accept(File dir, String name) {
                return name.startsWith(FRAG_PREFIX) && name.endsWith(FRAG_SUFFIX);
            }
        });
        if (frags == null) {
            frags = new File[0];
        }
        Arrays.sort(frags, new Comparator<File>() {
            public int compare(File a, File b) {
                return a.getName().compareTo(b.getName());
            }
        });
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"generated\": \"").append(stamp()).append("\",\n");
        sb.append("  \"bb_end_convention\": \"exclusive\",\n");
        sb.append("  \"cores\": {\n");
        for (int i = 0; i < frags.length; i++) {
            String n = frags[i].getName();
            String lab = n.substring(FRAG_PREFIX.length(), n.length() - FRAG_SUFFIX.length());
            if (i > 0) {
                sb.append(",\n");
            }
            sb.append("    \"").append(jq(lab)).append("\": ").append(readAll(frags[i]).trim());
        }
        sb.append("\n  }\n}\n");
        PrintWriter pw = open(od, "symbols.json");
        pw.print(sb.toString());
        pw.close();
        println("[export] symbols.json <- " + frags.length + " core fragment(s)");
    }

    // ---------- overlay bucketing ----------

    private static final Pattern OVL_NUM = Pattern.compile("(\\d+)\\s*$");

    /**
     * File suffix for the overlay an address belongs to; empty string for resident code.
     *
     * Ghidra keeps each code overlay in its own overlay block / address space, so two overlays
     * mapped at the same runtime address stay distinct here. Dumping raw offsets would merge
     * them - on this firmware 31% of functions and 44% of basic blocks live in overlays - so
     * everything is bucketed per overlay. Block names look like .OVL_REGION_04, and the
     * trailing number becomes the suffix (_ovl4). An overlay block with an unexpected name
     * still gets its own file rather than being dropped or merged into resident code.
     */
    private String overlaySuffix(Memory mem, Address a) {
        MemoryBlock b = mem.getBlock(a);
        if (b == null || !b.isOverlay()) {
            return "";
        }
        String n = b.getName();
        Matcher m = OVL_NUM.matcher(n);
        if (m.find()) {
            return "_ovl" + Integer.parseInt(m.group(1));
        }
        return "_ovl_" + n.replaceAll("[^A-Za-z0-9_-]", "_");
    }

    // ---------- overlay diagnostic ----------

    private void runOverlayInfo() throws Exception {
        Memory mem = currentProgram.getMemory();
        println("[ovlinfo] language=" + currentProgram.getLanguageID().getIdAsString());

        // Addresses are deliberately not printed - only names, sizes and counts, so the
        // diagnostic can be shared. Overlay identity comes from the block name.
        java.util.List<MemoryBlock> ovl = new ArrayList<MemoryBlock>();
        java.util.List<MemoryBlock> res = new ArrayList<MemoryBlock>();
        for (MemoryBlock b : mem.getBlocks()) {
            if (b.isOverlay()) {
                ovl.add(b);
            } else {
                res.add(b);
            }
        }
        println("[ovlinfo] blocks: " + (ovl.size() + res.size())
                + "  overlay=" + ovl.size() + "  resident=" + res.size());

        // functions / basic blocks per block name
        Map<String, int[]> per = new HashMap<String, int[]>();
        FunctionManager fm = currentProgram.getFunctionManager();
        int fnOvl = 0, fnRes = 0, fnNone = 0;
        for (Function f : fm.getFunctions(true)) {
            MemoryBlock b = mem.getBlock(f.getEntryPoint());
            if (b == null) {
                fnNone++;
                continue;
            }
            int[] c = per.get(b.getName());
            if (c == null) {
                c = new int[3];
                per.put(b.getName(), c);
            }
            c[0]++;
            c[2] = b.isOverlay() ? 1 : 0;
            if (b.isOverlay()) {
                fnOvl++;
            } else {
                fnRes++;
            }
        }
        BasicBlockModel bbm = new BasicBlockModel(currentProgram);
        CodeBlockIterator bit = bbm.getCodeBlocks(monitor);
        int bbOvl = 0, bbRes = 0, bbNone = 0;
        while (bit.hasNext()) {
            CodeBlock cb = bit.next();
            MemoryBlock b = mem.getBlock(cb.getMinAddress());
            if (b == null) {
                bbNone++;
                continue;
            }
            int[] c = per.get(b.getName());
            if (c == null) {
                c = new int[3];
                per.put(b.getName(), c);
            }
            c[1]++;
            c[2] = b.isOverlay() ? 1 : 0;
            if (b.isOverlay()) {
                bbOvl++;
            } else {
                bbRes++;
            }
        }
        println("[ovlinfo] functions: overlay=" + fnOvl + " resident=" + fnRes
                + " outside-any-block=" + fnNone);
        println("[ovlinfo] blocks(BB): overlay=" + bbOvl + " resident=" + bbRes
                + " outside-any-block=" + bbNone);

        int withCode = 0;
        for (MemoryBlock b : ovl) {
            int[] c = per.get(b.getName());
            if (c != null && (c[0] > 0 || c[1] > 0)) {
                withCode++;
            }
        }
        println("[ovlinfo] overlay blocks holding code: " + withCode + " of " + ovl.size());

        println("[ovlinfo] overlay block names (name / size / functions / BBs):");
        int shown = 0;
        for (MemoryBlock b : ovl) {
            int[] c = per.get(b.getName());
            int nf = c == null ? 0 : c[0];
            int nb = c == null ? 0 : c[1];
            println(String.format("[ovlinfo]   %-34s size=%-8d func=%-6d bb=%d",
                    b.getName(), b.getSize(), nf, nb));
            shown++;
            if (shown >= 60) {
                println("[ovlinfo]   ... (" + (ovl.size() - shown) + " more)");
                break;
            }
        }

        println("[ovlinfo] resident block names (name / size / functions / BBs):");
        shown = 0;
        for (MemoryBlock b : res) {
            int[] c = per.get(b.getName());
            int nf = c == null ? 0 : c[0];
            int nb = c == null ? 0 : c[1];
            if (!b.isExecute() && nf == 0 && nb == 0) {
                continue;
            }
            println(String.format("[ovlinfo]   %-34s size=%-8d func=%-6d bb=%d x=%s",
                    b.getName(), b.getSize(), nf, nb, b.isExecute()));
            shown++;
            if (shown >= 30) {
                println("[ovlinfo]   ... (more)");
                break;
            }
        }
    }
    // ---------- main ----------

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length >= 1 && args[0].equalsIgnoreCase("ovlinfo")) {
            runOverlayInfo();
            return;
        }
        if (args.length >= 1 && args[0].equalsIgnoreCase("pre")) {
            runPrePhase(args);
            return;
        }
        if (args.length < 2) {
            throw new Exception("usage: -postScript GhidraExportMaps.java <LABEL> <OUTDIR> [PC_LIST]"
                    + "   (or: -preScript GhidraExportMaps.java pre [nodwarf] [aggressive])");
        }
        String label = args[0];
        String outdir = args[1];
        if (!label.matches("[A-Za-z0-9_-]+")) {
            throw new Exception("LABEL must be alphanumeric (H F CM Q ...), got: " + label);
        }
        File od = new File(outdir);
        if (!od.isDirectory() && !od.mkdirs()) {
            throw new Exception("cannot create OUTDIR: " + outdir);
        }

        String lang = currentProgram.getLanguageID().getIdAsString();
        long base = currentProgram.getImageBase().getOffset();
        String sha = currentProgram.getExecutableSHA256();
        String md5 = currentProgram.getExecutableMD5();
        println("[export] label=" + label + " language=" + lang + " image_base=" + hx(base));

        if (args.length >= 3) {
            seedFromPcList(args[2]);
        }

        // executable memory ranges: lets the PC sampler validate addresses without the ELF
        List<long[]> execRanges = new ArrayList<long[]>();
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (b.isExecute()) {
                execRanges.add(new long[] { b.getStart().getOffset(), b.getEnd().getOffset() + 1L });
            }
        }
        execRanges.sort(PAIR);

        // basic blocks and functions, bucketed per overlay (END exclusive)
        Memory mem = currentProgram.getMemory();
        BasicBlockModel bbm = new BasicBlockModel(currentProgram);
        CodeBlockIterator bit = bbm.getCodeBlocks(monitor);
        TreeMap<String, List<long[]>> bbBuckets = new TreeMap<String, List<long[]>>();
        int multiRange = 0;
        int bbTotal = 0;
        while (bit.hasNext()) {
            CodeBlock cb = bit.next();
            if (cb.getNumAddressRanges() != 1) {
                multiRange++;
            }
            String sfx = overlaySuffix(mem, cb.getMinAddress());
            List<long[]> lst = bbBuckets.get(sfx);
            if (lst == null) {
                lst = new ArrayList<long[]>();
                bbBuckets.put(sfx, lst);
            }
            lst.add(new long[] { cb.getMinAddress().getOffset(),
                                 cb.getMaxAddress().getOffset() + 1L });
            bbTotal++;
        }
        for (String sfx : bbBuckets.keySet()) {
            List<long[]> lst = bbBuckets.get(sfx);
            lst.sort(PAIR);
            PrintWriter w = open(od, "basic_blocks_core" + label + sfx + ".txt");
            for (long[] r : lst) {
                w.println(hx(r[0]) + " " + hx(r[1]));
            }
            w.close();
        }
        println("[export] basic blocks: " + bbTotal + " in " + bbBuckets.size()
                + " file(s) (multi-range: " + multiRange + ")");

        FunctionManager fm = currentProgram.getFunctionManager();
        TreeMap<String, List<Object[]>> fnBuckets = new TreeMap<String, List<Object[]>>();
        int fnTotal = 0;
        for (Function f : fm.getFunctions(true)) {
            String sfx = overlaySuffix(mem, f.getEntryPoint());
            List<Object[]> lst = fnBuckets.get(sfx);
            if (lst == null) {
                lst = new ArrayList<Object[]>();
                fnBuckets.put(sfx, lst);
            }
            lst.add(new Object[] { Long.valueOf(f.getEntryPoint().getOffset()),
                                   Long.valueOf(f.getBody().getNumAddresses()),
                                   clean(f.getName(true)) });
            fnTotal++;
        }
        Comparator<Object[]> byEntry = new Comparator<Object[]>() {
            public int compare(Object[] x, Object[] y) {
                return Long.compare((Long) x[0], (Long) y[0]);
            }
        };
        for (String sfx : fnBuckets.keySet()) {
            List<Object[]> lst = fnBuckets.get(sfx);
            lst.sort(byEntry);
            PrintWriter w = open(od, "functions_core" + label + sfx + ".txt");
            for (Object[] f : lst) {
                w.println(hx((Long) f[0]) + " " + f[1] + " " + f[2]);
            }
            w.close();
        }
        println("[export] functions: " + fnTotal + " in " + fnBuckets.size() + " file(s)");
        for (String sfx : fnBuckets.keySet()) {
            List<long[]> bl = bbBuckets.get(sfx);
            println("[export]   " + (sfx.isEmpty() ? "(resident)" : sfx)
                    + ": functions=" + fnBuckets.get(sfx).size()
                    + " blocks=" + (bl == null ? 0 : bl.size()));
        }

        // kept for the JSON fragment below
        List<long[]> bbs = bbBuckets.containsKey("") ? bbBuckets.get("")
                                                      : new ArrayList<long[]>();
        List<Object[]> fns = fnBuckets.containsKey("") ? fnBuckets.get("")
                                                        : new ArrayList<Object[]>();
        // call graph: caller entry -> callee entry
        ReferenceManager refm = currentProgram.getReferenceManager();
        TreeSet<long[]> edges = new TreeSet<long[]>(PAIR);
        long unresolved = 0;
        for (Function f : fm.getFunctions(true)) {
            long caller = f.getEntryPoint().getOffset();
            AddressIterator ai = refm.getReferenceSourceIterator(f.getBody(), true);
            while (ai.hasNext()) {
                Address src = ai.next();
                for (Reference ref : refm.getReferencesFrom(src)) {
                    RefType rt = ref.getReferenceType();
                    if (rt == null || !rt.isCall()) {
                        continue;
                    }
                    Address to = ref.getToAddress();
                    Function cf = fm.getFunctionAt(to);
                    if (cf == null) {
                        cf = fm.getFunctionContaining(to);
                    }
                    if (cf == null) {
                        unresolved++;
                    } else {
                        edges.add(new long[] { caller, cf.getEntryPoint().getOffset() });
                    }
                }
            }
        }
        PrintWriter pw = open(od, "callgraph_core" + label + ".txt");
        for (long[] e : edges) {
            pw.println(hx(e[0]) + " " + hx(e[1]));
        }
        pw.close();
        println("[export] call edges: " + edges.size() + " (unresolved: " + unresolved + ")");

        // per-core fragment; kept so cores can be exported one at a time
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("      \"elf_sha256\": \"").append(jq(sha)).append("\",\n");
        sb.append("      \"elf_md5\": \"").append(jq(md5)).append("\",\n");
        sb.append("      \"language\": \"").append(jq(lang)).append("\",\n");
        sb.append("      \"image_base\": \"").append(hx(base)).append("\",\n");
        sb.append("      \"analyzed\": \"").append(stamp()).append("\",\n");
        sb.append("      \"exec_ranges\": [");
        for (int i = 0; i < execRanges.size(); i++) {
            long[] r = execRanges.get(i);
            if (i > 0) {
                sb.append(", ");
            }
            sb.append("[\"").append(hx(r[0])).append("\", \"").append(hx(r[1])).append("\"]");
        }
        sb.append("],\n");
        sb.append("      \"counts\": {\n");
        sb.append("        \"basic_blocks\": ").append(bbTotal).append(",\n");
        sb.append("        \"basic_blocks_resident\": ").append(bbs.size()).append(",\n");
        sb.append("        \"functions\": ").append(fnTotal).append(",\n");
        sb.append("        \"functions_resident\": ").append(fns.size()).append(",\n");
        sb.append("        \"overlay_files\": ").append(fnBuckets.size() - (fnBuckets.containsKey("") ? 1 : 0)).append(",\n");
        sb.append("        \"call_edges\": ").append(edges.size()).append(",\n");
        sb.append("        \"multi_range_blocks\": ").append(multiRange).append(",\n");
        sb.append("        \"unresolved_calls\": ").append(unresolved).append("\n");
        sb.append("      }\n");
        sb.append("    }");
        pw = open(od, FRAG_PREFIX + label + FRAG_SUFFIX);
        pw.println(sb.toString());
        pw.close();

        writeSymbolsJson(od);
    }
}
