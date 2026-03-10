#@title Fuzzer Coverage Export
#@author RelaxWide
#@category FuzzingTools
#@keybinding
#@menupath
#@toolbar

"""
ghidra_export.py - Ghidra Script (Jython compatible)

Exports firmware analysis results for coverage-guided fuzzer.

Output files (in OUTPUT_DIR):
  code_addrs.txt  - all instruction addresses  (use with --code-addrs)
  functions.txt   - function list: entry / size / name (use with --func-addrs)

Usage:
  Ghidra -> Window -> Script Manager -> ghidra_export.py -> Run

Note:
  - Run after Analyze is complete
  - ARM Cortex-R8: expect ~800K-1.2M instructions, ~1000-2000 functions
  - If instruction count < 500K, re-run ARM Aggressive Instruction Finder
"""

import os

# ---- output path -------------------------------------------------------
OUTPUT_DIR = "/tmp/ghidra_export"
# ------------------------------------------------------------------------

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

listing   = currentProgram.getListing()
func_mgr  = currentProgram.getFunctionManager()
prog_name = currentProgram.getName()

print("[GhidraExport] start: " + prog_name)
print("[GhidraExport] output: " + OUTPUT_DIR)

# ---- 1. instruction addresses ------------------------------------------
code_path   = os.path.join(OUTPUT_DIR, "code_addrs.txt")
instr_count = 0

with open(code_path, "w") as f:
    for instr in listing.getInstructions(True):
        f.write("0x{:08x}\n".format(instr.getAddress().getOffset()))
        instr_count += 1
        if instr_count % 100000 == 0:
            print("  [1] instructions: {:,} ...".format(instr_count))

print("[1] instructions: {:,} -> {}".format(instr_count, code_path))

# ---- 2. function list --------------------------------------------------
# format: <entry_addr> <byte_size> <name>
# unnamed functions appear as FUN_XXXXXXXX
func_path  = os.path.join(OUTPUT_DIR, "functions.txt")
func_count = 0

with open(func_path, "w") as f:
    for fn in func_mgr.getFunctions(True):
        entry = fn.getEntryPoint().getOffset()
        size  = fn.getBody().getNumAddresses()
        name  = fn.getName()
        f.write("0x{:08x} {} {}\n".format(entry, size, name))
        func_count += 1

print("[2] functions: {:,} -> {}".format(func_count, func_path))
print("[GhidraExport] done.")
print("")
print("  fuzzer usage:")
print("    --code-addrs " + os.path.join(OUTPUT_DIR, "code_addrs.txt"))
print("    --func-addrs " + os.path.join(OUTPUT_DIR, "functions.txt"))
