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
  basic_blocks.txt - basic block list: start_addr end_addr (exclusive)
  functions.txt    - function list: entry / size / name (use with --func-addrs)

Usage:
  Ghidra -> Window -> Script Manager -> ghidra_export.py -> Run

Note:
  - Run after Analyze is complete
  - ARM Cortex-R8: expect ~100K-300K basic blocks, ~1000-2000 functions
  - If BB count < 50K, re-run ARM Aggressive Instruction Finder first
  - basic_blocks.txt replaces code_addrs.txt (BB-level coverage is more accurate
    for PC sampling because one sampled PC hit proves the whole block was executed)
"""

import os
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor

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

# ---- 1. basic blocks ---------------------------------------------------
# format: <start_addr> <end_addr_exclusive>
# end_addr = maxAddress.getOffset() + 1  (exclusive upper bound)
bb_path    = os.path.join(OUTPUT_DIR, "basic_blocks.txt")
bb_model   = BasicBlockModel(currentProgram)
monitor    = ConsoleTaskMonitor()
blocks     = bb_model.getCodeBlocks(monitor)
bb_count   = 0

with open(bb_path, "w") as f:
    while blocks.hasNext():
        bb    = blocks.next()
        start = bb.getMinAddress().getOffset()
        end   = bb.getMaxAddress().getOffset() + 1  # exclusive
        f.write("0x{:08x} 0x{:08x}\n".format(start, end))
        bb_count += 1
        if bb_count % 50000 == 0:
            print("  [1] basic blocks: {:,} ...".format(bb_count))

print("[1] basic blocks: {:,} -> {}".format(bb_count, bb_path))

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
print("    --bb-addrs    " + os.path.join(OUTPUT_DIR, "basic_blocks.txt"))
print("    --func-addrs  " + os.path.join(OUTPUT_DIR, "functions.txt"))
