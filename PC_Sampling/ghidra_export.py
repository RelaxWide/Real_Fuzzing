#@title Fuzzer Coverage Export
#@author RelaxWide
#@category FuzzingTools
#@keybinding
#@menupath
#@toolbar

"""
ghidra_export.py — Ghidra Script
=================================
firmware.bin 분석 결과에서 퍼저용 정보를 export합니다.

출력 파일:
  code_addrs.txt  — 모든 instruction 주소 목록 (퍼저 --code-addrs 인자)
  functions.txt   — 함수 목록: 진입주소 / 크기 / 이름 (퍼저 --func-addrs 인자)

사용법:
  Ghidra 메뉴 → Window → Script Manager → ghidra_export.py → Run (▶)
  결과 파일: /tmp/ghidra_export/ 아래에 생성

주의:
  - Analyze 완료 후 실행할 것
  - ARM Cortex-R8 기준: instruction 수 약 80만~120만, 함수 수 약 1,000~2,000개
  - instruction 수가 50만 미만이면 분석 미완료 가능성 있음
    (Window → Script Manager → ARM Aggressive Instruction Finder 재실행 권장)
"""

import os

# ── 출력 경로 설정 ─────────────────────────────────────────────────────────────
OUTPUT_DIR = "/tmp/ghidra_export"
# ──────────────────────────────────────────────────────────────────────────────

os.makedirs(OUTPUT_DIR, exist_ok=True)

listing  = currentProgram.getListing()
func_mgr = currentProgram.getFunctionManager()
prog_name = currentProgram.getName()

print("[GhidraExport] 시작: {}".format(prog_name))
print("[GhidraExport] 출력 디렉터리: {}".format(OUTPUT_DIR))

# ── 1. Instruction 주소 목록 ───────────────────────────────────────────────────
# getInstructions() 사용 → Data 유닛(상수, 룩업테이블 등) 제외, 순수 instruction만 추출
code_path = os.path.join(OUTPUT_DIR, "code_addrs.txt")
instr_count = 0

with open(code_path, "w") as f:
    for instr in listing.getInstructions(True):
        f.write("0x{:08x}\n".format(instr.getAddress().getOffset()))
        instr_count += 1
        if instr_count % 100000 == 0:
            print("  [1] instructions: {:,} 개 처리 중...".format(instr_count))

print("[1] instruction 주소: {:,} 개 → {}".format(instr_count, code_path))

# ── 2. 함수 목록 ──────────────────────────────────────────────────────────────
# 심볼 없으면 FUN_XXXXXXXX 형식으로 출력됨
# 형식: <진입주소> <바이트크기> <이름>
func_path  = os.path.join(OUTPUT_DIR, "functions.txt")
func_count = 0

with open(func_path, "w") as f:
    for fn in func_mgr.getFunctions(True):
        entry = fn.getEntryPoint().getOffset()
        size  = fn.getBody().getNumAddresses()
        name  = fn.getName()
        f.write("0x{:08x} {} {}\n".format(entry, size, name))
        func_count += 1

print("[2] 함수: {:,} 개 → {}".format(func_count, func_path))
print("[GhidraExport] 완료.")
print("")
print("  퍼저 실행 예시:")
print("  sudo python3 pc_sampling_fuzzer_v5.1.py \\")
print("    --code-addrs {}/code_addrs.txt \\".format(OUTPUT_DIR))
print("    --func-addrs {}/functions.txt \\".format(OUTPUT_DIR))
print("    [기타 옵션]")
