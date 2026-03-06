#!/usr/bin/env python3
"""Cortex-R8 DBGPCSR 동작 검증

ROM Table 분석 결과:
  RomTbl[1][0]: CompAddr=0x80030000  Cortex-R8 Debug block
  DBGPCSR = 0x80030000 + 0x084 = 0x80030084

DBGPCSR를 halt 없이 읽을 수 있으면:
  → CPU 멈춤 없이 PC 샘플링 가능
  → NVMe 타임아웃 문제 근본 해결
"""

import pylink
import time

DEVICE     = 'Cortex-R8'
SPEED      = 4000                 # kHz
APB_AP_IDX = 0                   # AP[0] = APB-AP

DEBUG_BASE = 0x80030000
DBGPCSR    = DEBUG_BASE + 0x084  # 0x80030084  (Cortex-R8 TRM)
DBGPCSR_ALT= DEBUG_BASE + 0x0A0  # 0x800300A0  (alt offset)

FW_START   = 0x00000000
FW_END     = 0x00147FFF

_SWD = pylink.enums.JLinkInterfaces.SWD

# ── 연결 ──────────────────────────────────────────────────────────
jlink = pylink.JLink()
jlink.open()
jlink.set_tif(_SWD)
jlink.connect(DEVICE, speed=SPEED)
print(f"Connected: {DEVICE} @ {SPEED}kHz")
print(f"Core ID  : {hex(jlink.core_id())}")
print()

# ── APB-AP 를 memory read 용으로 지정 ─────────────────────────────
# J-Link 는 기본적으로 AHB-AP(AP[2])로 memory_read 를 수행한다.
# APB 공간(0x80030000)에 접근하려면 APB-AP(AP[0])로 전환 필요.
for cmd in [
    f"CORESIGHT_SetIndexAPToUse = {APB_AP_IDX}",
    f"CORESIGHT_SetIndexBGMemAPToUse = {APB_AP_IDX}",
]:
    try:
        jlink.exec_command(cmd)
        print(f"  exec_command: {cmd}  → OK")
    except Exception as e:
        print(f"  exec_command: {cmd}  → FAILED ({e})")
print()

# ── TEST 1: halt 방식으로 PC 기준값 ──────────────────────────────
print("=== TEST 1: halt 방식 PC (기준값) ===")
jlink.halt()
for _ in range(30):
    if jlink.halted(): break
    time.sleep(0.001)

ref_pc = None
for idx in jlink.register_list():
    name = jlink.register_name(idx).upper()
    if 'R15' in name or name in ('PC', 'EPC'):
        ref_pc = jlink.register_read(idx)
        print(f"  halt PC = 0x{ref_pc:08X}  (reg[{idx}] = {name})")
        break

jlink._dll.JLINKARM_Go()
time.sleep(0.1)
print()

# ── TEST 2: DBGPCSR 단일 읽기 ────────────────────────────────────
print("=== TEST 2: DBGPCSR 단일 읽기 (halt 없음) ===")
for label, addr in [("DBGPCSR     0x80030084", DBGPCSR),
                    ("DBGPCSR_ALT 0x800300A0", DBGPCSR_ALT)]:
    try:
        val = jlink.memory_read32(addr, 1)[0]
        in_fw = FW_START <= val <= FW_END
        tag = "  <<< FW 범위 내 — PC 후보!" if in_fw else ""
        print(f"  {label}  =  0x{val:08X}{tag}")
    except Exception as e:
        print(f"  {label}  =  READ FAILED ({type(e).__name__}: {e})")
print()

# ── TEST 3: DBGPCSR 반복 읽기 — PC가 변하는지 확인 ────────────────
print("=== TEST 3: DBGPCSR 반복 읽기 30회 (CPU 실행 중) ===")
pcs = []
for i in range(30):
    try:
        v = jlink.memory_read32(DBGPCSR, 1)[0] & ~1  # Thumb bit 제거
        in_fw = FW_START <= v <= FW_END
        tag = " [IN]" if in_fw else " [OUT]"
        print(f"  [{i+1:2d}] 0x{v:08X}{tag}")
        pcs.append(v)
    except Exception as e:
        print(f"  [{i+1:2d}] FAILED: {e}")
    time.sleep(0.05)

in_fw_pcs = [p for p in pcs if FW_START <= p <= FW_END]
unique = len(set(in_fw_pcs))
print()
print("=" * 50)
if unique >= 5:
    print(f"✓  DBGPCSR 동작 확인!")
    print(f"   FW 범위 내 unique PC = {unique}개 / 30회 읽기")
    print(f"   DBGPCSR_ADDR = 0x{DBGPCSR:08X}")
    print(f"   → halt 없는 PC 샘플링으로 교체 가능")
elif unique >= 1:
    print(f"△  FW 범위 내 PC {unique}개. 동작하지만 수가 적음.")
    print(f"   SSD idle 상태가 아닌지, fw_start/fw_end 범위 확인 필요.")
else:
    print(f"✗  FW 범위 내 PC 없음 (전체 {len(pcs)}회 중 0회)")
    print(f"   원인 후보:")
    print(f"   1) APB-AP 전환이 안 됨 → JLINK_ExecCommand 지원 여부 확인")
    print(f"   2) DBGPCSR 오프셋이 다름 → DBGPCSR_ALT(0x800300A0) 결과 확인")
    print(f"   3) 읽힌 값: {[hex(p) for p in pcs[:5]]}")
print("=" * 50)

jlink.close()
