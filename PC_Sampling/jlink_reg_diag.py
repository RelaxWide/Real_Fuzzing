#!/usr/bin/env python3
"""J-Link 레지스터 읽기 진단 스크립트
pylink에서 PC(R15)를 제대로 읽는지 확인

JLinkExe에서는 0x5DD4로 읽히는데
pylink register_read(15)는 0x27200이 나오는 문제 진단
"""

import pylink
import time

DEVICE = 'Cortex-R8'
SPEED  = 12000

jlink = pylink.JLink()
jlink.open()
jlink.set_tif(pylink.enums.JLinkInterfaces.JTAG)
jlink.connect(DEVICE, speed=SPEED)

print(f"Connected: {DEVICE} @ {SPEED}kHz")
print(f"Core ID   : {hex(jlink.core_id())}")
print(f"Device family: {jlink.device_family()}")
print()

# =============================================================
# TEST 1: 레지스터 인덱스 매핑 확인
# =============================================================
print("=== TEST 1: Register index mapping ===")
reg_indices = jlink.register_list()
for idx in reg_indices:
    name = jlink.register_name(idx)
    tag = ""
    if "R15" in name or "PC" in name.upper():
        tag = "  <-- PC"
    elif "CPSR" in name.upper():
        tag = "  <-- CPSR"
    print(f"  index {idx:3d} -> {name}{tag}")
print()

# =============================================================
# TEST 2: halt() 상태 확인 — halt가 실제로 완료되는지
# =============================================================
print("=== TEST 2: halt() completion check ===")
jlink.halt()
print(f"  halted() right after halt(): {jlink.halted()}")

# halted()가 False면 polling
if not jlink.halted():
    print("  CPU not halted yet, polling...")
    for i in range(100):
        time.sleep(0.001)
        if jlink.halted():
            print(f"  halted() became True after {i+1}ms")
            break
    else:
        print("  WARNING: CPU still not halted after 100ms!")

print(f"  halted() final: {jlink.halted()}")
print()

# =============================================================
# TEST 3: halt 후 즉시 읽기 vs 딜레이 후 읽기
# =============================================================
print("=== TEST 3: register_read(15) timing ===")
# 이미 halt 상태
val_immediate = jlink.register_read(15)
print(f"  Immediate read     : 0x{val_immediate:08X}")

time.sleep(0.01)
val_10ms = jlink.register_read(15)
print(f"  After 10ms delay   : 0x{val_10ms:08X}")

time.sleep(0.1)
val_100ms = jlink.register_read(15)
print(f"  After 100ms delay  : 0x{val_100ms:08X}")
print()

# =============================================================
# TEST 4: 전체 R0-R15 + CPSR 덤프
# =============================================================
print("=== TEST 4: Full register dump (halted state) ===")
for idx in reg_indices:
    name = jlink.register_name(idx)
    val = jlink.register_read(idx)
    print(f"  [{idx:3d}] {name:12s} = 0x{val:08X}")
print()

# =============================================================
# TEST 5: register_read 대안 — memory_read로 DBGDSCR 확인
# =============================================================
print("=== TEST 5: Debug status check ===")
try:
    # Cortex-R external debug base (common: 0x80030000, varies by SoC)
    # 읽기 실패해도 괜찮음
    dscr_candidates = [0x80030088, 0x80010088]  # DBGDSCR offsets
    for addr in dscr_candidates:
        try:
            val = jlink.memory_read32(addr, 1)[0]
            print(f"  mem32[{hex(addr)}] = 0x{val:08X}")
        except Exception as e:
            print(f"  mem32[{hex(addr)}] = FAILED ({e})")
except Exception as e:
    print(f"  Debug register read failed: {e}")
print()

# =============================================================
# TEST 6: go() → halt() 사이클 반복 — PC가 변하는지
# =============================================================
print("=== TEST 6: go() -> sleep -> halt() cycle (5 rounds) ===")
for i in range(5):
    jlink.go()
    time.sleep(0.2)  # CPU가 충분히 실행될 시간
    jlink.halt()
    # halt 완료 대기
    for _ in range(50):
        if jlink.halted():
            break
        time.sleep(0.001)
    pc = jlink.register_read(15)
    print(f"  Round {i+1}: PC = 0x{pc:08X}  halted={jlink.halted()}")
print()

# =============================================================
# TEST 7: JLINKARM_ReadMemU32로 현재 PC 주소의 명령어 읽기
# =============================================================
print("=== TEST 7: Instruction at reported PC ===")
pc_val = jlink.register_read(15)
try:
    insn = jlink.memory_read32(pc_val, 1)[0]
    print(f"  PC = 0x{pc_val:08X}, instruction @ PC = 0x{insn:08X}")
except Exception as e:
    print(f"  Failed to read memory at 0x{pc_val:08X}: {e}")

# 비교: 0x5DD4 주소의 명령어도 읽어보기
try:
    insn_expected = jlink.memory_read32(0x5DD4, 1)[0]
    print(f"  instruction @ 0x5DD4     = 0x{insn_expected:08X}")
except Exception as e:
    print(f"  Failed to read memory at 0x5DD4: {e}")
print()

jlink.go()
jlink.close()
print("Done. CPU resumed.")
