#!/usr/bin/env python3
"""J-Link 레지스터 읽기 진단 스크립트
Cortex-R8에서 R15(PC) = index 9 확인 및 resume 동작 검증
"""

import pylink
import time

DEVICE = 'Cortex-R8'
SPEED  = 12000
PC_REG_INDEX = 9  # Cortex-R8: R15(PC)의 실제 J-Link 레지스터 인덱스

def resume(jl):
    """halt 후 실행 재개 (CPU 리셋 없이)"""
    try:
        jl._dll.JLINKARM_Go()
        return "_dll.JLINKARM_Go()"
    except Exception:
        jl.restart()
        return "restart() [WARNING: resets CPU]"

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
# TEST 2: halt() 상태 확인
# =============================================================
print("=== TEST 2: halt() completion check ===")
jlink.halt()
print(f"  halted() right after halt(): {jlink.halted()}")

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
# TEST 3: index 9 (R15) vs index 15 비교
# =============================================================
print("=== TEST 3: register_read(9) vs register_read(15) ===")
val_idx9 = jlink.register_read(PC_REG_INDEX)
val_idx15 = jlink.register_read(15)
print(f"  register_read({PC_REG_INDEX})  [R15/PC] = 0x{val_idx9:08X}")
print(f"  register_read(15) [wrong]  = 0x{val_idx15:08X}")
print()

# =============================================================
# TEST 4: 전체 레지스터 덤프
# =============================================================
print("=== TEST 4: Full register dump (halted state) ===")
for idx in reg_indices:
    name = jlink.register_name(idx)
    val = jlink.register_read(idx)
    print(f"  [{idx:3d}] {name:12s} = 0x{val:08X}")
print()

# =============================================================
# TEST 5: resume 방법 확인
# =============================================================
print("=== TEST 5: Available resume methods ===")
has_go = hasattr(jlink, 'go')
has_restart = hasattr(jlink, 'restart')
has_dll_go = hasattr(getattr(jlink, '_dll', None), 'JLINKARM_Go')
print(f"  jlink.go()             : {'EXISTS' if has_go else 'NOT FOUND'}")
print(f"  jlink.restart()        : {'EXISTS' if has_restart else 'NOT FOUND'}")
print(f"  jlink._dll.JLINKARM_Go : {'EXISTS' if has_dll_go else 'NOT FOUND'}")
print()

# =============================================================
# TEST 6: resume → halt 사이클 (PC가 변하는지 확인)
# =============================================================
print("=== TEST 6: resume -> sleep -> halt cycle (5 rounds) ===")
for i in range(5):
    method = resume(jlink)
    if i == 0:
        print(f"  Resume method: {method}")
    time.sleep(0.2)
    jlink.halt()
    for _ in range(50):
        if jlink.halted():
            break
        time.sleep(0.001)
    pc = jlink.register_read(PC_REG_INDEX)
    print(f"  Round {i+1}: PC(reg[{PC_REG_INDEX}]) = 0x{pc:08X}  halted={jlink.halted()}")
print()

# =============================================================
# TEST 7: PC 주소의 명령어 읽기
# =============================================================
print("=== TEST 7: Instruction at reported PC ===")
pc_val = jlink.register_read(PC_REG_INDEX)
try:
    insn = jlink.memory_read32(pc_val, 1)[0]
    print(f"  PC = 0x{pc_val:08X}, instruction @ PC = 0x{insn:08X}")
except Exception as e:
    print(f"  Failed to read memory at 0x{pc_val:08X}: {e}")

try:
    insn_expected = jlink.memory_read32(0x5DD4, 1)[0]
    print(f"  instruction @ 0x5DD4     = 0x{insn_expected:08X}")
except Exception as e:
    print(f"  Failed to read memory at 0x5DD4: {e}")
print()

resume(jlink)
jlink.close()
print("Done. CPU resumed.")
