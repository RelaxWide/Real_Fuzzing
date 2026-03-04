#!/usr/bin/env python3
"""J-Link 레지스터 읽기 진단 스크립트

레지스터 인덱스 매핑, halt/resume 동작, PC 샘플링 동작을 검증합니다.
새 SSD 제품에서 PC 레지스터 인덱스를 확인할 때 사용합니다.

사용법:
  python3 jlink_reg_diag.py --device Cortex-M7 --speed 4000
  python3 jlink_reg_diag.py --device RH850F1KM --speed 1000 --swd
  python3 jlink_reg_diag.py --pc-reg 15   # 특정 인덱스가 PC인지 확인
"""

import pylink
import time
import argparse

parser = argparse.ArgumentParser(description='J-Link 레지스터 진단')
parser.add_argument('--device', default='Cortex-R8', help='J-Link 타깃 디바이스명 (default: Cortex-R8)')
parser.add_argument('--speed', type=int, default=12000, help='JTAG/SWD 속도 kHz (default: 12000)')
parser.add_argument('--swd', action='store_true', help='SWD 인터페이스 사용 (기본: JTAG)')
parser.add_argument('--pc-reg', type=int, default=None, help='PC 레지스터 인덱스 강제 지정 (auto-detect 건너뜀)')
args = parser.parse_args()

DEVICE = args.device
SPEED  = args.speed
INTERFACE = pylink.enums.JLinkInterfaces.SWD if args.swd else pylink.enums.JLinkInterfaces.JTAG

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
jlink.set_tif(INTERFACE)
jlink.connect(DEVICE, speed=SPEED)

iface_str = "SWD" if args.swd else "JTAG"
print(f"Connected: {DEVICE} @ {SPEED}kHz ({iface_str})")
print(f"Core ID   : {hex(jlink.core_id())}")
print(f"Device family: {jlink.device_family()}")
print()

# =============================================================
# TEST 1: 레지스터 인덱스 매핑 확인
# =============================================================
print("=== TEST 1: Register index mapping ===")
reg_indices = jlink.register_list()
auto_pc_index = None
for idx in reg_indices:
    name = jlink.register_name(idx)
    tag = ""
    name_up = name.upper()
    if "R15" in name_up or name_up in ("PC", "EPC", "MEPC", "SEPC"):
        tag = "  <-- PC (auto-detect)"
        if auto_pc_index is None:
            auto_pc_index = idx
    elif "CPSR" in name_up or "PSR" in name_up:
        tag = "  <-- status register"
    print(f"  index {idx:3d} -> {name}{tag}")
print()

# 사용할 PC 인덱스 결정
if args.pc_reg is not None:
    PC_REG_INDEX = args.pc_reg
    print(f"  => PC 인덱스: {PC_REG_INDEX} (--pc-reg 강제 지정)")
elif auto_pc_index is not None:
    PC_REG_INDEX = auto_pc_index
    print(f"  => PC 인덱스: {PC_REG_INDEX} (자동 탐지)")
else:
    PC_REG_INDEX = 15
    print(f"  => PC 인덱스: {PC_REG_INDEX} (탐지 실패, fallback 15)")
    print("  !! 위 레지스터 목록에서 PC에 해당하는 index를 확인 후")
    print("  !! --pc-reg N 으로 직접 지정하거나 퍼저에 --pc-reg-index N 을 쓰세요.")
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
print(f"=== TEST 3: register_read({PC_REG_INDEX}) vs register_read(15) ===")
val_pc  = jlink.register_read(PC_REG_INDEX)
val_idx15 = jlink.register_read(15)
print(f"  register_read({PC_REG_INDEX})  [PC 후보] = 0x{val_pc:08X}")
print(f"  register_read(15)          = 0x{val_idx15:08X}")
if PC_REG_INDEX != 15:
    print(f"  => 두 값이 다르면 index {PC_REG_INDEX}이 올바른 PC 인덱스입니다.")
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
