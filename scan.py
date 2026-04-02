"""
scan.py — CoreSight 컴포넌트 스캔 + 멀티코어 PC 읽기 테스트

진단 순서:
  1. DLL 가용 함수 탐색
  2. 전원 레지스터(0x30313f30) 활성화 시도
  3. Core 0/1/2 DBGDSCR 직접 비교 → Configure가 실제로 코어를 전환하는지 확인
  4. 멀티코어 PC 읽기
  5. CoreSight 컴포넌트 스캔
"""

import ctypes
import pylink
import logging

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
log = logging.getLogger(__name__)

CORE_DEBUG_BASES = [0x80030000, 0x80032000, 0x80034000]
DBGDSCR_OFFSET   = 0x084   # Debug Status and Control Register
PWR_REG_ADDR     = 0x30313f30

_PART_NAMES = {
    0xC18: "Cortex-R8 CPU Debug",
    0x906: "CTI",  0x907: "ETB",   0x908: "CSTF",
    0x912: "TPIU", 0x925: "ETMv3", 0x961: "TMC/ETB",
    0x9E8: "TMC-ETR", 0x95D: "ETMv4",
}


# ── DLL 함수 초기화 ───────────────────────────────────────────────────────
def probe_and_setup_dll(dll):
    available = {}
    candidates = {
        "JLINKARM_CORESIGHT_Configure": ([ctypes.c_char_p],          ctypes.c_int),
        "JLINKARM_WriteU32":            ([ctypes.c_uint32, ctypes.c_uint32], None),
        "JLINKARM_ReadU32":             ([ctypes.c_uint32],           ctypes.c_uint32),
        "JLINKARM_ExecCommand":         ([ctypes.c_char_p, ctypes.c_char_p,
                                          ctypes.c_int],              ctypes.c_int),
        "JLINKARM_Halt":                ([],                          ctypes.c_int),
        "JLINKARM_Go":                  ([],                          None),
    }
    print("\n=== DLL 함수 가용성 ===")
    for name, (args, ret) in candidates.items():
        try:
            fn = getattr(dll, name)
            fn.argtypes = args
            fn.restype  = ret
            available[name] = fn
            print(f"  {name:50s}  ✓")
        except AttributeError:
            print(f"  {name:50s}  ✗")
    return available


# ── 전원 레지스터 활성화 ──────────────────────────────────────────────────
def enable_cores_debug(jl, dll_fns):
    """0x30313f30에 3개 코어 디버그 활성화 비트 set.
    방법 1: JLINKARM_WriteU32 (AXI-AP 라우팅 가능성)
    방법 2: jl.memory_write32 (fallback)
    """
    print(f"\n=== [Step 1] 전원 레지스터 0x{PWR_REG_ADDR:08X} 활성화 ===")

    def _read():
        if "JLINKARM_ReadU32" in dll_fns:
            return dll_fns["JLINKARM_ReadU32"](PWR_REG_ADDR)
        return jl.memory_read32(PWR_REG_ADDR, 1)[0]

    def _write(val):
        if "JLINKARM_WriteU32" in dll_fns:
            dll_fns["JLINKARM_WriteU32"](PWR_REG_ADDR, ctypes.c_uint32(val))
            return "JLINKARM_WriteU32"
        jl.memory_write32(PWR_REG_ADDR, [val])
        return "memory_write32"

    try:
        cur = _read()
        print(f"  현재값: {cur:#010x}")
        new_val = cur | 0x00010101
        method = _write(new_val)
        verify = _read()
        ok = (verify & 0x00010101) == 0x00010101
        print(f"  쓰기 후: {verify:#010x}  ({method} 사용)")
        print(f"  결과: {'활성화 성공 ✓' if ok else '비트 미반영 ✗ — APB-AP는 이 주소 불가, AXI-AP 필요'}")
        return ok
    except Exception as e:
        print(f"  실패: {e}")
        return False


# ── 핵심 진단: DBGDSCR 직접 비교 ─────────────────────────────────────────
def diagnose_core_switch(jl, dll_fns):
    """Configure 전환 전후 DBGDSCR을 직접 읽어 실제로 다른 코어를 보는지 확인.
    DBGDSCR 주소: CoreBase + 0x084
    """
    print("\n=== [Step 2] DBGDSCR 직접 비교 (Configure 유효성 검증) ===")

    has_configure = "JLINKARM_CORESIGHT_Configure" in dll_fns

    for i, base in enumerate(CORE_DEBUG_BASES):
        dscr_addr = base + DBGDSCR_OFFSET

        if has_configure and i > 0:
            dll_fns["JLINKARM_CORESIGHT_Configure"](
                f"CoreBaseAddr={base:#010x}".encode())

        try:
            dscr = jl.memory_read32(dscr_addr, 1)[0]
        except Exception as e:
            dscr = None
            print(f"  Core {i}  0x{dscr_addr:08X} DBGDSCR = 읽기 실패: {e}")
            continue

        halted = dscr & 0x1 if dscr is not None else None
        if dscr == 0xFFFFFFFF:
            status = "⚠ debug block 미응답 (전원 비활성화 or 잘못된 주소)"
        elif dscr is None:
            status = "읽기 실패"
        else:
            status = f"HALTED={halted}"
        print(f"  Core {i}  0x{dscr_addr:08X} DBGDSCR = {dscr:#010x}  {status}")

    # Core 0 DBGDSCR vs Core 1 DBGDSCR 비교 요약
    try:
        if has_configure:
            dll_fns["JLINKARM_CORESIGHT_Configure"](b"CoreBaseAddr=0x80030000")
        d0 = jl.memory_read32(CORE_DEBUG_BASES[0] + DBGDSCR_OFFSET, 1)[0]
        if has_configure:
            dll_fns["JLINKARM_CORESIGHT_Configure"](b"CoreBaseAddr=0x80032000")
        d1 = jl.memory_read32(CORE_DEBUG_BASES[1] + DBGDSCR_OFFSET, 1)[0]

        print()
        if d0 == d1 and d1 != 0xFFFFFFFF:
            print("  ⚠ Core 0 DBGDSCR == Core 1 DBGDSCR")
            print("    → Configure가 코어를 전환하지 않거나, 두 주소가 같은 레지스터를 가리킴")
        elif d1 == 0xFFFFFFFF:
            print("  ✗ Core 1 debug block 응답 없음 → 전원 레지스터 write 실패")
        else:
            print(f"  ✓ Core 0 DBGDSCR({d0:#010x}) ≠ Core 1 DBGDSCR({d1:#010x})")
            print("    → 독립적인 debug block 접근 확인, Configure 유효")
    except Exception as e:
        print(f"  비교 실패: {e}")

    # Core 0 복귀
    if has_configure:
        dll_fns["JLINKARM_CORESIGHT_Configure"](b"CoreBaseAddr=0x80030000")


# ── 멀티코어 PC 읽기 ──────────────────────────────────────────────────────
def read_all_pcs(jl, dll_fns):
    """Core 0 여러 번 샘플 vs Core 1/2 비교.
    Core 0을 3번 읽어 idle loop 여부 확인 후, Core 1/2 비교.
    """
    print("\n=== [Step 3] PC 읽기 ===")
    has_configure = "JLINKARM_CORESIGHT_Configure" in dll_fns
    go = dll_fns.get("JLINKARM_Go")

    def _read_pc():
        jl.halt()
        pc = jl.register_read(15)
        if go:
            go()
        else:
            jl.go()
        return pc

    # Core 0 idle loop 확인 (3회 샘플)
    if has_configure:
        dll_fns["JLINKARM_CORESIGHT_Configure"](b"CoreBaseAddr=0x80030000")
    c0_samples = [_read_pc() for _ in range(3)]
    all_same = len(set(c0_samples)) == 1
    print(f"  Core 0 × 3회: {[f'{p:#010x}' for p in c0_samples]}")
    print(f"  {'  → idle loop 확인 (동일 PC 반복)' if all_same else '  → PC가 변화 중 (정상 실행)'}")

    # Core 1, 2
    for i, base in enumerate(CORE_DEBUG_BASES):
        if has_configure:
            dll_fns["JLINKARM_CORESIGHT_Configure"](
                f"CoreBaseAddr={base:#010x}".encode())
        try:
            pc = _read_pc()
            same_as_c0 = (pc == c0_samples[0])
            note = "  ← Core 0와 동일 (코어 전환 실패 의심)" if (same_as_c0 and i > 0) else ""
            print(f"  Core {i}  base={base:#010x}  PC = {pc:#010x}{note}")
        except Exception as e:
            print(f"  Core {i}  PC 읽기 실패: {e}")

    if has_configure:
        dll_fns["JLINKARM_CORESIGHT_Configure"](b"CoreBaseAddr=0x80030000")


# ── CoreSight 컴포넌트 스캔 ───────────────────────────────────────────────
def scan_coresight(jl, start=0x80000000, end=0x80060000, step=0x1000):
    print("\n=== [Step 4] CoreSight 컴포넌트 스캔 ===")
    found = []
    addr = start
    while addr < end:
        try:
            cidr = jl.memory_read32(addr + 0xFF0, 4)
            if cidr[0] != 0x0D or cidr[2] != 0x05 or cidr[3] != 0xB1:
                addr += step
                continue
            pidr = jl.memory_read32(addr + 0xFE0, 4)
            part = (pidr[0] & 0xFF) | ((pidr[1] & 0x0F) << 8)
            cls  = (cidr[1] >> 4) & 0xF
            name = _PART_NAMES.get(part, f"Unknown(0x{part:03X})")
            found.append({"base": addr, "part": part, "name": name, "class": cls})
            print(f"  0x{addr:08X}  {name}  Part=0x{part:03X}  Class=0x{cls:X}")
        except Exception:
            pass
        addr += step
    if not found:
        print("  컴포넌트 없음")
    return found


# ── main ──────────────────────────────────────────────────────────────────
def main():
    jl = pylink.JLink()
    jl.open()
    jl.set_tif(pylink.enums.JLinkInterfaces.SWD)
    jl.connect("Cortex-R8", speed=4000)
    log.info("J-Link SWD 연결 완료")

    dll_fns = probe_and_setup_dll(jl._dll)

    enable_cores_debug(jl, dll_fns)
    diagnose_core_switch(jl, dll_fns)
    read_all_pcs(jl, dll_fns)
    scan_coresight(jl)

    jl.close()
    print("\n완료")


if __name__ == "__main__":
    main()
