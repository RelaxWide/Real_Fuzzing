"""
scan.py — CoreSight 컴포넌트 스캔 + 멀티코어 PC 읽기 테스트

1. 0x80000000~0x80060000 에서 CoreSight 컴포넌트 자동 탐지
2. DLL 직접 호출로 AXI-AP 통해 코어 디버그 활성화 (0x30313f30)
3. 3개 코어 (base: 0x80030000 / 0x80032000 / 0x80034000) PC 읽기
"""

import ctypes
import pylink
import logging
import sys

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
log = logging.getLogger(__name__)

# ── 상수 ──────────────────────────────────────────────────────────────────
CORE_DEBUG_BASES = [0x80030000, 0x80032000, 0x80034000]
PWR_REG_ADDR     = 0x30313f30   # 코어 디버그 활성화 레지스터 (AXI-AP 경유)
AP_APB           = 0            # APB-AP index
AP_AXI           = 1            # AXI-AP index

# AXI-AP MEM-AP 레지스터 인덱스 (word index)
AP_REG_CSW = 0   # offset 0x00
AP_REG_TAR = 1   # offset 0x04
AP_REG_DRW = 3   # offset 0x0C

# CoreSight Part Number → 이름 테이블
_PART_NAMES = {
    0xC18: "Cortex-R8 CPU Debug",   # PID 000BBC18
    0x906: "CTI (Cross-Trigger)",
    0x907: "ETB",
    0x908: "CSTF",
    0x912: "TPIU",
    0x913: "ITM",
    0x925: "ETMv3",
    0x950: "PTM",
    0x961: "TMC/ETB",
    0x962: "STM",
    0x9E8: "TMC-ETR",
    0x95D: "ETMv4",
    0x4A9: "CTI",
    0x4C7: "Debug",
}


# ── DLL 함수 시그니처 등록 ─────────────────────────────────────────────────
def _setup_dll(dll):
    dll.JLINKARM_CORESIGHT_Configure.restype  = ctypes.c_int
    dll.JLINKARM_CORESIGHT_Configure.argtypes = [ctypes.c_char_p]

    dll.JLINKARM_CORESIGHT_WriteAP.restype    = ctypes.c_int
    dll.JLINKARM_CORESIGHT_WriteAP.argtypes   = [ctypes.c_uint, ctypes.c_uint,
                                                   ctypes.c_uint32]

    dll.JLINKARM_CORESIGHT_ReadAP.restype     = ctypes.c_int
    dll.JLINKARM_CORESIGHT_ReadAP.argtypes    = [ctypes.c_uint, ctypes.c_uint,
                                                   ctypes.POINTER(ctypes.c_uint32)]

    dll.JLINKARM_ExecCommand.restype          = ctypes.c_int
    dll.JLINKARM_ExecCommand.argtypes         = [ctypes.c_char_p, ctypes.c_char_p,
                                                   ctypes.c_int]


# ── CoreSight 컴포넌트 스캔 ──────────────────────────────────────────────────
def scan_coresight(jl, start=0x80000000, end=0x80060000, step=0x1000):
    """4KB 단위로 CoreSight 컴포넌트를 브루트포스 스캔"""
    found = []
    addr = start
    while addr < end:
        try:
            cidr = jl.memory_read32(addr + 0xFF0, 4)
            # CoreSight 고정 preamble: CID0=0x0D, CID2=0x05, CID3=0xB1
            if cidr[0] != 0x0D or cidr[2] != 0x05 or cidr[3] != 0xB1:
                addr += step
                continue
            pidr   = jl.memory_read32(addr + 0xFE0, 4)
            part   = (pidr[0] & 0xFF) | ((pidr[1] & 0x0F) << 8)
            cls    = (cidr[1] >> 4) & 0xF   # 0x1=ROM Table, 0x9=CoreSight
            name   = _PART_NAMES.get(part, f"Unknown(0x{part:03X})")
            found.append({"base": addr, "part": part, "name": name, "class": cls})
        except Exception:
            pass
        addr += step
    return found


# ── AXI-AP 경유 32비트 read/write ────────────────────────────────────────────
def _axi_read32(dll, addr):
    dll.JLINKARM_CORESIGHT_WriteAP(AP_AXI, AP_REG_CSW, ctypes.c_uint32(0x00000002))
    dll.JLINKARM_CORESIGHT_WriteAP(AP_AXI, AP_REG_TAR, ctypes.c_uint32(addr))
    val = ctypes.c_uint32(0)
    dll.JLINKARM_CORESIGHT_ReadAP(AP_AXI, AP_REG_DRW, ctypes.byref(val))
    return val.value


def _axi_write32(dll, addr, value):
    dll.JLINKARM_CORESIGHT_WriteAP(AP_AXI, AP_REG_CSW, ctypes.c_uint32(0x00000002))
    dll.JLINKARM_CORESIGHT_WriteAP(AP_AXI, AP_REG_TAR, ctypes.c_uint32(addr))
    dll.JLINKARM_CORESIGHT_WriteAP(AP_AXI, AP_REG_DRW, ctypes.c_uint32(value))


# ── 코어 디버그 활성화 ──────────────────────────────────────────────────────
def enable_cores_debug(dll):
    """AXI-AP 경유 0x30313f30 레지스터에 3개 코어 활성화 비트 set"""
    print("\n=== [Step 1] 코어 디버그 활성화 (AXI-AP DLL direct) ===")
    try:
        cur = _axi_read32(dll, PWR_REG_ADDR)
        print(f"  0x{PWR_REG_ADDR:08X} 현재: {cur:#010x}")
        new_val = cur | 0x00010101   # Core0 bit0, Core1 bit8, Core2 bit16
        _axi_write32(dll, PWR_REG_ADDR, new_val)
        verify = _axi_read32(dll, PWR_REG_ADDR)
        print(f"  0x{PWR_REG_ADDR:08X} 쓰기 후: {verify:#010x}")
        ok = (verify & 0x00010101) == 0x00010101
        print(f"  활성화 {'성공 ✓' if ok else '실패 ✗ (비트 미반영)'}")
        return ok
    except Exception as e:
        print(f"  AXI-AP 접근 실패: {e}")
        return False


# ── 코어 전환 후 PC 읽기 ──────────────────────────────────────────────────
def read_core_pc(jl, dll, core_idx, base_addr):
    """두 가지 방법으로 코어 전환 시도 후 PC 반환. 실패 시 None."""

    def _halt_read_go():
        jl.halt()
        pc = jl.register_read(15)
        jl.go()
        return pc

    # 방법 1: JLINKARM_CORESIGHT_Configure (CoreBaseAddr 전용 설정)
    cfg = f"CoreBaseAddr={base_addr:#010x}".encode()
    ret1 = dll.JLINKARM_CORESIGHT_Configure(cfg)
    log.debug(f"  Core{core_idx} Configure ret={ret1}")
    try:
        return _halt_read_go()
    except Exception as e1:
        log.debug(f"  Core{core_idx} Configure 후 read 실패: {e1}")

    # 방법 2: JLINKARM_ExecCommand 직접 (pylink 래퍼 우회)
    out  = ctypes.create_string_buffer(256)
    cmd  = f"CORESIGHT_CoreBaseAddr = {base_addr:#010x}".encode()
    ret2 = dll.JLINKARM_ExecCommand(cmd, out, 256)
    out_str = out.value.decode(errors="replace").strip()
    log.debug(f"  Core{core_idx} ExecCommand ret={ret2} out='{out_str}'")
    if ret2 == 0 and not out_str:
        try:
            return _halt_read_go()
        except Exception as e2:
            log.debug(f"  Core{core_idx} ExecCommand 후 read 실패: {e2}")

    return None


# ── main ──────────────────────────────────────────────────────────────────
def main():
    jl = pylink.JLink()
    jl.open()
    jl.set_tif(pylink.enums.JLinkInterfaces.JTAG)
    jl.connect("Cortex-R8", speed=4000)
    log.info("J-Link 연결 완료")

    dll = jl._dll
    _setup_dll(dll)

    # ── 1. CoreSight 스캔 ─────────────────────────────────────────────
    print("\n=== [Step 0] CoreSight 컴포넌트 스캔 (0x80000000-0x80060000) ===")
    comps = scan_coresight(jl)
    if comps:
        for c in comps:
            print(f"  0x{c['base']:08X}  {c['name']}"
                  f"  (Part=0x{c['part']:03X}, Class=0x{c['class']:X})")
    else:
        print("  컴포넌트 없음")

    # ── 2. Core 0 기준 PC ────────────────────────────────────────────
    print("\n=== [Step 0] Core 0 기준 PC ===")
    jl.halt()
    pc0 = jl.register_read(15)
    jl.go()
    print(f"  Core 0 PC = {pc0:#010x}")

    # ── 3. 코어 디버그 활성화 ─────────────────────────────────────────
    enable_cores_debug(dll)

    # ── 4. 3개 코어 PC 읽기 ──────────────────────────────────────────
    print("\n=== [Step 2] 멀티코어 PC 읽기 ===")
    results = {}
    for i, base in enumerate(CORE_DEBUG_BASES):
        pc = read_core_pc(jl, dll, i, base)
        results[i] = pc
        status = f"{pc:#010x}  ✓" if pc is not None else "읽기 실패  ✗"
        print(f"  Core {i}  base={base:#010x}  PC = {status}")

    # ── 5. Core 0으로 복귀 후 종료 ───────────────────────────────────
    dll.JLINKARM_CORESIGHT_Configure(b"CoreBaseAddr=0x80030000")
    jl.close()

    print("\n=== 결과 요약 ===")
    success = [i for i, pc in results.items() if pc is not None]
    fail    = [i for i, pc in results.items() if pc is None]
    if success:
        print(f"  성공 코어: {success}")
    if fail:
        print(f"  실패 코어: {fail}")
        if fail:
            print("  → DLL API가 CoreBaseAddr 전환을 지원하지 않을 수 있음")
            print("    JLinkScript 파일 경유 방식 검토 필요")


if __name__ == "__main__":
    main()
