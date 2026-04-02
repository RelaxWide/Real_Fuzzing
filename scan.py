"""
scan.py — CoreSight 컴포넌트 스캔 + 멀티코어 PC 읽기 테스트

1. 0x80000000~0x80060000 에서 CoreSight 컴포넌트 자동 탐지
2. AXI-AP 경유 0x30313f30 코어 디버그 활성화
3. 3개 코어 (base: 0x80030000 / 0x80032000 / 0x80034000) PC 읽기
"""

import ctypes
import ctypes.util
import pylink
import logging
import sys

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
log = logging.getLogger(__name__)

# ── 상수 ──────────────────────────────────────────────────────────────────
CORE_DEBUG_BASES = [0x80030000, 0x80032000, 0x80034000]
PWR_REG_ADDR     = 0x30313f30
AP_AXI           = 1

# CoreSight Part Number → 이름
_PART_NAMES = {
    0xC18: "Cortex-R8 CPU Debug",
    0x906: "CTI",
    0x907: "ETB",
    0x908: "CSTF",
    0x912: "TPIU",
    0x925: "ETMv3",
    0x961: "TMC/ETB",
    0x9E8: "TMC-ETR",
    0x95D: "ETMv4",
}


# ── DLL 가용 함수 탐색 ────────────────────────────────────────────────────
def probe_dll(dll):
    """V9.12에서 사용 가능한 CORESIGHT 관련 함수 목록 출력"""
    candidates = [
        "JLINKARM_CORESIGHT_Configure",
        "JLINKARM_CORESIGHT_WriteAP",
        "JLINKARM_CORESIGHT_ReadAP",
        "JLINKARM_CORESIGHT_WriteDP",
        "JLINKARM_CORESIGHT_ReadDP",
        "JLINKARM_CORESIGHT_ReadMem",
        "JLINKARM_WriteU32",
        "JLINKARM_ReadU32",
        "JLINKARM_ExecCommand",
    ]
    available = []
    print("\n=== DLL 함수 가용성 ===")
    for name in candidates:
        try:
            getattr(dll, name)
            print(f"  {name:50s}  ✓")
            available.append(name)
        except AttributeError:
            print(f"  {name:50s}  ✗")
    return available


# ── CoreSight 컴포넌트 스캔 ──────────────────────────────────────────────
def scan_coresight(jl, start=0x80000000, end=0x80060000, step=0x1000):
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
        except Exception:
            pass
        addr += step
    return found


# ── 코어 디버그 활성화: memory_write32 직접 시도 ─────────────────────────
def enable_cores_direct(jl):
    """memory_write32로 0x30313f30 직접 write 시도
    J-Link가 내부적으로 올바른 AP로 라우팅해줄 경우 동작."""
    print("\n=== [Step 1] 코어 디버그 활성화 (memory_write32 직접) ===")
    try:
        cur = jl.memory_read32(PWR_REG_ADDR, 1)[0]
        print(f"  0x{PWR_REG_ADDR:08X} 현재: {cur:#010x}")
        new_val = cur | 0x00010101
        jl.memory_write32(PWR_REG_ADDR, [new_val])
        verify = jl.memory_read32(PWR_REG_ADDR, 1)[0]
        print(f"  0x{PWR_REG_ADDR:08X} 쓰기 후: {verify:#010x}")
        ok = (verify & 0x00010101) == 0x00010101
        print(f"  활성화 {'성공 ✓' if ok else '실패 ✗ (비트 미반영, AP 라우팅 불가)'}")
        return ok
    except Exception as e:
        print(f"  memory_write32 실패: {e}")
        return False


# ── CORESIGHT_Configure로 CoreBaseAddr 전환 ──────────────────────────────
def switch_core_configure(dll, base_addr):
    """JLINKARM_CORESIGHT_Configure 로 CoreBaseAddr 설정"""
    dll.JLINKARM_CORESIGHT_Configure.restype  = ctypes.c_int
    dll.JLINKARM_CORESIGHT_Configure.argtypes = [ctypes.c_char_p]
    # 여러 포맷 시도
    for fmt in [
        f"CoreBaseAddr={base_addr:#010x}",
        f"CoreBaseAddr=0x{base_addr:08X}",
    ]:
        ret = dll.JLINKARM_CORESIGHT_Configure(fmt.encode())
        if ret == 0:
            return True, fmt
    return False, None


# ── 코어 PC 읽기 ─────────────────────────────────────────────────────────
def read_core_pc(jl, dll, core_idx, base_addr, has_configure):
    def _halt_read_go():
        jl.halt()
        pc = jl.register_read(15)
        jl.go()
        return pc

    if has_configure:
        ok, fmt = switch_core_configure(dll, base_addr)
        log.debug(f"  Core{core_idx} Configure('{fmt}') ok={ok}")
        try:
            return _halt_read_go()
        except Exception as e:
            log.debug(f"  Core{core_idx} read 실패: {e}")

    # ExecCommand 직접 (pylink 에러 핸들링 우회)
    if hasattr(dll, 'JLINKARM_ExecCommand'):
        dll.JLINKARM_ExecCommand.restype  = ctypes.c_int
        dll.JLINKARM_ExecCommand.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                                              ctypes.c_int]
        out = ctypes.create_string_buffer(256)
        cmd = f"CORESIGHT_CoreBaseAddr = {base_addr:#010x}".encode()
        ret = dll.JLINKARM_ExecCommand(cmd, out, 256)
        msg = out.value.decode(errors="replace").strip()
        log.debug(f"  Core{core_idx} ExecCommand ret={ret} out='{msg}'")
        if ret == 0 and not msg:
            try:
                return _halt_read_go()
            except Exception as e:
                log.debug(f"  Core{core_idx} ExecCommand 후 read 실패: {e}")

    return None


# ── main ──────────────────────────────────────────────────────────────────
def main():
    jl = pylink.JLink()
    jl.open()
    # SWD 연결
    jl.set_tif(pylink.enums.JLinkInterfaces.SWD)
    jl.connect("Cortex-R8", speed=4000)
    log.info("J-Link SWD 연결 완료")

    dll = jl._dll

    # ── 0. DLL 함수 가용성 확인 ───────────────────────────────────────
    avail = probe_dll(dll)
    has_configure = "JLINKARM_CORESIGHT_Configure" in avail

    # ── 1. CoreSight 스캔 ─────────────────────────────────────────────
    print("\n=== CoreSight 컴포넌트 스캔 (0x80000000-0x80060000) ===")
    comps = scan_coresight(jl)
    if comps:
        for c in comps:
            print(f"  0x{c['base']:08X}  {c['name']}"
                  f"  (Part=0x{c['part']:03X}, Class=0x{c['class']:X})")
    else:
        print("  컴포넌트 없음")

    # ── 2. Core 0 기준 PC ────────────────────────────────────────────
    print("\n=== Core 0 기준 PC ===")
    jl.halt()
    pc0 = jl.register_read(15)
    jl.go()
    print(f"  Core 0 PC = {pc0:#010x}")

    # ── 3. 코어 디버그 활성화 시도 ───────────────────────────────────
    enable_cores_direct(jl)

    # ── 4. 멀티코어 PC 읽기 ──────────────────────────────────────────
    print("\n=== 멀티코어 PC 읽기 ===")
    results = {}
    for i, base in enumerate(CORE_DEBUG_BASES):
        pc = read_core_pc(jl, dll, i, base, has_configure)
        results[i] = pc
        status = f"{pc:#010x}  ✓" if pc is not None else "실패  ✗"
        print(f"  Core {i}  base={base:#010x}  PC = {status}")

    # Core 0으로 복귀
    if has_configure:
        switch_core_configure(dll, CORE_DEBUG_BASES[0])
    jl.close()

    # ── 5. 결과 요약 ─────────────────────────────────────────────────
    print("\n=== 결과 요약 ===")
    success = [i for i, pc in results.items() if pc is not None]
    fail    = [i for i, pc in results.items() if pc is None]
    print(f"  성공: Core {success}" if success else "  성공한 코어 없음")
    if fail:
        print(f"  실패: Core {fail}")
        print("  → 다음 단계: subprocess로 JLinkScript 파일 경유 방식 검토")


if __name__ == "__main__":
    main()
