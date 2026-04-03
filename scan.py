"""
scan.py — CTI 검증 + DCC Instruction Injection PC 읽기

핵심 테스트:
  [Step 1] CTI 검증: Core 0 halt 유지 상태에서 Core 1/2 DBGDSCR 읽기
           → HALTED=1이면 CTI 동작, HALTED=0이면 CTI 미동작
  [Step 2] DCC injection 검증: Core 0에서 먼저 테스트
           MCR p14,0,R15,c0,c5,0 (0xEE00FE15) → DBGITR write → DBGDTRTX read
           → Core 0 known PC와 일치하면 방법 유효
  [Step 3] DCC injection으로 Core 1/2 PC 읽기 (CTI 동작 전제)

설계 근거:
  - DBGDSCR read  = CoreBase + 0x084
  - DBGITR write  = CoreBase + 0x084 (core halted 시 write → instruction 실행)
  - DBGDTRTX read = CoreBase + 0x080 (DCC TX result)
  - jl.halt()      → Core 0만 halt (SWD connection 고정)
  - memory_read32  → Configure로 지정한 CoreBase 주소 사용
"""

import ctypes
import pylink
import logging
import time

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
log = logging.getLogger(__name__)

CORE_BASES  = [0x80030000, 0x80032000, 0x80034000]
PWR_REG     = 0x30313f30

# DCC instruction injection 상수
MCR_R15_TO_DCC = 0xEE00FE15   # MCR p14, 0, R15, c0, c5, 0
DBGDSCR_OFF    = 0x084         # read = DBGDSCR / write (halted) = DBGITR
DBGDTRTX_OFF   = 0x08C         # read = DBGDTRTX (DCC result, core→debugger)
DBGDTRRX_OFF   = 0x080         # write = DBGDTRRX (debugger→core) — 읽으면 0xffffffff


# ── DLL 설정 ──────────────────────────────────────────────────────────────
def setup_dll(dll):
    fns = {}
    spec = {
        "JLINKARM_CORESIGHT_Configure": ([ctypes.c_char_p],                     ctypes.c_int),
        "JLINKARM_WriteU32":            ([ctypes.c_uint32, ctypes.c_uint32],     None),
        "JLINKARM_ReadU32":             ([ctypes.c_uint32],                      ctypes.c_uint32),
        "JLINKARM_ExecCommand":         ([ctypes.c_char_p, ctypes.c_char_p,
                                          ctypes.c_int],                          ctypes.c_int),
        "JLINKARM_Go":                  ([],                                      None),
        "JLINKARM_Halt":                ([],                                      ctypes.c_int),
    }
    for name, (args, ret) in spec.items():
        try:
            fn = getattr(dll, name)
            fn.argtypes = args
            fn.restype  = ret
            fns[name]   = fn
        except AttributeError:
            pass
    return fns


def configure_core(fns, base):
    if "JLINKARM_CORESIGHT_Configure" in fns:
        fns["JLINKARM_CORESIGHT_Configure"](f"CoreBaseAddr={base:#010x}".encode())


def go(jl, fns):
    if "JLINKARM_Go" in fns:
        fns["JLINKARM_Go"]()
    else:
        jl.go()


# ── 전원 활성화 ───────────────────────────────────────────────────────────
def enable_power(jl, fns):
    print(f"\n=== 전원 레지스터 0x{PWR_REG:08X} 활성화 ===")
    try:
        if "JLINKARM_WriteU32" in fns and "JLINKARM_ReadU32" in fns:
            cur = fns["JLINKARM_ReadU32"](PWR_REG)
            fns["JLINKARM_WriteU32"](PWR_REG, ctypes.c_uint32(cur | 0x00010101))
            verify = fns["JLINKARM_ReadU32"](PWR_REG)
        else:
            cur = jl.memory_read32(PWR_REG, 1)[0]
            jl.memory_write32(PWR_REG, [cur | 0x00010101])
            verify = jl.memory_read32(PWR_REG, 1)[0]
        ok = (verify & 0x00010101) == 0x00010101
        print(f"  전: {cur:#010x} → 후: {verify:#010x}  {'✓' if ok else '✗ (APB-AP 불가)'}")
    except Exception as e:
        print(f"  실패: {e}")


# ── Step 1: CTI 검증 ─────────────────────────────────────────────────────
def test_cti(jl, fns):
    """Core 0 halt 상태를 유지하면서 Core 1/2 DBGDSCR 읽기
    memory_read32는 이미 halted 상태에서는 추가 halt 없이 AP 통해 직접 읽음"""
    print("\n=== [Step 1] CTI 검증: Core 0 halt 유지 중 Core 1/2 DBGDSCR 읽기 ===")

    # Core 0 설정 후 halt
    configure_core(fns, CORE_BASES[0])
    jl.halt()
    c0_pc   = jl.register_read(15)
    c0_dscr = jl.memory_read32(CORE_BASES[0] + DBGDSCR_OFF, 1)[0]
    print(f"  Core 0  DBGDSCR={c0_dscr:#010x}  PC={c0_pc:#010x}  HALTED={bool(c0_dscr&1)}")

    # Core 0 resume 없이 Core 1/2 DBGDSCR 읽기
    results = {}
    for i in [1, 2]:
        configure_core(fns, CORE_BASES[i])
        dscr = jl.memory_read32(CORE_BASES[i] + DBGDSCR_OFF, 1)[0]
        halted = bool(dscr & 0x1)
        results[i] = (dscr, halted)
        status = "HALTED ← CTI 동작 ✓" if halted else "NOT HALTED → CTI 미동작"
        print(f"  Core {i}  DBGDSCR={dscr:#010x}  {status}")

    configure_core(fns, CORE_BASES[0])

    cti_ok = all(r[1] for r in results.values())
    if cti_ok:
        print("  → 전체 코어 CTI halt 확인. DCC injection 진행 가능.")
    else:
        print("  → CTI 미동작. Core 0 resume 후 수동 halt 시도 필요.")

    return c0_pc, cti_ok, results


# ── Step 2: DCC injection Core 0 검증 ────────────────────────────────────
def dcc_read_pc(jl, core_base):
    """MCR p14,0,R15,c0,c5,0 → DBGITR write → DBGDTRTX read
    전제: 코어가 halted 상태여야 함"""
    dbgitr  = core_base + DBGDSCR_OFF   # write path → DBGITR
    dtrtx   = core_base + DBGDTRTX_OFF  # read path  → DBGDTRTX

    try:
        # DCC TX 비어있는지 확인 (DBGDSCR bit 29 = TXfull_l)
        dscr_before = jl.memory_read32(core_base + DBGDSCR_OFF, 1)[0]
        if not (dscr_before & 0x1):
            return None, f"코어 미halt (DBGDSCR={dscr_before:#010x})"

        tx_was_full = bool((dscr_before >> 29) & 0x1)
        if tx_was_full:
            # 기존 데이터 drain
            _ = jl.memory_read32(dtrtx, 1)[0]

        # MCR p14,0,R15,c0,c5,0 주입
        jl.memory_write32(dbgitr, [MCR_R15_TO_DCC])
        time.sleep(0.002)

        # DBGDSCR에서 TXfull 확인
        dscr_after = jl.memory_read32(core_base + DBGDSCR_OFF, 1)[0]
        tx_full = bool((dscr_after >> 29) & 0x1)

        # DBGDTRTX 읽기 (0x08C)
        pc_dcc = jl.memory_read32(dtrtx, 1)[0]

        # 진단: 0x080~0x08C 전 오프셋 스캔
        scan_vals = {}
        for off in [0x080, 0x084, 0x088, 0x08C]:
            try:
                scan_vals[off] = jl.memory_read32(core_base + off, 1)[0]
            except Exception:
                scan_vals[off] = None
        scan_str = "  ".join(f"[{off:#05x}]={v:#010x}" if v is not None else f"[{off:#05x}]=ERR"
                             for off, v in scan_vals.items())

        return pc_dcc, f"TXfull_before={tx_was_full} TXfull_after={tx_full} DCC={pc_dcc:#010x}\n    scan: {scan_str}"
    except Exception as e:
        return None, f"예외: {e}"


def verify_dcc_on_core0(jl, fns, known_pc):
    """DCC injection을 Core 0에서 먼저 검증 (known_pc와 비교)"""
    print(f"\n=== [Step 2] DCC injection Core 0 검증 (expected PC ≈ {known_pc:#010x}) ===")
    configure_core(fns, CORE_BASES[0])

    # Core 0는 이미 halt된 상태
    pc_dcc, detail = dcc_read_pc(jl, CORE_BASES[0])
    print(f"  DCC 결과: {detail}")

    if pc_dcc is not None:
        diff = abs(pc_dcc - known_pc)
        if diff <= 8:
            print(f"  ✓ known PC와 {diff}바이트 차이 → DCC injection 유효")
            return True
        else:
            print(f"  ✗ known PC({known_pc:#010x})와 차이 큼({diff}) → DBGDTRTX 오프셋 불일치 가능")
            # 다른 오프셋 시도
            for alt_off in [0x084, 0x090, 0x08C]:
                alt_dtrtx = CORE_BASES[0] + alt_off
                try:
                    alt_val = jl.memory_read32(alt_dtrtx, 1)[0]
                    diff2 = abs(alt_val - known_pc)
                    print(f"    offset 0x{alt_off:03X}: {alt_val:#010x}  (diff={diff2})")
                    if diff2 <= 8:
                        print(f"    → ✓ 실제 DBGDTRTX offset = 0x{alt_off:03X}")
                except Exception:
                    pass
    return False


# ── Step 3: Core 1/2 PC 읽기 ─────────────────────────────────────────────
def read_multicore_pcs(jl, fns, c0_pc, cti_ok, dcc_valid):
    print(f"\n=== [Step 3] 멀티코어 PC 읽기 ===")
    print(f"  Core 0 (기준): {c0_pc:#010x}  [jl.register_read]")

    if not cti_ok:
        print("  CTI 미동작 → Core 1/2 halt 불가. PC 읽기 skip.")
        print("  → CTI 레지스터 직접 설정 또는 J-Link 업그레이드 필요")
        return

    if not dcc_valid:
        print("  DCC injection 검증 실패 → DBGDTRTX 오프셋 확인 필요")

    for i in [1, 2]:
        configure_core(fns, CORE_BASES[i])
        pc_dcc, detail = dcc_read_pc(jl, CORE_BASES[i])
        if pc_dcc is not None:
            same = (pc_dcc == c0_pc)
            note = "  ← Core 0와 동일 (DCC 오동작?)" if same else "  ✓ 독립 PC"
            print(f"  Core {i}: {pc_dcc:#010x}{note}  [{detail}]")
        else:
            print(f"  Core {i}: 읽기 실패  [{detail}]")

    configure_core(fns, CORE_BASES[0])


# ── CoreSight 스캔 ────────────────────────────────────────────────────────
_PART = {0xC18:"Cortex-R8 Debug", 0x906:"CTI", 0x907:"ETB",
         0x912:"TPIU", 0x925:"ETMv3", 0x961:"TMC/ETB", 0x95D:"ETMv4"}

def scan_coresight(jl):
    print("\n=== CoreSight 스캔 (0x80000000-0x80060000) ===")
    found = []
    for addr in range(0x80000000, 0x80060000, 0x1000):
        try:
            c = jl.memory_read32(addr + 0xFF0, 4)
            if c[0] != 0x0D or c[2] != 0x05 or c[3] != 0xB1:
                continue
            p = jl.memory_read32(addr + 0xFE0, 4)
            part = (p[0] & 0xFF) | ((p[1] & 0x0F) << 8)
            name = _PART.get(part, f"Unknown(0x{part:03X})")
            found.append((addr, part, name))
            print(f"  0x{addr:08X}  {name}  Part=0x{part:03X}")
        except Exception:
            pass
    if not found:
        print("  없음")


# ── main ──────────────────────────────────────────────────────────────────
def main():
    jl = pylink.JLink()
    jl.open()
    jl.set_tif(pylink.enums.JLinkInterfaces.SWD)
    jl.connect("Cortex-R8", speed=4000)
    log.info("SWD 연결 완료")

    fns = setup_dll(jl._dll)

    enable_power(jl, fns)

    # Step 1: CTI 검증 (Core 0 halt 유지 상태로 진행)
    c0_pc, cti_ok, _ = test_cti(jl, fns)

    # Step 2: DCC injection Core 0 검증 (Core 0 아직 halt 상태)
    dcc_valid = verify_dcc_on_core0(jl, fns, c0_pc)

    # Step 3: Core 1/2 PC (CTI + DCC 모두 성공 시)
    read_multicore_pcs(jl, fns, c0_pc, cti_ok, dcc_valid)

    # Core 0 resume
    go(jl, fns)

    scan_coresight(jl)
    jl.close()
    print("\n완료")


if __name__ == "__main__":
    main()
