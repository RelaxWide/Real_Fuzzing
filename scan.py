"""
scan.py — JLinkScript 방식 멀티코어 PC 읽기

핵심 원리:
  - exec_command('scriptfile "coreN.JLinkScript"') → connect() 순서로
    J-Link가 AP[0]=APB-AP, AP[1]=AXI-AP 로 올바르게 설정됨
  - register_read(15) 가 해당 스크립트 코어의 실제 PC 반환
  - Core 0 halt → CTI로 Core 1/2 동시 halt → 각 코어 스크립트로 재연결해 PC 읽기
  - DCC injection 불필요

AP 구조 (JLinkScript에서 확인):
  AP[0] = APB-AP  (CORESIGHT_AddAP(0, CORESIGHT_APB_AP)) → 디버그 레지스터
  AP[1] = AXI-AP  (_INDEX_AXI_AP = 1)                    → 시스템 메모리
  AP[2] = AHB-AP  (_INDEX_AHB_AP = 2)                    → Cortex-M 메모리
"""

import os
import ctypes
import pylink
import logging
import time

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
log = logging.getLogger(__name__)

# JLinkScript 파일 경로 (WSL에서 Windows 경로 접근)
SCRIPT_DIR = "/mnt/c/Users/Quiruri/Downloads/0L15RYM7_20260327_JLINKTool/0L15RYM7_20260327_JLINKTool/jlink_dump"
SCRIPTS = {
    0: os.path.join(SCRIPT_DIR, "core0.JLinkScript"),
    1: os.path.join(SCRIPT_DIR, "core1.JLinkScript"),
    2: os.path.join(SCRIPT_DIR, "core2.JLinkScript"),
}

CORE_BASES = [0x80030000, 0x80032000, 0x80034000]
PWR_REG    = 0x30313f30
DBGDSCR_OFF = 0x034   # Cortex-R8 APB-AP 기준 실제 DBGDSCR 오프셋


def make_jlink():
    return pylink.JLink()


def get_dll_go(jl):
    """JLINKARM_Go 직접 바인딩 (jl.go() 버그 우회)"""
    try:
        fn = getattr(jl._dll, "JLINKARM_Go")
        fn.argtypes = []
        fn.restype  = None
        return fn
    except AttributeError:
        return None


def connect_core(jl, core_idx, speed=4000):
    """지정 코어 스크립트로 J-Link 연결"""
    script = SCRIPTS[core_idx]
    if not os.path.isfile(script):
        raise FileNotFoundError(f"JLinkScript 없음: {script}")
    jl.set_tif(pylink.enums.JLinkInterfaces.SWD)
    jl.exec_command(f'scriptfile "{script}"')
    jl.connect("Cortex-R8", speed=speed)
    log.info(f"Core {core_idx} 연결 완료 (script: {os.path.basename(script)})")


def halt_and_keep(jl):
    """halt 후 close — J-Link는 go() 없이 닫으면 halt 상태 유지"""
    try:
        jl.halt()
        time.sleep(0.05)
    except Exception as e:
        log.warning(f"halt 실패: {e}")
    jl.close()


def read_dbgdscr(jl, core_base):
    """APB-AP 통해 DBGDSCR 읽기 (JLinkScript 연결 후에만 유효)"""
    try:
        return jl.memory_read32(core_base + DBGDSCR_OFF, 1)[0]
    except Exception:
        return None


# ── Step 1: Core 0 halt + CTI 확인 ───────────────────────────────────────
def step1_halt_core0_check_cti():
    print("\n=== [Step 1] Core 0 halt → CTI로 Core 1/2 halt 확인 ===")

    jl = make_jlink()
    jl.open()
    connect_core(jl, 0)

    jl.halt()
    time.sleep(0.05)
    c0_pc = jl.register_read(15)
    print(f"  Core 0  PC={c0_pc:#010x}  (register_read 기준)")

    # APB-AP로 Core 1/2 DBGDSCR 읽기 (Core 0 halt 유지 상태)
    cti_ok = True
    for i in [1, 2]:
        dscr = read_dbgdscr(jl, CORE_BASES[i])
        if dscr is None:
            print(f"  Core {i}  DBGDSCR=읽기실패")
            cti_ok = False
        else:
            halted = bool(dscr & 0x1)
            status = "HALTED ← CTI 동작 ✓" if halted else "NOT HALTED → CTI 미동작"
            print(f"  Core {i}  DBGDSCR={dscr:#010x}  {status}")
            if not halted:
                cti_ok = False

    # halt 상태 유지하며 disconnect
    halt_and_keep(jl)

    if cti_ok:
        print("  → CTI 확인됨. Core 1/2 halt 상태로 재연결 시도.")
    else:
        print("  → CTI 미동작. Core 1/2 PC 읽기 불가.")

    return c0_pc, cti_ok


# ── Step 2/3: 각 코어 스크립트로 재연결 → register_read(15) ─────────────
def step2_read_core_pc(core_idx, c0_pc):
    print(f"\n=== [Step {core_idx + 1}] Core {core_idx} PC 읽기 (재연결) ===")

    jl = make_jlink()
    jl.open()
    try:
        connect_core(jl, core_idx)
        time.sleep(0.1)

        # 이미 halt 상태여야 함 (CTI 유지)
        is_halted = jl.halted()
        print(f"  연결 직후 halted={is_halted}")

        if not is_halted:
            # CTI가 유지됐다면 이미 halt — 아니면 직접 halt
            print("  → halt 시도")
            jl.halt()
            time.sleep(0.05)

        pc = jl.register_read(15)
        same = (pc == c0_pc)
        note = "  ← Core 0와 동일 (CTI halt 이전 상태?)" if same else "  ✓ 독립 PC"
        print(f"  Core {core_idx}  PC={pc:#010x}{note}")

        halt_and_keep(jl)
        return pc

    except Exception as e:
        print(f"  Core {core_idx} 읽기 실패: {e}")
        try:
            jl.close()
        except Exception:
            pass
        return None


# ── Step 4: Core 0 재연결 후 resume ──────────────────────────────────────
def step4_resume_all():
    print("\n=== [Step 4] Core 0 재연결 → resume ===")
    jl = make_jlink()
    jl.open()
    connect_core(jl, 0)

    dll_go = get_dll_go(jl)
    if dll_go:
        dll_go()
        print("  JLINKARM_Go() 호출 완료")
    else:
        try:
            jl.go()
        except Exception as e:
            print(f"  go() 실패: {e}")

    time.sleep(0.1)
    print(f"  halted after go: {jl.halted()}")
    jl.close()


# ── main ──────────────────────────────────────────────────────────────────
def main():
    # 스크립트 파일 존재 확인
    for i, path in SCRIPTS.items():
        if not os.path.isfile(path):
            print(f"[ERROR] JLinkScript 없음: {path}")
            print("  SCRIPT_DIR를 실제 경로로 수정하세요.")
            return

    c0_pc, cti_ok = step1_halt_core0_check_cti()

    pcs = {0: c0_pc}

    if cti_ok:
        for i in [1, 2]:
            pcs[i] = step2_read_core_pc(i, c0_pc)
    else:
        print("\n  CTI 미동작 → Core 1/2 PC 읽기 skip")

    step4_resume_all()

    print("\n=== 결과 요약 ===")
    for i, pc in pcs.items():
        if pc is not None:
            print(f"  Core {i}: {pc:#010x}")
        else:
            print(f"  Core {i}: 읽기 실패")
    print("완료")


if __name__ == "__main__":
    main()
