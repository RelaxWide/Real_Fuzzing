"""
scan.py — 단일 세션 멀티코어 PC 읽기

전략:
  core0.JLinkScript로 한 번 연결 → AP[0]=APB-AP 세션 내 유지
  JLINKARM_CORESIGHT_Configure("CoreBaseAddr=...") 로 코어 전환
  각 코어 halt() + register_read(15) → PC

  재연결 없음. 전체 3코어를 한 세션에서 처리.
  PC가 전부 동일하면 CORESIGHT_Configure 코어 전환이 미동작임을 확인.
"""

import os, ctypes, pylink, logging, time

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
log = logging.getLogger(__name__)

SCRIPT_DIR  = "/mnt/c/Users/Quiruri/Downloads/0L15RYM7_20260327_JLINKTool/0L15RYM7_20260327_JLINKTool/jlink_dump"
SCRIPT_C0   = os.path.join(SCRIPT_DIR, "core0.JLinkScript")
CORE_BASES  = [0x80030000, 0x80032000, 0x80034000]
PWR_REG     = 0x30313f30


def bind(dll, name, argtypes, restype):
    try:
        fn = getattr(dll, name)
        fn.argtypes = argtypes
        fn.restype  = restype
        return fn
    except AttributeError:
        return None


def main():
    if not os.path.isfile(SCRIPT_C0):
        print(f"[ERROR] JLinkScript 없음: {SCRIPT_C0}")
        return

    jl = pylink.JLink()
    jl.open()
    jl.set_tif(pylink.enums.JLinkInterfaces.SWD)
    jl.exec_command(f'scriptfile "{SCRIPT_C0}"')
    jl.connect("Cortex-R8", speed=4000)
    log.info("연결 완료 (core0.JLinkScript)")

    dll = jl._dll
    cfg = bind(dll, "JLINKARM_CORESIGHT_Configure",
               [ctypes.c_char_p], ctypes.c_int)
    go  = bind(dll, "JLINKARM_Go", [], None)

    def switch(i):
        if cfg:
            cfg(f"CoreBaseAddr={CORE_BASES[i]:#010x}".encode())

    def resume():
        if go: go()
        else:
            try: jl.go()
            except Exception: pass

    # ── 전체 코어 디버그 전원 활성화 (AXI-AP 경유) ──────────────────────
    print(f"\n=== 전원 활성화 (0x{PWR_REG:08X}) ===")
    try:
        cur = jl.memory_read32(PWR_REG, 1)[0]
        jl.memory_write32(PWR_REG, [cur | 0x00010101])
        ver = jl.memory_read32(PWR_REG, 1)[0]
        print(f"  {cur:#010x} → {ver:#010x}  (Core0=bit0, Core1=bit8, Core2=bit16)")
    except Exception as e:
        print(f"  실패: {e}")

    # ── 코어별 halt + PC 읽기 ─────────────────────────────────────────────
    print("\n=== 멀티코어 PC 샘플링 (단일 세션) ===")
    pcs = {}

    for i in range(3):
        switch(i)
        time.sleep(0.01)
        try:
            jl.halt()
            time.sleep(0.02)
            pc = jl.register_read(15)
            pcs[i] = pc
            print(f"  Core {i}  halted={jl.halted()}  PC={pc:#010x}")
        except Exception as e:
            print(f"  Core {i}  오류: {e}")
            pcs[i] = None

        if i < 2:
            resume()
            time.sleep(0.02)

    # 마지막 코어 resume
    resume()
    switch(0)
    jl.close()

    # ── 결과 요약 ─────────────────────────────────────────────────────────
    print("\n=== 결과 요약 ===")
    for i, pc in pcs.items():
        print(f"  Core {i}: {pc:#010x}" if pc else f"  Core {i}: 읽기 실패")

    valid = [v for v in pcs.values() if v]
    if len(valid) > 1 and len(set(valid)) == 1:
        print("\n  ⚠ 전 코어 PC 동일 → CORESIGHT_Configure 코어 전환 미동작")
        print("  → halt/register_read 가 여전히 Core 0만 참조하는 것으로 추정")
        print("  → 이 칩에서 멀티코어 PC 샘플링 불가 (SWD 단일코어 한계)")
    elif len(set(valid)) > 1:
        print("\n  ✓ 코어별 독립 PC 확인 → 멀티코어 샘플링 유효")

    print("완료")


if __name__ == "__main__":
    main()
