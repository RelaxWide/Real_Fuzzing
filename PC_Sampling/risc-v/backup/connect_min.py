#!/usr/bin/env python3
"""SF-E76 — 성공했던 시퀀스의 **최소 재현**.

목적: 스윕 스크립트가 실패하는 원인이 (A) 내가 구조를 바꾸며 깨뜨린 것인지
      (B) 타깃/프로브 상태가 달라진 것인지 가른다. 그것만 한다.

최초 성공 시 실제로 일어난 일을 **글자 그대로** 재생한다:

    jl.open()                       ← 핸들 하나. 중간에 close 하지 않는다
    [1회차] setup(CoreBase=0x81480000) → connect  → 실패했다
    [2회차] setup(CoreBase=0x81481000) → connect  → 성공했다

즉 **1회차의 실패한 connect 가 예열**이었고, 그 상태를 물려받은 2회차가 붙었다.
스윕을 조합마다 open/close 로 격리하면서 이 예열이 사라진 것으로 의심된다.

판정:
  이 스크립트가 성공 → 스윕 구조가 원인. 스윕을 이 순서에 맞춰 고친다.
  이 스크립트도 실패 → 코드가 아니라 환경. 타깃 전원 사이클 후 재시도.

사용법:
    sudo python3 connect_min.py
    sudo python3 connect_min.py --no-warmup     # 예열 없이 바로 2회차만
"""

import argparse
import sys
import time

try:
    import pylink
except ImportError:
    sys.exit("pylink 없음 →  pip3 install pylink-square")

VERSION = "2026-08-08.3  최소 재현 (예열 connect + 본 connect)"

DEVICE      = 'RISC-V'
TIF_CJTAG   = 7
SPEED_KHZ   = 10000
CJTAG_MODE  = 0
APB_INDEX   = 0

WARMUP_BASE = 0x81480000     # 1회차 — 실패해도 된다(예열)
TARGET_BASE = 0x81481000     # 2회차 — 실제로 붙었던 값

AP_MAP = [
    ("APBAP1", 0x10000, "APB-AP"),
    ("APBAP2", 0x20000, "APB-AP"),
    ("AXIAP1", 0x30000, "AXI-AP"),
    ("AHBAP1", 0x40000, "AHB-AP"),
    ("APBAP3", 0x50000, "APB-AP"),
    ("APBAP4", 0x60000, "APB-AP"),
]


def ex(jl, cmd):
    try:
        jl.exec_command(cmd)
        print(f"      ok   {cmd}")
        return True
    except Exception as e:
        print(f"      FAIL {cmd} -> {e}")
        return False


def setup(jl, core_base):
    ex(jl, f"SetcJTAGInitMode = {CJTAG_MODE}")
    jl.set_tif(TIF_CJTAG)
    jl.set_speed(SPEED_KHZ)
    for i, (n, a, t) in enumerate(AP_MAP):
        ex(jl, f"CORESIGHT_AddAP = Index={i} Type={t} Addr=0x{a:X}")
    ex(jl, f"CORESIGHT_SetIndexAPBAPToUse = {APB_INDEX}")
    ex(jl, f"CORESIGHT_SetCoreBaseAddr = 0x{core_base:X}")


def try_connect(jl, core_base, label):
    print(f"\n  --- {label}: CoreBase=0x{core_base:X} ---")
    setup(jl, core_base)
    try:
        jl.connect(DEVICE, speed=SPEED_KHZ)
    except Exception as e:
        print(f"      connect 실패: {e}")
        return False
    print("      ★ connect 성공")
    for fn, nm in ((jl.halted, 'halted'), (jl.core_name, 'core_name'),
                   (jl.core_id, 'core_id')):
        try:
            print(f"        {nm} = {fn()}")
        except Exception:
            pass
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--order', default=f"0x{WARMUP_BASE:X},0x{TARGET_BASE:X}",
                    help=("시도할 CoreBase 를 순서대로 콤마 구분. 예:\n"
                          "  0x81481000                    단독 (예열이 필요한가)\n"
                          "  0x81481000,0x81480000         순서 뒤집기\n"
                          "  0x81480000,0x81480000         ★ 같은 주소 두 번\n"
                          "     -> 2번째가 붙으면 '위치' 문제, 둘 다 실패면 '주소' 문제"))
    ap.add_argument('--stop-on-success', action='store_true',
                    help='첫 성공에서 중단 (기본: 목록 끝까지 전부 시도)')
    args = ap.parse_args()

    bases = [int(x, 0) for x in args.order.split(',') if x.strip()]

    print(f"\n{'=' * 62}\n SF-E76 최소 재현\n{'=' * 62}")
    print(f"  version: {VERSION}")
    print("  ※ 핸들 하나로 진행하고 중간에 close 하지 않는다 (성공 당시와 동일)")

    jl = pylink.JLink()
    try:
        jl.open()
    except Exception as e:
        sys.exit(f"J-Link open 실패: {e}\n  (다른 프로그램이 점유 중인지 확인)")
    print(f"  J-Link : {jl.product_name} SN={jl.serial_number}")

    results = []
    try:
        for i, b in enumerate(bases, 1):
            r = try_connect(jl, b, f"{i}회차")
            results.append((i, b, r))
            if r and args.stop_on_success:
                break
    finally:
        try:
            jl.close()
        except Exception:
            pass

    print(f"\n{'=' * 62}\n 결과\n{'=' * 62}")
    for i, b, r in results:
        print(f"  {i}회차  CoreBase=0x{b:X}  →  {'성공' if r else '실패'}")

    ok = any(r for _, _, r in results)

    # ── 위치 vs 주소 판정 ────────────────────────────────────────────
    print(f"\n{'=' * 62}\n 판정\n{'=' * 62}")

    if not results:
        print("  시도 없음")
        return

    first_ok = results[0][2]
    later_ok = any(r for _, _, r in results[1:])
    same_addr = len({b for _, b, _ in results}) == 1

    if first_ok:
        print("  ★ 1회차부터 성공 → **예열은 필요 없다.** '첫 connect 는 예열' 가설 무효.")
        print("     이전에 1회차가 실패했던 건 그 주소(0x81480000) 때문이다.")
    elif same_addr and len(results) > 1:
        if later_ok:
            print(f"  ★ 같은 주소 0x{results[0][1]:X} 인데 1회차 실패 / 이후 성공")
            print("     → **위치(순서) 문제.** 첫 connect 는 무조건 실패하며 예열 역할을 한다.")
            print("     → 그 주소 자체는 정상. 샘플러는 connect 를 2회 이상 시도해야 한다.")
        else:
            print(f"  ★ 같은 주소 0x{results[0][1]:X} 를 {len(results)}회 시도해 전부 실패")
            print("     → **그 주소가 실제로 안 되는 것**(순서 무관).")
            print("     → 해당 코어가 리셋/정지 상태이거나 AP/주소가 다르다.")
    elif later_ok:
        print("  1회차 실패 / 이후 성공 — 주소가 서로 달라 원인 분리 불가.")
        print("  → 같은 주소를 두 번 시도해 확정할 것:")
        print(f"     sudo python3 connect_min.py --order 0x{results[0][1]:X},0x{results[0][1]:X}")
    else:
        print("  ❌ 전부 실패 → 코드가 아니라 환경일 수 있다.")
        print("     1) 타깃(SSD) 전원 사이클 후 즉시 재실행")
        print("        — cJTAG 는 4선→2선 전환이 타깃에 상태를 남긴다")
        print("     2) J-Link USB 재연결")
        print("     3) ps aux | grep -i jlink   (다른 프로세스 점유)")
        print("     4) nvme list                (컨트롤러 생존)")


if __name__ == '__main__':
    main()
