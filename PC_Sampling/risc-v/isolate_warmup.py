#!/usr/bin/env python3
"""SF-E76 — '첫 connect 는 왜 실패하는가' 메커니즘 분리 (feedback.md §8.3).

배경: 같은 handle 에서 1회차 connect 는 실패하고 2회차는 성공한다는 것까지는
      통제 실험으로 확정했다(주소가 아니라 순서 문제). 그러나 각 회차가
      `setup → connect` 를 통째로 반복했기 때문에 **무엇이 필요한지**는 미분리다:

        1. 실패한 connect 자체가 초기화를 수행한다
        2. setup 명령을 두 번 적용해야 설정이 유효해진다
        3. 그냥 시간이 지나 debug domain/DM 이 준비된다

실험 (각각 cold handle 에서 시작):

    A  setup 1회 → connect → connect          2회차 성공 = **failed connect 가 초기화**
    B  setup 2회 → connect 1회                 성공     = **setup 이중 적용 필요**
    C  setup 1회 → sleep(N) → connect 1회      성공     = **readiness 지연**

가능하면 **각 실험 사이에 타깃 전원 사이클**을 하는 것이 이상적이다.
(못 하면 최소한 실행 사이 간격을 두고, 결과를 여러 번 재현할 것)

사용법:
    sudo python3 isolate_warmup.py            # A, B, C 순서대로
    sudo python3 isolate_warmup.py --only A
    sudo python3 isolate_warmup.py --sleep 3  # C 의 대기 시간(초)
    sudo python3 isolate_warmup.py --base 0x81481000
"""

import argparse
import sys
import time

try:
    import pylink
except ImportError:
    sys.exit("pylink 없음 →  pip3 install pylink-square")

VERSION = "2026-08-08.4  warmup 메커니즘 분리 (A/B/C)"

DEVICE     = 'RISC-V'
TIF_CJTAG  = 7
SPEED_KHZ  = 10000
CJTAG_MODE = 0
APB_INDEX  = 0
BASE       = 0x81480000

AP_MAP = [
    ("APBAP1", 0x10000, "APB-AP"), ("APBAP2", 0x20000, "APB-AP"),
    ("AXIAP1", 0x30000, "AXI-AP"), ("AHBAP1", 0x40000, "AHB-AP"),
    ("APBAP3", 0x50000, "APB-AP"), ("APBAP4", 0x60000, "APB-AP"),
]


def setup(jl, base, tag=""):
    try:
        jl.exec_command(f"SetcJTAGInitMode = {CJTAG_MODE}")
        jl.set_tif(TIF_CJTAG)
        jl.set_speed(SPEED_KHZ)
        for i, (n, a, t) in enumerate(AP_MAP):
            jl.exec_command(f"CORESIGHT_AddAP = Index={i} Type={t} Addr=0x{a:X}")
        jl.exec_command(f"CORESIGHT_SetIndexAPBAPToUse = {APB_INDEX}")
        jl.exec_command(f"CORESIGHT_SetCoreBaseAddr = 0x{base:X}")
        print(f"    setup{tag} 완료")
        return True
    except Exception as e:
        print(f"    setup{tag} 실패: {e}")
        return False


def conn(jl, tag=""):
    try:
        jl.connect(DEVICE, speed=SPEED_KHZ)
        print(f"    connect{tag} ★ 성공")
        return True
    except Exception as e:
        print(f"    connect{tag} 실패: {e}")
        return False


def fresh():
    jl = pylink.JLink()
    jl.open()
    return jl


def close(jl):
    try:
        jl.close()
    except Exception:
        pass
    time.sleep(0.5)          # DLL/프로브가 핸들을 놓을 시간


# ══════════════════════════════════════════════════════════════════
def exp_a(base):
    """setup 1회 → connect → connect.  2회차 성공이면 failed connect 가 초기화."""
    print("\n[A] setup 1회 → connect 2회  (setup 재적용 없음)")
    jl = fresh()
    try:
        if not setup(jl, base):
            return None
        r1 = conn(jl, " 1회차")
        r2 = False if r1 else conn(jl, " 2회차")
        return (r1, r2)
    finally:
        close(jl)


def exp_b(base):
    """setup 2회 → connect 1회.  성공이면 setup 이중 적용이 필요."""
    print("\n[B] setup 2회 → connect 1회")
    jl = fresh()
    try:
        if not setup(jl, base, " 1st"):
            return None
        if not setup(jl, base, " 2nd"):
            return None
        return (conn(jl, ""),)
    finally:
        close(jl)


def exp_c(base, secs):
    """setup → sleep → connect 1회.  성공이면 readiness 지연."""
    print(f"\n[C] setup → {secs}s 대기 → connect 1회")
    jl = fresh()
    try:
        if not setup(jl, base):
            return None
        print(f"    {secs}s 대기...")
        time.sleep(secs)
        return (conn(jl, ""),)
    finally:
        close(jl)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--only', choices=['A', 'B', 'C'])
    ap.add_argument('--sleep', type=float, default=1.0, help='C 의 대기 시간(초)')
    ap.add_argument('--base', type=lambda x: int(x, 0), default=BASE)
    args = ap.parse_args()

    print(f"\n{'=' * 62}\n warmup 메커니즘 분리\n{'=' * 62}")
    print(f"  version : {VERSION}")
    print(f"  CoreBase: 0x{args.base:X}")
    print("  ※ 각 실험은 cold handle 에서 시작한다.")
    print("  ※ 가능하면 실험 사이에 타깃 전원 사이클을 하는 것이 이상적이다.")

    res = {}
    if args.only in (None, 'A'):
        res['A'] = exp_a(args.base)
    if args.only in (None, 'B'):
        res['B'] = exp_b(args.base)
    if args.only in (None, 'C'):
        res['C'] = exp_c(args.base, args.sleep)

    print(f"\n{'=' * 62}\n 판정\n{'=' * 62}")
    a, b, c = res.get('A'), res.get('B'), res.get('C')

    if a:
        if not a[0] and a[1]:
            print("  ★ [A] setup 재적용 없이 2회차 connect 성공")
            print("      → **실패한 connect 자체가 초기화를 수행한다.**")
            print("      → 해결책: 정식 ConfigTargetSettings() 로 cold connect 를 성공시킨다")
            print("        (임시로는 동일 handle 에서 bounded retry)")
        elif a[0]:
            print("  ★ [A] 1회차부터 성공 — 이번 세션엔 warmup 이 불필요했다(재현 확인 필요)")
        else:
            print("  [A] 2회 모두 실패 — connect 반복만으로는 안 된다")

    if b:
        if b[0]:
            print("  ★ [B] setup 2회 후 첫 connect 성공")
            print("      → **setup(설정 명령)을 두 번 적용해야 유효하다.**")
            print("      → connect 재시도가 아니라 설정 재적용이 해법")
        else:
            print("  [B] setup 2회로도 첫 connect 실패 → setup 이중 적용은 원인이 아니다")

    if c:
        if c[0]:
            print(f"  ★ [C] {args.sleep}s 대기 후 첫 connect 성공")
            print("      → **readiness 지연**. warmup 이 아니라 시간 문제다.")
            print("      → 해법: setup 후 고정 대기. 최소 시간을 --sleep 로 좁힐 것")
        else:
            print(f"  [C] {args.sleep}s 대기로는 불충분")
            print("      → --sleep 3 / 5 로 늘려 재시도하면 경계를 찾을 수 있다")

    print("\n  ※ 한 번의 결과로 확정하지 말 것. 각 실험을 2~3회 재현하고,")
    print("     가능하면 타깃 전원 사이클을 사이에 넣어 초기조건을 맞출 것.")


if __name__ == '__main__':
    main()
