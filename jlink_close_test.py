#!/usr/bin/env python3
"""jlink.close() DBGPWRUPREQ 해제 검증 스크립트.

J-Link close() 호출 시 DBGPWRUPREQ가 실제로 해제되어
SSD 전류가 낮아지는지 확인.

PMU 전류 변화로 판단:
  [2] close() 후 전류 하락 → DBGPWRUPREQ 해제 효과 있음
  [3] open()+connect() 후 전류 복귀 → 정상 재연결 확인

사용:
    sudo python3 jlink_close_test.py --device Cortex-R8
"""
import argparse
import time
import sys

try:
    import pylink
except ImportError:
    print("pylink-square 가 설치되지 않았습니다: pip install pylink-square")
    sys.exit(1)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--device', default='Cortex-R8')
    p.add_argument('--speed',  type=int, default=4000)
    args = p.parse_args()

    jl = pylink.JLink()
    jl.open()
    jl.set_tif(pylink.enums.JLinkInterfaces.SWD)
    jl.connect(args.device, speed=args.speed)
    print(f"[J-Link] Connected: {args.device} @ {args.speed}kHz")

    # ── Step 1: 기준 전류 ─────────────────────────────────────────────────
    print("\n[1] 연결 직후 — PMU 전류 기준값 확인 (예상: ~470mA)")
    input("    Enter to continue...")

    # ── Step 2: jlink.close() ─────────────────────────────────────────────
    jl.close()
    print("\n[2] jlink.close() 완료 — PMU 전류 확인")
    print("    목표: 전류 하락 (예상: ~285mA 수준)")
    input("    Enter to continue...")

    # ── Step 3: 재연결 ────────────────────────────────────────────────────
    jl2 = pylink.JLink()
    jl2.open()
    jl2.set_tif(pylink.enums.JLinkInterfaces.SWD)
    jl2.connect(args.device, speed=args.speed)
    print(f"\n[3] 재연결 완료 — PMU 전류 확인 (예상: ~470mA 복귀)")
    input("    Enter to continue...")

    jl2.close()
    print("\n[완료]")
    print("\n결과 해석:")
    print("  [2]에서 전류 하락 → jlink.close()로 DBGPWRUPREQ 해제 확인")
    print("  [2]에서 변화 없음 → 물리 핀 자체가 전류 원인 (하드웨어 스위치 필요)")


if __name__ == '__main__':
    main()
