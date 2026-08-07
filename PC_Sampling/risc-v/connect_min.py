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
    ap.add_argument('--no-warmup', action='store_true',
                    help='예열(1회차) 없이 본 시도만 — 예열이 정말 필요한지 확인용')
    ap.add_argument('--base', type=lambda x: int(x, 0), default=TARGET_BASE)
    args = ap.parse_args()

    print(f"\n{'=' * 62}\n SF-E76 최소 재현\n{'=' * 62}")
    print(f"  version: {VERSION}")
    print("  ※ 핸들 하나로 진행하고 중간에 close 하지 않는다 (성공 당시와 동일)")

    jl = pylink.JLink()
    try:
        jl.open()
    except Exception as e:
        sys.exit(f"J-Link open 실패: {e}\n  (다른 프로그램이 점유 중인지 확인)")
    print(f"  J-Link : {jl.product_name} SN={jl.serial_number}")

    ok = False
    try:
        if not args.no_warmup:
            w = try_connect(jl, WARMUP_BASE, "1회차 (예열 — 실패해도 정상)")
            if w:
                print("\n  참고: 예열 단계가 성공했다. 0x81480000 도 붙는다는 뜻이다.")
                ok = True
        if not ok:
            ok = try_connect(jl, args.base, "2회차 (본 시도)")
    finally:
        try:
            jl.close()
        except Exception:
            pass

    print(f"\n{'=' * 62}\n 판정\n{'=' * 62}")
    if ok:
        print("  ✅ 재현 성공 → 원인은 스윕 구조다.")
        print("     스윕을 이 순서(핸들 유지 + 예열 후 본 시도)로 맞춰 고친다.")
    else:
        print("  ❌ 재현 실패 → 코드가 아니라 환경이다.")
        print("     확인 순서:")
        print("       1) 타깃(SSD) 전원 사이클 후 즉시 재실행")
        print("          — cJTAG 는 4선→2선 전환이 상태를 남긴다. 반복 open/close 로")
        print("            타깃이 어중간한 모드에 갇혔을 수 있다")
        print("       2) J-Link USB 재연결")
        print("       3) 다른 프로세스가 J-Link 을 잡고 있는지: ps aux | grep -i jlink")
        print("       4) nvme list 로 컨트롤러 생존 확인")


if __name__ == '__main__':
    main()
