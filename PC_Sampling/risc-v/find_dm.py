#!/usr/bin/env python3
"""SF-E76 — DM 이 **어디에 있는지** 찾는다. J-Link 자신을 오라클로 쓴다.

════════════════════════════════════════════════════════════════════
왜 방향을 바꾸는가 (2026-08-10)
════════════════════════════════════════════════════════════════════
지금까지 raw DAP 로 직접 메모리를 읽어 DM 을 찾으려 했다. 그런데
SEGGER 공식 문서(J-Link RISC-V, "RISC-V behind a CoreSight DAP")가 못박는다:

    * There is no ROM table scan available for RISC-V
    * J-Link cannot auto-detect behind which AP the RISC-V can be found
    * J-Link cannot auto-detect where in the AP address space the
      RISC-V DMI registers can be found
    * the user needs to manually specify where to find the RISC-V core

**ROM 테이블은 처음부터 없는 기능이었다.** "ROM 테이블 없음" 이 나온 건
버그가 아니라 사양이다. 그쪽 길은 막힌 게 아니라 애초에 길이 아니었다.

그리고 같은 문서의 SEGGER 예제가 결정적이다:

    CORESIGHT_SetIndexAPBAPToUse = 1
    CORESIGHT_SetCoreBaseAddr    = 0x0   ← "Address in AP address space
                                            where DMI registers can be found"

**`0x0` 이다.** 우리가 쓰던 `0x81480000` 은 T32 의 **APB 버스 주소**이고,
J-Link 이 요구하는 건 **AP 주소공간 내 오프셋**이다. 같다는 보장이 없다.
이게 `dmactive` 타임아웃의 가장 그럴듯한 설명이다.

════════════════════════════════════════════════════════════════════
접근 — 우리가 DMI 를 구현하지 않는다
════════════════════════════════════════════════════════════════════
DMI 프로토콜은 J-Link 이 이미 안다. 우리가 할 일은 **어디인지 알려주는 것**뿐이다.
그래서 후보를 넣고 **J-Link 의 connect 가 DM 을 깨우는지**로 판정한다.

오라클(성공 판정):
    1. DAP 전원 ACK        — 세션이 유효한가 (아니면 그 시행은 **무효**)
    2. connect 예외 없음
    3. `halted()` 가 동작  — ★ **DM 이 살아야만 된다.** 비침습(halt 아님)
    4. 에러 문자열에 'debug module' 이 없다

모드:
  --devices  AP 맵을 **수동 지정하지 않고** 장치명만 준다.
             SEGGER: "If a specific device is selected, J-Link usually has a
             compiled-in script which already specifies the parameters"
             → 우리가 손으로 넣던 걸 J-Link 이 대신 해줄 수 있다. **가장 싸다.**
  --sweep    AP 인덱스 × CoreBase 후보 전수. 위가 안 될 때.

사용:
    sudo python3 find_dm.py --devices
    sudo python3 find_dm.py --sweep
"""

import argparse
import json
import os
import subprocess
import sys
import time

import pylink

from sfe76_link import TIF_CJTAG, SPEED_KHZ, CJTAG_MODE, AP_MAP, EXIT_OK, EXIT_INSUFFICIENT

VERSION = "2026-08-10.1"

DEVICES = ['E76', 'E76-MC', 'E76ARTY', 'RISC-V']
# CoreBase 후보 — SEGGER 예제의 0x0 을 **앞에 둔다**
CORE_BASES = [0x0, 0x81480000, 0x81481000, 0x1480000, 0x480000, 0x80000]


def head(t):
    print(f"\n{'=' * 68}\n {t}\n{'=' * 68}")


# ══════════════════════════════════════════════════════════════════
# 자식 프로세스: 후보 하나만 시도한다 (핸들 재사용 = 거짓 성공, 실측으로 확인됨)
# ══════════════════════════════════════════════════════════════════
def run_one(a):
    rec = {'device': a.device, 'ap_index': a.ap_index, 'core_base': a.core_base,
           'manual_ap': a.manual_ap, 'power': False, 'connect': False,
           'dm_alive': False, 'error': None}
    jl = pylink.JLink()
    try:
        jl.open()
        jl.exec_command(f"SetcJTAGInitMode = {CJTAG_MODE}")
        jl.set_tif(TIF_CJTAG)
        jl.set_speed(SPEED_KHZ)

        if a.manual_ap:
            for i, (_n, addr, typ) in enumerate(AP_MAP):
                jl.exec_command(f"CORESIGHT_AddAP = Index={i} Type={typ} Addr=0x{addr:X}")
            jl.exec_command(f"CORESIGHT_SetIndexAPBAPToUse = {a.ap_index}")
            jl.exec_command(f"CORESIGHT_SetCoreBaseAddr = 0x{a.core_base:X}")

        for t in range(1, a.tries + 1):
            try:
                jl.connect(a.device, speed=SPEED_KHZ)
                rec['connect'] = True
                rec['tries'] = t
                break
            except Exception as e:
                rec['error'] = str(e)[:150]
                time.sleep(0.3)

        # 세션 유효성 — 전원 ACK 가 없으면 이 시행은 '실패' 가 아니라 '무효'
        try:
            jl.coresight_configure(ir_pre=0, dr_pre=0, ir_post=0, dr_post=0,
                                   ir_len=4, perform_tif_init=False)
            v = jl.coresight_read(1, ap=False)
            rec['power'] = bool(v and v > 0 and v & (1 << 29))
            rec['ctrl_stat'] = f"0x{v & 0xFFFFFFFF:08X}" if v and v > 0 else None
        except Exception:
            pass

        # ★ DM 오라클 — halted() 는 DM 이 살아야만 동작한다. halt 하지 않는다.
        if rec['connect']:
            try:
                rec['halted'] = bool(jl.halted())
                rec['dm_alive'] = True
            except Exception as e:
                rec['error'] = rec['error'] or str(e)[:150]
    except Exception as e:
        rec['error'] = str(e)[:150]
    finally:
        try:
            jl.close()
        except Exception:
            pass
    print("@@JSON@@" + json.dumps(rec, ensure_ascii=False))
    return EXIT_OK if rec['dm_alive'] else EXIT_INSUFFICIENT


def spawn(device, ap_index, core_base, manual_ap, tries):
    cmd = [sys.executable, os.path.abspath(__file__), '--single',
           '--device', str(device), '--ap-index', str(ap_index),
           '--core-base', hex(core_base), '--tries', str(tries)]
    if manual_ap:
        cmd.append('--manual-ap')
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=180).stdout
    except subprocess.TimeoutExpired:
        return {'error': 'timeout', 'dm_alive': False, 'power': False, 'connect': False}
    for line in out.splitlines():
        if line.startswith("@@JSON@@"):
            return json.loads(line[len("@@JSON@@"):])
    return {'error': 'no result', 'dm_alive': False, 'power': False, 'connect': False}


def show(tag, r):
    if r.get('dm_alive'):
        mark = "★★ DM 살아있음"
    elif r.get('connect'):
        mark = "connect만 성공"
    elif not r.get('power'):
        mark = "무효(전원 ACK 없음)"
    else:
        mark = "실패"
    err = (r.get('error') or "")
    dm_err = " ←'debug module' 에러" if 'debug module' in err.lower() else ""
    print(f"  {tag:44s} {mark}{dm_err}")
    if err and not r.get('dm_alive'):
        print(f"      {err[:110]}")


# ══════════════════════════════════════════════════════════════════
def mode_devices(a):
    head("[A] 장치명만 준다 — J-Link 내장 스크립트에 맡긴다")
    print("  SEGGER: 특정 장치를 고르면 J-Link 에 그 장치용 스크립트가 이미 있어")
    print("  AP 맵과 DMI 위치를 자동 설정한다. **우리가 손으로 넣을 필요가 없다.**")
    print("  → AP 맵을 수동 지정하지 **않고** 장치명만 바꿔가며 시도한다.\n")
    best = []
    for dev in DEVICES:
        r = spawn(dev, 0, 0, False, a.tries)
        show(f"device={dev!r}  (AP 맵 수동지정 없음)", r)
        if r.get('dm_alive'):
            best.append(dev)
        time.sleep(0.4)
    return best


def mode_sweep(a):
    head("[B] AP 인덱스 × CoreBase 전수 — AP 맵은 수동 지정")
    print("  SEGGER 예제의 CoreBase 는 0x0 이다. 우리가 쓰던 0x81480000 은")
    print("  T32 의 **APB 버스 주소**이고, J-Link 이 원하는 건 **AP 주소공간 오프셋**이다.")
    print("  같다는 보장이 없으므로 0x0 을 포함해 전수로 본다.\n")
    hits = []
    for ap_i in a.ap_indexes:
        for cb in CORE_BASES:
            r = spawn(a.device, ap_i, cb, True, a.tries)
            show(f"AP idx={ap_i} ({AP_MAP[ap_i][0]})  CoreBase=0x{cb:08X}", r)
            if r.get('dm_alive'):
                hits.append((ap_i, cb))
            time.sleep(0.3)
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--devices', action='store_true', help='[A] 장치명 모드')
    ap.add_argument('--sweep', action='store_true', help='[B] 전수 모드')
    ap.add_argument('--device', default='RISC-V')
    ap.add_argument('--ap-indexes', default="0,1,4,5",
                    help='시험할 APB-AP 인덱스 (기본: APB 타입 4개)')
    ap.add_argument('--tries', type=int, default=3)
    ap.add_argument('--single', action='store_true', help=argparse.SUPPRESS)
    ap.add_argument('--ap-index', type=int, default=0, help=argparse.SUPPRESS)
    ap.add_argument('--core-base', type=lambda x: int(x, 0), default=0,
                    help=argparse.SUPPRESS)
    ap.add_argument('--manual-ap', action='store_true', help=argparse.SUPPRESS)
    a = ap.parse_args()

    if a.single:
        return run_one(a)

    a.ap_indexes = [int(x) for x in a.ap_indexes.split(',')]
    head(f"DM 위치 탐색 — J-Link 을 오라클로 (v{VERSION})")
    print("  판정: 전원 ACK(세션 유효) + connect + **halted() 동작(=DM 살아있음)**")
    print("  halted() 는 비침습이다. halt 하지 않는다.")

    found_dev = mode_devices(a) if (a.devices or not a.sweep) else []
    hits = mode_sweep(a) if (a.sweep or not a.devices) else []

    head("결론")
    if found_dev:
        print(f"  ★★ 장치명만으로 DM 이 살아났다: {found_dev}")
        print("     → AP 맵 수동 지정을 버리고 이 장치명을 쓴다. 브링업의 블로커 해소.")
    if hits:
        print(f"  ★★ 동작한 (AP 인덱스, CoreBase): {hits}")
        print("     → sfe76_link 의 APB_INDEX / CORE_BASE 를 이 값으로 고정한다.")
    if not found_dev and not hits:
        print("  ❌ 어느 조합도 DM 을 깨우지 못했다.")
        print()
        print("  여기까지 확정된 것 (전부 실측):")
        print("    · cJTAG / DP 통신 / DAP 전원(디버그·시스템 둘 다) 정상")
        print("    · AP 6개 전부 실재, IDR.TYPE 이 T32 선언과 6/6 일치, DESIGNER=SiFive")
        print("    · AP 레지스터 읽기·쓰기 동작")
        print("    · 남은 한 가지: **DMI 위치를 J-Link 에 알려주지 못했다**")
        print()
        print("  → 이건 추측으로 더 좁힐 수 있는 문제가 아니다. 둘 중 하나로 간다:")
        print("     (a) 벤더/설계팀에 질문 — 'RISC-V DM 의 DMI 레지스터가 어느 AP 뒤,")
        print("         그 AP 주소공간 내 **어느 오프셋**에 있는가?' (T32 의 APB 주소 말고)")
        print("     (b) SEGGER 지원에 문의 — 위 실측을 그대로 첨부하면 답이 빠르다.")
        print("         SiFive ADIv6 DAP + cJTAG + RISC-V DM 조합은 그쪽 전문 영역이다.")
    return EXIT_OK if (found_dev or hits) else EXIT_INSUFFICIENT


if __name__ == '__main__':
    sys.exit(main())
