#!/usr/bin/env python3
"""SF-E76 — DAP 전원 인가가 되는지만 본다. **가장 아래 층.**

════════════════════════════════════════════════════════════════════
목적
════════════════════════════════════════════════════════════════════
"Failed to power-up DAP" 가 떴다. 이게 사실이면 **AP 접근이 전부 실패하는 게
당연**하고, dmactive 타임아웃도 같은 원인으로 설명된다(DM 은 AP 뒤에 있다).

그런데 **예전엔 CTRL/STAT = 0xF0000000 (전원 ACK)이 떴었다** — V9.12 시절.
지금 안 된다면 회귀인지 조건 차이인지 가려야 한다.

이 도구는 **DP 계층만** 본다. connect 도, AP 도, DM 도 건드리지 않는다:

    1. DPIDR 읽기           → DP 와 통신되나
    2. ABORT + 전원 요청    → CTRL/STAT 에 ACK 가 서나
    3. AP map 개수 변화     → AP 를 6개 등록하는 게 방해가 되나

3번이 중요하다: **존재하지 않는 AP 를 등록하면 J-Link 열거가 깨질 수 있다.**
지금 6개를 등록하는데, 실제로 확인된 건 하나도 없다.

판정:
  DPIDR 유효 + ACK 섬     → DP 는 정상. 문제는 그 위(AP/DM)
  DPIDR 유효 + ACK 없음   → 전원 인가 실패가 진짜 블로커
  DPIDR 무효              → cJTAG/스캔 계층부터 문제 (회귀)

════════════════════════════════════════════════════════════════════
사용
════════════════════════════════════════════════════════════════════
    sudo python3 probe_dap.py                 # AP 등록 없음 / 1개 / 6개 비교
    sudo python3 probe_dap.py --no-connect    # connect 아예 안 함
"""

import argparse
import sys
import time

try:
    import pylink
except ImportError:
    sys.exit("pylink 없음 →  pip3 install pylink-square")

from sfe76_link import (TIF_CJTAG, SPEED_KHZ, CJTAG_MODE, DEVICE, AP_MAP,
                        APB_INDEX, CORE_BASE_NCORE, EXIT_OK, EXIT_INSUFFICIENT)

VERSION = "2026-08-10.1"

DP_IDR_ABORT = 0
DP_CTRL_STAT = 1


def hx(v):
    if v is None:
        return "실패"
    return f"0x{v & 0xFFFFFFFF:08X}" + (f" [음수 {v}]" if v < 0 else "")


def dp_read(jl, reg):
    try:
        return jl.coresight_read(reg, ap=False)
    except Exception as e:
        print(f"      !! DP read {reg}: {e}")
        return None


def dp_write(jl, reg, val):
    try:
        jl.coresight_write(reg, val, ap=False)
        return True
    except Exception as e:
        print(f"      !! DP write {reg}: {e}")
        return False


def valid_dpidr(v):
    """DPIDR 은 bit0 = RAO(항상 1). 짝수면 데이터가 아니다."""
    return v is not None and v > 0 and (v & 1) == 1 and v not in (1, 0xFFFFFFFF)


def attempt(nap, do_connect, device):
    """AP 를 nap 개 등록하고 DP 전원을 확인한다."""
    label = f"AP 등록 {nap}개 / connect={'O' if do_connect else 'X'}"
    print(f"\n{'-' * 66}\n {label}\n{'-' * 66}")

    jl = pylink.JLink()
    try:
        jl.open()
    except Exception as e:
        print(f"  open 실패: {e}")
        return None
    try:
        jl.exec_command(f"SetcJTAGInitMode = {CJTAG_MODE}")
        jl.set_tif(TIF_CJTAG)
        jl.set_speed(SPEED_KHZ)
        for i, (nm, addr, typ) in enumerate(AP_MAP[:nap]):
            jl.exec_command(f"CORESIGHT_AddAP = Index={i} Type={typ} Addr=0x{addr:X}")
        if nap:
            jl.exec_command(f"CORESIGHT_SetIndexAPBAPToUse = {min(APB_INDEX, nap - 1)}")
            jl.exec_command(f"CORESIGHT_SetCoreBaseAddr = 0x{CORE_BASE_NCORE:X}")

        if do_connect:
            try:
                jl.connect(device, speed=SPEED_KHZ)
                print("  connect 성공")
            except Exception as e:
                print(f"  connect 실패: {str(e)[:90]}")

        # CoreSight 계층 준비 — 단일 TAP, IRLen 4
        for kw in ({'ir_pre': 0, 'dr_pre': 0, 'ir_post': 0, 'dr_post': 0, 'ir_len': 4}, {}):
            try:
                jl.coresight_configure(**kw)
                print(f"  coresight_configure({kw or '기본'}) OK")
                break
            except Exception as e:
                print(f"  coresight_configure 실패: {e}")
        else:
            return None

        idr = dp_read(jl, DP_IDR_ABORT)
        print(f"  DPIDR      = {hx(idr)}", end="")
        if valid_dpidr(idr):
            ver = (idr >> 12) & 0xF
            des = (idr >> 1) & 0x7FF
            print(f"   ✅ 유효 (DPv{ver}, DESIGNER=0x{des:03X})")
        else:
            print("   ❌ 무효 — DP 통신 자체가 안 된다")
            return {'dpidr': idr, 'ack': False}

        dp_write(jl, DP_IDR_ABORT, 0x0000001E)      # sticky 클리어
        dp_write(jl, DP_CTRL_STAT, 0x50000000)      # CSYSPWRUPREQ|CDBGPWRUPREQ
        ctrl = None
        for _ in range(20):
            time.sleep(0.01)
            ctrl = dp_read(jl, DP_CTRL_STAT)
            if ctrl is not None and ctrl > 0 and (ctrl & 0xA0000000) == 0xA0000000:
                break
        ack = ctrl is not None and ctrl > 0 and (ctrl & 0xA0000000) == 0xA0000000
        print(f"  CTRL/STAT  = {hx(ctrl)}   {'✅ 전원 ACK' if ack else '❌ ACK 없음'}")
        if ctrl and ctrl > 0 and (ctrl & 0x000000A0):
            print("               ⚠ STICKYERR/STICKYORUN — 접근이 거부되고 있다")
        return {'dpidr': idr, 'ack': ack, 'ctrl': ctrl}
    finally:
        try:
            jl.close()
        except Exception:
            pass
        time.sleep(0.4)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--device', default=DEVICE)
    ap.add_argument('--no-connect', action='store_true',
                    help='connect 를 아예 하지 않고 DP 만 본다')
    a = ap.parse_args()

    print(f"\n{'=' * 66}")
    print(f" DAP 전원 인가 확인 — 가장 아래 층만 (v{VERSION})")
    print(f"{'=' * 66}")
    print("  'Failed to power-up DAP' 가 진짜인지, AP 등록이 방해가 되는지 가른다.")
    print("  connect / AP 접근 / DM 은 건드리지 않는다.")

    combos = [(0, False), (1, False), (len(AP_MAP), False)]
    if not a.no_connect:
        combos += [(1, True), (len(AP_MAP), True)]

    res = []
    for nap, conn in combos:
        r = attempt(nap, conn, a.device)
        res.append((nap, conn, r))

    print(f"\n{'=' * 66}\n 판정\n{'=' * 66}")
    ok_dp = [(n, c) for n, c, r in res if r and valid_dpidr(r.get('dpidr'))]
    ok_ack = [(n, c) for n, c, r in res if r and r.get('ack')]

    print(f"  DPIDR 유효한 조합 : {ok_dp if ok_dp else '없음'}")
    print(f"  전원 ACK 뜬 조합  : {ok_ack if ok_ack else '없음'}")

    if not ok_dp:
        print("\n  ❌ DP 통신 자체가 안 된다 — cJTAG/스캔 계층 문제(회귀 의심).")
        print("     예전에 DPIDR=0x11013913 을 읽었으므로 조건이 달라진 것이다.")
        print("     타깃 전원 사이클 후 재시도, J-Link USB 재연결 확인.")
    elif not ok_ack:
        print("\n  ★ DP 는 되는데 **전원 ACK 가 안 뜬다** → 'Failed to power-up DAP' 가 진짜다.")
        print("     이게 AP/DM 실패의 상위 원인이다. 여기부터 풀어야 한다.")
        print("     → T32 는 이 단계를 통과한다. **T32 의 연결/초기화 스크립트가 답이다.**")
    else:
        nap_ok = sorted(set(n for n, _ in ok_ack))
        print(f"\n  ✅ 전원 ACK 성공. AP 등록 개수 {nap_ok} 에서 통과.")
        if 0 in nap_ok and len(AP_MAP) not in nap_ok:
            print("     ★ AP 를 6개 등록하면 실패하고 안 하면 성공 →")
            print("       **존재하지 않는 AP 등록이 방해**하고 있다. AP map 을 줄일 것.")
        print("     DP/전원은 정상이므로 문제는 그 위(AP 주소 또는 DM)다.")
    return EXIT_OK if ok_ack else EXIT_INSUFFICIENT


if __name__ == '__main__':
    sys.exit(main())
