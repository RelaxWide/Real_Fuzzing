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
    4. ★ 전원 요청 방식     → SYS 전원까지 요청하면 실패하나

════════════════════════════════════════════════════════════════════
★ 4번이 새로 추가된 이유 — attach.cmm 실물
════════════════════════════════════════════════════════════════════
T32 는 이 칩에 붙을 때 **명시적으로 SYS 전원 요청을 끈다**:

    SYStem.Option.DAPSYSPWRUPREQ OFF      ← CSYSPWRUPREQ 안 씀
    SYStem.Option.DAPDBGPWRUPREQ ON       ← CDBGPWRUPREQ 만 씀

기본값이 ON 인 옵션을 굳이 OFF 로 적어 뒀다는 건 **켜면 안 되기 때문**이다.
J-Link 은 기본적으로 둘 다 요청하고 **둘 다 ACK 될 때까지 기다린다.**
CSYSPWRUPACK 이 영영 안 오는 칩이면 그대로 "Failed to power-up DAP" 다.

그래서 이 도구는 전원 요청을 **두 가지로 나눠** 시험하고 ACK 비트를 따로 본다:

    DBG only : CTRL/STAT = 0x10000000   (CDBGPWRUPREQ)
    BOTH     : CTRL/STAT = 0x50000000   (CDBG + CSYSPWRUPREQ)  ← J-Link 기본

    bit28 CDBGPWRUPREQ   bit29 CDBGPWRUPACK
    bit30 CSYSPWRUPREQ   bit31 CSYSPWRUPACK

판정:
  DBG ACK O / SYS ACK X   → ★ **T32 설정이 옳다.** J-Link 기본 동작이 블로커
  둘 다 ACK               → 전원은 문제 아님. 원인은 그 위(AP 주소/DM)
  DBG ACK 도 X            → 전원 인가 실패가 진짜 블로커
  DPIDR 무효              → cJTAG/스캔 계층부터 문제 (회귀)

════════════════════════════════════════════════════════════════════
사용
════════════════════════════════════════════════════════════════════
    sudo python3 probe_dap.py                 # AP 0/1/6개 × 전원요청 2종
    sudo python3 probe_dap.py --no-connect    # connect 아예 안 함
"""

import argparse
import sys
import time

try:
    import pylink
except ImportError:
    sys.exit("pylink 없음 →  pip3 install pylink-square")

from sfe76_link import (require_api, TIF_CJTAG, SPEED_KHZ, CJTAG_MODE, DEVICE, AP_MAP,
                        APB_INDEX, CORE_BASE_NCORE, EXIT_OK, EXIT_INSUFFICIENT)

VERSION = "2026-08-10.2  전원요청 분리 (attach.cmm DAPSYSPWRUPREQ OFF)"

DP_IDR_ABORT = 0
DP_CTRL_STAT = 1

CDBGPWRUPREQ = 1 << 28
CDBGPWRUPACK = 1 << 29
CSYSPWRUPREQ = 1 << 30
CSYSPWRUPACK = 1 << 31

# (라벨, CTRL/STAT 에 쓸 값, 기다릴 ACK 마스크)
PWR_MODES = [
    ("DBG only (T32 방식)", CDBGPWRUPREQ,                CDBGPWRUPACK),
    ("BOTH (J-Link 기본)",  CDBGPWRUPREQ | CSYSPWRUPREQ, CDBGPWRUPACK | CSYSPWRUPACK),
]


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


def decode_ctrl(v):
    """CTRL/STAT 의 전원 비트와 sticky 에러를 사람이 읽게 푼다."""
    if v is None or v < 0:
        return "읽기 실패"
    bits = []
    for m, nm in ((CDBGPWRUPREQ, 'CDBGPWRUPREQ'), (CDBGPWRUPACK, 'CDBGPWRUPACK'),
                  (CSYSPWRUPREQ, 'CSYSPWRUPREQ'), (CSYSPWRUPACK, 'CSYSPWRUPACK'),
                  (1 << 7, 'STICKYERR'), (1 << 6, 'READOK'), (1 << 5, 'STICKYORUN')):
        bits.append(f"{nm}={'1' if v & m else '0'}")
    return "  ".join(bits)


def try_power(jl, label, req, want, tries=25):
    """전원 요청 하나를 시험한다. 반환: (ack, ctrl, dbg_ack, sys_ack)"""
    dp_write(jl, DP_IDR_ABORT, 0x0000001E)          # sticky 클리어
    dp_write(jl, DP_CTRL_STAT, req)
    ctrl = None
    for _ in range(tries):
        time.sleep(0.01)
        ctrl = dp_read(jl, DP_CTRL_STAT)
        if ctrl is not None and ctrl > 0 and (ctrl & want) == want:
            break
    ok = ctrl is not None and ctrl > 0 and (ctrl & want) == want
    dbg = bool(ctrl and ctrl > 0 and ctrl & CDBGPWRUPACK)
    sysa = bool(ctrl and ctrl > 0 and ctrl & CSYSPWRUPACK)
    print(f"    [{label}]  write=0x{req:08X}  →  CTRL/STAT = {hx(ctrl)}"
          f"   {'✅ ACK' if ok else '❌ ACK 없음'}")
    print(f"                {decode_ctrl(ctrl)}")
    if ctrl and ctrl > 0 and (ctrl & 0x000000A0):
        print("                ⚠ STICKY 에러 — 접근이 거부되고 있다")
    return ok, ctrl, dbg, sysa


def valid_dpidr(v):
    """DPIDR 은 bit0 = RAO(항상 1). 짝수면 데이터가 아니다."""
    return v is not None and v > 0 and (v & 1) == 1 and v not in (1, 0xFFFFFFFF)


def attempt(nap, do_connect, device, tries=1):
    """AP 를 nap 개 등록하고 DP 전원을 확인한다.

    tries: connect 재시도 횟수. **1 은 단발 측정용**이다.
      2026-08-10 통제 실험에서 단발 성공률이 3/6 으로 나왔고, 같은 설정(AP 1개)이
      시행 위치에 따라 3/3 · 0/3 으로 갈렸다 → 설정이 아니라 **연결 자체가 불안정**.
      실사용 경로(`Link.connect_checked`)는 원래 3회 재시도한다.
    """
    label = f"AP 등록 {nap}개 / connect={'O' if do_connect else 'X'} / tries={tries}"
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

        conn_ok, conn_tries = None, 0
        if do_connect:
            for t in range(1, tries + 1):
                conn_tries = t
                try:
                    jl.connect(device, speed=SPEED_KHZ)
                    conn_ok = True
                    print(f"  connect 성공 ({t}회차)")
                    break
                except Exception as e:
                    conn_ok = False
                    print(f"  connect 실패 ({t}/{tries}): {str(e)[:80]}")
                    if t < tries:
                        time.sleep(0.3)

        # CoreSight 계층 준비 — 단일 TAP, IRLen 4
        #   ★ perform_tif_init=False 를 **먼저** 쓴다.
        #     기본값(True)은 JTAG 스위칭 시퀀스를 내보내는데, 그게 cJTAG(2선)
        #     상태를 깨뜨린다 — JLinkScript 경로가 IRPrint=0x..0000 으로
        #     망가졌던 것과 같은 원인으로 보인다.
        base_kw = {'ir_pre': 0, 'dr_pre': 0, 'ir_post': 0, 'dr_post': 0, 'ir_len': 4}
        for kw in (dict(base_kw, perform_tif_init=False), base_kw, {}):
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

        # 진입 시점의 값을 먼저 본다 — 우리가 쓰기 전에 이미 어떤 상태인가
        print(f"  진입 시 CTRL/STAT = {hx(dp_read(jl, DP_CTRL_STAT))}")

        print("\n  전원 요청 2종 비교 (attach.cmm: T32 는 SYS 를 끈다)")
        pwr = {}
        for label, req, want in PWR_MODES:
            ok, ctrl, dbg, sysa = try_power(jl, label, req, want)
            pwr[label] = {'ok': ok, 'ctrl': ctrl, 'dbg_ack': dbg, 'sys_ack': sysa}
        return {'dpidr': idr, 'pwr': pwr,
                'connect_ok': conn_ok, 'connect_tries': conn_tries,
                'ack': any(p['ok'] for p in pwr.values()),
                'dbg_ack': any(p['dbg_ack'] for p in pwr.values()),
                'sys_ack': any(p['sys_ack'] for p in pwr.values())}
    finally:
        try:
            jl.close()
        except Exception:
            pass
        time.sleep(0.4)


def ap_count_test(device, reps, tries):
    """AP 등록 개수 1 vs 6 — **순서를 통제해서** 가른다.

    ── 2026-08-10 결과 (tries=1, reps=3) ─────────────────────────────
      AP 1개 : 3/6      AP 6개 : 3/6      → **AP 개수는 원인이 아니다**
      같은 설정(AP 1개)이 rep 내 위치에 따라 3/3 · 0/3 으로 갈렸다
      = 설정을 고정해도 결과가 갈린다 → **연결 자체가 불안정한 것**

    그래서 이 실험의 목적이 바뀌었다. 이제 보는 것은 **재시도가 답인가**다.
    `--tries 3` 으로 돌려 성공률이 올라가면 전원 문제는 운영상 해결된 것이고,
    안 올라가면 재시도로 못 덮는 상태 의존성이 따로 있는 것이다.
    """
    print(f"\n{'=' * 66}\n [AP 개수 통제 실험] 1 vs 6, 정방향·역방향 × {reps}회, "
          f"connect tries={tries}\n{'=' * 66}")
    res = {1: [], 6: []}
    log = []                       # (시행번호, nap, rep내위치, 성공)
    n = 0
    for rep in range(reps):
        for label, seq in (("정방향 1→6", [1, 6]), ("역방향 6→1", [6, 1])):
            print(f"\n### rep {rep + 1} / {label}")
            for nap in seq:
                n += 1
                r = attempt(nap, True, device, tries=tries)
                ok = bool(r and r.get('dbg_ack'))
                res[nap].append(ok)
                log.append((n, nap, ok, (r or {}).get('connect_tries')))

    print(f"\n{'=' * 66}\n [AP 개수 통제 실험] 판정\n{'=' * 66}")
    print("  시행 순서대로:")
    for n_, nap, ok, ct in log:
        print(f"    {n_:2d}회  AP{nap}개  {'성공' if ok else '실패'}"
              f"{f'  (connect {ct}회차)' if ct else ''}")

    one, six = res[1], res[6]
    print(f"\n  AP 1개 : {sum(one)}/{len(one)}   {one}")
    print(f"  AP 6개 : {sum(six)}/{len(six)}   {six}")

    if sum(one) == sum(six):
        print("\n  ★ **AP 개수는 원인이 아니다** — 성공률이 같다.")
    elif all(one) and not any(six):
        print("\n  ★★ AP 개수가 원인. AP map 을 APBAP1 하나로 줄인다.")
    else:
        print(f"\n  성공률이 다르다({sum(one)} vs {sum(six)}) — 반복을 늘려 재확인할 것.")

    total = sum(one) + sum(six)
    print(f"\n  전체 성공률 {total}/{len(one) + len(six)}  (connect tries={tries})")
    if tries == 1 and total < len(one) + len(six):
        print("     → **`--tries 3` 으로 다시 돌려볼 것.** 재시도로 덮이는지가 핵심이다.")
    elif tries > 1 and total == len(one) + len(six):
        print("     ★★ 재시도하면 100% → **전원 문제는 운영상 해결.**")
        print("        AP 는 6개 그대로 두고 다음 단계(DM)로 간다.")
    elif tries > 1:
        print("     ⚠ 재시도해도 못 덮는다 → 재시도 밖의 상태 의존성이 있다.")
        print("        타깃 전원 사이클 세대별로 묶어서 재측정할 것.")
    return EXIT_OK if total else EXIT_INSUFFICIENT


def main():
    require_api(2, "probe_dap.py")
    ap = argparse.ArgumentParser()
    ap.add_argument('--device', default=DEVICE)
    ap.add_argument('--no-connect', action='store_true',
                    help='connect 를 아예 하지 않고 DP 만 본다')
    ap.add_argument('--ap-count-test', action='store_true',
                    help='AP 1개 vs 6개를 순서 통제해서 비교한다')
    ap.add_argument('--ap-count', type=int, default=None,
                    help='단발 모드에서 등록할 AP 개수를 이 값 하나로 고정한다')
    ap.add_argument('--reps', type=int, default=3)
    ap.add_argument('--tries', type=int, default=1,
                    help='connect 재시도 횟수 (기본 1 = 단발 측정)')
    a = ap.parse_args()

    if a.ap_count_test:
        return ap_count_test(a.device, a.reps, a.tries)

    print(f"\n{'=' * 66}")
    print(f" DAP 전원 인가 확인 — 가장 아래 층만 (v{VERSION})")
    print(f"{'=' * 66}")
    print("  'Failed to power-up DAP' 가 진짜인지, AP 등록이 방해가 되는지 가른다.")
    print("  connect / AP 접근 / DM 은 건드리지 않는다.")

    if a.ap_count is not None:
        combos = [(a.ap_count, False)] + ([] if a.no_connect else [(a.ap_count, True)])
    else:
        combos = [(0, False), (1, False), (len(AP_MAP), False)]
        if not a.no_connect:
            combos += [(1, True), (len(AP_MAP), True)]

    res = []
    for nap, conn in combos:
        r = attempt(nap, conn, a.device, tries=a.tries)
        res.append((nap, conn, r))

    print(f"\n{'=' * 66}\n 판정\n{'=' * 66}")
    ok_dp = [(n, c) for n, c, r in res if r and valid_dpidr(r.get('dpidr'))]
    dbg_ok = [(n, c) for n, c, r in res if r and r.get('dbg_ack')]
    sys_ok = [(n, c) for n, c, r in res if r and r.get('sys_ack')]

    print(f"  DPIDR 유효한 조합    : {ok_dp if ok_dp else '없음'}")
    print(f"  CDBGPWRUPACK 뜬 조합 : {dbg_ok if dbg_ok else '없음'}")
    print(f"  CSYSPWRUPACK 뜬 조합 : {sys_ok if sys_ok else '없음'}")

    if not ok_dp:
        print("\n  ❌ DP 통신 자체가 안 된다 — cJTAG/스캔 계층 문제(회귀 의심).")
        print("     예전에 DPIDR=0x11013913 을 읽었으므로 조건이 달라진 것이다.")
        print("     타깃 전원 사이클 후 재시도, J-Link USB 재연결 확인.")
    elif dbg_ok and not sys_ok:
        print("\n  ★★ 결정적: **디버그 전원은 ACK, 시스템 전원은 ACK 안 됨.**")
        print("     attach.cmm 의 `DAPSYSPWRUPREQ OFF` 와 정확히 일치한다.")
        print("     J-Link 은 기본적으로 둘 다 요청하고 둘 다 기다리므로")
        print("     → 'Failed to power-up DAP' 의 **원인이 이것**이다.")
        print("     다음: CSYSPWRUPREQ 를 빼고 connect 하는 경로를 만든다.")
        print("           (JLinkScript InitTarget + PerformTIFInit=0 — README 참조)")
    elif not dbg_ok:
        print("\n  ★ 디버그 전원조차 ACK 가 없다 → 전원 인가 실패가 진짜 블로커다.")
        print("     T32 는 이 단계를 통과한다(DAPDBGPWRUPREQ ON). 우리 쪽 시퀀스 문제.")
    else:
        nap_ok = sorted(set(n for n, _ in dbg_ok))
        print(f"\n  ✅ 전원 ACK 성공(둘 다). AP 등록 개수 {nap_ok} 에서 통과.")
        if 0 in nap_ok and len(AP_MAP) not in nap_ok:
            print("     ★ AP 를 6개 등록하면 실패하고 안 하면 성공 →")
            print("       **존재하지 않는 AP 등록이 방해**하고 있다. AP map 을 줄일 것.")
        print("     전원은 원인이 아니다 → 문제는 그 위(AP 주소 또는 DM aperture).")
        print("     다음: probe_dm.py — DM 은 0x81480000 + (dmi_addr<<2) 로 본다.")
    return EXIT_OK if dbg_ok else EXIT_INSUFFICIENT


if __name__ == '__main__':
    sys.exit(main())
