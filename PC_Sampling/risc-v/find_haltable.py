#!/usr/bin/env python3
"""SF-E76 — **실제로 halt 되는** (CoreBase, hart) 조합을 찾는다.

배경: `connect()` 는 성공하는데 `halt()` 가 DLL 레벨에서 실패한다
(`JLINKARM_Halt()` 가 non-zero 반환). 즉 **connect 성공이 제어 가능한
하트에 도달했다는 뜻이 아니다** — feedback 이 반복 경고한 지점이다.

게다가 J-Link 의 connect 도 1회차에 "Error while halting CPU" 로 실패한다.
2회차 "성공" 이 **halt 실패를 눈감고 통과한 것**일 가능성이 있다.

그래서 이 스크립트는 **halt 가 되는 조합**을 기준으로 찾는다.
connect 성공은 통과 기준이 아니다.

★ 조합마다 **별도 프로세스**를 쓴다. 한 프로세스에서 순회하면 앞 조합의
  상태가 이월돼 거짓 성공/전체 실패가 난다(이 프로젝트에서 두 번 겪었다).

★ halt 에 성공하면 **반드시 resume 하고 확인**한다. 실패 시 즉시 중단하고
  보드 복구를 요구한다 — 코어가 멈춘 채 남으면 SSD 가 hang 한다.

사용:
    sudo python3 find_haltable.py                       # 전 조합
    sudo python3 find_haltable.py --harts 0,1,2,3,4
    sudo python3 find_haltable.py --core-bases 0x81481000
    sudo python3 find_haltable.py --power-cycle-id 3
"""

import argparse
import json
import os
import subprocess
import sys
import time

from sfe76_link import (Link, LinkError, CORE_BASE_MAIN, CORE_BASE_NCORE,
                        CORE_BASE_LABEL, DEVICE, CONNECT_TRIES,
                        EXIT_OK, EXIT_HALT_FAIL)

VERSION = "2026-08-07.1"


def run_single(a):
    """자식: 한 조합만 시도하고 JSON 한 줄을 출력한다."""
    rec = {'core_base': f"0x{a.core_base:X}", 'hart': a.hart, 'apb': a.apb,
           'connect': False, 'halt': False, 'resume': False,
           'tries': None, 'error': None, 'recovery_required': False}
    lk = Link(core_base=a.core_base, hart=a.hart, device=a.device,
              serial=a.serial, verbose=False, apb_index=a.apb)
    try:
        with lk:
            lk.connect_checked(tries=a.tries)
            rec['connect'] = True
            rec['tries'] = lk.connect_tries_used

            lk.halt_checked()
            rec['halt'] = True

            # halt 됐다면 PC 후보를 몇 개 찍어둔다(귀속 판단용 fingerprint)
            regs = {}
            for idx in (32, 33, 0, 1, 2):
                try:
                    regs[idx] = f"0x{lk.jl.register_read(idx) & 0xFFFFFFFF:08X}"
                except Exception:
                    pass
            rec['regs'] = regs

            lk.resume_checked()
            rec['resume'] = True
    except LinkError as e:
        rec['error'] = str(e)
    rec['recovery_required'] = lk.recovery_required
    print("@@JSON@@" + json.dumps(rec, ensure_ascii=False))
    return EXIT_OK if rec['halt'] else EXIT_HALT_FAIL


def spawn(core_base, hart, apb, a):
    cmd = [sys.executable, os.path.abspath(__file__), '--single',
           '--core-base', hex(core_base), '--device', a.device,
           '--apb', str(apb), '--tries', str(a.tries)]
    if hart is not None:
        cmd += ['--hart', str(hart)]
    if a.serial:
        cmd += ['--serial', a.serial]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=180).stdout
    except subprocess.TimeoutExpired:
        return {'core_base': f"0x{core_base:X}", 'hart': hart,
                'connect': False, 'halt': False, 'error': 'timeout'}
    for line in out.splitlines():
        if line.startswith("@@JSON@@"):
            return json.loads(line[len("@@JSON@@"):])
    return {'core_base': f"0x{core_base:X}", 'hart': hart,
            'connect': False, 'halt': False, 'error': 'no result'}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--core-bases', default=f"{hex(CORE_BASE_NCORE)},{hex(CORE_BASE_MAIN)}",
                    help='콤마 구분. 기본: Ncore 먼저(단순), 그다음 4코어 DM')
    ap.add_argument('--harts', default="none,0,1,2,3,4",
                    help="콤마 구분. 'none' = RISCV_SetHartSel 미지정")
    ap.add_argument('--device', default=DEVICE)
    ap.add_argument('--serial', default=None)
    ap.add_argument('--tries', type=int, default=CONNECT_TRIES)
    ap.add_argument('--power-cycle-id', default=None,
                    help='타깃 전원 사이클 세대 기록용')
    ap.add_argument('--core-base', type=lambda x: int(x, 0), default=CORE_BASE_NCORE)
    ap.add_argument('--hart', type=int, default=None)
    ap.add_argument('--apb', type=int, default=0, help='CORESIGHT_SetIndexAPBAPToUse')
    ap.add_argument('--apbs', default="0,1,4,5",
                    help='훑을 APB-AP 인덱스. 기본 = AP map 의 APB-AP 4개')
    ap.add_argument('--single', action='store_true', help=argparse.SUPPRESS)
    ap.add_argument('--json', default=None)
    a = ap.parse_args()

    if a.single:
        return run_single(a)

    bases = [int(x, 0) for x in a.core_bases.split(',') if x.strip()]
    harts = [None if x.strip().lower() == 'none' else int(x)
             for x in a.harts.split(',') if x.strip()]
    apbs = [int(x) for x in a.apbs.split(',') if x.strip()]

    print(f"\n{'=' * 68}\n halt 되는 (CoreBase, hart) 조합 찾기  v{VERSION}\n{'=' * 68}")
    print(f"  power_cycle_id={a.power_cycle_id}   "
          f"조합 {len(bases) * len(harts) * len(apbs)}개 "
          f"(CoreBase {len(bases)} x hart {len(harts)} x APB {len(apbs)})")
    print("  ※ 조합마다 별도 프로세스. connect 성공은 통과 기준이 아니다 — halt 기준.")

    rows = []
    stop = False
    for base in bases:
        if stop:
            break
        for apb in apbs:
            if stop:
                break
            for hart in harts:
                label = (f"0x{base:X}[{CORE_BASE_LABEL.get(base, '?')}] "
                         f"APB={apb} hart={hart}")
                print(f"\n  ── {label}")
                r = spawn(base, hart, apb, a)
                rows.append(r)
                mark = ("HALT OK" if r.get('halt') else
                        "connect만" if r.get('connect') else "connect 실패")
                print(f"     {mark}"
                      + (f"  (connect 시도 {r['tries']}회)" if r.get('tries') else "")
                      + (f"  resume={'OK' if r.get('resume') else 'NG'}"
                         if r.get('halt') else ""))
                if r.get('regs'):
                    print(f"     regs: {r['regs']}")
                if r.get('error'):
                    print(f"     err : {str(r['error'])[:110]}")
                if r.get('recovery_required'):
                    print("     ⚠⚠ 코어가 halt 로 남았을 수 있다 — 여기서 중단한다.")
                    print("        nvme list 확인 후 전원 사이클, 그다음 재개할 것.")
                    stop = True
                    break
                time.sleep(0.3)

    print(f"\n{'=' * 68}\n 결과\n{'=' * 68}")
    ok = [r for r in rows if r.get('halt')]
    conn_only = [r for r in rows if r.get('connect') and not r.get('halt')]

    if ok:
        print(f"  ★ halt 성공 조합 {len(ok)}개:")
        for r in ok:
            print(f"      {r['core_base']} APB={r.get('apb')} hart={r['hart']}  "
                  f"resume={r.get('resume')}")
            if r.get('regs'):
                print(f"        regs {r['regs']}")
        print("\n  → 이 조합으로 verify_halt_pc.py 를 돌린다:")
        r = ok[0]
        print(f"      sudo python3 verify_halt_pc.py --core-base {r['core_base']}"
              + (f" --hart {r['hart']}" if r['hart'] is not None else "")
              + " --scan-registers")
        if r.get('apb') not in (None, 0):
            print(f"      (APB index {r['apb']} — sfe76_link.APB_INDEX 도 맞출 것)")
    else:
        print("  ✗ halt 되는 조합 없음.")
        print(f"    connect 만 성공한 조합: {len(conn_only)}개")
        print("\n  → connect 성공이 코어 도달을 뜻하지 않는다는 것이 확인된 셈이다.")
        print("     다음 후보:")
        print("       1) 벤더에 DM 주소·hart 번호 확인 (지금 질문이 가장 구체적이다)")
        print("       2) CoreBase 후보를 T32 설정에서 재확인")
        print("       3) J-Link 소프트웨어 팩 최신 버전 (RISC-V 지원이 빠르게 바뀌는 영역)")

    if a.json:
        with open(a.json, 'a') as f:
            f.write(json.dumps({'version': VERSION, 'ts': time.time(),
                                'power_cycle_id': a.power_cycle_id,
                                'rows': rows}, ensure_ascii=False) + "\n")
        print(f"\n  결과 기록: {a.json}")
    return EXIT_OK if ok else EXIT_HALT_FAIL


if __name__ == '__main__':
    sys.exit(main())
