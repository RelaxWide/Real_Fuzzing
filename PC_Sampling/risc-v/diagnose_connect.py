#!/usr/bin/env python3
"""SF-E76 — 첫 connect 실패의 **근본 원인** 후보 비교.

★ 왜 프로세스를 나누는가 (feedback §10.1.3)

  이전 판은 한 프로세스에서 후보(device/hart)를 순서대로 시도했다. 그러면:
    - 앞 후보의 **실패한 connect 가 뒤 후보를 예열**해 거짓 성공을 만든다
    - DLL 전역 상태와 probe 펌웨어 상태가 후보 사이에 이월된다
    - 후보 효과와 실행 순서 효과가 **교락**된다
  실제로 이 프로젝트에서 같은 함정을 두 번 겪었다(핸들 재사용 → 23/24 거짓 성공).

  그래서 **후보 하나 = 프로세스 하나**로 격리하고, 순서 효과를 보기 위해
  정방향/역방향을 모두 돌린다.

  ⚠ 그래도 **타깃과 probe 는 공유**된다. 완전한 격리는 후보마다 타깃 POR 이
    필요하다. `--power-cycle-id` 로 전원 사이클 세대를 기록해 두면 나중에
    결과를 그 기준으로 묶어 볼 수 있다.

실험:
  D  세션 지속성   성공 후 새 프로세스에서 1회 connect
                   성공 = 상태가 **타깃**에 남음 (dmactive 가설 지지)
                   실패 = DLL/probe 상태이거나 close 가 타깃을 리셋
  E  장치명        generic 'RISC-V' 프로파일이 CPU setup 을 실패시키는가
  F  하트 선택     connect 前 RISCV_SetHartSel 지정으로 1회에 붙는가

사용:
    sudo python3 diagnose_connect.py --only D
    sudo python3 diagnose_connect.py --only E --devices "RISC-V,RV32,SiFive-E76"
    sudo python3 diagnose_connect.py --power-cycle-id 3      # 전원 사이클 후
"""

import argparse
import json
import os
import subprocess
import sys
import time

from sfe76_link import (require_api, Link, LinkError, CORE_BASE_NCORE, add_common_args,
                        EXIT_OK, EXIT_CONNECT_FAIL)

VERSION = "2026-08-07.6  프로세스 격리"


def head(t):
    print(f"\n{'=' * 64}\n {t}\n{'=' * 64}")


# ── 자식 프로세스 모드: 후보 하나만 시도하고 결과를 JSON 으로 출력 ──
def run_single(args):
    rec = {'device': args.device, 'hart': args.hart,
           'core_base': f"0x{args.core_base:X}", 'ok': False,
           'tries_used': None, 'error': None}
    lk = Link(core_base=args.core_base, hart=args.hart, device=args.device,
              serial=args.serial, verbose=False, ap_count=args.ap_count)
    try:
        with lk:
            lk.connect_checked(tries=args.tries)
            rec['ok'] = True
            rec['tries_used'] = lk.connect_tries_used
    except LinkError as e:
        rec['error'] = str(e)
    rec['recovery_required'] = lk.recovery_required
    print("@@JSON@@" + json.dumps(rec, ensure_ascii=False))
    return EXIT_OK if rec['ok'] else EXIT_CONNECT_FAIL


def spawn(device, hart, core_base, serial, tries, ap_count=None):
    """후보 하나를 **별도 프로세스**에서 시도한다."""
    cmd = [sys.executable, os.path.abspath(__file__), '--single',
           '--device', str(device), '--core-base', hex(core_base),
           '--tries', str(tries)]
    if ap_count is not None:
        cmd += ['--ap-count', str(ap_count)]
    if hart is not None:
        cmd += ['--hart', str(hart)]
    if serial:
        cmd += ['--serial', str(serial)]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error': 'timeout', 'device': device, 'hart': hart}
    for line in out.splitlines():
        if line.startswith("@@JSON@@"):
            return json.loads(line[len("@@JSON@@"):])
    return {'ok': False, 'error': 'no result', 'device': device, 'hart': hart}


def show(tag, r):
    if r.get('ok'):
        print(f"    {tag}: ★ 성공 (connect 시도 {r.get('tries_used')}회)")
    else:
        print(f"    {tag}: 실패 — {str(r.get('error'))[:90]}")
    if r.get('recovery_required'):
        print("      ⚠ 이 시도에서 코어가 halt 로 남았을 수 있다")


# ══════════════════════════════════════════════════════════════════
def exp_d(a):
    head("[D] 세션 지속성 — 상태가 타깃에 남나, DLL/probe 에 남나")
    print("  1단계: 별도 프로세스에서 정상 절차(retry 포함)로 성공시킨다")
    r1 = spawn(a.device, a.hart, a.core_base, a.serial, a.tries, a.ap_count)
    show("1단계", r1)
    if not r1.get('ok'):
        print("  → 1단계 실패로 D 판정 불가")
        return None

    print("\n  2단계: **새 프로세스**에서 connect 를 1회만 시도")
    r2 = spawn(a.device, a.hart, a.core_base, a.serial, 1, a.ap_count)
    show("2단계(1회 제한)", r2)
    return r2.get('ok')


def exp_e(a, devices):
    head("[E] 장치명 — 후보마다 별도 프로세스, 정방향/역방향 모두")
    res = {}
    for label, seq in (("정방향", devices), ("역방향", list(reversed(devices)))):
        print(f"\n  ── {label} ──")
        for dev in seq:
            r = spawn(dev, a.hart, a.core_base, a.serial, 1, a.ap_count)   # 1회 제한이 핵심
            show(f"{dev!r}", r)
            res.setdefault(dev, []).append(bool(r.get('ok')))
            time.sleep(0.3)
    return res


def exp_f(a, nharts=5):
    head("[F] 하트 선택 — 후보마다 별도 프로세스, 정방향/역방향 모두")
    res = {}
    for label, seq in (("정방향", range(nharts)), ("역방향", reversed(range(nharts)))):
        print(f"\n  ── {label} ──")
        for h in seq:
            r = spawn(a.device, h, a.core_base, a.serial, 1, a.ap_count)
            show(f"hart {h}", r)
            res.setdefault(h, []).append(bool(r.get('ok')))
            time.sleep(0.3)
    return res


def main():
    require_api(2, "diagnose_connect.py")
    ap = add_common_args(argparse.ArgumentParser())
    ap.add_argument('--only', choices=['D', 'E', 'F'])
    ap.add_argument('--devices', default="RISC-V,RV32,RV32IMAC,SiFive-E76,E76",
                    help="E 실험 장치명(콤마). JLinkExe 의 Device> ? 목록에서 확인할 것")
    ap.add_argument('--power-cycle-id', default=None,
                    help='타깃 전원 사이클 세대 — 결과를 이 기준으로 묶기 위한 기록용')
    ap.add_argument('--single', action='store_true', help=argparse.SUPPRESS)
    ap.add_argument('--json', default=None, help='결과를 JSONL 로 추가 기록')
    a = ap.parse_args()

    if a.single:
        return run_single(a)

    head(f"첫 connect 실패 — 근본원인 후보 비교 ({VERSION})")
    print(f"  CoreBase 0x{a.core_base:X}   power_cycle_id={a.power_cycle_id}")
    print("  ※ 후보마다 별도 프로세스. 그래도 타깃/probe 는 공유되므로")
    print("     완전한 격리는 후보마다 타깃 POR 이 필요하다.")

    out = {'version': VERSION, 'ts': time.time(),
           'power_cycle_id': a.power_cycle_id, 'core_base': f"0x{a.core_base:X}"}

    if a.only in (None, 'D'):
        out['D'] = exp_d(a)
    if a.only in (None, 'E'):
        out['E'] = exp_e(a, [x.strip() for x in a.devices.split(',') if x.strip()])
    if a.only in (None, 'F'):
        out['F'] = exp_f(a)

    head("판정")
    d = out.get('D')
    if d is not None:
        if d:
            print("  ★ [D] 새 프로세스에서 1회로 성공 → 상태가 **타깃**에 남는다.")
            print("      dmactive 가설 지지. 퍼저는 전원 사이클당 1회만 예열하면 된다.")
        else:
            print("  ★ [D] 새 프로세스에선 1회로 실패 → **DLL/probe 상태**이거나")
            print("      close 가 타깃을 리셋한다. 매 연결마다 예열이 필요하다.")

    for key, nm in (('E', '장치명'), ('F', 'hart')):
        r = out.get(key)
        if not r:
            continue
        always = [k for k, v in r.items() if all(v)]
        never = [k for k, v in r.items() if not any(v)]
        mixed = [k for k, v in r.items() if any(v) and not all(v)]
        print(f"\n  [{key}] {nm}")
        print(f"      정방향·역방향 **모두 성공**: {always if always else '없음'}")
        print(f"      모두 실패            : {never if never else '없음'}")
        if mixed:
            print(f"      ⚠ 방향에 따라 갈림    : {mixed}")
            print("        → 후보 효과가 아니라 **순서 효과**다. 결론 내지 말 것.")
        if always:
            print(f"      ★ {nm} 이 원인일 가능성 — 재현 3회 이상으로 확인할 것")

    print("\n  ※ 각 조건을 최소 3회 반복하고, 가능하면 후보마다 타깃 POR 후 재실행.")
    print("     --power-cycle-id 로 세대를 기록해 두면 나중에 묶어 볼 수 있다.")

    if a.json:
        with open(a.json, 'a') as f:
            f.write(json.dumps(out, ensure_ascii=False) + "\n")
        print(f"\n  결과 기록: {a.json}")
    return EXIT_OK


if __name__ == '__main__':
    sys.exit(main())
