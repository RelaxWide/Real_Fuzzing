#!/usr/bin/env python3
"""SF-E76 — G2/G3/G4 검증: halt → PC 읽기 → resume.

v10.0 샘플러 착수 조건이 바로 이것이다. 연결(G1)은 `sfe76_link.Link` 가 담당하고
이 스크립트는 **상태 전이의 안전성과 PC 유효성**만 본다.

★ 설계 원칙 (feedback §10)
  - 연결 로직을 복사하지 않는다. `sfe76_link.Link` 의 checked API 만 쓴다.
  - `halt()`/`restart()` 의 **반환값과 사후 상태를 강제 검증**한다.
    pylink 는 실패 시 예외가 아니라 False 를 반환하므로, 무시하면
    "halted=False 인데 halt 성공" 같은 거짓 성공이 난다.
  - **PC 인덱스를 추측하지 않는다.** 확정 전에는 샘플링으로 넘어가지 않는다.
    잘못된 인덱스로 일반 레지스터를 읽으면 G3 를 거짓 통과한다.
  - 실패는 **종료 코드로 구분**한다 (자동화가 실패를 성공으로 읽지 않게).
  - **한 실행 = 한 설정.** 여러 hart/CoreBase 를 한 프로세스에서 섞지 않는다.
    (이전 --enum-harts 는 한 handle 에서 hart 를 바꿔가며 connect 해
     "한 handle = 한 설정" 원칙을 위반했다 → 제거)

사용:
    # 1단계 — PC 레지스터 후보 조사 (샘플링 안 함)
    sudo python3 verify_halt_pc.py --scan-registers

    # 2단계 — 확정된 인덱스로 검증
    sudo python3 verify_halt_pc.py --pc-index 32 --samples 100

    # 다른 코어 (프로세스를 새로 띄운다)
    sudo python3 verify_halt_pc.py --core-base 0x81480000 --hart 0 --scan-registers

종료 코드: 0 정상 / 2 connect / 3 halt / 4 PC / 5 resume(복구필요) / 6 불충분
"""

import argparse
import json
import sys
import time

from sfe76_link import (Link, LinkError, CORE_BASE_LABEL, add_common_args,
                        EXIT_OK, EXIT_PC_FAIL, EXIT_INSUFFICIENT, EXIT_RESUME_FAIL)

VERSION = "2026-08-07.3  checked G2/G3/G4"


def head(t):
    print(f"\n{'=' * 66}\n {t}\n{'=' * 66}")


# ══════════════════════════════════════════════════════════════════
def scan_registers(lk, count=48):
    """PC 후보를 **조사만** 한다. 확정은 사람이 한다.

    두 번 halt 해서 값이 변하는 인덱스를 본다. 실행 중인 코어라면 PC 는
    변하고 대부분의 일반 레지스터는 잘 안 변한다 — 결정적 근거는 아니지만
    후보를 좁힌다. 최종 확정은 register name / T32 교차검증 / fingerprint 로.
    """
    head("[A] PC 레지스터 후보 조사")

    # 1) 이름을 주는 API 가 있으면 그게 가장 확실하다
    named = {}
    try:
        for idx in lk.jl.register_list():
            try:
                nm = str(lk.jl.register_name(idx))
            except Exception:
                continue
            named[idx] = nm
            if nm.lower() in ('pc', 'dpc'):
                print(f"  ★ 이름으로 확정 가능: index={idx} name={nm}")
    except Exception as e:
        print(f"  register_list/name 불가: {e}")

    # 2) 두 시점의 값 비교
    snaps = []
    for _run in range(2):
        lk.halt_checked()
        vals = {}
        for idx in range(count):
            try:
                vals[idx] = lk.jl.register_read(idx) & 0xFFFFFFFF
            except Exception:
                pass
        snaps.append(vals)
        lk.resume_checked()
        time.sleep(0.05)

    a, b = snaps
    common = sorted(set(a) & set(b))
    changed = [i for i in common if a[i] != b[i]]
    print(f"\n  두 halt 사이에 값이 변한 인덱스: {changed if changed else '없음'}")
    print("\n  idx  1차값       2차값       이름")
    for i in common:
        if a[i] == 0 and b[i] == 0:
            continue
        mark = "  ←변함" if a[i] != b[i] else ""
        print(f"  [{i:2d}] 0x{a[i]:08X}  0x{b[i]:08X}  {named.get(i, '')}{mark}")

    print("\n  ※ 값이 변하고 코드 주소처럼 보이는 인덱스가 PC 후보다.")
    print("    **추측으로 진행하지 않는다.** 확정 근거(이름 / T32 교차검증 /")
    print("    독립 fingerprint)를 갖춘 뒤 --pc-index <번호> 로 재실행할 것.")
    return changed


def sample_pc(lk, pc_index, n, settle_ms):
    """halt → PC → resume 반복. 샘플러의 핵심 루프 그대로."""
    head(f"[C] PC 샘플링 {n}회 (index={pc_index})")
    pcs, fails = [], 0
    t0 = time.time()
    for i in range(n):
        try:
            lk.halt_checked()
            pcs.append(lk.read_pc(pc_index))
        except LinkError as e:
            fails += 1
            if fails <= 3:
                print(f"    {i}회차 실패: {e}")
        finally:
            # 어떤 경우에도 코어를 돌려놓는다. 실패하면 즉시 중단한다.
            try:
                lk.resume_checked()
            except LinkError as e:
                print(f"    ⚠ {i}회차 resume 실패 — 중단: {e}")
                break
        if settle_ms:
            time.sleep(settle_ms / 1000.0)
    dt = time.time() - t0

    uniq = sorted(set(pcs))
    print(f"\n  성공 {len(pcs)}/{n}  실패 {fails}")
    if dt > 0:
        print(f"  소요 {dt:.2f}s → {len(pcs) / dt:.1f} 샘플/초")
    print(f"  고유 PC {len(uniq)}개")
    if uniq:
        print(f"  범위 0x{uniq[0]:08X} ~ 0x{uniq[-1]:08X}")
        for v in uniq[:20]:
            print(f"    0x{v:08X}  x{pcs.count(v)}")
    return pcs, uniq


# ══════════════════════════════════════════════════════════════════
def main():
    ap = add_common_args(argparse.ArgumentParser())
    ap.add_argument('--scan-registers', action='store_true',
                    help='PC 후보 조사만 하고 끝낸다 (샘플링 안 함)')
    ap.add_argument('--pc-index', type=int, default=None,
                    help='확정된 PC 레지스터 인덱스. 없으면 샘플링하지 않는다')
    ap.add_argument('--samples', type=int, default=30)
    ap.add_argument('--settle-ms', type=float, default=0.0,
                    help='resume 후 대기 (ARM 의 go_settle 대응)')
    ap.add_argument('--json', default=None, help='결과 레코드를 JSONL 로 추가 기록')
    args = ap.parse_args()

    head("SF-E76 halt / PC / resume 검증")
    print(f"  version  : {VERSION}")
    print(f"  CoreBase : 0x{args.core_base:X} "
          f"[{CORE_BASE_LABEL.get(args.core_base, '?')}]  hart={args.hart}")

    rec = {'version': VERSION, 'ts': time.time(),
           'measurement_status': 'not_started',
           'target_recovery_status': 'ok'}
    rc = EXIT_OK
    lk = Link(core_base=args.core_base, hart=args.hart,
              device=args.device, serial=args.serial, ap_count=args.ap_count)
    try:
        with lk:
            head("[G1] connect")
            lk.connect_checked(tries=args.tries)
            rec['meta'] = lk.meta()

            head("[G2] halt")
            lk.halt_checked()
            print("  ✅ halt 성공 (명령 반환값 + halted 상태 확인)")

            head("[G4] resume")
            lk.resume_checked()
            print("  ✅ resume 성공 (running 상태 확인)")
            rec['measurement_status'] = 'g2_g4_ok'

            if args.scan_registers:
                rec['pc_candidates'] = scan_registers(lk)
                rec['measurement_status'] = 'scan_only'
            elif args.pc_index is None:
                head("[G3] 건너뜀")
                print("  ⚠ PC 인덱스가 확정되지 않았다. 샘플링하지 않는다.")
                print("     먼저 --scan-registers 로 후보를 조사할 것.")
                rc = EXIT_PC_FAIL
                rec['measurement_status'] = 'pc_index_unconfirmed'
            else:
                pcs, uniq = sample_pc(lk, args.pc_index, args.samples, args.settle_ms)
                rec.update(pc_index=args.pc_index, samples=len(pcs),
                           unique_pcs=len(uniq),
                           pc_min=(f"0x{uniq[0]:08X}" if uniq else None),
                           pc_max=(f"0x{uniq[-1]:08X}" if uniq else None))
                if not uniq:
                    rc = EXIT_INSUFFICIENT
                    rec['measurement_status'] = 'no_samples'
                elif len(uniq) == 1:
                    print("\n  ⚠ PC 가 한 값에 고정 — 코어가 안 돌거나 잘못된 하트/인덱스")
                    rc = EXIT_INSUFFICIENT
                    rec['measurement_status'] = 'pc_constant'
                else:
                    rec['measurement_status'] = 'ok'
    except LinkError as e:
        print(f"\n  ❌ {e}")
        rc = e.exit_code
        rec['measurement_status'] = 'failed'
        rec['error'] = str(e)

    # 결과 상태와 복구 상태를 분리한다 — 복구 실패는 다른 결과를 덮는다
    if lk.recovery_required:
        rec['target_recovery_status'] = 'failed'
        rc = EXIT_RESUME_FAIL
        print("\n  ⚠⚠ 보드 복구 필요 — 코어가 halt 로 남았을 수 있다.")
        print("      nvme list 로 SSD 확인 후 전원 사이클할 것.")
        print("      복구 전에는 다음 실험을 진행하지 말 것.")
    rec['overall_status'] = ('failed_recovery_required' if lk.recovery_required
                             else ('ok' if rc == EXIT_OK else 'failed'))
    rec['exit_code'] = rc

    head("결과")
    print(f"  measurement_status      = {rec['measurement_status']}")
    print(f"  target_recovery_status  = {rec['target_recovery_status']}")
    print(f"  overall_status          = {rec['overall_status']}  (exit {rc})")
    if rec['measurement_status'] == 'ok':
        print("\n  ✅ G2/G3/G4 통과 — 기존 JLinkHaltSampler 이식 가능. v10.0 착수 조건 충족")

    if args.json:
        with open(args.json, 'a') as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        print(f"\n  결과 기록: {args.json}")
    return rc


if __name__ == '__main__':
    sys.exit(main())
