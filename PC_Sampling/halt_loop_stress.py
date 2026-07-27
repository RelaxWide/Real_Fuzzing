#!/usr/bin/env python3
"""halt 루프 단독 스트레스 — OS freeze 원인 분리 실험 (T1)

퍼저/NVMe 트래픽을 **전혀 쓰지 않고** J-Link halt→PC read→go 루프만 돌린다.
목적: 호스트 프리즈가

  (C) halt × 호스트 MMIO/DMA 상호작용    ← NVMe 트래픽이 있어야만 발생
  (B) halt 자체의 PCIe 링크 교란          ← 트래픽 없이도 발생

중 어느 쪽인지 가른다. 퍼저 run 과 **같은 halt 횟수**를 채웠는데 프리즈가 안 나면 (C)/(F),
나면 (B) 다.

**`--no-halt` 대조군(T2):** SWD/USB 트래픽은 같게 내면서 **코어를 멈추지 않는다**(halted() =
디버그 레지스터 read 만 반복). `--no-jlink` 는 halt 뿐 아니라 J-Link USB 트래픽 전체를 뺐기
때문에 "halt 가 유일 변수"가 엄밀히는 참이 아니었다 — 이 모드가 그 confound 를 **같은 장치·같은
리그에서** 닫는다. PM9M1/BM9H1(=`sampler_type=pcsr`, halt 없음)로 비교하면 halt 유무와 제품이
동시에 바뀌어 깨끗한 대조가 안 된다. P7·P9 는 둘 다 `jlink_halt` 라 제품 교체로는 halt 를 뺄 수 없다.

퍼징 run 의 halt 는 명령당 ~1.7회꼴이었다(실측 665758 halts). 프리즈까지 30만~48만 명령 =
**~50만~80만 halt** 가 "1회분 노출".

**주의 — 기본값이 200만인 이유:** 프리즈까지의 명령수가 9만~48만로 5배 넘게 흩어진다. 이는
누적 손상이 아니라 **halt 마다 독립적인 작은 확률 p 로 발생하는 사건(기하분포)** 의 지문이다.
따라서 1회분 노출(~70만)만 채우고 프리즈가 없었다고 "halt 단독은 무죄"라 결론내면 안 된다 —
절반은 그냥 운이다. **음성 결과로 (F)/(C) 를 주장하려면 3배 노출(~200만 halt)** 이 필요하다.
go_settle 5ms + halt ~1.8ms ≈ 6.8ms/halt → 200만 halt ≈ 3.8시간(야간 1회분).

사용법:
  # 1) NVMe 드라이버를 떼서 링크를 완전히 idle 로 (가장 깨끗한 T1)
  sudo nvme_bdf=0000:04:00.0; echo $nvme_bdf | sudo tee /sys/bus/pci/drivers/nvme/unbind

  # 2) 모니터링 PC 에서 ssh 로 돌려 출력이 프리즈를 넘겨 살아남게 한다
  ssh rig 'sudo /home/ssd/gdbfuzz/.venv/bin/python3 \
      /home/ssd/gdbfuzz/PC_Sampling/halt_loop_stress.py' | tee halt_loop.log

  # 참고: --device/--speed/--interface/--go-settle-ms/--halt-poll-ms 는 fuzzer_config.json
  #       products.P7 값이 기본(Cortex-R5 / 2000kHz / swd / 5ms / 8ms).

주의: 출력은 매 줄 flush + stdout 무버퍼라 프리즈 직전까지의 진행이 원격에 남는다.
      로컬 리다이렉트(> file)는 프리즈 때 유실될 수 있으니 ssh/tee 를 쓸 것.
"""

import argparse
import os
import sys
import time

import pylink

_JTAG = pylink.enums.JLinkInterfaces.JTAG
_SWD = pylink.enums.JLinkInterfaces.SWD

_PC_NAME_EXACT = {'PC', 'R15', 'R15 (PC)'}


def _p(msg: str) -> None:
    """즉시 flush 출력 — 프리즈해도 이미 나간 줄은 원격에 남는다."""
    sys.stdout.write(msg + '\n')
    sys.stdout.flush()


def detect_pc_reg_index(jl) -> int:
    """register_list 에서 R15/PC 인덱스 자동 탐지. 실패 시 15 폴백. (퍼저와 동일 로직)"""
    try:
        for idx in jl.register_list():
            nm = (jl.register_name(idx) or '').upper()
            if 'R15' in nm or nm in _PC_NAME_EXACT:
                return idx
    except Exception as e:
        _p(f"[J-Link] PC 레지스터 자동 탐지 실패: {e}")
    _p("[J-Link] PC 레지스터 미탐지 — 인덱스 15 폴백 (--pc-reg-index 로 지정 가능)")
    return 15


def main() -> int:
    ap = argparse.ArgumentParser(description='J-Link halt 루프 단독 스트레스 (NVMe 무트래픽)')
    ap.add_argument('--device', default='Cortex-R5', help='J-Link 타깃 (default: Cortex-R5 = P7)')
    ap.add_argument('--speed', type=int, default=2000, help='인터페이스 속도 kHz (default: 2000)')
    ap.add_argument('--interface', choices=['jtag', 'swd'], default='swd', help='default: swd (P7)')
    ap.add_argument('--ap-index', type=int, default=0, help='CORESIGHT APB-AP index (default: 0)')
    ap.add_argument('--pc-reg-index', type=int, default=None, help='PC 레지스터 인덱스 강제 지정')
    ap.add_argument('--go-settle-ms', type=float, default=5.0,
                    help='resume→다음 halt 사이 최소 실행시간 ms (default: 5 = P7 프로파일)')
    ap.add_argument('--halt-poll-ms', type=int, default=8,
                    help='halt 후 halted() 확인 최대 대기 ms (default: 8 = P7 프로파일)')
    ap.add_argument('--halts', type=int, default=2000000,
                    help='목표 halt 횟수 (default: 2000000 = 1회분 노출(~70만)의 3배. '
                         '기하분포라 음성 결론에는 3배 노출이 필요 — 상단 docstring 참조)')
    ap.add_argument('--max-minutes', type=float, default=0.0,
                    help='시간 상한(분). 0=무제한 (default: 0)')
    ap.add_argument('--report-every', type=int, default=5000, help='진행 보고 간격(halt 수)')
    ap.add_argument('--no-halt', action='store_true',
                    help='대조군(T2): SWD/USB 트래픽은 동일하게 내되 **코어를 멈추지 않는다**. '
                         'halted() 폴링(디버그 레지스터 read)만 반복 → J-Link USB confound 분리용. '
                         '이쪽이 프리즈하면 원인은 halt 가 아니라 J-Link/SWD/USB 경로.')
    args = ap.parse_args()

    _p("=" * 72)
    if args.no_halt:
        _p("[대조군 T2] --no-halt — SWD/USB 트래픽만, **코어 정지 없음**")
        _p("  이쪽이 프리즈하면 원인은 halt 가 아니라 J-Link/SWD/USB 경로다.")
    else:
        _p("halt 루프 단독 스트레스 (T1) — NVMe 트래픽 없음, J-Link halt/go 만")
    _p(f"  target={args.halts} {'polls' if args.no_halt else 'halts'}  "
       f"device={args.device} {args.speed}kHz "
       f"{args.interface.upper()}  go_settle={args.go_settle_ms}ms poll={args.halt_poll_ms}ms")
    _p(f"  pid={os.getpid()}  start={time.strftime('%Y-%m-%d %H:%M:%S')}")
    _p("=" * 72)

    jl = pylink.JLink()
    jl.open()
    jl.set_tif(_SWD if args.interface == 'swd' else _JTAG)
    try:
        jl.exec_command(f"CORESIGHT_SetIndexAPBAPToUse = {args.ap_index}")
    except Exception as e:
        _p(f"[J-Link] CORESIGHT_SetIndexAPBAPToUse 경고: {e}")
    jl.connect(args.device, speed=args.speed)

    pc_idx = args.pc_reg_index if args.pc_reg_index is not None else detect_pc_reg_index(jl)
    try:
        pc_name = jl.register_name(pc_idx)
    except Exception:
        pc_name = '?'
    _p(f"[J-Link] 연결 성공. PC reg index={pc_idx} (name={pc_name})")

    # DLL 함수 캐싱 — 퍼저의 tight halt 루프와 동일 경로/오버헤드
    halt_func = jl._dll.JLINKARM_Halt
    read_reg_func = jl._dll.JLINKARM_ReadReg
    go_func = jl._dll.JLINKARM_Go

    settle_s = args.go_settle_ms / 1000.0
    n_ok = n_fail = 0
    freeze_accum = 0.0
    t0 = time.monotonic()
    last_report = t0

    try:
        while n_ok + n_fail < args.halts:
            if args.max_minutes > 0 and (time.monotonic() - t0) / 60.0 >= args.max_minutes:
                _p(f"[stop] --max-minutes {args.max_minutes} 도달")
                break

            halted = False
            try:
                if args.no_halt:
                    # 대조군: Halt/Go 를 절대 보내지 않는다. halted() = 디버그 레지스터 read 라
                    # SWD 트랜잭션·USB 트래픽은 발생하지만 코어는 계속 실행. halt 경로와 폴링
                    # 횟수를 맞춰 트래픽 양을 비슷하게 유지한다.
                    for _ in range(args.halt_poll_ms):
                        jl.halted()
                        time.sleep(0.001)
                    n_ok += 1
                    if settle_s > 0:
                        time.sleep(settle_s)
                    total = n_ok + n_fail
                    if total % args.report_every == 0:
                        el = time.monotonic() - t0
                        _p(f"[{time.strftime('%H:%M:%S')}] [no-halt] polls={total} "
                           f"elapsed={el:.0f}s rate={total / el if el > 0 else 0:.0f}/s "
                           f"freeze_accum=0.0s (코어 정지 없음)")
                    continue

                halt_func()
                for _ in range(args.halt_poll_ms):      # 1ms 간격 폴링 (퍼저와 동일)
                    if jl.halted():
                        halted = True
                        break
                    time.sleep(0.001)
                if halted:
                    # halted 확정 → Go 반환 까지가 코어 실제 정지 구간
                    fz0 = time.monotonic()
                    read_reg_func(pc_idx)
                    go_func()                            # halt 성공 시에만 resume
                    freeze_accum += time.monotonic() - fz0
                    n_ok += 1
                else:
                    # 코어가 clock-gated/WFI 라 안 멈춤 → Go 보내지 않는다(퍼저와 동일)
                    n_fail += 1
            except Exception as e:
                n_fail += 1
                if n_fail <= 5 or n_fail % 1000 == 0:
                    _p(f"[warn] halt 예외 #{n_fail}: {e}")
                if halted:
                    try:
                        go_func()
                    except Exception:
                        pass

            if settle_s > 0:
                time.sleep(settle_s)

            total = n_ok + n_fail
            if total % args.report_every == 0:
                now = time.monotonic()
                el = now - t0
                rate = total / el if el > 0 else 0.0
                _p(f"[{time.strftime('%H:%M:%S')}] halts={total} ok={n_ok} fail={n_fail} "
                   f"elapsed={el:.0f}s rate={rate:.0f}/s freeze_accum={freeze_accum:.1f}s "
                   f"({100.0 * freeze_accum / el if el > 0 else 0:.1f}% 정지)")
                last_report = now
    except KeyboardInterrupt:
        _p("[stop] Ctrl-C")
    finally:
        try:
            jl.close()
        except Exception:
            pass

    el = time.monotonic() - t0
    _p("=" * 72)
    _p(f"완료: halts={n_ok + n_fail} (ok={n_ok} fail={n_fail}) elapsed={el:.0f}s "
       f"freeze_accum={freeze_accum:.1f}s")
    if args.no_halt:
        _p("판정(대조군): 여기서 프리즈 → 원인은 halt 가 아니라 J-Link/SWD/USB 경로.")
        _p("              무사 → J-Link USB confound 닫힘. halt 가 트리거로 확정.")
    else:
        _p("판정: 목표 halt 를 채우고도 호스트가 살아있으면 → halt 단독은 무죄.")
        _p("      halt × 호스트 posted write 상호작용이 필요 = 가설 (F) 지지.")
        _p("      프리즈했으면 → halt 자체가 링크를 죽임 = 가설 (B).")
    _p("=" * 72)
    return 0


if __name__ == '__main__':
    sys.exit(main())
