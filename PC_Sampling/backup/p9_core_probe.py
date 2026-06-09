#!/usr/bin/env python3
"""p9_core_probe.py — P9(Cortex-R5) 멀티코어 자동 탐색 (DBGPCSR 비침습 샘플링)

J-Link connect 에서 확인한 debug base(기본 0x80030000)부터 stride(기본 0x2000)로
후보 코어 base 들을 스윕하며, 각 코어가 "실재(DBGDIDR 유효) + 샘플 가능(DBGPCSR 가
유효하게 변함)"인지 자동 판정한다.

기존 jlink_dbgpcsr_probe.py(단일 base) 의 멀티-base 확장판. ARMv7-R(R5/R8 동일) 디버그
레지스터 맵을 사용하므로 DBGPCSR offset 은 0x084 가 기본.

사용 예:
  python3 p9_core_probe.py                         # base=0x80030000, stride=0x2000, 8개 스윕
  python3 p9_core_probe.py --count 12              # 더 많이 스윕
  python3 p9_core_probe.py --bases 0x80030000,0x80032000,0x80040000   # 명시 후보(비연속)
  python3 p9_core_probe.py --ap-index 1            # 멀티 AP: APB-AP 인덱스 변경
  python3 p9_core_probe.py --device Cortex-R5 --interface swd --speed 4000

확정 후 입력 위치 (P9_BRINGUP.md 참조):
  PRODUCT_PROFILES['P9']['pcsr_addrs'] = [<LIVE base + 0x84>, ...]   # 개수 = 코어 수
  r5_pcsr.cfg 의 APB target -ap-num = (통한 --ap-index 값)

주의: 코어가 idle(WFI)면 DBGPCSR 이 한 값에 고정될 수 있다. 이때는 다른 터미널에서
NVMe 부하(예: sudo dd if=/dev/nvme0n1 of=/dev/null bs=1M)를 주면서 다시 실행할 것.
"""
import argparse
import sys
import time

try:
    import pylink
except ImportError:
    sys.exit("[!] pylink 미설치 — pip3 install pylink-square")

# ARMv7-R Debug 레지스터 오프셋 (Cortex-R5/R8 공통)
OFF_DIDR  = 0x000   # Debug ID Register
OFF_DSCR  = 0x088   # Debug Status and Control
OFF_OSLAR = 0x300   # OS Lock Access  (write key 로 unlock)
OFF_OSLSR = 0x304   # OS Lock Status  (bit0 = locked)
OFF_AUTH  = 0xFB8   # Authentication Status (NIDEN 등 비침습 디버그 권한)
OSLOCK_KEY = 0xC5ACCE55
BAD = (0x00000000, 0xFFFFFFFF)


def parse_args():
    p = argparse.ArgumentParser(description='P9(Cortex-R5) 멀티코어 자동 탐색')
    p.add_argument('--device', default='Cortex-R5', help='J-Link 타깃명 (default: Cortex-R5)')
    p.add_argument('--interface', choices=['swd', 'jtag'], default='swd')
    p.add_argument('--speed', type=int, default=4000, help='kHz (default: 4000)')
    p.add_argument('--base', type=lambda x: int(x, 0), default=0x80030000,
                   help='첫 debug base (default: 0x80030000)')
    p.add_argument('--stride', type=lambda x: int(x, 0), default=0x2000,
                   help='코어 간 간격 (default: 0x2000 — PM9M1 패턴)')
    p.add_argument('--count', type=int, default=8, help='스윕할 후보 수 (default: 8)')
    p.add_argument('--bases', default=None,
                   help='쉼표구분 명시 base 리스트(비연속 레이아웃용). 지정 시 base/stride/count 무시')
    p.add_argument('--pcsr-offset', type=lambda x: int(x, 0), default=0x084,
                   help='DBGPCSR offset (default: 0x084, ARMv7-R)')
    p.add_argument('--ap-index', type=int, default=0,
                   help='APB-AP 인덱스 (CORESIGHT_SetIndexAPBAPToUse). 안 읽히면 1 시도')
    p.add_argument('--samples', type=int, default=24, help='base 당 DBGPCSR 샘플 횟수')
    p.add_argument('--settle', type=float, default=0.01, help='샘플 간 대기(초)')
    return p.parse_args()


def rd(jl, addr):
    try:
        return jl.memory_read32(addr, 1)[0]
    except Exception:
        return None


def probe_base(jl, base, pcsr_off, samples, settle):
    """한 후보 base 판정 → dict."""
    didr = rd(jl, base + OFF_DIDR)
    if didr is None or didr in BAD:
        return {'base': base, 'present': False, 'live': False, 'didr': didr,
                'reason': 'DBGDIDR 무응답/무효 → 미장착'}

    # OS Lock 걸려 있으면 해제 시도
    oslsr = rd(jl, base + OFF_OSLSR)
    if oslsr is not None and (oslsr & 1):
        try:
            jl.memory_write32(base + OFF_OSLAR, [OSLOCK_KEY])
            time.sleep(0.01)
        except Exception:
            pass
        oslsr = rd(jl, base + OFF_OSLSR)
    auth = rd(jl, base + OFF_AUTH)

    # DBGPCSR 비침습 샘플
    seen = set()
    for _ in range(samples):
        v = rd(jl, base + pcsr_off)
        if v is not None:
            seen.add(v)
        time.sleep(settle)
    valid = {v for v in seen if v not in BAD}
    live = len(valid) > 1     # 유효 PC 가 2개 이상 = 실행 중인 코어

    if live:
        reason = 'LIVE — 실행 중 코어 ✅'
    elif len(valid) == 1:
        reason = 'PCSR 고정(1값) — idle/WFI 가능 → NVMe 부하 주고 재시도'
    else:
        reason = 'PCSR 무효(0/FFFF) — NIDEN 차단/비파워 가능'
    return {'base': base, 'present': True, 'live': live, 'didr': didr,
            'auth': auth, 'oslsr': oslsr, 'uniq': len(seen), 'valid': len(valid),
            'sample': sorted(seen)[:4], 'reason': reason}


def main():
    args = parse_args()

    if args.bases:
        candidates = [int(x, 0) for x in args.bases.split(',') if x.strip()]
    else:
        candidates = [args.base + i * args.stride for i in range(args.count)]

    jl = pylink.JLink()
    jl.open()
    tif = (pylink.enums.JLinkInterfaces.JTAG if args.interface == 'jtag'
           else pylink.enums.JLinkInterfaces.SWD)
    jl.set_tif(tif)
    jl.exec_command(f"CORESIGHT_SetIndexAPBAPToUse = {args.ap_index}")
    try:
        jl.connect(args.device, speed=args.speed)
    except Exception as e:
        jl.close()
        sys.exit(f"[!] connect 실패 ({args.device}/{args.interface}): {e}")

    print(f"Connected: {args.device} @ {args.speed}kHz {args.interface.upper()}, "
          f"AP-index={args.ap_index}")
    try:
        print(f"Core ID: {hex(jl.core_id())}")
    except Exception:
        pass
    print(f"DBGPCSR offset=0x{args.pcsr_offset:03x}, 후보 {len(candidates)}개 "
          f"(base=0x{candidates[0]:08x} stride=0x{args.stride:x})\n")

    results = []
    for base in candidates:
        r = probe_base(jl, base, args.pcsr_offset, args.samples, args.settle)
        results.append(r)
        if not r['present']:
            print(f"  0x{base:08x}: -            {r['reason']}")
        else:
            samp = ' '.join(f'{v:#010x}' for v in r['sample'])
            print(f"  0x{base:08x}: DBGDIDR={r['didr']:#010x} "
                  f"PCSR(uniq={r['uniq']},valid={r['valid']}) [{samp}]  {r['reason']}")
    jl.close()

    live = [r for r in results if r['live']]
    idle = [r for r in results if r['present'] and not r['live']]

    print("\n=== 요약 ===")
    if not live and not idle:
        print("응답한 코어 없음. --ap-index 1 (또는 다른 값)로 재시도하거나 base 확인.")
        return
    if live:
        addrs = [r['base'] + args.pcsr_offset for r in live]
        print(f"LIVE 코어: {len(live)}개 → 코어 수 후보 = {len(live)}")
        print("  PRODUCT_PROFILES['P9']['pcsr_addrs'] = ["
              + ", ".join(f"0x{a:08x}" for a in addrs) + "]")
        print(f"  r5_pcsr.cfg APB -ap-num = {args.ap_index}")
    if idle:
        bases = ", ".join(f"0x{r['base']:08x}" for r in idle)
        print(f"보류(존재하나 PCSR 고정/무효): {bases}")
        print("  → NVMe 부하(sudo dd if=/dev/nvme0n1 of=/dev/null bs=1M) 주면서 재실행 권장.")


if __name__ == '__main__':
    main()
