#!/usr/bin/env python3
"""p9_core_probe_offline.py — P9(Cortex-R5) 멀티코어 자동 탐색 (JLinkExe 전용, 오프라인)

p9_core_probe.py 와 동일한 일을 하되 **pylink 없이** SEGGER `JLinkExe` 만으로 동작.
오프라인/새 머신용 — pip 설치 불필요(파이썬 표준 라이브러리만). J-Link 로 connect 가
되는 환경이면 JLinkExe 는 이미 있으므로 추가 설치가 필요 없다.

동작: J-Link Commander CommandFile 을 만들어 JLinkExe 로 실행하고, mem32 출력을
파싱해 각 후보 debug base 의 코어 실재/샘플가능 여부를 자동 판정한다.
ARMv7-R(R5/R8) 디버그 맵 — DBGDIDR=base+0x000, DBGPCSR=base+0x084, DBGOSLAR=base+0x300.

사용 예:
  python3 p9_core_probe_offline.py                       # base=0x80030000, stride=0x2000, 8개
  python3 p9_core_probe_offline.py --jlink /opt/SEGGER/JLink/JLinkExe
  python3 p9_core_probe_offline.py --bases 0x80030000,0x80032000,0x80040000
  python3 p9_core_probe_offline.py --ap-index 1          # 멀티 AP 면 0→1 시도
  python3 p9_core_probe_offline.py --dry-run             # CommandFile 만 출력(연결 안 함)

확정 후 입력 위치 (P9_BRINGUP.md):
  PRODUCT_PROFILES['P9']['pcsr_addrs'] = [<LIVE base + 0x84>, ...]   # 개수 = 코어 수
  r5_pcsr.cfg APB target -ap-num = (통한 --ap-index)

주의: idle(WFI) 코어는 DBGPCSR 이 한 값에 고정될 수 있다. 다른 터미널에서 NVMe 부하
(sudo dd if=/dev/nvme0n1 of=/dev/null bs=1M) 를 주면서 재실행할 것.
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile

OFF_DIDR  = 0x000   # Debug ID Register
OFF_PCSR  = 0x084   # PC Sample Register (DBGPCSR)  ← ARMv7-R 기본
OFF_OSLAR = 0x300   # OS Lock Access (key write 로 unlock)
OSLOCK_KEY = 0xC5ACCE55
BAD = (0x00000000, 0xFFFFFFFF)


def parse_args():
    p = argparse.ArgumentParser(description='P9(Cortex-R5) 멀티코어 자동 탐색 (JLinkExe 전용)')
    p.add_argument('--jlink', default='JLinkExe', help='JLinkExe 경로 (default: PATH의 JLinkExe)')
    p.add_argument('--device', default='Cortex-R5', help='J-Link 타깃명 (default: Cortex-R5)')
    p.add_argument('--interface', choices=['swd', 'jtag'], default='swd')
    p.add_argument('--speed', type=int, default=4000, help='kHz (default: 4000)')
    p.add_argument('--base', type=lambda x: int(x, 0), default=0x80030000)
    p.add_argument('--stride', type=lambda x: int(x, 0), default=0x2000)
    p.add_argument('--count', type=int, default=8)
    p.add_argument('--bases', default=None, help='쉼표구분 명시 base(비연속용). 지정 시 base/stride/count 무시')
    p.add_argument('--pcsr-offset', type=lambda x: int(x, 0), default=0x084)
    p.add_argument('--ap-index', type=int, default=0,
                   help='APB-AP 인덱스 (CORESIGHT_SetIndexAPBAPToUse). 안 잡히면 1 시도')
    p.add_argument('--samples', type=int, default=8, help='base 당 DBGPCSR 반복 read 횟수')
    p.add_argument('--sleep-ms', type=int, default=10, help='샘플 간 Sleep (ms)')
    p.add_argument('--dry-run', action='store_true', help='CommandFile 만 출력(JLinkExe 미실행)')
    return p.parse_args()


def build_commandfile(candidates, args):
    """JLinkExe CommandFile 텍스트 생성."""
    lines = [
        f'exec CORESIGHT_SetIndexAPBAPToUse = {args.ap_index}',
        'connect',
    ]
    for base in candidates:
        lines.append(f'mem32 0x{base + OFF_DIDR:08x} 1')        # DBGDIDR
        lines.append(f'w4 0x{base + OFF_OSLAR:08x} 0x{OSLOCK_KEY:08x}')  # OS Lock 해제
        for _ in range(args.samples):                          # DBGPCSR 반복
            lines.append(f'mem32 0x{base + args.pcsr_offset:08x} 1')
            lines.append(f'Sleep {args.sleep_ms}')
    lines.append('q')
    return '\n'.join(lines) + '\n'


# mem32 결과 라인: "80030000 = 35070003" / "0x80030000 = 0x35070003" 등
_MEM_RE = re.compile(r'(?:0x)?([0-9A-Fa-f]{8})\s*=\s*(?:0x)?([0-9A-Fa-f]{8})')


def parse_mem(stdout):
    """addr(int) -> [value(int), ...] (등장 순서대로)."""
    out = {}
    for line in stdout.splitlines():
        m = _MEM_RE.search(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        val = int(m.group(2), 16)
        out.setdefault(addr, []).append(val)
    return out


def main():
    args = parse_args()
    if args.bases:
        candidates = [int(x, 0) for x in args.bases.split(',') if x.strip()]
    else:
        candidates = [args.base + i * args.stride for i in range(args.count)]

    cmdtext = build_commandfile(candidates, args)
    if args.dry_run:
        print(cmdtext, end='')
        return

    with tempfile.NamedTemporaryFile('w', suffix='.jlink', delete=False) as f:
        f.write(cmdtext)
        cmdfile = f.name
    cmd = [args.jlink, '-device', args.device,
           '-if', args.interface.upper(), '-speed', str(args.speed),
           '-NoGui', '1', '-ExitOnError', '1', '-CommandFile', cmdfile]
    print('실행:', ' '.join(cmd), '\n')
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        stdout = r.stdout + r.stderr
    except FileNotFoundError:
        os.unlink(cmdfile)
        sys.exit(f"[!] JLinkExe 를 찾을 수 없음: {args.jlink} (--jlink 로 풀경로 지정)")
    except subprocess.TimeoutExpired:
        os.unlink(cmdfile)
        sys.exit("[!] JLinkExe timeout (120s)")
    finally:
        try:
            os.unlink(cmdfile)
        except OSError:
            pass

    mem = parse_mem(stdout)
    if not mem:
        print(stdout)
        sys.exit("[!] mem32 결과 파싱 실패 — 위 JLinkExe 출력 확인 "
                 "(connect 실패/디바이스명/AP 인덱스).")

    live, idle = [], []
    print("=== 후보 base 판정 ===")
    for base in candidates:
        didr_l = mem.get(base + OFF_DIDR, [])
        didr = didr_l[0] if didr_l else None
        pcsr = mem.get(base + args.pcsr_offset, [])
        valid = {v for v in pcsr if v not in BAD}
        if didr is None or didr in BAD:
            print(f"  0x{base:08x}: -            DBGDIDR 무응답/무효 → 미장착")
            continue
        samp = ' '.join(f'{v:#010x}' for v in pcsr[:4])
        if len(valid) > 1:
            print(f"  0x{base:08x}: DBGDIDR={didr:#010x} PCSR valid={len(valid)} [{samp}]  LIVE ✅")
            live.append(base)
        elif len(valid) == 1:
            print(f"  0x{base:08x}: DBGDIDR={didr:#010x} PCSR 고정 [{samp}]  idle/WFI? (부하 후 재시도)")
            idle.append(base)
        else:
            print(f"  0x{base:08x}: DBGDIDR={didr:#010x} PCSR 무효 [{samp}]  NIDEN 차단/비파워?")
            idle.append(base)

    print("\n=== 요약 ===")
    if live:
        addrs = [b + args.pcsr_offset for b in live]
        print(f"LIVE 코어: {len(live)}개 → 코어 수 후보 = {len(live)}")
        print("  PRODUCT_PROFILES['P9']['pcsr_addrs'] = ["
              + ", ".join(f"0x{a:08x}" for a in addrs) + "]")
        print(f"  r5_pcsr.cfg APB -ap-num = {args.ap_index}")
    else:
        print("LIVE 코어 없음. --ap-index 1 로 재시도하거나 --bases 로 base 직접 지정.")
    if idle:
        print("보류:", ", ".join(f"0x{b:08x}" for b in idle),
              "→ NVMe 부하 주며 재실행 권장.")


if __name__ == '__main__':
    main()
