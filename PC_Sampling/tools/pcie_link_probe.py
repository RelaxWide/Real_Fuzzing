#!/usr/bin/env python3
"""PCIe 링크 상태 폴러 — pci=noaer 환경에서 카나리아 복구 + Completion Timeout 점검

`pci=noaer` 는 커널 AER **서비스**만 끈다. PCIe 하드웨어는 에러 상태 비트를 계속 셋하므로
setpci 로 직접 읽으면 인터럽트 없이 링크 건강도를 볼 수 있다. 즉 noaer 로 잃은 가시성을
되찾는 도구.

읽는 것 (root port + endpoint 각각):
  - DevSta  (CAP_EXP+0x0a.w)  bit0 CorrErr / bit1 NonFatalErr / bit2 FatalErr / bit3 UnsuppReq
      ※ AER 유무와 무관하게 하드웨어가 셋. noaer 에서도 살아있는 핵심 신호.
  - LnkSta  (CAP_EXP+0x12.w)  현재 링크 속도(bit3:0) / 폭(bit9:4)  → 링크 저하·재훈련 감지
  - AER Correctable Error Status   (ECAP_AER+0x10.l)
  - AER Uncorrectable Error Status (ECAP_AER+0x04.l)
  - DevCtl2 (CAP_EXP+0x28.w)  Completion Timeout 설정 (--show-cto 로 해석 출력)

사용법:
  # 상태 1회 덤프 + Completion Timeout 해석 (재현 불필요, 즉시)
  sudo python3 pcie_link_probe.py --root 0000:00:01.1 --ep 0000:04:00.0 --show-cto --once

  # 퍼징/halt 루프와 나란히 폴링 (원격 ssh 로 받아야 프리즈를 넘겨 살아남는다)
  ssh rig 'sudo python3 .../pcie_link_probe.py --root 0000:00:01.1 --ep 0000:04:00.0 \
      --interval 1 --clear' | tee link_probe.log

  --clear 는 매 폴 뒤 status 비트를 W1C 로 지워 **구간별 발생률**을 본다(누적 아님).
  프리즈 직전 구간에서 카운트가 치솟으면 링크 악화(가설 B), 끝까지 0 이면 링크는 무죄.

  # Completion Timeout 을 짧게 강제 (가설 C 검증 — 아래 주의 참조)
  sudo python3 pcie_link_probe.py --root 0000:00:01.1 --set-cto 2

주의(--set-cto): root port 의 Device Control 2 를 **실제로 씁니다.** 완료되지 않는 MMIO read 가
  무한 정지 대신 타임아웃 후 all-Fs 를 반환하게 만드는 실험입니다. 그러면 nvme 드라이버가
  컨트롤러를 dead 로 보고 리셋할 수 있어 **퍼징 run 은 깨지지만**, "호스트 전체 프리즈"가
  "장치 리셋"으로 바뀌면 가설 C 가 확정됩니다. 재부팅하면 원복됩니다.
"""

import argparse
import re
import subprocess
import sys
import time

# Completion Timeout Value (DevCtl2 bit3:0) → 범위. PCIe Base Spec.
_CTO_RANGES = {
    0x0: '50us~50ms (default)',
    0x1: '50us~100us',
    0x2: '1ms~10ms',
    0x5: '16ms~55ms',
    0x6: '65ms~210ms',
    0x9: '260ms~900ms',
    0xa: '1s~3.5s',
    0xd: '4s~13s',
    0xe: '17s~64s',
}

_DEVSTA_BITS = [(0, 'CorrErr'), (1, 'NonFatalErr'), (2, 'FatalErr'), (3, 'UnsuppReq')]

# AER Correctable Error Status 주요 비트
_COR_BITS = [(0, 'RxErr'), (6, 'BadTLP'), (7, 'BadDLLP'), (8, 'Rollover'),
             (12, 'Timeout'), (13, 'AdvNonFatal'), (14, 'CorrIntErr'), (15, 'HeaderOF')]
# AER Uncorrectable Error Status 주요 비트
_UNC_BITS = [(4, 'DLP'), (12, 'PoisonTLP'), (13, 'FCP'), (14, 'CmpltTO'), (15, 'CmpltAbrt'),
             (16, 'UnxCmplt'), (17, 'RxOF'), (18, 'MalfTLP'), (19, 'ECRC'), (20, 'UnsupReq')]

_LNK_SPEED = {1: '2.5GT/s', 2: '5GT/s', 3: '8GT/s', 4: '16GT/s', 5: '32GT/s', 6: '64GT/s'}


def _p(msg: str) -> None:
    sys.stdout.write(msg + '\n')
    sys.stdout.flush()


def setpci_read(bdf: str, reg: str) -> int:
    """setpci 로 레지스터 1개 읽기. 실패 시 -1."""
    try:
        out = subprocess.run(['setpci', '-s', bdf, reg],
                             capture_output=True, text=True, timeout=5)
        if out.returncode != 0:
            return -1
        return int(out.stdout.strip(), 16)
    except Exception:
        return -1


def setpci_write(bdf: str, reg: str, val: int) -> bool:
    try:
        out = subprocess.run(['setpci', '-s', bdf, f'{reg}={val:x}'],
                             capture_output=True, text=True, timeout=5)
        return out.returncode == 0
    except Exception:
        return False


def decode_bits(val: int, table) -> str:
    if val <= 0:
        return '-' if val == 0 else 'ERR'
    hits = [name for bit, name in table if val & (1 << bit)]
    return ','.join(hits) if hits else f'0x{val:x}'


def show_cto(bdf: str, label: str) -> None:
    """Completion Timeout 설정/지원범위 해석 출력 — 가설 C 성립 조건 확인."""
    cap2 = setpci_read(bdf, 'CAP_EXP+0x24.l')     # DevCap2
    ctl2 = setpci_read(bdf, 'CAP_EXP+0x28.w')     # DevCtl2
    if cap2 < 0 or ctl2 < 0:
        _p(f"  [{label} {bdf}] DevCap2/DevCtl2 읽기 실패 (root 권한? BDF 확인?)")
        return
    cur_val = ctl2 & 0xf
    disabled = bool(ctl2 & 0x10)
    sup_ranges = cap2 & 0xf
    sup_disable = bool(cap2 & 0x10)
    _p(f"  [{label} {bdf}] DevCtl2=0x{ctl2:04x} DevCap2=0x{cap2:08x}")
    _p(f"      Completion Timeout: value=0x{cur_val:x} ({_CTO_RANGES.get(cur_val, '예약/불명')})"
       f"  Disable={'ON  ← 무한 대기 가능(가설 C 성립 조건)' if disabled else 'off'}")
    _p(f"      지원: ranges=0x{sup_ranges:x} (A=50us~10ms B=10ms~250ms C=250ms~4s D=4s~64s 중 비트)"
       f"  DisableSupported={sup_disable}")


def poll_once(bdf: str, label: str, clear: bool) -> str:
    devsta = setpci_read(bdf, 'CAP_EXP+0x0a.w')
    lnksta = setpci_read(bdf, 'CAP_EXP+0x12.w')
    cor = setpci_read(bdf, 'ECAP_AER+0x10.l')
    unc = setpci_read(bdf, 'ECAP_AER+0x04.l')

    if lnksta >= 0:
        spd = _LNK_SPEED.get(lnksta & 0xf, f'?{lnksta & 0xf}')
        wid = (lnksta >> 4) & 0x3f
        link = f'{spd} x{wid}'
    else:
        link = 'n/a'

    parts = [f'{label}: link={link}',
             f'DevSta={decode_bits(devsta, _DEVSTA_BITS)}',
             f'AERcor={decode_bits(cor, _COR_BITS)}',
             f'AERunc={decode_bits(unc, _UNC_BITS)}']

    if clear:
        # W1C — 다음 폴이 '이 구간에 새로 생긴 에러'만 보게 한다
        if devsta > 0:
            setpci_write(bdf, 'CAP_EXP+0x0a.w', devsta & 0xf)
        if cor > 0:
            setpci_write(bdf, 'ECAP_AER+0x10.l', cor)
        if unc > 0:
            setpci_write(bdf, 'ECAP_AER+0x04.l', unc)

    return '  '.join(parts)


def main() -> int:
    ap = argparse.ArgumentParser(description='PCIe 링크/에러 상태 폴러 (noaer 환경용)')
    ap.add_argument('--root', required=True, help='root port BDF (예 0000:00:01.1)')
    ap.add_argument('--ep', default=None, help='endpoint(SSD) BDF (예 0000:04:00.0)')
    ap.add_argument('--interval', type=float, default=1.0, help='폴링 주기 초 (default: 1)')
    ap.add_argument('--once', action='store_true', help='1회만 읽고 종료')
    ap.add_argument('--clear', action='store_true',
                    help='매 폴 뒤 status 비트 W1C 로 클리어 → 구간별 발생률로 관측')
    ap.add_argument('--show-cto', action='store_true', help='Completion Timeout 설정 해석 출력')
    ap.add_argument('--set-cto', type=lambda s: int(s, 0), default=None,
                    help='root port DevCtl2 의 Completion Timeout Value 를 설정 '
                         '(예 2 = 1ms~10ms). Disable 비트는 함께 clear. 재부팅 시 원복.')
    args = ap.parse_args()

    targets = [(args.root, 'root')] + ([(args.ep, 'ep')] if args.ep else [])

    if not re.match(r'^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f]$', args.root):
        _p(f"[warn] --root '{args.root}' 형식이 0000:00:01.1 꼴이 아닙니다.")

    if args.set_cto is not None:
        cur = setpci_read(args.root, 'CAP_EXP+0x28.w')
        if cur < 0:
            _p("[error] DevCtl2 읽기 실패 — root 권한/BDF 확인")
            return 1
        new = (cur & ~0x1f) | (args.set_cto & 0xf)     # CTO value 설정 + Disable(bit4) clear
        _p(f"[set-cto] {args.root} DevCtl2 0x{cur:04x} → 0x{new:04x} "
           f"(value=0x{args.set_cto & 0xf:x} = {_CTO_RANGES.get(args.set_cto & 0xf, '예약/불명')})")
        if not setpci_write(args.root, 'CAP_EXP+0x28.w', new):
            _p("[error] DevCtl2 쓰기 실패")
            return 1
        _p(f"[set-cto] 확인: DevCtl2=0x{setpci_read(args.root, 'CAP_EXP+0x28.w'):04x}")
        return 0

    if args.show_cto:
        _p("=" * 72)
        _p("Completion Timeout 설정 (가설 C: 미완료 MMIO read 가 CPU 를 무한 정지시키는가)")
        for bdf, label in targets:
            show_cto(bdf, label)
        _p("=" * 72)

    _p(f"# PCIe 링크 폴링 시작 interval={args.interval}s clear={args.clear} "
       f"start={time.strftime('%Y-%m-%d %H:%M:%S')}")
    _p("# DevSta 는 AER 유무와 무관하게 하드웨어가 셋 — noaer 에서도 유효한 카나리아")

    try:
        while True:
            ts = time.strftime('%H:%M:%S')
            for bdf, label in targets:
                _p(f"[{ts}] {poll_once(bdf, label, args.clear)}")
            if args.once:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        _p("[stop] Ctrl-C")
    return 0


if __name__ == '__main__':
    sys.exit(main())
