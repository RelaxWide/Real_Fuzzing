#!/usr/bin/env python3
"""SF-E76 — DM 이 dmactive 로 안 깨어나는 이유를 가른다.

증상: J-Link 이 "Timeout waiting for debug module to become active".
      DPIDR / AP map / CoreBase 는 인식되는데 DM 이 active 로 응답하지 않는다.

RISC-V Debug Spec: `dmcontrol.dmactive` 를 1 로 쓴 뒤 **되읽어 1 이 될 때까지**
폴링해야 DM 이 리셋에서 깨어난다. 그게 타임아웃이라는 건 넷 중 하나다:

  A 디버그 인증/잠금   SiFive Insight 의 password/fuse/PKI 기반 접근 제어
  B DMI aperture 주소·매핑이 틀림   쓰기가 엉뚱한 곳에 떨어진다
  C DM 전원/클럭 게이팅 (ARM DAP 디버그 전원과 별개 도메인)
  D 잘못된 DM (DM 이 둘인데 J-Link 은 하나만 지원)

**A 와 B 는 `dmstatus` 를 직접 읽으면 갈린다:**
  - 값이 통째로 0 또는 0xFFFFFFFF  → B/C (aperture 가 아니거나 죽어 있다)
  - version 이 2(0.13) 또는 3(1.0)  → **aperture 는 맞다.** 그러면 A/C/D
  - authenticated == 0              → ★ **디버그 잠김.** 벤더 해제 절차 필요
  - allnonexistent == 1             → hartsel 이 없는 하트를 가리킴

DM 레지스터는 DMI 주소이므로 aperture 안에서 보통 `base + (dmi_addr << 2)` 다.
stride 가 다를 수 있어 <<2 와 <<0 을 모두 시도한다.

사용:
    sudo python3 probe_dm.py
    sudo python3 probe_dm.py --core-base 0x81480000
    sudo python3 probe_dm.py --device E76        # SEGGER 지원 목록에 E76 있음
"""

import argparse
import sys

from sfe76_link import (Link, LinkError, CORE_BASE_MAIN, CORE_BASE_NCORE,
                        CORE_BASE_LABEL, add_common_args, EXIT_OK, EXIT_INSUFFICIENT)

VERSION = "2026-08-10.1"

# RISC-V Debug Spec DMI 레지스터 주소
DM_REGS = [
    (0x04, 'data0'), (0x10, 'dmcontrol'), (0x11, 'dmstatus'),
    (0x12, 'hartinfo'), (0x16, 'abstractcs'), (0x17, 'command'),
    (0x1D, 'nextdm'), (0x38, 'sbcs'),
]

DM_VERSION = {0: '없음', 1: '0.11', 2: '0.13', 3: '1.0'}


def decode_dmstatus(v):
    out = []
    ver = v & 0xF
    out.append(f"version={ver}({DM_VERSION.get(ver, '?')})")
    for bit, name in ((6, 'authbusy'), (7, 'authenticated'),
                      (8, 'anyhalted'), (9, 'allhalted'),
                      (10, 'anyrunning'), (11, 'allrunning'),
                      (12, 'anyunavail'), (13, 'allunavail'),
                      (14, 'anynonexistent'), (15, 'allnonexistent')):
        if v & (1 << bit):
            out.append(name)
    return "  ".join(out)


def read32(lk, addr):
    """가능한 경로를 차례로 시도한다."""
    for fn in ('memory_read32', 'memory_read'):
        try:
            r = getattr(lk.jl, fn)(addr, 1)
            return (r[0] & 0xFFFFFFFF) if r else None
        except Exception:
            continue
    return None


def scan_aperture(lk, base, shift):
    print(f"\n  ── base=0x{base:X}  매핑= base + (dmi_addr << {shift})")
    vals = {}
    for a, nm in DM_REGS:
        v = read32(lk, base + (a << shift))
        vals[nm] = v
        s = "읽기 실패" if v is None else f"0x{v:08X}"
        print(f"     {nm:11s} @+0x{a << shift:03X} = {s}")
    return vals


def verdict(vals, tag):
    ds = vals.get('dmstatus')
    print(f"\n  [{tag}] 판정")
    if ds is None:
        print("     읽기 자체가 실패 — 이 경로로는 메모리 접근이 안 된다")
        return None
    if ds in (0x00000000, 0xFFFFFFFF):
        print(f"     dmstatus=0x{ds:08X} → **aperture 가 아니거나 죽어 있다** (가설 B/C)")
        return False
    ver = ds & 0xF
    print(f"     dmstatus=0x{ds:08X}  {decode_dmstatus(ds)}")
    if ver in (2, 3):
        print("     ★ version 이 유효 → **aperture 는 맞다.** 남은 건 A/C/D")
        if not (ds & (1 << 7)):
            print("     ★★ authenticated=0 → **디버그가 잠겨 있다.**")
            print("         벤더 해제 절차(패스워드/퓨즈/PKI) 없이는 진행 불가")
        if ds & (1 << 15):
            print("     ⚠ allnonexistent=1 → hartsel 이 없는 하트를 가리킨다")
        if ds & (1 << 13):
            print("     ⚠ allunavail=1 → 하트가 사용 불가 상태(리셋/전원)")
        nd = vals.get('nextdm')
        if nd not in (None, 0, 0xFFFFFFFF):
            print(f"     nextdm=0x{nd:08X} → **다음 DM 이 이 주소에 있다** "
                  f"(J-Link 은 DM 하나만 지원하니 선택이 중요)")
        sb = vals.get('sbcs')
        if sb not in (None, 0, 0xFFFFFFFF):
            print(f"     sbcs=0x{sb:08X} → **SBA 구현됨** "
                  f"(halt 없는 메모리 접근 가능 — 트레이스 설정에 유리)")
        elif sb == 0:
            print("     sbcs=0 → SBA 미구현으로 보임 (SiFive Insight 에서 optional)")
        return True
    print(f"     version={ver} → 유효한 DM 이 아니다 (가설 B)")
    return False


def main():
    ap = add_common_args(argparse.ArgumentParser())
    ap.add_argument('--shifts', default="2,0", help='시도할 매핑 stride (콤마)')
    ap.add_argument('--both-bases', action='store_true',
                    help='CoreBase 두 후보 모두 (프로세스는 하나 — 진단 전용)')
    a = ap.parse_args()

    print(f"\n{'=' * 66}\n DM aperture 직접 읽기 — dmactive 실패 원인 분리 (v{VERSION})\n{'=' * 66}")
    print(f"  device={a.device!r}  CoreBase=0x{a.core_base:X} "
          f"[{CORE_BASE_LABEL.get(a.core_base, '?')}]  hart={a.hart}")

    lk = Link(core_base=a.core_base, hart=a.hart, device=a.device, serial=a.serial,
              ap_count=a.ap_count)
    ok = None
    try:
        with lk:
            print("\n  connect 시도 (dmactive 타임아웃으로 실패해도 계속 진행한다 —")
            print("  실패한 connect 가 DAP 를 설정해 두면 메모리 읽기가 될 수 있다)")
            try:
                lk.connect_checked(tries=a.tries)
                print("  connect 성공")
            except LinkError as e:
                print(f"  connect 실패(예상됨): {e}")

            bases = [a.core_base]
            if a.both_bases:
                bases = [CORE_BASE_NCORE, CORE_BASE_MAIN]
            for b in bases:
                for sh in [int(x) for x in a.shifts.split(',')]:
                    vals = scan_aperture(lk, b, sh)
                    r = verdict(vals, f"0x{b:X} <<{sh}")
                    ok = ok or r
    except Exception as e:
        print(f"\n  예외: {e}")

    print(f"\n{'=' * 66}\n 다음\n{'=' * 66}")
    if ok:
        print("  aperture 가 맞는 조합이 있었다 → dmstatus 비트로 원인 확정.")
        print("  authenticated=0 이면 벤더 해제 절차가 선행 조건이다.")
    else:
        print("  어느 조합에서도 유효한 dmstatus 를 못 읽었다.")
        print("  1) --core-base 를 바꿔 재시도 (0x81480000 / 0x81481000)")
        print("  2) --device E76  (SEGGER 지원 목록에 E76/E76-MC/E76ARTY 있음)")
        print("  3) 메모리 읽기 경로 자체가 막힌 것일 수 있다 —")
        print("     그 경우 T32 의 DMI/aperture 설정을 확보하는 게 유일한 길이다")
    return EXIT_OK if ok else EXIT_INSUFFICIENT


if __name__ == '__main__':
    sys.exit(main())
