#!/usr/bin/env python3
"""SF-E76 — DM 이 dmactive 로 안 깨어나는 이유를 가른다.

⚠⚠ **이 도구는 설계 결함이 있다. `probe_ap_raw.py` 를 쓸 것.** (2026-08-10)

    여기서 쓰는 `memory_read32` 는 J-Link 의 **CPU 컨텍스트**를 거친다.
    CPU 컨텍스트는 **DM 이 active 여야** 생긴다. 그런데 우리가 알고 싶은 게
    바로 DM 상태다 — **순환이다.**

    실측: 유효 세션(DAP 전원 ACK 확인)에서도 **전 레지스터 읽기 실패.**
    이 결과는 "DM 이 없다/틀렸다" 는 증거가 **아니다.** 물어볼 수 없는
    질문을 물었을 뿐이다. 가설 B 판정에 이 결과를 쓰지 말 것.

    → `probe_ap_raw.py` 는 DP→AP 레지스터를 직접 두드려 코어를 우회한다.


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

★ 불안정한 연결 위에서 어떻게 판단하는가 (2026-08-10)

  connect 는 상태 의존적으로 실패한다(가설 G, 단발 성공률 6/12). 그래서
  **1회 실행의 성패는 증거가 아니다.** 이 도구는 두 가지로 대응한다:

    1) 세션 유효성 게이트 — connect 성공만으로 안 믿고 **DAP 전원 ACK**
       (`CDBGPWRUPACK`)를 확인한다. 전원이 안 선 세션의 값은 '측정 실패'가
       아니라 **무효**이고, 집계에서 아예 뺀다.
    2) 독립 세션 반복 — `--sessions N` 회 붙었다 떼며 반복하고,
       **모든 유효 세션에서 같게 나온 값만** 실측으로 인정한다.
       세션마다 달라지는 값은 노이즈다.

사용:
    sudo python3 probe_dm.py --core-base 0x81480000 --hart 0 --sessions 5
    sudo python3 probe_dm.py --shifts 2 --sessions 10      # 확신이 필요할 때
"""

import argparse
import sys
import time

from sfe76_link import (require_api, Link, LinkError,
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


def one_session(a, base, shifts):
    """세션 하나 = 프로세스 내 1회 연결. **유효 세션에서만** 값을 돌려준다.

    반환: (valid, {(base,shift): {reg: value}})
      valid=False 면 그 세션의 값은 **무효**다 — 실패로 세지 않는다.
    """
    lk = Link(core_base=a.core_base, hart=a.hart, device=a.device, serial=a.serial,
              ap_count=a.ap_count, verbose=True)
    out = {}
    try:
        with lk:
            try:
                lk.connect_checked(tries=a.tries, require_power=True)
            except LinkError as e:
                print(f"    세션 무효: {e}")
                return False, out
            for sh in shifts:
                out[(base, sh)] = scan_aperture(lk, base, sh)
    except Exception as e:
        print(f"    세션 예외: {e}")
        return False, out
    return True, out


def main():
    require_api(2, "probe_dm.py")
    ap = add_common_args(argparse.ArgumentParser())
    ap.add_argument('--shifts', default="2,0", help='시도할 매핑 stride (콤마)')
    ap.add_argument('--sessions', type=int, default=5,
                    help='독립 세션 반복 횟수. 연결이 불안정하므로 1회로 판단하지 않는다')
    a = ap.parse_args()

    shifts = [int(x) for x in a.shifts.split(',')]
    print(f"\n{'=' * 66}\n DM aperture 직접 읽기 (v{VERSION})\n{'=' * 66}")
    print(f"  device={a.device!r}  CoreBase=0x{a.core_base:X} "
          f"[{CORE_BASE_LABEL.get(a.core_base, '?')}]  hart={a.hart}")
    print(f"  독립 세션 {a.sessions}회 — **DAP 전원 ACK 로 유효성을 검증한 세션만** 집계한다.")
    print("  연결이 상태 의존적으로 불안정하므로(가설 G) 1회 결과는 증거가 아니다.")

    valid, sessions = 0, []
    for i in range(a.sessions):
        print(f"\n{'-' * 66}\n 세션 {i + 1}/{a.sessions}\n{'-' * 66}")
        vok, vals = one_session(a, a.core_base, shifts)
        if vok:
            valid += 1
            sessions.append(vals)
        time.sleep(0.5)

    print(f"\n{'=' * 66}\n 집계 — 유효 세션 {valid}/{a.sessions}\n{'=' * 66}")
    if not valid:
        print("  ❌ 유효 세션이 하나도 없다. 값을 해석하지 말 것.")
        print("     타깃 전원 사이클 후 재실행, 그래도 0 이면 연결 계층부터 회귀.")
        return EXIT_INSUFFICIENT

    # 같은 값이 독립 세션에서 반복되면 실측, 한 번만 나오면 노이즈다
    ok = None
    for sh in shifts:
        key = (a.core_base, sh)
        print(f"\n  ── base=0x{a.core_base:X}  stride <<{sh}")
        agreed = {}
        for _, nm in DM_REGS:
            seen = [s[key].get(nm) for s in sessions if key in s]
            uniq = {}
            for v in seen:
                uniq[v] = uniq.get(v, 0) + 1
            top, cnt = max(uniq.items(), key=lambda kv: kv[1]) if uniq else (None, 0)
            mark = "✅ 일치" if cnt == valid else f"⚠ {cnt}/{valid} 만 일치"
            shown = "읽기 실패" if top is None else f"0x{top:08X}"
            print(f"     {nm:11s} = {shown:12s} {mark}"
                  + ("" if len(uniq) <= 1 else f"   (관측값 {len(uniq)}종)"))
            agreed[nm] = top if cnt == valid else None
        r = verdict(agreed, f"0x{a.core_base:X} <<{sh}  (전 세션 일치값만)")
        ok = ok or r

    print(f"\n{'=' * 66}\n 판단 기준\n{'=' * 66}")
    print("  · **전 세션 일치값만** 실측으로 인정한다. 세션마다 다른 값은 노이즈다.")
    print("  · 유효 세션이 적으면(<3) 결론 내지 말고 --sessions 를 늘린다.")
    if ok:
        print("\n  aperture 가 맞다 → dmstatus 비트로 원인 확정. 가설 B 종료.")
    else:
        print("\n  유효 세션에서도 dmstatus 가 안 나온다 →")
        print("  1) --shifts 를 넓히거나 --core-base 를 바꿔 재시도")
        print("  2) 메모리 읽기 경로 자체가 막힌 것일 수 있다 —")
        print("     그 경우 T32 의 DMI/aperture 설정 확보가 유일한 길이다")
    return EXIT_OK if ok else EXIT_INSUFFICIENT


if __name__ == '__main__':
    sys.exit(main())
