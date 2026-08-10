#!/usr/bin/env python3
"""SF-E76 — AP 에 **직접** 트랜잭션을 걸어 (1) AP 실재 확인 (2) DM 읽기.

════════════════════════════════════════════════════════════════════
왜 이 도구가 필요한가 — probe_dm.py 의 설계 결함
════════════════════════════════════════════════════════════════════
`probe_dm.py` 는 `memory_read32(0x81480040)` 으로 DM 을 읽으려 했다.
그런데 pylink/J-Link 의 memory read 는 **CPU 컨텍스트를 거친다.**
CPU 컨텍스트는 DM 이 active 여야 생긴다. 즉:

    DM 을 읽으려면 → CPU 컨텍스트가 필요하고 → DM 이 active 여야 한다

**순환이다.** 그래서 유효 세션(DAP 전원 ACK)에서도 전 레지스터가 읽기 실패였다.
그 결과는 "DM 이 없다" 는 증거가 **아니다** — 애초에 물어볼 수 없는 질문이었다.

여기서는 **DP → AP 레지스터를 직접** 두드린다. 코어도 DM 도 거치지 않는다.
DAP 전원만 서 있으면 동작해야 한다.

════════════════════════════════════════════════════════════════════
주소 체계 — ADIv6 / SoC-600 (DPIDR=0x11013913, VERSION=3)
════════════════════════════════════════════════════════════════════
ADIv5 는 AP 를 APSEL(번호)로 골랐지만, **ADIv6 는 주소로 고른다.**
그리고 MEM-AP 레지스터가 뱅크 맨 위로 옮겨갔다:

    AP_base + 0xD00  CSW    AP_base + 0xD04  TAR
    AP_base + 0xD0C  DRW    AP_base + 0xDFC  IDR

DP SELECT 에 **레지스터 주소의 상위 비트**를 넣고, 트랜잭션의 A[3:2] 로
16바이트 창 안의 워드를 고른다. J-Link 의 AP 레지스터 인덱스가 곧 그 A[3:2] 다:

    SELECT = AP_base + 0xD00  →  idx0=CSW  idx1=TAR  idx3=DRW
    SELECT = AP_base + 0xDF0  →  idx3=IDR

    ⇒ 고전적인 CTRL=0 / ADDR=1 / DATA=3 과 그대로 맞아떨어진다.

════════════════════════════════════════════════════════════════════
무엇을 알 수 있나
════════════════════════════════════════════════════════════════════
[1] **AP 실재 확인** — IDR 이 0 도 0xFFFFFFFF 도 아니면 그 AP 는 실재한다.
    선언한 AP 6개 중 실재가 확인된 건 **지금까지 하나도 없다.** 이게 첫 확인이다.
    IDR 은 AP 종류(APB/AHB/AXI)와 제조사도 알려준다.

[2] **TAR 되읽기** — 쓴 값이 그대로 읽히면 그 AP 로 가는 경로가 살아 있다.
    이게 되면 "우리 코드로 AP 접근이 원래 안 된다" 는 오랜 불확실성이 끝난다.

[3] **DM 읽기** — TAR 에 0x81480040 을 넣고 DRW 를 읽으면 dmcontrol 이다.
    CPU 컨텍스트 없이 읽으므로 순환이 없다.

사용:
    sudo python3 probe_ap_raw.py                       # AP 열거만
    sudo python3 probe_ap_raw.py --dm 0x81480000       # 열거 + DM 읽기
    sudo python3 probe_ap_raw.py --dm 0x81480000 --sessions 3
"""

import argparse
import sys
import time

from sfe76_link import (Link, LinkError, AP_MAP, add_common_args,
                        EXIT_OK, EXIT_INSUFFICIENT)

VERSION = "2026-08-10.1"

# DP 레지스터 인덱스
DP_ABORT, DP_CTRL_STAT, DP_SELECT, DP_RDBUF = 0, 1, 2, 3
# AP 레지스터 인덱스 = 16바이트 창 안의 워드 번호 (A[3:2])
AP_IDX_CSW, AP_IDX_TAR, AP_IDX_DRW = 0, 1, 3

# ADIv6 MEM-AP 레지스터의 AP 공간 내 오프셋
OFF_CSW, OFF_TAR, OFF_DRW, OFF_IDR = 0xD00, 0xD04, 0xD0C, 0xDFC

# RISC-V DMI 레지스터 (aperture = base + (addr << 2) 로 추정)
DM_REGS = [(0x10, 'dmcontrol'), (0x11, 'dmstatus'), (0x12, 'hartinfo'),
           (0x16, 'abstractcs'), (0x1D, 'nextdm'), (0x38, 'sbcs')]

DM_VERSION = {0: '없음', 1: '0.11', 2: '0.13', 3: '1.0'}

AP_CLASS = {0x0: '없음/JTAG-AP', 0x8: 'MEM-AP'}
AP_TYPE = {0x1: 'AHB3', 0x2: 'APB2/APB3', 0x4: 'AXI3/AXI4',
           0x5: 'AHB5', 0x6: 'APB4/APB5', 0x7: 'AXI5', 0x8: 'AHB5-hprot'}


def hx(v):
    return "실패" if v is None else f"0x{v & 0xFFFFFFFF:08X}"


class Dap:
    """DP/AP 원시 접근. 실패는 None 으로 돌린다 (예외로 흐름을 끊지 않는다)."""

    def __init__(self, jl, verbose=True):
        self.jl = jl
        self.verbose = verbose
        self._select = None

    def _say(self, m):
        if self.verbose:
            print(m)

    def dp_read(self, reg):
        try:
            v = self.jl.coresight_read(reg, ap=False)
            return None if (v is None or v < 0) else (v & 0xFFFFFFFF)
        except Exception:
            return None

    def dp_write(self, reg, val):
        try:
            self.jl.coresight_write(reg, val & 0xFFFFFFFF, ap=False)
            return True
        except Exception:
            return False

    def select(self, addr):
        """DP SELECT 에 AP 레지스터 주소의 상위 비트를 넣는다 (ADIv6)."""
        val = addr & 0xFFFFFFF0
        if self._select != val:
            if not self.dp_write(DP_SELECT, val):
                return False
            self._select = val
        return True

    def ap_read(self, ap_base, off):
        if not self.select(ap_base + off):
            return None
        try:
            v = self.jl.coresight_read((off >> 2) & 0x3, ap=True)
            return None if (v is None or v < 0) else (v & 0xFFFFFFFF)
        except Exception:
            return None

    def ap_write(self, ap_base, off, val):
        if not self.select(ap_base + off):
            return False
        try:
            self.jl.coresight_write((off >> 2) & 0x3, val & 0xFFFFFFFF, ap=True)
            return True
        except Exception:
            return False

    def clear_sticky(self):
        self.dp_write(DP_ABORT, 0x0000001E)
        self._select = None          # ABORT 후 SELECT 는 다시 쓴다

    # ── MEM-AP 를 통한 32비트 메모리 읽기 ────────────────────────────
    def mem_read32(self, ap_base, addr):
        csw = self.ap_read(ap_base, OFF_CSW)
        if csw is None:
            return None
        # Size=2(word), AddrInc=off. 나머지 비트(Prot/SPIDEN 등)는 보존한다.
        new_csw = (csw & ~0x37) | 0x02
        if not self.ap_write(ap_base, OFF_CSW, new_csw):
            return None
        if not self.ap_write(ap_base, OFF_TAR, addr):
            return None
        back = self.ap_read(ap_base, OFF_TAR)
        if back is None or back != (addr & 0xFFFFFFFF):
            self._say(f"      TAR 되읽기 불일치: 쓴값={hx(addr)} 읽은값={hx(back)}")
            return None
        return self.ap_read(ap_base, OFF_DRW)


def decode_idr(v):
    if v is None:
        return "읽기 실패"
    if v in (0, 0xFFFFFFFF):
        return f"{hx(v)}  ← **AP 없음** (선언만 되어 있고 실재하지 않는다)"
    cls = (v >> 13) & 0xF
    typ = v & 0xF
    rev = (v >> 28) & 0xF
    desg = (v >> 17) & 0x7FF
    return (f"{hx(v)}  ✅ **실재**  class={cls:#x}({AP_CLASS.get(cls, '?')})  "
            f"type={typ:#x}({AP_TYPE.get(typ, '?')})  DESIGNER={desg:#05x}  rev={rev}")


def enumerate_aps(dap):
    print(f"\n{'=' * 66}\n [1] AP 실재 확인 — IDR 읽기\n{'=' * 66}")
    print("  선언한 AP 6개 중 실재가 확인된 건 지금까지 하나도 없었다.")
    real = []
    for name, base, typ in AP_MAP:
        dap.clear_sticky()
        idr = dap.ap_read(base, OFF_IDR)
        print(f"\n  {name:7s} @ 0x{base:05X}  (선언 타입 {typ})")
        print(f"      IDR = {decode_idr(idr)}")
        if idr not in (None, 0, 0xFFFFFFFF):
            real.append((name, base, idr))
    return real


def probe_ap_path(dap, name, base):
    """TAR 되읽기로 그 AP 로 가는 경로가 살아 있는지 본다."""
    dap.clear_sticky()
    for pat in (0xA5A50000, 0x5A5A0000):
        if not dap.ap_write(base, OFF_TAR, pat):
            return False
        if dap.ap_read(base, OFF_TAR) != pat:
            return False
    print(f"      {name}: ✅ TAR 되읽기 일치 — **AP 접근 경로가 살아 있다**")
    return True


def read_dm(dap, name, base, dm_base, shift=2):
    print(f"\n  ── {name} @0x{base:05X} 로 DM 0x{dm_base:X} 읽기 (stride <<{shift})")
    vals = {}
    for addr, nm in DM_REGS:
        dap.clear_sticky()
        v = dap.mem_read32(base, dm_base + (addr << shift))
        vals[nm] = v
        print(f"     {nm:11s} @0x{dm_base + (addr << shift):08X} = {hx(v)}")
    return vals


def verdict_dm(vals):
    ds = vals.get('dmstatus')
    if ds is None:
        print("     → dmstatus 읽기 실패")
        return None
    if ds in (0, 0xFFFFFFFF):
        print(f"     → dmstatus={hx(ds)} — 여기는 DM aperture 가 아니다")
        return False
    ver = ds & 0xF
    print(f"     → dmstatus={hx(ds)}  version={ver}({DM_VERSION.get(ver, '?')})")
    if ver in (2, 3):
        print("     ★★ **DM aperture 확정.** 가설 B 종료.")
        if not (ds & (1 << 7)):
            print("     ★ authenticated=0 → **디버그 잠김.** 벤더 해제 절차 필요 (가설 A)")
        else:
            print("     authenticated=1 → 잠금은 아니다 (가설 A 반증)")
        if ds & (1 << 13):
            print("     ⚠ allunavail=1 → 하트가 사용 불가 (리셋/전원 게이팅 — 가설 C)")
        if ds & (1 << 15):
            print("     ⚠ allnonexistent=1 → hartsel 이 없는 하트를 가리킨다")
        return True
    print(f"     version={ver} → 유효한 DM 이 아니다")
    return False


def one_session(a):
    lk = Link(core_base=a.core_base, hart=a.hart, device=a.device,
              serial=a.serial, ap_count=getattr(a, 'ap_count', None))
    out = {'valid': False, 'real_aps': [], 'dm': {}}
    try:
        with lk:
            try:
                lk.connect_checked(tries=a.tries, require_power=True)
            except LinkError as e:
                print(f"  세션 무효: {e}")
                return out
            out['valid'] = True
            dap = Dap(lk.jl)

            real = enumerate_aps(dap)
            out['real_aps'] = [(n, b, i) for n, b, i in real]

            print(f"\n{'=' * 66}\n [2] AP 접근 경로 확인 — TAR 되읽기\n{'=' * 66}")
            usable = []
            targets = real if real else [(n, b, None) for n, b, _t in AP_MAP]
            if not real:
                print("  실재 확인된 AP 가 없다. 그래도 전 AP 에 TAR 되읽기를 시도한다")
                print("  (IDR 오프셋이 틀렸을 가능성과 AP 부재를 구분하기 위해)")
            for n, b, _ in targets:
                if probe_ap_path(dap, n, b):
                    usable.append((n, b))
            out['usable_aps'] = usable

            if a.dm and usable:
                print(f"\n{'=' * 66}\n [3] DM 읽기\n{'=' * 66}")
                for n, b in usable:
                    vals = read_dm(dap, n, b, a.dm, a.shift)
                    out['dm'][n] = vals
                    verdict_dm(vals)
            elif a.dm:
                print("\n  접근 가능한 AP 가 없어 DM 읽기를 건너뛴다.")
    except Exception as e:
        print(f"  세션 예외: {e}")
    return out


def main():
    ap = add_common_args(argparse.ArgumentParser())
    ap.add_argument('--dm', type=lambda x: int(x, 0), default=None,
                    help='DM base (예: 0x81480000). 주면 AP 를 통해 DM 을 읽는다')
    ap.add_argument('--shift', type=int, default=2, help='DMI stride (기본 2 = <<2)')
    ap.add_argument('--sessions', type=int, default=3,
                    help='독립 세션 반복. 전 세션 일치값만 인정한다')
    a = ap.parse_args()

    print(f"\n{'=' * 66}\n AP 직접 접근 — 코어/DM 을 거치지 않는다 (v{VERSION})\n{'=' * 66}")
    print("  probe_dm.py 는 memory_read32 로 DM 을 읽으려 했다. 그건 CPU 컨텍스트를")
    print("  거치는데, CPU 컨텍스트는 DM 이 살아야 생긴다 — **순환이었다.**")
    print("  여기서는 DP→AP 레지스터를 직접 두드린다. DAP 전원만 있으면 된다.")

    runs = []
    for i in range(a.sessions):
        print(f"\n{'#' * 66}\n# 세션 {i + 1}/{a.sessions}\n{'#' * 66}")
        runs.append(one_session(a))
        time.sleep(0.5)

    valid = [r for r in runs if r['valid']]
    print(f"\n{'=' * 66}\n 집계 — 유효 세션 {len(valid)}/{a.sessions}\n{'=' * 66}")
    if not valid:
        print("  ❌ 유효 세션 0 — 해석하지 말 것. 타깃 전원 사이클 후 재실행.")
        return EXIT_INSUFFICIENT

    # 전 유효 세션에서 일관되게 실재로 나온 AP 만 인정한다
    names = [n for n, _, _ in AP_MAP]
    print("\n  AP 실재 (전 세션 일치한 것만 ✅):")
    solid = []
    for n in names:
        cnt = sum(1 for r in valid if any(x[0] == n for x in r['real_aps']))
        use = sum(1 for r in valid if any(x[0] == n for x in r.get('usable_aps', [])))
        mark = "✅" if cnt == len(valid) else ("⚠" if cnt else "  ")
        print(f"    {mark} {n:7s} IDR 실재 {cnt}/{len(valid)}   TAR 경로 {use}/{len(valid)}")
        if cnt == len(valid):
            solid.append(n)

    print(f"\n{'=' * 66}\n 다음\n{'=' * 66}")
    if solid:
        print(f"  ★ 실재 확인된 AP: {solid}")
        print("     → AP_MAP 을 이걸로 줄이고, DM/트레이스 접근을 여기로 건다.")
    else:
        print("  실재 확인된 AP 가 없다. 둘 중 하나다:")
        print("    a) ADIv6 오프셋(0xDFC)이 이 구현과 다르다 → TAR 되읽기 결과를 볼 것")
        print("    b) AP 주소(T32 의 DP:0x10000 등)가 J-Link 에선 다르게 해석된다")
        print("  TAR 되읽기가 하나라도 성공했다면 (a) 이고, 그 AP 는 쓸 수 있다.")
    return EXIT_OK if valid else EXIT_INSUFFICIENT


if __name__ == '__main__':
    sys.exit(main())
