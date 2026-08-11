#!/usr/bin/env python3
"""SF-E76 — **AXI-AP 로 읽는다.** 읽기 전용. 쓰기는 절대 하지 않는다.

════════════════════════════════════════════════════════════════════
왜 AXI 인가 — T32 리셋 해제 루틴이 알려줬다
════════════════════════════════════════════════════════════════════
    ALL MPCore Reset Release   Data.Set **AXI**:0xC81040 %LE %Long 0x13333
    NCore  Reset Release       Data.Set **AXI**:0xC81044 %LE %Long 0x10001
    (+ MD:0x0 ← 0x6F,  sys.m.down,  0xC81044 ← 0x0 → 0x10001 → 0x10003)

접근 클래스가 **`AXI:`** 다. APB 가 아니다.
→ `AXIAP1` (index 2, `DP:0x30000`). IDR TYPE=4(AXI3/4)로 실재가 확인된 AP.
→ **우리는 AXI-AP 로 아무것도 해본 적이 없다.** 내내 APB-AP 만 썼다.

그리고 `0x0000006F` 는 RISC-V `j .` (자기 자신으로 점프 = 무한루프)다.
리셋 풀기 전에 코어를 묶어두는 전형적인 수법 —
**이 시퀀스가 코어를 실제로 재시작시킨다**는 뜻이다.

════════════════════════════════════════════════════════════════════
⚠⚠ 이 도구는 **절대 쓰지 않는다**
════════════════════════════════════════════════════════════════════
지금 SSD 는 **살아서 동작 중**이다(`nvme list` 됨). 즉 코어는 이미 리셋에서
나와 있다. 거기에 리셋 컨트롤러를 쓰면 **동작 중인 SSD 를 리셋**하는 것이고,
최악의 경우 장치가 hang 하거나 펌웨어 상태가 깨진다.

**먼저 읽기만 한다.** 읽히는 것만으로도 큰 진전이다:
  · AXI-AP 경로가 동작한다는 증명
  · 리셋 컨트롤러 현재 값 → 코어가 리셋 상태인지 아닌지 판정
  · "AP 너머는 전부 죽어 있다" 는 지금까지의 결론이 맞는지 재검증

쓰기가 필요하다고 판단되면 **그때 별도 도구로, 명시적 동의를 받고** 한다.

사용:
    sudo python3 probe_axi.py                 # 리셋 컨트롤러 주변 읽기
    sudo python3 probe_axi.py --addrs 0xC81040,0xC81044
"""

import argparse
import sys
import time

from sfe76_link import (require_api, Link, LinkError, AP_MAP,
                        add_common_args, EXIT_OK, EXIT_INSUFFICIENT)

VERSION = "2026-08-11.27  Prot 스윕"

# ★ probe_rom_dm 결과가 해석을 바꿨다:
#     전송단계 ok:66, DP 오류비트 없음, TrInProg=False
#   → 66번 전송이 전부 **정상 완료**됐다. 즉 0/0xEAFFFFFE 는 버스 기본값이
#     아니라 **진짜 읽은 데이터**다. 버스는 응답하고 있다.
#
# ★ 그리고 AP 마다 CSW.Prot 이 다르다:
#     APB Prot=0x00      AXI Prot=0x30
#   AXI 는 AxPROT/AxCACHE 가 접근 권한을 결정하고, 권한이 안 맞으면
#   **에러 없이 0 을 돌려준다(RAZ)** — AXI 가 전부 0 인 것과 정확히 맞는다.
#   ⇒ Prot 을 바꿔가며 같은 주소를 읽어본다. 이건 읽기만 하므로 안전하다.
PROT_CANDIDATES = [None,        # 현재 값 그대로
                   0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
                   0x23, 0x33, 0x43, 0x63]

OFF_CSW, OFF_TAR, OFF_DRW, OFF_IDR = 0xD00, 0xD04, 0xD0C, 0xDFC
DP_ABORT, DP_SELECT = 0, 2
SUSPECT = 0x80000000
DEAD = {0x00000000, 0xFFFFFFFF, 0xEAFFFFFE, 0xEAFFFFFC, 0x00000001, 0x00040700}

AXI_AP = 'AXIAP1'          # index 2, DP:0x30000

# T32 가 건드리는 리셋 컨트롤러와 그 주변
RESET_ADDRS = [
    (0xC81040, 'ALL MPCore Reset Release  (T32 가 0x13333 을 쓴다)'),
    (0xC81044, 'NCore Reset Release       (T32 가 0x10001/0x10003 을 쓴다)'),
    (0xC81000, '  블록 시작 근처'),
    (0xC81004, ''),
    (0xC81008, ''),
    (0xC8100C, ''),
    (0xC81020, ''),
    (0xC81030, ''),
    (0xC81048, '  0xC81044 다음'),
    (0xC8104C, ''),
]


def hx(v):
    return "----" if v is None else f"{v & 0xFFFFFFFF:08X}"


def live(v):
    return v is not None and v not in DEAD


class Rd:
    """읽기 전용 MEM-AP. **쓰기는 CSW/TAR 뿐** — 데이터 버스에 쓰지 않는다."""

    def __init__(self, jl, base):
        self.jl, self.base, self.sel = jl, base, None
        self.csw0 = self._r(OFF_CSW)

    def _sel(self, addr):
        v = addr & 0xFFFFFFF0
        if self.sel == v:
            return True
        try:
            self.jl.coresight_write(DP_SELECT, v, ap=False)
        except Exception:
            return False
        self.sel = v
        try:
            self.jl.coresight_read(0, ap=True)
        except Exception:
            pass
        return True

    def _r(self, off):
        if not self._sel(self.base + off):
            return None
        try:
            v = self.jl.coresight_read((off >> 2) & 3, ap=True)
            return None if (v is None or v < 0) else v & 0xFFFFFFFF
        except Exception:
            return None

    def _w(self, off, val):
        if not self._sel(self.base + off):
            return False
        try:
            self.jl.coresight_write((off >> 2) & 3, val & 0xFFFFFFFF, ap=True)
            return True
        except Exception:
            return False

    def abort(self):
        try:
            self.jl.coresight_write(DP_ABORT, 0x1E, ap=False)
        except Exception:
            pass
        self.sel = None

    def read32(self, addr, prot=None):
        """prot 을 주면 CSW 의 Prot 필드(bits 30:24)를 바꿔서 읽는다."""
        self.abort()
        if self.csw0 is None or self.csw0 == SUSPECT:
            return None
        csw = (self.csw0 & ~0x37) | 0x02
        if prot is not None:
            csw = (csw & ~(0x7F << 24)) | ((prot & 0x7F) << 24)
        if not self._w(OFF_CSW, csw):
            return None
        if not self._w(OFF_TAR, addr):        # TAR 은 주소 레지스터 — 데이터 쓰기 아님
            return None
        if self._r(OFF_TAR) != (addr & 0xFFFFFFFF):
            return None
        return self._r(OFF_DRW)               # ★ 읽기만

    def restore(self):
        if self.csw0 is not None and self.csw0 != SUSPECT:
            self._w(OFF_CSW, self.csw0)


def prot_sweep(a, addrs):
    """★ CSW.Prot 를 바꿔가며 읽는다. **읽기만 하므로 안전하다.**

    AXI 는 AxPROT/AxCACHE 로 접근 권한이 정해지고, 권한이 안 맞으면
    에러 없이 0 을 돌려준다(RAZ). 지금 AXI 가 전부 0 이고 오류비트도
    없는 것이 정확히 그 모양이다. Prot 을 바꾸면 값이 달라질 수 있다.
    """
    lk = Link(device=a.device, serial=a.serial, verbose=False)
    base = dict((n, b) for n, b, _t in AP_MAP)[a.ap_name]
    print(f"\n{'=' * 68}\n [PROT] {a.ap_name} 에서 CSW.Prot 을 바꿔가며 읽기"
          f"\n{'=' * 68}")
    print("  AXI 는 권한이 안 맞으면 에러 없이 0 을 준다(RAZ). 그래서 Prot 을 훑는다.")
    print("  ★ 읽기만 한다 — CSW/TAR 외에는 아무것도 쓰지 않는다.\n")
    try:
        with lk:
            try:
                lk.open_dap(tries=a.tries)
            except LinkError as e:
                print(f"  세션 무효: {e}")
                return EXIT_INSUFFICIENT
            r = Rd(lk.jl, base)
            print(f"  {a.ap_name} IDR={hx(r._r(OFF_IDR))}  CSW원본={hx(r.csw0)}"
                  f"  (Prot=0x{((r.csw0 or 0) >> 24) & 0x7F:02X})\n")
            hdr = "  Prot  " + "  ".join(f"0x{ad:08X}" for ad, _l in addrs[:6])
            print(hdr)
            hits = []
            for p in PROT_CANDIDATES:
                vals = [r.read32(ad, p) for ad, _l in addrs[:6]]
                tag = "orig" if p is None else f"0x{p:02X}"
                line = f"  {tag:5s} " + "  ".join(f"{hx(v):>10s}" for v in vals)
                if any(live(v) for v in vals):
                    line += "   ★ live"
                    hits.append((p, vals))
                print(line)
            r.restore()
    except Exception as e:
        print(f"  예외: {e}")
        return EXIT_INSUFFICIENT

    print(f"\nv={VERSION.split()[0]}")
    print("VERDICT:", "PROT_FOUND" if hits else "PROT_NO_EFFECT")
    if hits:
        p = hits[0][0]
        print(f"  ★★★ Prot={'orig' if p is None else f'0x{p:02X}'} 에서 값이 나온다.")
        print("     접근 권한이 원인이었다. 이 Prot 으로 다른 도구도 맞춘다.")
    else:
        print("  Prot 을 바꿔도 전부 같다 → 권한 문제가 아니다.")
        print("  그 주소들이 이 AP 의 주소공간에 실제로 없다는 뜻에 가깝다.")
    return EXIT_OK if hits else EXIT_INSUFFICIENT


def one_session(a, addrs):
    lk = Link(device=a.device, serial=a.serial, verbose=not a.brief)
    out = {'valid': False, 'idr': None, 'vals': {}}
    try:
        with lk:
            try:
                lk.open_dap(tries=a.tries)
            except LinkError as e:
                out['error'] = str(e)
                return out
            out['valid'] = True
            base = dict((n, b) for n, b, _t in AP_MAP)[a.ap_name]
            r = Rd(lk.jl, base)
            out['idr'] = hx(r._r(OFF_IDR))
            out['csw'] = hx(r.csw0)
            for addr, _label in addrs:
                out['vals'][addr] = r.read32(addr)
            r.restore()
    except Exception as e:
        out['error'] = str(e)
    return out


def main():
    require_api(5, "probe_axi.py")
    ap = add_common_args(argparse.ArgumentParser())
    ap.add_argument('--ap-name', default=AXI_AP,
                    choices=[n for n, _b, _t in AP_MAP])
    ap.add_argument('--addrs', default=None, help='콤마 구분 주소 (기본: 리셋 블록)')
    ap.add_argument('--sessions', type=int, default=3)
    ap.add_argument('--prot-sweep', action='store_true',
                    help='★ CSW.Prot 를 바꿔가며 같은 주소를 읽는다 (읽기 전용)')
    ap.add_argument('--brief', action='store_true')
    ap.add_argument('--version', action='store_true')
    a = ap.parse_args()
    if a.version:
        print(f"probe_axi {VERSION}")
        return EXIT_OK

    addrs = ([(int(x, 0), '') for x in a.addrs.split(',') if x.strip()]
             if a.addrs else RESET_ADDRS)

    if not a.brief:
        print(f"\n{'=' * 68}\n AXI-AP 읽기 (v{VERSION})  ★ 읽기 전용\n{'=' * 68}")
        print(f"  AP = {a.ap_name}   주소 {len(addrs)}개   세션 {a.sessions}회")
        print("  T32 리셋 해제가 AXI: 클래스를 쓴다 — 우리는 AXI-AP 를 써본 적이 없다.")
        print("  ⚠ **쓰기는 하지 않는다.** 동작 중인 SSD 를 리셋할 위험이 있다.\n")

    if a.prot_sweep:
        return prot_sweep(a, addrs)

    runs = [one_session(a, addrs) for _ in range(a.sessions)]
    for _ in range(0):
        time.sleep(0)
    valid = [r for r in runs if r['valid']]

    print(f"\nv={VERSION.split()[0]}  valid={len(valid)}/{a.sessions}")
    if not valid:
        print("VERDICT: NO_VALID_SESSION")
        return EXIT_INSUFFICIENT
    print(f"{a.ap_name} IDR={valid[-1]['idr']} CSW={valid[-1].get('csw')}")

    nlive = 0
    for addr, label in addrs:
        vs = {r['vals'].get(addr) for r in valid}
        one = vs.pop() if len(vs) == 1 else None
        ok = live(one)
        nlive += bool(ok)
        print(f"0x{addr:08X} = {hx(one) if len(vs) == 0 else '불안정'}"
              + ("   ★ live" if ok else "")
              + (f"   {label}" if label and not a.brief else ""))

    print(f"live={nlive}/{len(addrs)}")
    print("VERDICT:", "AXI_READABLE" if nlive else "AXI_ALL_DEAD")
    if nlive:
        print("  ★★★ **AXI-AP 로 실제 값이 읽힌다.**")
        print("     ⇒ 'AP 너머는 전부 죽어 있다' 는 결론이 틀렸다 — APB 만 죽어 있었다.")
        print("     ⇒ 리셋 컨트롤러 값으로 코어 리셋 상태를 판정할 수 있다.")
        print("     ⚠ 쓰기는 별도 판단이 필요하다. 동작 중인 SSD 를 리셋할 수 있다.")
    else:
        print("  AXI 로도 전부 죽은 값 → APB 와 같은 상태. 가설을 다시 봐야 한다.")
    return EXIT_OK if nlive else EXIT_INSUFFICIENT


if __name__ == '__main__':
    sys.exit(main())
