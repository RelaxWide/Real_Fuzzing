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

from sfe76_link import (require_api, Link, LinkError, AP_MAP, add_common_args,
                        EXIT_OK, EXIT_INSUFFICIENT)

VERSION = "2026-08-10.1"

# DP 레지스터 인덱스
DP_ABORT, DP_CTRL_STAT, DP_SELECT, DP_RDBUF = 0, 1, 2, 3
# AP 레지스터 인덱스 = 16바이트 창 안의 워드 번호 (A[3:2])
AP_IDX_CSW, AP_IDX_TAR, AP_IDX_DRW = 0, 1, 3

# ADIv6 MEM-AP 레지스터의 AP 공간 내 오프셋
OFF_CSW, OFF_TAR, OFF_DRW = 0xD00, 0xD04, 0xD0C
OFF_BASE, OFF_IDR = 0xDF8, 0xDFC
OFF_CFG = 0xDF4

# RISC-V DMI 레지스터 (aperture = base + (addr << 2) 로 추정)
DM_REGS = [(0x10, 'dmcontrol'), (0x11, 'dmstatus'), (0x12, 'hartinfo'),
           (0x16, 'abstractcs'), (0x1D, 'nextdm'), (0x38, 'sbcs')]

DM_VERSION = {0: '없음', 1: '0.11', 2: '0.13', 3: '1.0'}

AP_CLASS = {0x0: '없음/JTAG-AP', 0x8: 'MEM-AP'}
AP_TYPE = {0x1: 'AHB3', 0x2: 'APB2/APB3', 0x4: 'AXI3/AXI4',
           0x5: 'AHB5', 0x6: 'APB4/APB5', 0x7: 'AXI5', 0x8: 'AHB5-hprot'}

# T32 가 선언한 AP 타입 → IDR.TYPE 으로 나와야 하는 값
DECLARED_TYPE = {'APB-AP': (0x2, 0x6), 'AHB-AP': (0x1, 0x5, 0x8), 'AXI-AP': (0x4, 0x7)}


def hx(v):
    return "실패" if v is None else f"0x{v & 0xFFFFFFFF:08X}"


class Dap:
    """DP/AP 원시 접근. 실패는 None 으로 돌린다 (예외로 흐름을 끊지 않는다)."""

    def __init__(self, jl, verbose=True):
        self.jl = jl
        self.verbose = verbose
        self._select = None
        self.last = {}

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
        """DP SELECT 에 AP 레지스터 주소의 상위 비트를 넣는다 (ADIv6).

        ★ SELECT 를 바꾼 직후의 **첫 트랜잭션은 버린다**(priming).
          DAP 의 AP 접근은 파이프라인이라 컨텍스트가 바뀐 직후 한 박자가
          비어 있을 수 있다. 실측에서 **매번 첫 번째로 시험한 AP 만 실패**했다
          (APBAP1 0/3, 0/3 인데 나머지는 2~3/3) — AP 의 성질이 아니라
          '첫 트랜잭션' 의 성질이다. 이 프로젝트에서 세 번째로 만난 순서 함정.
        """
        val = addr & 0xFFFFFFF0
        if self._select != val:
            if not self.dp_write(DP_SELECT, val):
                return False
            self._select = val
            try:                       # priming — 반환값은 쓰지 않는다
                self.jl.coresight_read(AP_IDX_CSW, ap=True)
            except Exception:
                pass
        return True

    def ap_read(self, ap_base, off, retry=1):
        for _ in range(retry + 1):
            if not self.select(ap_base + off):
                return None
            try:
                v = self.jl.coresight_read((off >> 2) & 0x3, ap=True)
                if v is not None and v >= 0:
                    return v & 0xFFFFFFFF
            except Exception:
                pass
            self.clear_sticky()
        return None

    def ap_write(self, ap_base, off, val, retry=1):
        for _ in range(retry + 1):
            if not self.select(ap_base + off):
                return False
            try:
                self.jl.coresight_write((off >> 2) & 0x3, val & 0xFFFFFFFF, ap=True)
                return True
            except Exception:
                pass
            self.clear_sticky()
        return False

    def clear_sticky(self):
        self.dp_write(DP_ABORT, 0x0000001E)
        self._select = None          # ABORT 후 SELECT 는 다시 쓴다

    def sticky(self):
        """CTRL/STAT 의 에러 비트를 문자열로. 실패 원인을 가른다."""
        v = self.dp_read(DP_CTRL_STAT)
        if v is None:
            return "CTRL/STAT 읽기 실패"
        bits = [nm for m, nm in ((1 << 7, 'STICKYERR'), (1 << 5, 'STICKYORUN'),
                                 (1 << 4, 'TRNMODE'), (1 << 1, 'STICKYCMP'))
                if v & m]
        pw = ('DBGACK' if v & (1 << 29) else 'DBG없음')
        return f"CTRL/STAT={hx(v)} {pw} " + (" ".join(bits) if bits else "에러비트 없음")

    # ── MEM-AP 를 통한 32비트 메모리 읽기 ────────────────────────────
    def mem_read32(self, ap_base, addr):
        """실패하면 **왜 실패했는지**를 self.last 에 남긴다."""
        self.last = {}
        csw = self.ap_read(ap_base, OFF_CSW)
        self.last['csw'] = csw
        # ★ 버그였다: CSW 가 에러 센티널(0x80000000)이어도 그대로 가공해
        #   CSW 에 써 넣고 있었다 → AP 를 우리 손으로 망가뜨린다.
        if is_error(csw):
            self.last['why'] = f"CSW 읽기 실패/에러값 {hx(csw)} — 쓰지 않고 중단"
            return None
        # Size=2(word), AddrInc=off. 나머지 비트(Prot/SPIDEN 등)는 보존한다.
        if not self.ap_write(ap_base, OFF_CSW, (csw & ~0x37) | 0x02):
            self.last['why'] = "CSW 쓰기 실패"
            return None
        if not self.ap_write(ap_base, OFF_TAR, addr):
            self.last['why'] = "TAR 쓰기 실패"
            return None
        back = self.ap_read(ap_base, OFF_TAR)
        self.last['tar_back'] = back
        if back is None or back != (addr & 0xFFFFFFFF):
            # ★ 되읽기 값이 정보다. 상위 비트가 잘려 있으면 그 AP 의
            #   주소 디코드 폭이 좁다는 뜻 — 그 주소는 그 AP 로 못 간다.
            self.last['why'] = f"TAR 불일치 쓴값={hx(addr)} 읽은값={hx(back)}"
            if back is not None and not is_error(back):
                lost = (addr ^ back) & 0xFFFFFFFF
                self.last['why'] += f"  (달라진 비트 {hx(lost)})"
                if back == (addr & back):
                    width = max((back | 1).bit_length(), 1)
                    self.last['why'] += f" → 주소가 잘렸다. 유효폭 약 {width}비트"
            return None
        return self.ap_read(ap_base, OFF_DRW)


def walk_rom(dap, name, base, max_entries=64):
    """AP 의 **BASE(0xDF8) → ROM 테이블**을 걸어 실제 주소 맵을 얻는다.

    ★ 왜 이게 중요한가. 지금까지 DM 주소 `0x81480000` 은 **T32 스크립트 해석에서
      온 추정**이었고, 그걸 전제로 읽다 실패했다. ROM 테이블은 **칩이 스스로
      알려주는 목록**이다 — 추정이 아니라 실측이다. 여기서 나온 주소로
      DM 과 트레이스 블록(0xFD000000/0xFD180000)의 실재를 대조할 수 있다.
    """
    print(f"\n  ── {name} ROM 테이블")
    b = dap.ap_read(base, OFF_BASE)
    if b is None:
        print(f"     BASE 읽기 실패   ({dap.sticky()})")
        return []
    print(f"     BASE = {hx(b)}", end="")
    if b == 0xFFFFFFFF or not (b & 1):
        print("  → ROM 테이블 없음 (legacy 또는 미구현)")
        return []
    rom = b & 0xFFFFF000
    print(f"  → ROM @0x{rom:08X}")

    found = []
    for i in range(max_entries):
        e = dap.mem_read32(base, rom + i * 4)
        if e is None:
            print(f"     엔트리 {i} 읽기 실패 — 중단   ({dap.sticky()})")
            break
        if e == 0:                       # 목록의 끝
            break
        if not (e & 1):                  # present=0 → 빈 슬롯
            continue
        off = e & 0xFFFFF000
        if off & 0x80000000:             # 음수 오프셋
            off -= 1 << 32
        comp = (rom + off) & 0xFFFFFFFF
        cid1 = dap.mem_read32(base, comp + 0xFF4)
        klass = ((cid1 >> 4) & 0xF) if cid1 is not None else None
        kind = {0x1: 'ROM 테이블', 0x9: 'CoreSight 컴포넌트',
                0xE: '비-CoreSight'}.get(klass, f'class={klass}')
        pid0 = dap.mem_read32(base, comp + 0xFE0)
        pid1 = dap.mem_read32(base, comp + 0xFE4)
        part = (((pid1 & 0xF) << 8) | (pid0 & 0xFF)) if None not in (pid0, pid1) else None
        print(f"     [{i:2d}] 0x{comp:08X}  {kind}"
              + (f"  part=0x{part:03X}" if part is not None else ""))
        found.append((comp, klass, part))
    if not found:
        print("     엔트리 없음")
    return found


def decode_csw(v):
    """★ MEM-AP CSW — **디버그 접근 제어(secure JTAG)를 가르는 레지스터.**

    SiFive Insight 의 "Multilayered Debug Access Control" 은 fuse / 32비트
    패스워드 / PKI 로 TAP 을 잠근다. 그게 걸려 있으면 **AP 는 열거되지만
    버스 포트가 죽는다** — 정확히 우리 증상이다(IDR 은 읽히고 메모리는 전부 실패).

    핵심 비트:
      bit6  DeviceEn   0이면 **이 AP 의 버스 포트가 하드웨어로 꺼져 있다.**
                       소프트웨어로 되돌릴 방법이 없다. → 잠금 또는 버스 미전원
      bit23 SDeviceEn  (SPIDEN) 보안 접근 허용 여부
      bit31 DbgSwEnable
      bit7  TrInProg   전송 진행 중 (1로 멈춰 있으면 앞 트랜잭션이 안 끝난 것)
    """
    if v is None:
        return "읽기 실패"
    if v == 0x80000000:
        return f"{hx(v)}  ← API 에러 센티널"
    dev = bool(v & (1 << 6))
    parts = [
        f"DeviceEn={int(dev)}" + ("  ★★ 0 = 버스 포트 꺼짐" if not dev else ""),
        f"SDeviceEn/SPIDEN={int(bool(v & (1 << 23)))}",
        f"DbgSwEnable={int(bool(v & (1 << 31)))}",
        f"TrInProg={int(bool(v & (1 << 7)))}",
        f"Prot=0x{(v >> 24) & 0x7F:02X}",
        f"AddrInc={(v >> 4) & 3}", f"Size={v & 7}",
    ]
    return f"{hx(v)}  " + "  ".join(parts)


def decode_cfg(v):
    if v is None or v == 0x80000000:
        return "읽기 실패"
    return (f"{hx(v)}  BE={v & 1}  LargeAddr(64bit TAR)={(v >> 1) & 1}  "
            f"LargeData={(v >> 2) & 1}")


def is_error(v):
    """J-Link API 에러 센티널. 값이 아니다.

    `0x80000000` 은 DLL 이 돌려주는 에러 코드다(브링업 초기부터 반복 관측).
    간헐적으로 뒤쪽 AP 에 붙는다 — **AP 가 없다는 뜻이 아니다.**
    """
    return v is None or v in (0x80000000, 0xFFFFFFFF, 0)


def decode_idr(v, declared=None):
    """IDR 디코드 + **선언 타입과 교차검증.**

    IDR 의 TYPE 은 우리가 넣은 적 없는 값이다. 그게 T32 선언과 맞으면
    그 AP 는 실재하고 주소도 맞다 — 우연이나 stale 로는 안 맞는다.
    """
    if v is None:
        return "읽기 실패"
    if v == 0x80000000:
        return f"{hx(v)}  ← API 에러 센티널 (값 아님. 재시도로 사라짐)"
    if v in (0, 0xFFFFFFFF):
        return f"{hx(v)}  ← **AP 없음**"
    cls, typ = (v >> 13) & 0xF, v & 0xF
    rev, desg = (v >> 28) & 0xF, (v >> 17) & 0x7FF
    who = 'SiFive' if desg == 0x489 else '?'
    s = (f"{hx(v)}  ✅ class={cls:#x}({AP_CLASS.get(cls, '?')})  "
         f"type={typ:#x}({AP_TYPE.get(typ, '?')})  DESIGNER={desg:#05x}({who})  rev={rev}")
    if declared:
        want = DECLARED_TYPE.get(declared)
        if want is None:
            pass
        elif typ in want:
            s += f"   ★ 선언({declared})과 일치"
        else:
            s += f"   ⚠ 선언은 {declared} 인데 type={typ:#x}"
    return s


def enumerate_aps(dap):
    print(f"\n{'=' * 66}\n [1] AP 실재 확인 — IDR 읽기\n{'=' * 66}")
    print("  선언한 AP 6개 중 실재가 확인된 건 지금까지 하나도 없었다.")
    real = []
    dev_en = {}
    for name, base, typ in AP_MAP:
        dap.clear_sticky()
        idr = dap.ap_read(base, OFF_IDR, retry=2)
        print(f"\n  {name:7s} @ 0x{base:05X}  (선언 타입 {typ})")
        print(f"      IDR = {decode_idr(idr, typ)}")
        csw = dap.ap_read(base, OFF_CSW, retry=2)
        print(f"      CSW = {decode_csw(csw)}")
        print(f"      CFG = {decode_cfg(dap.ap_read(base, OFF_CFG, retry=2))}")
        if csw is not None and not is_error(csw) and not (csw & (1 << 6)):
            print("            ⚠ DeviceEn=0 → 이 AP 로는 메모리 접근이 **원천 불가**")
        if not is_error(idr):
            real.append((name, base, idr))
        dev_en[name] = (None if is_error(csw) else bool(csw & (1 << 6)))
    return real, dev_en


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
        note = "" if v is not None else f"   ({dap.sticky()})"
        print(f"     {nm:11s} @0x{dm_base + (addr << shift):08X} = {hx(v)}{note}")
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


# T32 ViewNexusTracedump.cmm 실물에서 온 트레이스 블록 주소
TRACE_ADDRS = [
    (0xFD000000, 'NEXUS.0 TE  (hcore/hart0)'),
    (0xFD001000, 'NEXUS.1 TE  (CMCore/hart1)'),
    (0xFD002000, 'NEXUS.2 TE  (FCore/hart2)'),
    (0xFD003000, 'NEXUS.3 TE  (QCore/hart3)'),
    (0xFD180000, 'RVFUNNEL1 / RVSRAMTRACEsink1'),
    (0xFD18001C, '  +0x1C write ptr (bit0=wrap)'),
    (0xFD180020, '  +0x20 read ptr'),
]


def read_addrs(dap, aps, addrs):
    """임의 절대주소를 **모든 AP 로** 읽어 어느 AP 가 그 주소를 디코드하는지 본다.

    ★ 왜 결정적인가. T32 는 트레이스 블록에 `SB:` (System Bus = RISC-V SBA)로
      접근한다. SBA 는 **DM 의 일부**라 DM 이 필요하다 — 우리가 막힌 지점이다.
      그런데 AXI-AP 는 시스템 메모리로 가는 **독립 경로**다. 같은 버스 주소를
      AXI-AP 로 읽을 수 있으면 **DM 없이 트레이스 파이프라인을 세울 수 있다.**
      그러면 지금 블로커를 통째로 우회한다.
    """
    print(f"\n{'=' * 66}\n [T] 트레이스 블록 — 모든 AP 로 시도 (DM 우회 가능성)\n{'=' * 66}")
    print("  T32 는 SB:(=SBA, DM 필요)로 접근한다. AXI/AHB-AP 는 독립 경로다.")
    print("  하나라도 읽히면 **DM 블로커를 우회**할 수 있다.\n")
    hits = {}
    for addr, label in addrs:
        print(f"  0x{addr:08X}  {label}")
        for n, b in aps:
            dap.clear_sticky()
            v = dap.mem_read32(b, addr)
            ok = v is not None and v not in (0xFFFFFFFF,)
            if v is None:
                why = dap.last.get('why', '?')
                print(f"      {n:7s} = 실패   {why}")
                print(f"                {dap.sticky()}")
            else:
                print(f"      {n:7s} = {hx(v)}" + ("   ★ 읽힘" if ok else ""))
            if ok:
                hits.setdefault(n, []).append((addr, v))
    return hits


def one_session(a):
    lk = Link(core_base=a.core_base, hart=a.hart, device=a.device,
              serial=a.serial, ap_count=getattr(a, 'ap_count', None))
    out = {'valid': False, 'real_aps': [], 'dm': {}, 'rom': {},
           'addr_hits': {}, 'device_en': {}}
    try:
        with lk:
            # ★ connect 성공을 요구하지 않는다. AP 접근에 필요한 건 DAP 전원뿐.
            #   'Could not find supported CPU' 는 **CPU 계층** 실패이지
            #   DAP 계층 실패가 아니다 — 그걸로 측정을 건너뛰면 안 된다.
            try:
                conn_ok, _ = lk.open_dap(tries=a.tries)
            except LinkError as e:
                print(f"  세션 무효(전원 미확보): {e}")
                return out
            out['valid'] = True
            out['connect_ok'] = conn_ok
            dap = Dap(lk.jl)

            real, dev_en = enumerate_aps(dap)
            out['device_en'] = dev_en
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

            if usable and not a.no_rom:
                print(f"\n{'=' * 66}\n [3] ROM 테이블 — 칩이 알려주는 진짜 주소 맵"
                      f"\n{'=' * 66}")
                print("  DM 주소 0x81480000 은 T32 스크립트 해석에서 온 **추정**이다.")
                print("  ROM 테이블은 추정이 아니라 칩이 스스로 알려주는 목록이다.")
                for n, b in usable:
                    out['rom'][n] = walk_rom(dap, n, b)

            if a.addrs and usable:
                lst = (TRACE_ADDRS if a.addrs.strip() == 'trace'
                       else [(int(x, 0), '') for x in a.addrs.split(',') if x.strip()])
                out['addr_hits'] = read_addrs(dap, usable, lst)

            if a.dm and usable:
                print(f"\n{'=' * 66}\n [4] DM 읽기 (추정 주소 0x{a.dm:X})\n{'=' * 66}")
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
    require_api(3, "probe_ap_raw.py")
    ap = add_common_args(argparse.ArgumentParser())
    ap.add_argument('--dm', type=lambda x: int(x, 0), default=None,
                    help='DM base (예: 0x81480000). 주면 AP 를 통해 DM 을 읽는다')
    ap.add_argument('--shift', type=int, default=2, help='DMI stride (기본 2 = <<2)')
    ap.add_argument('--sessions', type=int, default=3,
                    help='독립 세션 반복. 전 세션 일치값만 인정한다')
    ap.add_argument('--no-rom', action='store_true', help='ROM 테이블 워크 생략')
    ap.add_argument('--addrs', default=None,
                    help='임의 절대주소를 **모든 AP 로** 읽는다 (콤마). '
                         "예: 'trace' 프리셋 또는 0xFD000000,0xFD180000")
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
    solid, idr_seen = [], {}
    for n in names:
        cnt = sum(1 for r in valid if any(x[0] == n for x in r['real_aps']))
        use = sum(1 for r in valid if any(x[0] == n for x in r.get('usable_aps', [])))
        vs = {x[2] for r in valid for x in r['real_aps'] if x[0] == n}
        idr_seen[n] = vs
        mark = "✅" if cnt == len(valid) else ("⚠" if cnt else "  ")
        shown = ", ".join(hx(v) for v in sorted(vs)) if vs else "-"
        print(f"    {mark} {n:7s} IDR 실재 {cnt}/{len(valid)}  "
              f"TAR 경로 {use}/{len(valid)}   IDR={shown}")
        if cnt == len(valid):
            solid.append(n)

    # ★ 6개 AP 의 IDR 이 전부 같으면 SELECT 가 AP 를 바꾸지 못하고 있는 것이다
    allv = {v for vs in idr_seen.values() for v in vs}
    if len(solid) == len(names) and len(allv) == 1:
        print(f"\n  ⚠⚠ **6개 AP 의 IDR 이 전부 동일**({hx(next(iter(allv)))}).")
        print("     실재 6개가 아니라 **SELECT 가 AP 를 전환하지 못하는 것**일 가능성이 크다.")
        print("     → 같은 AP(또는 stale 값)를 여섯 번 읽고 있다. 주소 해석을 의심할 것.")
    elif len(allv) > 1:
        print(f"\n  ✅ IDR 값이 서로 다르다({len(allv)}종) → **SELECT 가 실제로 AP 를 전환한다.**")

    th = {}
    for r in valid:
        for n, lst in (r.get('addr_hits') or {}).items():
            th.setdefault(n, set()).update(a_ for a_, _v in lst)
    if th:
        print(f"\n{'=' * 66}\n ★★ 트레이스 블록에 닿은 AP\n{'=' * 66}")
        for n, addrs in th.items():
            print(f"    {n}: " + ", ".join(f"0x{x:08X}" for x in sorted(addrs)))
        print("\n  → **DM 없이 트레이스 파이프라인을 세울 수 있다.** 블로커 우회.")
        print("     이 AP 를 RISCV_Set*BaseAddr 의 APIndex 로 쓰거나,")
        print("     raw AP 접근으로 ETB 드레인을 직접 구현한다.")

    de = {}
    for r in valid:
        for n, v in (r.get('device_en') or {}).items():
            de.setdefault(n, []).append(v)
    if de:
        print(f"\n{'=' * 66}\n ★ CSW.DeviceEn — 디버그 접근 제어(secure JTAG) 판정\n{'=' * 66}")
        for n, vs in de.items():
            print(f"    {n:7s} DeviceEn = {vs}")
        flat = [v for vs in de.values() for v in vs if v is not None]
        if flat and not any(flat):
            print("\n  ★★ **전 AP DeviceEn=0.** 버스 포트가 하드웨어로 꺼져 있다.")
            print("     소프트웨어로 되돌릴 수 없다. 원인은 둘 중 하나다:")
            print("       (a) SiFive Insight 의 디버그 접근 제어(퓨즈/패스워드/PKI) 잠금")
            print("       (b) 해당 버스 도메인에 전원/클럭이 안 들어와 있음")
            print("     → 우리 코드로 더 할 수 있는 게 없다. ASK.md 로 넘어간다.")
        elif flat and all(flat):
            print("\n  ✅ DeviceEn=1 — AP 버스 포트는 **열려 있다.**")
            print("     잠금이 아니다. 실패 원인은 주소/코드 쪽이다.")
        elif flat:
            print("\n  ⚠ AP 마다 다르다 → DeviceEn=1 인 AP 로만 진행할 것.")

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
