#!/usr/bin/env python3
"""ADIv6 DP/AP 원시 접근 primitive — J-Link(pylink) coresight_read/write 기반.

CoreSight/ADIv6 **표준** 레지스터 인덱스·오프셋만 담는다(특정 SoC 주소 없음).
sjtag_unlock 등이 MEM-AP 로 메모리를 읽고 쓰는 데 쓰는 최소 계층.
(원래 probe_ap_raw.py 의 진단 로직에서 분리 — 주소는 sjtag_addrs.json 으로 외부화.)
"""

# DP 레지스터 인덱스
DP_ABORT, DP_CTRL_STAT, DP_SELECT, DP_RDBUF = 0, 1, 2, 3
# AP 레지스터 인덱스 = 16바이트 창 안의 워드 번호 (A[3:2])
AP_IDX_CSW, AP_IDX_TAR, AP_IDX_DRW = 0, 1, 3

# ADIv6 MEM-AP 레지스터의 AP 공간 내 오프셋
OFF_CSW, OFF_TAR, OFF_DRW = 0xD00, 0xD04, 0xD0C
OFF_BASE, OFF_IDR = 0xDF8, 0xDFC
OFF_CFG = 0xDF4

# DLL 오류 센티널로 관측되는 값(API 계약 아님 — '의심' 으로만 취급).
SUSPECT = 0x80000000


def hx(v):
    return "실패" if v is None else f"0x{v & 0xFFFFFFFF:08X}"


def csw_usable(v):
    """CSW: 값 자체로 정오를 못 가린다. **쓰기 전에 안전한지**만 본다.
    읽기 실패(None)·의심값(SUSPECT)일 때만 가공·기입을 막는다."""
    return v is not None and v != SUSPECT


class Dap:
    """DP/AP 원시 접근. 실패는 None 으로 돌린다(예외로 흐름을 끊지 않는다)."""

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
        SELECT 변경 직후 첫 트랜잭션은 priming 으로 버린다(파이프라인 컨텍스트 갱신)."""
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
        bits = [nm for m, nm in ((1 << 7, 'WDATAERR'), (1 << 5, 'STICKYERR'),
                                 (1 << 4, 'STICKYCMP'), (1 << 1, 'STICKYORUN'))
                if v & m]
        pw = ('DBGACK' if v & (1 << 29) else 'DBG없음')
        return f"CTRL/STAT={hx(v)} {pw} " + (" ".join(bits) if bits else "에러비트 없음")

    def mem_read32(self, ap_base, addr):
        """MEM-AP 로 32비트 읽기. 실패 이유는 self.last 에 남긴다.
        TAR 되읽기로 주소 디코드 폭(잘림)까지 진단한다."""
        self.last = {}
        csw = self.ap_read(ap_base, OFF_CSW)
        self.last['csw'] = csw
        if not csw_usable(csw):
            self.last['why'] = f"CSW 읽기 실패/의심값 {hx(csw)} — 쓰지 않고 중단"
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
            self.last['why'] = f"TAR 불일치 쓴값={hx(addr)} 읽은값={hx(back)}"
            if back is not None and back != SUSPECT:
                lost = (addr ^ back) & 0xFFFFFFFF
                self.last['why'] += f"  (달라진 비트 {hx(lost)})"
                if back == (addr & back):
                    width = max((back | 1).bit_length(), 1)
                    self.last['why'] += f" → 주소가 잘렸다. 유효폭 약 {width}비트"
            return None
        return self.ap_read(ap_base, OFF_DRW)
