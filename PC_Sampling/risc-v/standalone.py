#!/usr/bin/env python3
"""SF-E76 — **단일 파일 진단기.** 다른 파일을 하나도 import 하지 않는다.

════════════════════════════════════════════════════════════════════
왜 단일 파일인가
════════════════════════════════════════════════════════════════════
지금까지 다섯 번, "인자를 못 알아듣는다 / 함수가 없다" 가 전부
**파일 버전이 서로 안 맞아서** 생겼다. `sfe76_link.py` 만 옛것이어도
전 도구가 깨진다. 받아오는 방식이 무엇이든 그 위험이 남는다.

이 파일은 **`pylink` 외에 아무것도 필요 없다.** 복사 한 번이면 끝이고
버전 스큐가 원리적으로 생기지 않는다.

════════════════════════════════════════════════════════════════════
무엇을 재나 (전부 읽기 전용)
════════════════════════════════════════════════════════════════════
  1. J-Link 정보 / cJTAG / DP  — DPIDR, 하드웨어 버전
  2. DAP 전원                   — CTRL/STAT, ACK 비트
  3. AP 6개                     — IDR / CSW / CFG / BASE
  4. DM 후보 읽기               — ROM 엔트리와 그것이 가리키는 곳
  5. DP 오류 비트               — ★ STICKYERR 는 **bit5** (bit7 아님)

★ 쓰기는 CSW/TAR/DP-SELECT/ABORT 뿐이다. **DRW 에 쓰지 않는다** =
  타깃 메모리에 아무것도 쓰지 않는다.

════════════════════════════════════════════════════════════════════
사용
════════════════════════════════════════════════════════════════════
    sudo python3 standalone.py                # 전체
    sudo python3 standalone.py --sessions 3   # 재현성 확인
    sudo python3 standalone.py --json out.json
"""

import argparse
import json
import sys
import time

try:
    import pylink
except ImportError:
    sys.exit("pylink 없음 →  pip3 install pylink-square")

VERSION = "standalone 2026-08-11.16  --link 물리계층 (속도 스윕)"

# ★ DPIDR 로 FFFFFFFF / 6BA0009D / 80000000 이 **실행마다 섞여** 나온다.
#   설정이 원인이면 조합마다 일관되게 같은 값이 나와야 한다.
#   값이 뒤섞이는 건 **링크 계층 불안정**의 신호다 → 소프트웨어 조합
#   스윕으로는 못 고친다. 속도부터 낮춰본다(지금껏 10MHz 만 썼다).

# ★ NOT_FOUND 후 확인: standalone 이 원래 경로와 **명령이 다르다.**
#   0x11013913 을 읽던 sfe76_link 는 AddAP 뒤에 이 셋을 더 보냈다:
#     CORESIGHT_SetIndexAPBAPToUse / CORESIGHT_SetCoreBaseAddr / RISCV_SetHartSel
#   standalone 은 셋 다 생략했다. DP 초기화 경로가 달라질 수 있다.
#   device 도 그때는 'RISC-V', 지금은 'E76' 이다.
#   ⇒ recover 를 명령셋 × device 까지 넓힌다.
#
# ⚠ 그리고 **타깃 상태 자체가 변했을 수 있다.** 긴 세션 동안 CSW 를 여러 번
#   쓰고 connect 를 수없이 시도했다. **전원 사이클 후 재시도가 먼저다.**

# ★ 유효 DPIDR(0x11013913)이 나왔던 브링업 초기와 지금의 차이:
#     TAP 선언 스크립트   그때 없음        → 지금 항상 적용
#     SetcJTAGInitMode   그때 0 (LONG)    → 지금 1 (SHORT)
#     device             그때 RISC-V      → 지금 E76
#   앞의 둘은 "개선" 이라고 생각하고 넣은 것인데 **유효 DPIDR 을 잃은 시점과
#   겹친다.** 스크립트 유무 × 모드 0/1 을 훑어 그 조건을 되찾는다.

# ⚠ discovery 가 두 가지를 안 지켰다 (실측에서 드러남):
#   ① 세션이 무효(DPIDR VERSION=0)인데도 값을 찍고 파생값까지 계산했다
#   ② 네 뱅크가 **전부 같은 값**이면 DPBANKSEL 이 안 먹은 것인데 그대로 해석했다
#      → 서로 다른 레지스터가 같은 값일 리 없다. 읽기가 일어나지 않은 것이다.
#      (J-Link 이 DP 읽기 전에 자기 SELECT 로 덮어쓰는 것으로 보인다)
#   두 경우 모두 **파생값을 계산하지 않는다.**

# ★★ 게이트가 너무 약했다 (feedback). bit0 홀수만 보다가 VERSION=0 인
#   0x6BA0009D 를 유효 세션으로 통과시켰다.
#   ADIv6 IHI0074 §B2.2.6: DPIDR.VERSION = bits[15:12], 유효값 1/2/3.
#     0x6BA0009D → VERSION 0 (reserved) → **무효**
#     0x11013913 → VERSION 3 (DPv3), DESIGNER 0x489 SiFive → 유효
#   그리고 coresight_read(0, ap=False) 는 **DP 레지스터**를 읽는다.
#   TAP IDCODE 가 아니므로 그렇게 재해석하면 안 된다.
EXPECT_DPIDR = 0x11013913          # 이 타깃에서 기대하는 값
EXPECT_AP_IDR = {0x10000: 0x09130006, 0x20000: 0x09130006, 0x30000: 0x09130004,
                 0x40000: 0x09130001, 0x50000: 0x09130006, 0x60000: 0x09130006}


def classify_dpidr(v):
    """읽힌 값의 정체를 분류한다. 전부 '못 읽음' 이지만 이유가 다르다."""
    if v is None:
        return "읽기 실패"
    if v == EXPECT_DPIDR:
        return "★ 유효 (DPv3/SiFive)"
    if v == 0xFFFFFFFF:
        return "라인 계속 1 — 응답 없음"
    if v == 0x00000001:
        return "스캔 실패 (0만 읽고 RAO 만 1)"
    if v == 0x80000000:
        return "J-Link API 에러 센티널 (데이터 아님)"
    ver = (v >> 12) & 0xF
    if ver in (1, 2, 3):
        return f"DPv{ver} 형식이나 기대값과 다름"
    return f"VERSION={ver} (reserved) — DPIDR 아님"


def dpidr_valid(v, strict=True):
    """ADIv6 DPIDR 유효성. strict 면 이 타깃의 기대값까지 요구한다."""
    if v is None or (v & 1) != 1:
        return False
    if ((v >> 12) & 0xF) not in (1, 2, 3):       # VERSION
        return False
    return (v == EXPECT_DPIDR) if strict else True

# ★ T32 가 코어 enable 판정에 **실제로 읽는** AXI 주소 (CMM 실물, feedback):
#     0xC81024  FCore  enable bit0                (AttachPrepare.cmm)
#     0xC81028  NCore0 bit0 / NCore1 bit16        (AttachPrepare.cmm)
#     0xC8102C  CMCore enable bit0                (AttachPrepare.cmm)
#     0xC81040  MPCore clock/reset bitmap         (AllCoreAnalysis.cmm)
#     0xC81044  NCore  clock/reset bitmap         (AllCoreAnalysis.cmm)
#   이전 시험은 0xC81020 과 0xC81030 은 읽으면서 **그 사이 0x24/28/2C 를
#   건너뛰었다.** ⇒ "AXI 전부 0" 결과는 결정적이지 않았다.
#   그리고 0x40/44 는 T32 가 DATA.LONG 으로 **읽는다** — write-only 가 아니다.
AXI_T32_ADDRS = [(0xC81024, 'FCore  en bit0'), (0xC81028, 'NCore0 b0/NCore1 b16'),
                 (0xC8102C, 'CMCore en bit0'), (0xC81040, 'MPCore clk/rst'),
                 (0xC81044, 'NCore  clk/rst')]

# ★★ 인터커넥트의 **default slave 라인**을 식별한다.
#   실측 14/14 로 확인: 응답이 주소가 아니라 **16바이트 정렬**만 따라간다.
#       16B 정렬 → 0x00000001,  아니면 → 0xEAFFFFFE
#   이는 버스가 128비트 한 줄을 고정값으로 돌려주고 우리가 lane 을 집는 것이다:
#       00000001 EAFFFFFE EAFFFFFE EAFFFFFE
#   ⇒ 그런 값은 **데이터가 아니라 미매핑 응답**이다. 이제 자동으로 표시한다.
DEFAULT_LINE = [0x00000001, 0xEAFFFFFE, 0xEAFFFFFE, 0xEAFFFFFE]


def is_default_line(addr, val):
    """그 주소에서 default slave 라인이 나온 것인가."""
    if val is None:
        return False
    return val == DEFAULT_LINE[(addr % 16) // 4]

# ⚠ wrap 테스트의 허점을 막는다.
#   그 AP 가 **모든 주소에서 같은 값**을 주면 2^N 도 당연히 0 과 같다.
#   그러면 wrap 이 아닌데도 width 가 잡힌다 — 실제로 AXIAP1(전부 0),
#   AHBAP1(전부 0xEAFFFFFC), APBAP4(전부 0xEAFFFFFE)가 그렇게 나왔다.
#   ⇒ `ref0 == ref4` 면 **판정불가**로 표시한다. 기준점이 구별되지 않으면
#     wrap 을 판정할 수 없다.

# ★★ APBAP3 에서 aliasing 을 확인했다:
#     오프셋 0x00000000 = 0x00040700   ==   오프셋 0x81592000 = 0x00040700
#     오프셋 0x00000004 = 0x00000010   ==   오프셋 0x81592004 = 0x00000010
#   상위 비트가 무시되고 주소가 접힌다.
#
#   ⇒ **AP 마다 디코드 폭을 먼저 재야 한다.** 그걸 모르고 큰 주소를 찍으면
#     전부 첫 페이지로 접혀서 같은 곳을 읽고 "없다" 고 결론내게 된다.
#     지금까지의 주소 탐색 상당수가 이 함정 위에 있었을 수 있다.

# ★ APBAP3 앞 4워드에 내용이 있다 (유효 세션, DPIDR=0x6BA0009D):
#     0x00=0x00040700  0x04=0x00000010  0x08=0x81592158  0x0C=0x000002C3
#     0x10~0x1C = 0
#   0x08 은 0x81xxxxxx 대역 — DM base(0x81480000/0x81481000)와 같은 계열이다.
#   여기가 **DMI aperture** 라면(stride 4) dmstatus 는 바이트 0x44 다.
#   우리는 0x0~0x1C 만 봤고 **그 자리를 아직 안 봤다.**
#   → 'dmi' 프리셋으로 스펙상 의미 있는 오프셋만 골라 읽는다.

# ★ 결과를 **손으로 옮겨 적는** 환경이다. 그래서 기본 출력을 3줄로 줄인다.
#   전체가 필요하면 --full, 파일이 필요하면 --json.
#   지금 판단에 실제로 필요한 것은 셋뿐이다:
#     ① STICKYERR 가 뜨는가 (비트 수정 후 재측정의 핵심)
#     ② 전송이 어느 단계에서 끝나는가
#     ③ AP 별로 읽은 값이 **몇 종류**인가 (1종 = 변화 없음)

TIF_CJTAG, SPEED_KHZ, CJTAG_MODE, DEVICE = 7, 10000, 1, 'E76'
# ★ **선언값과 읽은 값을 구분한다.** 실측:
#     선언 0x5BA00477 (알려진 ARM DAP) → DPIDR 읽기 = 0x6BA0009D   ← 유효
#     선언 0x6BA0009D (읽은 값 그대로) → DPIDR 읽기 = 0xFFFFFFFF   ← 무효
#   J-Link 은 **선언된 ID 로 어떤 프로토콜로 말할지**를 정한다. 0x5BA00477 은
#   알려진 CoreSight DAP 이라 ARM DAP 경로를 타고, 0x6BA0009D 는 모르는 ID 라
#   다른 처리로 빠져 스캔이 깨진다.
#   ⇒ **선언은 0x5BA00477**, 그 상태에서 읽히는 0x6BA0009D 가 실리콘의 IDCODE.
OBSERVED_TAP_ID = 0x6BA0009D      # 실리콘에서 읽은 값 (선언용 아님)
CHAIN_TAP_ID = 0x5BA00477         # J-Link 에 선언하는 값

AP_MAP = [("APBAP1", 0x10000, "APB-AP"), ("APBAP2", 0x20000, "APB-AP"),
          ("AXIAP1", 0x30000, "AXI-AP"), ("AHBAP1", 0x40000, "AHB-AP"),
          ("APBAP3", 0x50000, "APB-AP"), ("APBAP4", 0x60000, "APB-AP")]

# RISC-V Debug Spec DMI 레지스터 (주소, 이름). 바이트 오프셋 = 주소 << 2
DMI_REGS = [(0x10, 'dmcontrol'), (0x11, 'dmstatus'), (0x12, 'hartinfo'),
            (0x16, 'abstractcs'), (0x17, 'command'), (0x1D, 'nextdm'),
            (0x38, 'sbcs'), (0x04, 'data0')]
DM_VER = {0: '없음', 1: '0.11', 2: '★0.13', 3: '★1.0'}

DP_ABORT, DP_CTRL, DP_SELECT = 0, 1, 2
OFF_CSW, OFF_TAR, OFF_DRW = 0xD00, 0xD04, 0xD0C
OFF_CFG, OFF_BASE, OFF_IDR = 0xDF4, 0xDF8, 0xDFC

TAP_SCRIPT = """void ConfigTargetSettings(void) {
  JTAG_AllowTAPReset = 1;            /* 1 = 자동 검출 OFF */
  JLINK_JTAG_SetDeviceId(0, 0x%08X);
  JLINK_JTAG_IRPre  = 0;
  JLINK_JTAG_DRPre  = 0;
  JLINK_JTAG_IRPost = 0;
  JLINK_JTAG_DRPost = 0;
  JLINK_JTAG_IRLen  = 4;
  return 0;
}
"""


def hx(v):
    return "----" if v is None else f"{v & 0xFFFFFFFF:08X}"


def decode_ctrl(v):
    """★ STICKYERR 는 **bit5**. 이전 코드가 `1 << 5 + 2`(=bit7)로 잘못 봤다."""
    if v is None:
        return {}
    return {'raw': f"0x{v:08X}",
            'STICKYORUN': bool(v & (1 << 1)),
            'STICKYERR': bool(v & (1 << 5)),
            'READOK': bool(v & (1 << 6)),
            'WDATAERR': bool(v & (1 << 7)),
            'CDBGACK': bool(v & (1 << 29)),
            'CSYSACK': bool(v & (1 << 31))}


class Dap:
    def __init__(self, jl):
        self.jl, self.sel = jl, None

    def dpr(self, r):
        try:
            v = self.jl.coresight_read(r, ap=False)
            return None if (v is None or v < 0) else v & 0xFFFFFFFF
        except Exception:
            return None

    def dpw(self, r, v):
        try:
            self.jl.coresight_write(r, v & 0xFFFFFFFF, ap=False)
            return True
        except Exception:
            return False

    def abort(self):
        self.dpw(DP_ABORT, 0x1E)
        self.sel = None

    def _sel(self, addr):
        v = addr & 0xFFFFFFF0
        if self.sel == v:
            return True
        if not self.dpw(DP_SELECT, v):
            return False
        self.sel = v
        try:
            self.jl.coresight_read(0, ap=True)      # priming
        except Exception:
            pass
        return True

    def apr(self, base, off):
        if not self._sel(base + off):
            return None
        try:
            v = self.jl.coresight_read((off >> 2) & 3, ap=True)
            return None if (v is None or v < 0) else v & 0xFFFFFFFF
        except Exception:
            return None

    def apw(self, base, off, val):
        if not self._sel(base + off):
            return False
        try:
            self.jl.coresight_write((off >> 2) & 3, val & 0xFFFFFFFF, ap=True)
            return True
        except Exception:
            return False

    def mem32(self, base, addr, csw0):
        """읽기 전용. CSW/TAR 만 쓰고 **DRW 에는 쓰지 않는다.**"""
        self.abort()
        before = decode_ctrl(self.dpr(DP_CTRL))
        if csw0 is None:
            return None, {'stage': 'no_csw', 'before': before}
        if not self.apw(base, OFF_CSW, (csw0 & ~0x37) | 0x02):
            return None, {'stage': 'csw_write_fail', 'before': before}
        if not self.apw(base, OFF_TAR, addr):
            return None, {'stage': 'tar_write_fail', 'before': before}
        back = self.apr(base, OFF_TAR)
        if back != (addr & 0xFFFFFFFF):
            return None, {'stage': 'tar_mismatch', 'tar_back': hx(back),
                          'before': before, 'after': decode_ctrl(self.dpr(DP_CTRL))}
        v = self.apr(base, OFF_DRW)
        after = decode_ctrl(self.dpr(DP_CTRL))
        err = any(after.get(k) for k in ('STICKYERR', 'WDATAERR', 'STICKYORUN'))
        # ★ 오류가 있으면 값이 있어도 'ok' 가 아니다
        stage = 'dp_error' if err else ('ok' if v is not None else 'drw_fail')
        return (None if err else v), {'stage': stage, 'dp_error': err,
                                      'before': before, 'after': after}


def discover(d):
    """★ ADIv6 **architectural discovery 레지스터**. 한 번도 안 읽었다.

    ADIv6 는 DP SELECT 의 **DPBANKSEL**(bits[3:0])로 DP 주소 0x0 에서
    서로 다른 레지스터를 노출한다:

        bank 0 → DPIDR      (지금까지 읽던 것)
        bank 1 → DPIDR1     ASIZE=bits[6:0] (주소 폭), ERRMODE=bit7
        bank 2 → BASEPTR0   bit0=VALID, bits[31:12]=루트 ROM 주소 하위
        bank 3 → BASEPTR1   루트 ROM 주소 상위 32비트

    **BASEPTR 가 곧 "디버그 구성의 루트가 어디인가" 다.**
    우리는 그동안 그 주소를 T32 스크립트에서 추측해 왔는데,
    ADIv6 에서는 **하드웨어가 직접 알려준다.** 시험 이력이 없다.
    """
    out = {}
    sel0 = 0
    for bank, name in ((0, 'DPIDR'), (1, 'DPIDR1'),
                       (2, 'BASEPTR0'), (3, 'BASEPTR1')):
        d.dpw(DP_SELECT, (sel0 & ~0xF) | bank)
        out[name] = d.dpr(0)
    d.dpw(DP_SELECT, sel0)          # bank 0 으로 복구
    d.sel = None

    r = {'raw': {k: hx(v) for k, v in out.items()}}
    # ★ 자기검증: 네 뱅크가 전부 같으면 DPBANKSEL 이 안 먹은 것이다
    vals = [v for v in out.values() if v is not None]
    if len(vals) == 4 and len(set(vals)) == 1:
        r['bank_failed'] = True
        r['why'] = ('네 뱅크가 전부 같은 값 — DPBANKSEL 이 반영되지 않았다. '
                    'discovery 읽기가 일어나지 않았으므로 파생값을 내지 않는다')
        return r
    d1 = out.get('DPIDR1')
    if d1 is not None:
        r['ASIZE'] = d1 & 0x7F
        r['ERRMODE'] = bool(d1 & 0x80)
    b0, b1 = out.get('BASEPTR0'), out.get('BASEPTR1')
    if b0 is not None:
        r['BASE_VALID'] = bool(b0 & 1)
        lo = b0 & 0xFFFFF000
        r['BASEPTR'] = (f"0x{(b1 or 0):08X}{lo:08X}" if b1 else f"0x{lo:08X}")
    return r


def alias_probe(jl, d, base, name):
    """★ 그 AP 의 **주소 디코드 폭**을 잰다.

    N비트만 디코드하면 주소 `2^N` 은 주소 `0` 과 같은 곳이다.
    우연 배제를 위해 `2^N + 4` 가 `4` 와도 같은지 **함께** 본다.
    """
    csw = d.apr(base, OFF_CSW)
    if csw is None:
        return {'ap': name, 'width': None, 'note': 'CSW 못 읽음'}
    r0, m0 = d.mem32(base, 0x0, csw)
    r4, m4 = d.mem32(base, 0x4, csw)
    if m0.get('dp_error') or m4.get('dp_error'):
        d.apw(base, OFF_CSW, csw)
        return {'ap': name, 'width': None, 'undecidable': True,
                'note': '기준 전송에 DP 오류 — 폭 판정 금지'}
    if r0 is None:
        return {'ap': name, 'width': None, 'note': '0x0 못 읽음'}
    # ★ 기준점이 서로 달라야 wrap 판정이 성립한다
    if r0 == r4:
        d.apw(base, OFF_CSW, csw)
        return {'ap': name, 'width': None, 'ref0': hx(r0), 'ref4': hx(r4),
                'undecidable': True,
                'note': '0x0 과 0x4 가 같은 값 — 기준점이 구별 안 됨'}
    width, matches = None, []
    err_seen = False
    for n in range(12, 32):
        a0, ma = d.mem32(base, 1 << n, csw)
        if ma.get('dp_error'):
            err_seen = True
        if a0 != r0:
            continue
        a4, mb = d.mem32(base, (1 << n) + 4, csw)
        if mb.get('dp_error'):
            err_seen = True
        if a4 == r4:
            matches.append(n)
            if width is None:
                width = n
    d.apw(base, OFF_CSW, csw)
    if err_seen:
        return {'ap': name, 'width': None, 'undecidable': True,
                'ref0': hx(r0), 'ref4': hx(r4),
                'note': '전송 중 DP 오류 — 폭 판정 금지'}
    return {'ap': name, 'width': width, 'ref0': hx(r0), 'ref4': hx(r4),
            'matches': matches}


def _val_of(reads, addr):
    v = reads.get(f"0x{addr:08X}")
    if v in (None, '----'):
        return None
    try:
        return int(v, 16)
    except ValueError:
        return None


def session(a, idx):
    import os
    import tempfile
    use_script = not getattr(a, 'no_tap_script', False)
    mode = getattr(a, 'cjtag_mode', CJTAG_MODE)
    sp = None
    if use_script:
        sp = os.path.join(tempfile.gettempdir(), f"sfe76_sa_{os.getpid()}.JLinkScript")
        with open(sp, 'w') as f:
            f.write(TAP_SCRIPT % CHAIN_TAP_ID)

    out = {'session': idx, 'ok': False, 'aps': {}, 'log': []}
    logs = []
    cb = lambda m: logs.append(str(m).rstrip())
    jl = pylink.JLink(log=cb, detailed_log=cb, error=cb, warn=cb)
    try:
        if sp:
            try:
                jl.exec_command(f"ScriptFile = {sp}")
            except Exception:
                pass
        jl.open()
        out['probe'] = f"{jl.product_name} HW={jl.hardware_version} FW={jl.firmware_version}"
        if sp:
            try:
                jl.exec_command(f"ScriptFile = {sp}")
            except Exception:
                pass
        jl.exec_command(f"SetcJTAGInitMode = {mode}")
        jl.set_tif(TIF_CJTAG)
        spd = getattr(a, 'speed', SPEED_KHZ)
        jl.set_speed(spd)
        for i, (_n, addr, typ) in enumerate(AP_MAP):
            jl.exec_command(f"CORESIGHT_AddAP = Index={i} Type={typ} BaseAddr=0x{addr:X}")
        if getattr(a, 'full_cmds', True):
            # ★ 0x11013913 을 읽던 경로가 보내던 셋. standalone 은 빠뜨렸었다.
            for c in (f"CORESIGHT_SetIndexAPBAPToUse = {getattr(a, 'apidx', 0)}",
                      f"CORESIGHT_SetCoreBaseAddr = 0x{getattr(a, 'corebase', 0x81480000):X}",
                      "RISCV_SetHartSel = 0"):
                try:
                    jl.exec_command(c)
                except Exception:
                    pass
        try:
            jl.connect(a.device, speed=spd)
            out['connect'] = True
        except Exception as e:
            out['connect'] = False
            out['connect_err'] = str(e)[:100]

        d = Dap(jl)
        try:
            jl.coresight_configure(ir_pre=0, dr_pre=0, ir_post=0, dr_post=0,
                                   ir_len=4, perform_tif_init=False)
        except Exception:
            try:
                jl.coresight_configure()
            except Exception as e:
                out['error'] = f"coresight_configure: {e}"
                return out

        dpidr = d.dpr(0)
        out['DPIDR'] = hx(dpidr)
        # ★ DPIDR 이 무효면 그 세션의 AP 값은 **전부 무효**다.
        #   bit0 은 RAO 이므로 짝수이거나 0/0xFFFFFFFF 면 데이터가 아니다.
        out['dpidr_ok'] = dpidr_valid(dpidr, strict=not a.loose)
        out['dpidr_version'] = (None if dpidr is None else (dpidr >> 12) & 0xF)
        d.dpw(DP_ABORT, 0x1E)
        d.dpw(DP_CTRL, 0x50000000)
        for _ in range(30):
            time.sleep(0.01)
            c = d.dpr(DP_CTRL)
            if c and c & (1 << 29):
                break
        out['CTRL'] = decode_ctrl(d.dpr(DP_CTRL))
        out['ok'] = bool(out['CTRL'].get('CDBGACK')) and out['dpidr_ok']

        if getattr(a, 'discover', False):
            # ★ 세션이 무효면 discovery 를 시도조차 하지 않는다
            if not out['dpidr_ok']:
                out['discover'] = {'skipped': True,
                                   'why': f"세션 무효 (DPIDR={out['DPIDR']}, "
                                          f"VERSION={out['dpidr_version']})"}
            else:
                out['discover'] = discover(d)
            return out

        if getattr(a, 'alias', False):
            out['alias'] = [alias_probe(jl, d, b, n) for n, b, _t in AP_MAP]
            return out

        for name, base, _t in AP_MAP:
            csw = d.apr(base, OFF_CSW)
            ap = {'IDR': hx(d.apr(base, OFF_IDR)), 'CSW': hx(csw),
                  'CFG': hx(d.apr(base, OFF_CFG)), 'BASE': hx(d.apr(base, OFF_BASE))}
            if csw is not None:
                ap['DeviceEn'] = bool(csw & (1 << 6))
                ap['Prot'] = f"0x{(csw >> 24) & 0x7F:02X}"
            reads = {}
            for addr in a.addrs:
                v, meta = d.mem32(base, addr, csw)
                reads[f"0x{addr:08X}"] = hx(v)
                out['log'].append({'ap': name, 'addr': f"0x{addr:08X}", **meta})
            ap['reads'] = reads
            ap['unmapped'] = sum(1 for x in a.addrs
                                 if is_default_line(x, _val_of(reads, x)))
            if csw is not None:
                d.apw(base, OFF_CSW, csw)        # CSW 원복
            out['aps'][name] = ap
    except Exception as e:
        out['error'] = str(e)[:120]
    finally:
        try:
            jl.close()
        except Exception:
            pass
        if sp:
            try:
                os.unlink(sp)
            except OSError:
                pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--device', default=DEVICE)
    ap.add_argument('--sessions', type=int, default=3)
    ap.add_argument('--addrs', default="0x0,0x4,0x81480000,0x81480044,0xC81040,0xC81044",
                    help="콤마 구분 주소. 'dmi' 를 주면 DMI 레지스터 자리를 자동 계산")
    ap.add_argument('--json', default=None)
    ap.add_argument('--link', action='store_true',
                    help='★ 물리 계층 — 원래 설정 고정 후 cJTAG 모드 × 속도 스윕')
    ap.add_argument('--speeds', default="10000,4000,2000,1000,500")
    ap.add_argument('--recover', action='store_true',
                    help='★ 유효 DPIDR 조건을 찾는다 — 스크립트 유무 × cJTAG 모드')
    ap.add_argument('--no-tap-script', action='store_true',
                    help='TAP 선언 스크립트를 깔지 않는다 (브링업 초기 조건)')
    ap.add_argument('--cjtag-mode', type=int, default=CJTAG_MODE)
    ap.add_argument('--min-cmds', dest='full_cmds', action='store_false',
                    help='SetIndexAPBAPToUse/SetCoreBaseAddr/SetHartSel 을 보내지 않는다')
    ap.add_argument('--apidx', type=int, default=0)
    ap.add_argument('--corebase', type=lambda x: int(x, 0), default=0x81480000)
    ap.add_argument('--discover', action='store_true',
                    help='★ ADIv6 DPIDR1 / BASEPTR0 / BASEPTR1 을 읽는다 (미시도)')
    ap.add_argument('--loose', action='store_true',
                    help='DPIDR 기대값 일치를 요구하지 않는다 (VERSION 검사만)')
    ap.add_argument('--alias', action='store_true',
                    help='★ AP 마다 주소 디코드 폭을 잰다 (2^N 이 0 과 같아지는 지점)')
    ap.add_argument('--ap', default=None,
                    help='이 AP 하나만 읽는다 (예: APBAP3). 기본은 6개 전부')
    ap.add_argument('--tapid', type=lambda x: int(x, 0), default=None,
                    help='선언할 TAP IDCODE (기본: 실측값 0x6BA0009D)')
    ap.add_argument('--full', action='store_true',
                    help='AP 별 상세까지 전부 출력 (기본은 3줄 요약)')
    ap.add_argument('--version', action='store_true')
    a = ap.parse_args()
    if a.version:
        print(VERSION)
        return 0
    if a.addrs.strip() == 'axi':
        a.addrs = [x for x, _n in AXI_T32_ADDRS]
        a.dmi_mode = False
        a.axi_mode = False
        a.axi_mode = True
    elif a.addrs.strip() == 'dmi':
        # RISC-V Debug Spec 의 DMI 주소 × stride 4
        a.addrs = [d * 4 for d, _n in DMI_REGS]
        a.dmi_mode = True
        a.axi_mode = False
    else:
        a.addrs = [int(x, 0) for x in a.addrs.split(',') if x.strip()]
        a.dmi_mode = False
    global CHAIN_TAP_ID, AP_MAP
    if a.tapid is not None:
        CHAIN_TAP_ID = a.tapid
    if a.ap:
        names = [n for n, _b, _t in AP_MAP]
        if a.ap not in names:
            sys.exit(f"--ap 는 {names} 중 하나여야 한다")
        AP_MAP = [x for x in AP_MAP if x[0] == a.ap]

    print(f"\n{'=' * 70}\n {VERSION}   ★ 단일 파일 · 읽기 전용\n{'=' * 70}")
    print(f"  device={a.device}  cJTAG mode={CJTAG_MODE}  {SPEED_KHZ}kHz")
    print(f"  TAP ID 수동 선언 0x{CHAIN_TAP_ID:08X}  (AllowTAPReset=1)")
    print(f"  AP {[n for n, _b, _t in AP_MAP]}")
    print(f"  주소 {[hex(x) for x in a.addrs]}\n")

    if a.link:
        print(f"\n{'=' * 70}\n [LINK] 물리 계층 — 속도를 낮춰본다"
              f"\n{'=' * 70}")
        print("  DPIDR 이 실행마다 FFFFFFFF / 6BA0009D / 80000000 로 흔들린다.")
        print("  설정이 원인이면 조합마다 일관돼야 한다 → **링크 불안정** 신호다.")
        print("  지금껏 10MHz 만 썼다. 낮춰본다.")
        print("  ⚠ 타깃 전원 사이클을 먼저 하는 것을 권한다.\n")
        print("---8<---")
        a.no_tap_script, a.full_cmds, a.device = True, True, 'RISC-V'
        speeds = [int(x) for x in a.speeds.split(',') if x.strip()]
        found = None
        for mode in (0, 1):
            for spd in speeds:
                a.cjtag_mode = mode
                a.speed = spd
                got = [session(a, i).get('DPIDR') for i in range(min(a.sessions, 3))]
                hit = sum(1 for g in got if g == f"{EXPECT_DPIDR:08X}")
                kinds = sorted({classify_dpidr(int(g, 16) if g and g != '----' else None)
                                for g in got})
                print(f"mode={mode} {spd:>5d}kHz  {','.join(g or '-' for g in got)}"
                      + (f"  ★ 유효 {hit}/{len(got)}" if hit else f"  [{kinds[0]}]"))
                if hit and not found:
                    found = f"mode={mode} {spd}kHz"
                time.sleep(0.3)
        print("VERDICT:", f"FOUND ({found})" if found else "LINK_UNSTABLE")
        if not found:
            print("  어느 속도에서도 유효 DPIDR 이 안 나온다.")
            print("  → 타깃 전원 사이클 / cJTAG 배선·풀업 / 프로브 케이블 순으로 본다.")
        print("---8<---")
        return 0 if found else 6

    if a.recover:
        print(f"\n{'=' * 70}\n [RECOVER] 유효 DPIDR(0x{EXPECT_DPIDR:08X}) 조건 탐색"
              f"\n{'=' * 70}")
        print("  브링업 초기에 이 값이 나왔다. 그 뒤 바뀐 것을 전부 되돌려 본다:")
        print("    TAP 스크립트 유무 × cJTAG 모드 0/1 × 명령셋 full/min × device")
        print("    (full = SetIndexAPBAPToUse/SetCoreBaseAddr/SetHartSel 포함)")
        print("  ⚠ 그 전에 **타깃 전원 사이클**을 권한다 — 긴 세션 동안 상태가")
        print("     바뀌었을 수 있다.\n")
        print("---8<---")
        best = None
        for no_script in (True, False):
          for mode in (0, 1):
            for full in (True, False):
              for dev in ('RISC-V', 'E76'):
                a.no_tap_script, a.cjtag_mode = no_script, mode
                a.full_cmds, a.device = full, dev
                got = []
                for i in range(min(a.sessions, 2)):
                    r = session(a, i)
                    got.append(r.get('DPIDR'))
                    time.sleep(0.25)
                hit = sum(1 for g in got if g == f"{EXPECT_DPIDR:08X}")
                tag = (f"script={'X' if no_script else 'O'} mode={mode} "
                       f"cmds={'full' if full else 'min'} dev={dev}")
                # 유효값이 없으면 서로 다른 결과만 요약해 전사량을 줄인다
                uniq = ",".join(sorted({g or '-' for g in got}))
                print(f"{tag}  DPIDR={uniq}"
                      + (f"   ★ 유효 {hit}/{len(got)}" if hit else ""))
                if len({g for g in got}) > 1:
                    print("      ⚠ 같은 조합에서 값이 흔들린다 — 링크 불안정")
                if hit and best is None:
                    best = tag
        print("VERDICT:", f"FOUND ({best})" if best else "NOT_FOUND")
        print("---8<---")
        return 0 if best else 6

    runs = [session(a, i) for i in range(a.sessions)]
    ok = [r for r in runs if r.get('ok')]

    last = ok[-1] if ok else (runs[-1] if runs else None)
    stages, errs = {}, {}
    if last:
        for e in last.get('log', []):
            stages[e['stage']] = stages.get(e['stage'], 0) + 1
            for k in ('STICKYERR', 'WDATAERR', 'STICKYORUN'):
                if (e.get('after') or {}).get(k):
                    errs[k] = errs.get(k, 0) + 1

    print(f"\n---8<---")
    if getattr(a, 'discover', False):
        print(f"ok={len(ok)}/{a.sessions} DPIDR={(last or {}).get('DPIDR')} "
              f"ver={(last or {}).get('dpidr_version')}")
        dv = (last or {}).get('discover') or {}
        if dv.get('skipped'):
            print(f"DISCOVERY 건너뜀 — {dv['why']}")
            print("★ 유효 DPIDR 세션(0x11013913)부터 확보해야 한다.")
        else:
            for k, v in (dv.get('raw') or {}).items():
                print(f"{k}={v}")
            if dv.get('bank_failed'):
                print(f"DISCOVERY 무효 — {dv['why']}")
            else:
                if 'ASIZE' in dv:
                    print(f"ASIZE={dv['ASIZE']} ERRMODE={dv['ERRMODE']}")
                if 'BASE_VALID' in dv:
                    print(f"BASE_VALID={dv['BASE_VALID']} BASEPTR={dv.get('BASEPTR')}")
        print("---8<---")
        return 0 if ok else 6

    if getattr(a, 'alias', False):
        print(f"ok={len(ok)}/{a.sessions} DPIDR={(last or {}).get('DPIDR')}")
        for r in ((last or {}).get('alias') or []):
            w = r.get('width')
            if r.get('undecidable'):
                print(f"{r['ap']} 판정불가 (0x0==0x4={r.get('ref0')}) "
                      f"— 균일해서 wrap 을 가릴 수 없다")
                continue
            sz = (f"{(1 << w) // 1024}KB" if w and w < 22 else
                  f"{(1 << w) // 1024 // 1024}MB" if w else "wrap없음(32비트 전부)")
            print(f"{r['ap']} width={w if w else '-'} ({sz}) "
                  f"ref0={r.get('ref0')} ref4={r.get('ref4')}")
        print("---8<---")
        return 0 if ok else 6

    bad = [r for r in runs if not r.get('dpidr_ok')]
    if bad:
        print(f"\n⚠⚠ DPIDR 무효 세션 {len(bad)}/{a.sessions} — "
              f"그 세션의 AP 값은 **전부 무효**다. 해석하지 말 것.")
    print(f"ok={len(ok)}/{a.sessions} DPIDR={(last or {}).get('DPIDR')} "
          f"CTRL={((last or {}).get('CTRL') or {}).get('raw')}")
    print("ERR " + (" ".join(f"{k}={v}" for k, v in sorted(errs.items()))
                    if errs else "없음")
          + "  stages=" + ",".join(f"{k}:{v}" for k, v in sorted(stages.items())))
    # AP 별로 **읽은 값의 종류 수**만 낸다 — 1종이면 변화 없음
    parts = []
    for n, apd in ((last or {}).get('aps') or {}).items():
        u = len(set(apd['reads'].values()))
        parts.append(f"{n}:B={apd['BASE'][-1]}/u{u}")
    print(" ".join(parts))
    for n, apd in ((last or {}).get('aps') or {}).items():
        vs = sorted(set(apd['reads'].values()))
        un = apd.get('unmapped')
        if un:
            print(f"{n}: {un}/{len(apd['reads'])} 이 **default slave 라인** "
                  f"= 미매핑 (데이터 아님)")
        if getattr(a, 'axi_mode', False) and len(vs) == 1:
            nm = {x: n for x, n in AXI_T32_ADDRS}
            for x, _n in AXI_T32_ADDRS:
                print(f"  0x{x:08X} {nm[x]:22s} = "
                      f"{apd['reads'].get(f'0x{x:08X}')}")
        elif len(vs) == 1:
            # ★ 전부 같아도 **그 값이 무엇인지**는 찍는다. 이전엔 생략해서
            #   "u1 만 나오고 끝" 이 됐다 — 정보를 버리고 있었다.
            print(f"{n}= 전부 {vs[0]}")
        else:
            if getattr(a, 'dmi_mode', False):
                names = {d * 4: nm for d, nm in DMI_REGS}
                print(" ".join(
                    f"{names.get(int(k, 16), k)}={v}"
                    for k, v in apd['reads'].items()))
            elif getattr(a, 'axi_mode', False):
                nm = {x: n for x, n in AXI_T32_ADDRS}
                for x, _n in AXI_T32_ADDRS:
                    v = apd['reads'].get(f"0x{x:08X}")
                    print(f"  0x{x:08X} {nm[x]:22s} = {v}")
            elif len(AP_MAP) == 1:      # AP 하나만 볼 땐 주소별로 낸다
                print(" ".join(f"{k.replace('0x', '')}={v}"
                                for k, v in apd['reads'].items()))
            else:
                print(f"{n}= " + ",".join(vs))
        # dmi 모드면 값이 몇 종이든 dmstatus 를 해석한다
        if getattr(a, 'dmi_mode', False):
            ds = apd['reads'].get(f"0x{0x11 * 4:08X}")
            if ds and ds != '----':
                ver = int(ds, 16) & 0xF
                print(f"  dmstatus={ds} version={ver} ({DM_VER.get(ver, '무효')})"
                      + ("   ★★★ DM 을 찾았다" if ver in (2, 3) else ""))
    print("---8<---")

    if a.full and last:
        print(f"\n{'=' * 70}\n 상세\n{'=' * 70}")
        if last.get('probe'):
            print(f"  {last['probe']}")
        for n, apd in (last.get('aps') or {}).items():
            print(f"  {n} IDR={apd['IDR']} CSW={apd['CSW']} CFG={apd['CFG']} "
                  f"BASE={apd['BASE']} DevEn={apd.get('DeviceEn')} Prot={apd.get('Prot')}")
            for k, v in apd['reads'].items():
                print(f"      {k} = {v}")

    if a.json:
        with open(a.json, 'w') as f:
            json.dump(runs, f, ensure_ascii=False, indent=1)
        print(f"(상세 {a.json})")
    return 0 if ok else 6


if __name__ == '__main__':
    sys.exit(main())
