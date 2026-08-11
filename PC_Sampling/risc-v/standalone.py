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

VERSION = "standalone 2026-08-11.29  --axi: AXI-AP 가 살아있나 (TAR 되읽기 대조)"

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

# ★ (철회) 아래 '브링업 초기에 유효 DPIDR 이 나왔다'는 전제는 근거가 없다.
#   그래도 조합 스윕 자체는 유효하다 — 합격 기준만 AP IDR 일치로 바꿨다.
#   브링업 초기와 지금의 설정 차이:
#     TAP 선언 스크립트   그때 없음        → 지금 항상 적용
#     SetcJTAGInitMode   그때 0 (LONG)    → 지금 1 (SHORT)
#     device             그때 RISC-V      → 지금 E76
#   앞의 둘은 "개선" 이라고 생각하고 넣은 것인데 **AP 접근을 잃은 시점과
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

# ★★★ 2026-08-11 철회 — 게이트를 DPIDR 에서 떼어낸다.
#   `0x11013913` 의 출처를 저장소 이력 전체에서 추적한 결과:
#     · 측정 로그 / JSON / raw 출력 어디에도 **없다**
#     · 최초 등장이 4a6edd9 의 **코드 주석 안 전제문**이다
#     · 그 위로는 git 이전 세션의 인수인계 산문뿐이다
#   즉 이 값은 관측 기록이 아니라 전제로 들어와 상수로 굳은 것이고,
#   사용자도 본 적이 없다고 한다. **재현 시도(--recover/--link)의 합격
#   기준을 이 값에 걸어둔 것 자체가 오류**였고 두 결과 다 무효다.
#
#   대신 우리가 실제로 검증할 수 있고 실제로 필요한 능력으로 건다:
#   **AP IDR 일치.** 6개 AP 의 IDR 이 T32 선언 타입(APB/AXI/AHB)과 맞는 것은
#   우연으로 나올 수 없고(32bit × 6), AP 트랜잭션이 성립한다는 직접 증거다.
#   DPIDR 은 이제 **관측 기록**일 뿐 합격/불합격을 가르지 않는다.
EXPECT_DPIDR = 0x11013913          # 출처 불명 — 게이트 아님, 표시용으로만 둔다
EXPECT_AP_IDR = {0x10000: 0x09130006, 0x20000: 0x09130006, 0x30000: 0x09130004,
                 0x40000: 0x09130001, 0x50000: 0x09130006, 0x60000: 0x09130006}
AP_GATE_MIN = 4                    # 6개 중 몇 개가 맞아야 유효 세션으로 보는가


def ap_idr_match(d):
    """6개 AP 의 IDR 을 읽어 기대값과 대조한다. (일치수, {base: 값}) 반환.

    이것이 세션 유효성 게이트다. AP 주소공간에 트랜잭션이 실제로 도달해
    **주소마다 다른 알려진 값**이 돌아와야만 성립한다 — 링크가 죽어 있으면
    0xFFFFFFFF / 0x80000000 / 전부 동일값이 되어 통과할 수 없다.
    """
    idrs, hit = {}, 0
    for base in EXPECT_AP_IDR:
        v = d.apr(base, OFF_IDR)
        idrs[base] = v
        if v is not None and v == EXPECT_AP_IDR[base]:
            hit += 1
    return hit, idrs


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

# ★ 트레이스 블록 (ViewNexusTracedump.cmm 실물).
#   NEXUS.Type SiFive / TE n at SB:0xFD00n000 / funnel·sink at SB:0xFD180000
#   sink 포인터는 legacy SiFive 오프셋: +0x1C write(bit0=wrap) +0x20 read +0x24 data
#   ★ T32 는 SB:(=System Bus, DM 의 SBA)로 간다. 우리가 AP 로 직접 닿으면
#     **DM 이 필요 없어진다** — connect 실패가 블로커가 아니게 된다.
TRACE_ADDRS = [(0xFD000000, 'TE0 ctrl (bit1=enable)'), (0xFD001000, 'TE1 ctrl'),
               (0xFD180000, 'funnel/sink ctrl'), (0xFD18001C, 'sink write ptr'),
               (0xFD180020, 'sink read ptr'), (0xFD180FF0, 'sink CIDR0 (=0x0D?)')]

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

# ★★ 2026-08-11 --replay 실측: AP IDR **6/6 일치**, DPIDR=6BA0009D, CTRL=F0000000.
#   ⇒ DAP·AP 계층은 완전히 정상이다. 기본값을 그 검증된 조합으로 맞춘다.
#     cJTAG mode 0 / CoreBase 0x81481000 / TAP 스크립트 없음
#
# ⚠ 그런데 `.19` 에서 device 까지 'RISC-V' 로 바꾼 것은 **잘못된 추론**이었다.
#   근거로 삼은 --replay 는 **connect=X 로 둘 다 실패**했다. AP 6/6 은 raw DAP
#   접근에서 나온 것이고 그건 device 이름과 무관하다 — replay 는 device 선택에
#   대해 아무것도 증명하지 않았는데 "검증된 조합" 으로 싸잡았다.
#   실측은 반대를 말한다:
#     · 사용자: "RISC-V 로 하면 connect 가 제대로 안 되고 E76 으로 해야 된다"
#     · --recover 스윕: 유효 IDCODE 는 **mode=1 device=E76** 에서 나왔다
#   ⇒ device 는 'E76' 으로 되돌린다.
#   (지금 하는 raw DAP 작업엔 영향이 없지만, 기본값이 실측과 어긋나면 안 된다)
TIF_CJTAG, SPEED_KHZ, CJTAG_MODE, DEVICE = 7, 10000, 0, 'E76'
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


# ★★★ --replay: 저장소가 기록한 **실제 성공 설정**의 글자 그대로 재생.
#
#   f45f0ca "J-Link connect 성공 — 최대 관문 통과" (Aug 8) 커밋 메시지:
#       SetcJTAGInitMode = 0 / TIF=7(cJTAG) / speed=10000
#       CORESIGHT_AddAP Index=0..5
#       CORESIGHT_SetIndexAPBAPToUse = 0
#       CORESIGHT_SetCoreBaseAddr    = 0x81481000     ← 0x81480000 아님
#       connect('RISC-V')
#   917bacf (Aug 8) 같은 시기 실측:
#       DP 통신 OK (DPIDR 0x6BA0009D) / CTRL/STAT 0xF0000000
#   caf874e: 성공 당시 실제로 일어난 일은 **핸들 하나로 open, 중간에 close
#       하지 않고** 1회차 CoreBase=0x81480000(실패) → 2회차 0x81481000(성공).
#
#   지금 standalone 의 기본값은 이것과 **네 군데** 다르다:
#       cJTAG mode  0 → 1        TAP 스크립트  없음 → 항상 적용
#       CoreBase    0x81481000 → 0x81480000        device  RISC-V → E76
#   그리고 --recover 는 앞의 셋만 훑고 **CoreBase 는 한 번도 안 바꿨다.**
#   순서 의존(같은 핸들 2회 시도)도 재현한 적이 없다.
#
#   ⇒ 이 함수는 스윕이 아니다. 기록된 그 한 조합을 그대로 다시 한다.
def replay(a):
    out = []
    logs = []
    cb = lambda m: logs.append(str(m).rstrip())
    jl = pylink.JLink(log=cb, detailed_log=cb, error=cb, warn=cb)
    try:
        jl.open()                                   # ★ 핸들 하나. 중간에 안 닫는다
        jl.exec_command("SetcJTAGInitMode = 0")     # ★ 0 (LONG) — 지금 기본은 1
        jl.set_tif(TIF_CJTAG)
        jl.set_speed(10000)
        for i, (_n, addr, typ) in enumerate(AP_MAP):
            jl.exec_command(f"CORESIGHT_AddAP = Index={i} Type={typ} BaseAddr=0x{addr:X}")
        jl.exec_command("CORESIGHT_SetIndexAPBAPToUse = 0")

        for attempt, cb_addr in enumerate((0x81480000, 0x81481000), 1):
            r = {'attempt': attempt, 'corebase': f"0x{cb_addr:08X}"}
            jl.exec_command(f"CORESIGHT_SetCoreBaseAddr = 0x{cb_addr:X}")
            try:
                # ★ replay 는 f45f0ca 기록의 **글자 그대로의 재생**이므로
                #   여기만 'RISC-V' 를 유지한다. 다른 모드의 기본값은 E76 이다.
                jl.connect('RISC-V', speed=10000)
                r['connect'] = True
            except Exception as e:
                r['connect'] = False
                r['err'] = str(e)[:70]
            try:
                jl.coresight_configure(ir_pre=0, dr_pre=0, ir_post=0, dr_post=0,
                                       ir_len=4, perform_tif_init=False)
            except Exception:
                try:
                    jl.coresight_configure()
                except Exception:
                    pass
            d = Dap(jl)
            r['DPIDR'] = hx(d.dpr(0))
            d.dpw(DP_ABORT, 0x1E)
            d.dpw(DP_CTRL, 0x50000000)
            for _ in range(30):
                time.sleep(0.01)
                c = d.dpr(DP_CTRL)
                if c and c & (1 << 29):
                    break
            r['CTRL'] = hx(d.dpr(DP_CTRL))
            hit, _ = ap_idr_match(d)
            r['ap_match'] = hit
            out.append(r)
    except Exception as e:
        out.append({'fatal': str(e)[:120]})
    finally:
        try:
            jl.close()
        except Exception:
            pass
    return out



# ★★★ --rom : BASE 레지스터 **전체**를 읽고 ROM 테이블을 실제로 판독한다.
#
#   지금까지 BASE 를 **마지막 니블만** 찍었다(B=3 / B=2). 그래서 ROM 테이블이
#   **어디 있는지** 한 번도 안 봤다. ADIv6 BASE[31:12] 가 그 주소다.
#
#   그리고 APBAP1 오프셋 0 에서 나온 0x81480003 은 default-slave 도 균일값도
#   아닌 **진짜 데이터**이고, 형태가 정확히 CoreSight ROM 엔트리다:
#       bits[31:12] = 오프셋 0x81480,  bit1 = FORMAT,  bit0 = PRESENT
#   APBAP2 는 0x81481003 — attach.cmm 의 두 DM 주소와 정확히 일치한다.
#
#   ⇒ 진짜인지 가르는 건 **CIDR** 하나다. CoreSight 컴포넌트면
#       0xFF0..0xFFC = 0x0D, 0x10, 0x05, 0xB1 (preamble)
#     맞으면 ROM 테이블이 실재하고 엔트리를 믿어도 된다.
#     아니면 0x81480003 은 우연히 그렇게 생긴 버스 값일 뿐이다.
# ⚠ 판정 기준이 틀렸었다. CIDR1 의 **상위 니블은 컴포넌트 클래스**이고
#   하위 니블만 preamble(0x0)이다. 0x10 만 받으면 클래스 1(레거시 ROM)만 통과한다.
#   실측 `0D9005B1` = 클래스 **9** = ADIv6 CoreSight 클래스 → **유효**.
#   (ADIv6 의 ROM 테이블이 바로 Class 9 ROM Table 이다)
CID_PREAMBLE = (0x0D, 0x00, 0x05, 0xB1)     # CIDR1 은 하위 니블만 본다


def cid_ok(cid):
    if len(cid) != 4 or any(c is None for c in cid):
        return False, None
    if cid[0] != 0x0D or cid[2] != 0x05 or cid[3] != 0xB1:
        return False, None
    if (cid[1] & 0x0F) != 0x00:
        return False, None
    return True, (cid[1] >> 4) & 0xF        # 컴포넌트 클래스


# ★★★ --dm : ROM 엔트리가 가리키는 곳에 **DM 이 실제로 응답하나.**
#
#   실측으로 여기까지 왔다:
#     · APBAP1/2 의 BASE 에 진짜 CoreSight 컴포넌트 (CID=0D9005B1, 클래스 9)
#     · ent[0] = 0x81480003 / 0x81481003 — PRESENT=1 FORMAT=1 인 정상 ROM 엔트리
#       가리키는 곳이 attach.cmm 의 두 DM 주소와 정확히 일치
#     · ent[1..3] = 0 → 테이블 끝. AP 당 컴포넌트 **하나**뿐이다
#
#   ★ 그런데 J-Link 의 "Unsupported or invalid DM version 14" 가 풀렸다:
#       0xEAFFFFFE & 0xF = 0xE = 14
#     = **default slave 라인의 하위 니블**이다. J-Link 은 dmstatus 를 읽어
#     응답 없는 버스의 기본값을 받은 것이다. 설정 문제가 아니라 **부재**다.
#
#   ⇒ 남은 질문 하나: 우리가 DM 을 **엉뚱한 주소**에서 찾고 있었나?
#     ROM 엔트리 오프셋은 ROM 베이스 상대이고(ADIv5/v6 에서 bits[31:12], 부호 있음),
#     우리는 BASE 를 안 본 채 리터럴 0x81480000 만 읽었다.
#     세 후보를 전부 dmcontrol/dmstatus 자리에서 확인한다.
DM_REGS = [(0x10, 'dmcontrol'), (0x11, 'dmstatus'), (0x38, 'sbcs')]

# ★★★ --pwr : 우리가 T32 와 다르게 해온 것 하나.
#
#   attach.cmm:
#       SYStem.Option.DAPSYSPWRUPREQ OFF    ← CSYSPWRUPREQ 를 **일부러 안 쓴다**
#       SYStem.Option.DAPDBGPWRUPREQ ON     ← CDBGPWRUPREQ 만
#   우리는 처음부터 CTRL/STAT 에 0x50000000 = **둘 다** 걸어왔다.
#   "CSYSPWRUPACK 이 떴으니 무해하다" 고 판단했었는데 그건 근거가 아니다.
#   ACK 은 핸드셰이크가 성립했다는 뜻일 뿐, 그 결과 시스템 전원 도메인이
#   어떤 상태로 가는지는 말해주지 않는다. 기본값이 ON 인 옵션을 T32 가 굳이
#   OFF 로 적어둔 데는 이유가 있다고 봐야 한다.
#
#   ★ 이 시험은 **DP CTRL/STAT 쓰기뿐**이다 — 타깃 버스에 아무것도 안 쓴다.
#     되돌릴 수 있고 실기에 안전하다.
#
#   함께 볼 것: **APB Prot**. DM 이 secure 공간에 있고 우리 접근이
#   non-secure 로 나가면 응답 대신 기본값이 온다. 이전 Prot 스윕은
#   AXI 에만 했고 APB 에는 한 적이 없다.
PWR_CFGS = [(0x10000000, 'DBG만 (T32와 동일)'),
            (0x50000000, 'DBG+SYS (지금까지)'),
            (0x00000000, '요청 없음')]


def pwr_probe(d, dm_addr):
    """전원요청 조합마다 DM 이 응답하는지 본다. APBAP1 고정."""
    apbase = AP_MAP[0][1]
    out = []
    for req, label in PWR_CFGS:
        d.dpw(DP_ABORT, 0x1E)
        d.dpw(DP_CTRL, req)
        for _ in range(30):
            time.sleep(0.01)
            c = d.dpr(DP_CTRL)
            if c is not None and (req == 0 or c & (1 << 29)):
                break
        ctrl = d.dpr(DP_CTRL)
        hit, _ = ap_idr_match(d)
        csw = d.apr(apbase, OFF_CSW)
        st, _ = d.mem32(apbase, dm_addr + (0x11 << 2), csw)
        out.append({'how': label, 'CTRL': hx(ctrl), 'ap': hit,
                    'dmstatus': hx(st), 'ver': None if st is None else st & 0xF})
        if csw is not None:
            d.apw(apbase, OFF_CSW, csw)
    d.dpw(DP_CTRL, 0x50000000)          # 원상복구
    return out



# ★★★ --prot : secure/privileged 접근 가설. 사용자가 일찍 물었던 것이고
#   아직 **APB 에는 한 번도 안 해봤다** (이전 Prot 스윕은 AXI 전용이었다).
#
#   가설: DM 이 secure 공간에 있고 우리 접근이 non-secure 로 나가면
#         응답 대신 버스 기본값이 온다 — 지금 보이는 그림 그대로다.
#
#   ★ 이전 prot_probe 의 결함: **양성 대조가 없었다.** Prot 값이 그냥 무효라
#     실패한 건지, 유효한데 DM 만 안 나오는 건지 구별할 수 없었다.
#     이제 Prot 마다 **ROM 의 CIDR0 도 같이 읽는다** — 그건 0x0D 가 나와야
#     하는 곳이다(실측 확인됨). 판정:
#       CID0 = 0D 인데 dmstatus 만 기본값  →  그 Prot 는 유효, DM 이 없다
#       CID0 도 깨짐                       →  그 Prot 자체가 무효. 판정 불가

# ★★★ --ident : 검증 없이 깔고 온 전제를 친다.
#
#   우리는 "CID 클래스 9 = ROM 테이블" 이라고 읽고, 그래서 오프셋 0 의
#   0x81480003 을 **ROM 엔트리**로 해석했다. 그런데 **클래스 9 는 모든
#   CoreSight 컴포넌트**를 뜻한다 — ROM 테이블만이 아니다.
#   ROM 테이블이라면 DEVARCH(0xFBC).ARCHID = 0x0AF7 이어야 한다.
#   아니면 0x81480003 은 그냥 레지스터 값이고 "DM 은 0x81480000" 이라는
#   추론 전체가 무너진다.
#
#   함께: PIDR 로 컴포넌트의 정체(설계자/부품번호)를 읽고,
#         APBAP1 주소공간을 성기게 훑어 **응답하는 곳이 ROM 말고 또 있나** 본다.
ARCHID_ROM = 0x0AF7

# 성긴 스캔 격자. 응답이 default slave 라인이 아닌 곳만 보고한다.
SCAN_ADDRS = [0x0, 0x1000, 0x2000, 0x10000, 0x100000, 0x1000000,
              0x10000000, 0x40000000, 0x80000000, 0x81000000, 0x81400000,
              0x81480000, 0x81481000, 0x81500000, 0x81592000,
              0xC0000000, 0xC81000, 0xE0000000, 0xFD000000, 0xFD180000]



# ★★★ --axi : 쓰기 승인을 묻기 **전에** 반드시 답해야 하는 것.
#
#   T32 의 Reset Release 는 AXI:0xC81040 / 0xC81044 에 쓴다. 그런데
#   AXIAP1 은 **모든 주소에서 0x00000000** 을 준다. 0 은 default slave
#   라인(0x00000001 / 0xEAFFFFFE)이 **아니다** — APBAP1 과 거동이 다르다.
#   둘 중 하나인데 구별한 적이 없다:
#       (a) AXI 버스가 진짜 0 을 돌려준다 (리셋 중이면 그럴 수 있다)
#       (b) AXI-AP 가 데이터를 아예 전달하지 못한다
#
#   ★ (b) 라면 0xC81040 에 써봐야 **검증조차 못 한다.** 실기 장치에 쓰기를
#     제안하면서 결과를 못 읽는다는 건 말이 안 된다. 먼저 가른다.
#
#   양성 대조: **TAR 되읽기.** TAR 는 AP 레지스터이므로 쓰고 되읽어도
#   타깃 버스에는 아무것도 안 쓴다. 되읽기가 맞으면 AP 는 살아 있고,
#   그때의 0 은 **버스가 준 진짜 값**이다.
TAR_PATTERNS = [0xC8104000, 0x00C81040, 0xDEADBEE0, 0x12345670, 0x00000000]


def axi_health(d):
    out = {'aps': []}
    for name, apbase, _t in AP_MAP:
        if name not in ('AXIAP1', 'AHBAP1', 'APBAP1'):
            continue
        csw0 = d.apr(apbase, OFF_CSW)
        r = {'ap': name, 'CSW': hx(csw0), 'IDR': hx(d.apr(apbase, OFF_IDR)),
             'CFG': hx(d.apr(apbase, OFF_CFG)), 'tar_ok': 0, 'tar_n': 0}
        for pat in TAR_PATTERNS:
            if not d.apw(apbase, OFF_TAR, pat):
                continue
            back = d.apr(apbase, OFF_TAR)
            r['tar_n'] += 1
            if back == pat:
                r['tar_ok'] += 1
        # T32 가 실제로 읽는 다섯 자리
        r['reads'] = {}
        for addr, note in AXI_T32_ADDRS:
            v, _ = d.mem32(apbase, addr, csw0)
            r['reads'][f"0x{addr:X}"] = hx(v)
        if csw0 is not None:
            d.apw(apbase, OFF_CSW, csw0)
        out['aps'].append(r)
    return out

def ident_probe(d):
    out = {'aps': [], 'scan': []}
    for name, apbase, _t in AP_MAP:
        if not name.startswith('APBAP'):
            continue
        base = d.apr(apbase, OFF_BASE)
        if base is None or base == 0xFFFFFFFF or not (base & 1):
            continue
        rb = base & 0xFFFFF000
        csw = d.apr(apbase, OFF_CSW)

        def rd(off):
            v, _ = d.mem32(apbase, rb + off, csw)
            return v

        cid1 = rd(0xFF0 + 4)
        if cid1 is None:
            continue
        devarch, devtype, devid = rd(0xFBC), rd(0xFCC), rd(0xFC8)
        pid = [rd(0xFE0), rd(0xFE4), rd(0xFE8), rd(0xFEC), rd(0xFD0)]
        r = {'ap': name, 'cls': (cid1 >> 4) & 0xF,
             'DEVARCH': hx(devarch), 'DEVTYPE': hx(devtype), 'DEVID': hx(devid)}
        if devarch is not None and (devarch & (1 << 20)):        # PRESENT
            aid = devarch & 0xFFFF
            r['ARCHID'] = f"0x{aid:04X}"
            r['is_rom'] = (aid == ARCHID_ROM)
        else:
            r['ARCHID'] = '없음'
            r['is_rom'] = False
        if all(x is not None for x in pid):
            part = ((pid[1] & 0xF) << 8) | (pid[0] & 0xFF)
            des = ((pid[2] & 0x7) << 4) | ((pid[1] >> 4) & 0xF)
            cont = pid[4] & 0xF
            r['PART'] = f"0x{part:03X}"
            r['DESIGNER'] = f"0x{((cont << 7) | des):03X}"
        out['aps'].append(r)
        if csw is not None:
            d.apw(apbase, OFF_CSW, csw)

    # APBAP1 주소공간 성긴 스캔 — ROM 말고 응답하는 곳이 있나
    apbase = AP_MAP[0][1]
    csw = d.apr(apbase, OFF_CSW)
    for addr in SCAN_ADDRS:
        v, _ = d.mem32(apbase, addr, csw)
        if v is None:
            continue
        if is_default_line(addr, v):
            continue
        out['scan'].append((addr, hx(v)))
    if csw is not None:
        d.apw(apbase, OFF_CSW, csw)
    return out

def prot_probe2(d, dm_addr):
    apbase = AP_MAP[0][1]
    base = d.apr(apbase, OFF_BASE)
    csw0 = d.apr(apbase, OFF_CSW)
    info = {'BASE': hx(base), 'CSW': hx(csw0),
            'Prot0': None if csw0 is None else f"0x{(csw0 >> 24) & 0x7F:02X}"}
    rows = []
    if csw0 is None or base is None or base == 0xFFFFFFFF:
        return info, rows
    rb = base & 0xFFFFF000
    # APB4-AP CSW[31:24] = Prot.  bit28=HNONSEC 상당, bit29/30 privileged 등
    # 구현마다 다르므로 의미 부여 없이 **훑고 관측만** 한다.
    for p in (None, 0x00, 0x10, 0x20, 0x30, 0x40, 0x60, 0x70):
        csw = csw0 if p is None else ((csw0 & ~0x7F000000) | (p << 24))
        cid, _ = d.mem32(apbase, rb + 0xFF0, csw)          # 양성 대조
        st, _ = d.mem32(apbase, dm_addr + (0x11 << 2), csw)
        rows.append({
            'prot': '기본' if p is None else f"0x{p:02X}",
            'cid0': hx(cid),
            'ctl_ok': cid is not None and (cid & 0xFF) == 0x0D,
            'dmstatus': hx(st),
            'ver': None if st is None else st & 0xF,
        })
    d.apw(apbase, OFF_CSW, csw0)
    return info, rows


def prot_probe(d, dm_addr):
    """APB Prot 를 바꿔가며 dmstatus 를 읽는다. CSW[31:24] = Prot."""
    apbase = AP_MAP[0][1]
    csw0 = d.apr(apbase, OFF_CSW)
    out = []
    if csw0 is None:
        return out
    for p in (None, 0x00, 0x20, 0x40, 0x60):
        csw = csw0 if p is None else ((csw0 & ~0x7F000000) | (p << 24))
        st, _ = d.mem32(apbase, dm_addr + (0x11 << 2), csw)
        out.append({'prot': '기본' if p is None else f"0x{p:02X}",
                    'dmstatus': hx(st), 'ver': None if st is None else st & 0xF})
    d.apw(apbase, OFF_CSW, csw0)
    return out



def dm_probe(d):
    out = []
    for name, apbase, _t in AP_MAP:
        if not name.startswith('APBAP'):
            continue
        b = d.apr(apbase, OFF_BASE)
        if b is None or b == 0xFFFFFFFF:
            continue
        rb = b & 0xFFFFF000
        csw = d.apr(apbase, OFF_CSW)
        e0, _ = d.mem32(apbase, rb, csw)
        if not e0 or not (e0 & 1):              # PRESENT 아니면 볼 것 없다
            continue
        off_u = e0 & 0xFFFFF000
        off_s = off_u - (1 << 32) if off_u & 0x80000000 else off_u
        cands = [('리터럴', off_u),
                 ('ROM+부호없음', (rb + off_u) & 0xFFFFFFFF),
                 ('ROM+부호있음', (rb + off_s) & 0xFFFFFFFF)]
        seen = set()
        for label, addr in cands:
            if addr in seen:
                continue
            seen.add(addr)
            r = {'ap': name, 'how': label, 'addr': f"0x{addr:08X}", 'regs': {}}
            for dmi, rn in DM_REGS:
                v, _ = d.mem32(apbase, addr + (dmi << 2), csw)
                r['regs'][rn] = hx(v)
                if rn == 'dmstatus':
                    r['ver'] = None if v is None else v & 0xF
                    r['default'] = is_default_line(addr + (dmi << 2), v)
            out.append(r)
        if csw is not None:
            d.apw(apbase, OFF_CSW, csw)
    return out


def rom_probe(d):
    out = []
    for name, apbase, _t in AP_MAP:
        r = {'ap': name}
        b = d.apr(apbase, OFF_BASE)
        r['BASE'] = hx(b)
        if b is None or b == 0xFFFFFFFF:
            out.append(r)
            continue
        r['P'] = bool(b & 1)                 # Debug entry Present
        r['FMT'] = bool(b & 2)               # 1 = ADIv5+ 포맷
        rb = b & 0xFFFFF000
        r['rom'] = f"0x{rb:08X}"
        csw = d.apr(apbase, OFF_CSW)
        cid = []
        for off in (0xFF0, 0xFF4, 0xFF8, 0xFFC):
            v, _ = d.mem32(apbase, rb + off, csw)
            cid.append(None if v is None else v & 0xFF)
        r['CID'] = "".join('--' if c is None else f"{c:02X}" for c in cid)
        ok, cls = cid_ok(cid)
        r['CID_OK'], r['class'] = ok, cls
        v, _ = d.mem32(apbase, rb + 0xFCC, csw)
        r['MEMTYPE'] = hx(v)
        ent = []
        for i in range(4):
            v, _ = d.mem32(apbase, rb + i * 4, csw)
            ent.append(hx(v))
        r['ent'] = ent
        if csw is not None:
            d.apw(apbase, OFF_CSW, csw)
        out.append(r)
    return out

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
        # ★★ sys.m prepare = SYStem.Mode Prepare — **디버그 포트만 올리고
        #   CPU 에는 붙지 않는다.** T32 의 attach 경로는 이 모드를 쓴다.
        #   우리는 매번 connect 를 불러왔다. --no-connect 로 그걸 뺀다.
        if getattr(a, 'no_connect', False):
            out['connect'] = None
        else:
            try:
                jl.connect(a.device, speed=spd)
                out['connect'] = True
            except Exception as e:
                out['connect'] = False
                out['connect_err'] = str(e)[:100]

        d = Dap(jl)
        # ⚠ 버그였다. connect 를 빼면 cJTAG 인터페이스를 초기화하는 게 아무것도
        #   없다. perform_tif_init=False 인 채로 --no-connect 를 돌리면 모든 읽기가
        #   실패해 None 이 된다 — 결과가 아니라 시험이 안 일어난 것이다.
        #   connect 가 없을 때는 여기서 TIF 를 초기화해야 한다.
        tif_init = bool(getattr(a, 'no_connect', False))
        try:
            jl.coresight_configure(ir_pre=0, dr_pre=0, ir_post=0, dr_post=0,
                                   ir_len=4, perform_tif_init=tif_init)
        except Exception:
            try:
                jl.coresight_configure()
            except Exception as e:
                out['error'] = f"coresight_configure: {e}"
                return out

        dpidr = d.dpr(0)
        out['DPIDR'] = hx(dpidr)          # ★ 관측 기록일 뿐 — 게이트가 아니다
        out['dpidr_version'] = (None if dpidr is None else (dpidr >> 12) & 0xF)
        # ★★★ 순서가 핵심이다. attach.cmm 은 옵션을 **sys.m prepare 앞**에 건다:
        #     SYStem.Option.DAPSYSPWRUPREQ OFF / DAPDBGPWRUPREQ ON
        #     sys.m prepare
        #   사용자 증언: "이게 없으면 debug port fail, 재시도하면 성공" —
        #   즉 **전원 요청 조합과 그 시점**이 디버그 포트 성립을 좌우한다.
        #   지금까지 우리는 여기서 무조건 0x50000000(둘 다)을 걸었고,
        #   --pwr 은 그 뒤에 바꿨다 — 순서가 반대였다.
        # ★★ 한 번도 안 본 것: **J-Link 이 자기 혼자 무엇을 걸어놨나.**
        #   우리는 항상 여기서 즉시 CTRL/STAT 을 덮어써 버렸다. 그래서
        #   "우리가 SYS 를 안 걸면 된다" 는 가정을 검증한 적이 없다.
        #   J-Link 의 DAP 기동(connect / coresight_configure)이 이미
        #   CSYSPWRUPREQ 를 걸어놨다면, 우리가 뒤에 지우는 것은 T32 의
        #   "처음부터 안 건다" 와 **다른 것**이다.
        out['CTRL0'] = decode_ctrl(d.dpr(DP_CTRL))

        pwrreq = getattr(a, 'pwrreq', 0x50000000)
        out['pwrreq'] = f"0x{pwrreq:08X}"
        d.dpw(DP_ABORT, 0x1E)
        d.dpw(DP_CTRL, pwrreq)
        for _ in range(30):
            time.sleep(0.01)
            c = d.dpr(DP_CTRL)
            if c and c & (1 << 29):
                break
        out['CTRL'] = decode_ctrl(d.dpr(DP_CTRL))

        # ★ 세션 유효성 게이트 = DAP 전원 ACK + AP IDR 일치 (DPIDR 아님)
        hit, idrs = ap_idr_match(d)
        out['ap_match'] = hit
        out['ap_idrs'] = {f"0x{b:X}": hx(v) for b, v in idrs.items()}
        need = 1 if a.loose else AP_GATE_MIN
        out['ok'] = bool(out['CTRL'].get('CDBGACK')) and hit >= need

        if getattr(a, 'discover', False):
            # ★ 세션이 무효면 discovery 를 시도조차 하지 않는다
            if not out['ok']:
                out['discover'] = {'skipped': True,
                                   'why': f"세션 무효 (AP IDR 일치 {hit}/6, "
                                          f"기준 {need})"}
            else:
                out['discover'] = discover(d)
            return out

        if getattr(a, 'axi', False):
            out['axi'] = axi_health(d)
            return out

        if getattr(a, 'ident', False):
            out['ident'] = ident_probe(d)
            return out

        if getattr(a, 'prot', False):
            out['prot2'] = prot_probe2(d, a.dmaddr)
            return out

        if getattr(a, 'pwr', False):
            out['pwr'] = pwr_probe(d, a.dmaddr)
            out['prot'] = prot_probe(d, a.dmaddr)
            return out

        if getattr(a, 'dm', False):
            out['dm'] = dm_probe(d)
            return out

        if getattr(a, 'rom', False):
            out['rom'] = rom_probe(d)
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
    ap.add_argument('--axi', action='store_true',
                    help='* AXI-AP 가 데이터를 전달하나. TAR 되읽기 양성대조')
    ap.add_argument('--ident', action='store_true',
                    help='* DEVARCH 로 ROM 테이블 전제를 검증 + APBAP1 주소공간 스캔')
    ap.add_argument('--prot', action='store_true',
                    help='* APB Prot 스윕. Prot 마다 ROM CIDR0 를 양성대조로 같이 읽는다')
    ap.add_argument('--prepare', action='store_true',
                    help='* sys.m prepare 재현: 전원요청을 처음부터 x connect 유무')
    ap.add_argument('--pwrreq', type=lambda x: int(x, 0), default=0x50000000)
    ap.add_argument('--no-connect', action='store_true')
    ap.add_argument('--pwr', action='store_true',
                    help='* 전원요청 조합(T32 는 DBG 만) x APB Prot 스윕. DP 쓰기만')
    ap.add_argument('--dmaddr', type=lambda x: int(x, 0), default=0x81480000)
    ap.add_argument('--dm', action='store_true',
                    help='★ ROM 엔트리가 가리키는 곳에 DM 이 실재하나 (주소 후보 3종)')
    ap.add_argument('--rom', action='store_true',
                    help='★ AP 별 BASE **전체** + 그곳의 CoreSight ROM 테이블 판독')
    ap.add_argument('--replay', action='store_true',
                    help='★ f45f0ca 가 기록한 실제 성공 설정을 글자 그대로 재생'
                         ' (mode=0, CoreBase 0x81480000→0x81481000, device RISC-V,'
                         ' 스크립트 없음, 핸들 하나)')
    ap.add_argument('--link', action='store_true',
                    help='★ 물리 계층 — 원래 설정 고정 후 cJTAG 모드 × 속도 스윕')
    ap.add_argument('--speeds', default="10000,4000,2000,1000,500")
    ap.add_argument('--recover', action='store_true',
                    help='★ AP IDR 이 맞는 조건을 찾는다 — 스크립트 유무 × cJTAG 모드')
    ap.add_argument('--tap-script', dest='no_tap_script', action='store_false',
                    default=True,
                    help='TAP 선언 스크립트를 깐다 (기본은 안 깖 — 검증된 설정)')
    ap.add_argument('--no-tap-script', dest='no_tap_script', action='store_true',
                    help='TAP 선언 스크립트를 깔지 않는다 (브링업 초기 조건)')
    ap.add_argument('--cjtag-mode', type=int, default=CJTAG_MODE)
    ap.add_argument('--min-cmds', dest='full_cmds', action='store_false',
                    help='SetIndexAPBAPToUse/SetCoreBaseAddr/SetHartSel 을 보내지 않는다')
    ap.add_argument('--apidx', type=int, default=0)
    ap.add_argument('--corebase', type=lambda x: int(x, 0), default=0x81481000)
    ap.add_argument('--discover', action='store_true',
                    help='★ ADIv6 DPIDR1 / BASEPTR0 / BASEPTR1 을 읽는다 (미시도)')
    ap.add_argument('--loose', action='store_true',
                    help='AP IDR 게이트를 1/6 로 완화한다 (기본 %d/6)' % AP_GATE_MIN)
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
    elif a.addrs.strip() == 'trace':
        # ViewNexusTracedump.cmm 의 트레이스 토폴로지. AP 가 여기 닿으면
        # **DM 을 완전히 우회**해서 커버리지를 뽑을 수 있다 — 그게 목표다.
        a.addrs = [x for x, _n in TRACE_ADDRS]
        a.dmi_mode = False
        a.axi_mode = False
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

    if a.axi:
        print(f"\n{'=' * 70}\n [AXI] AXI-AP 가 데이터를 전달하나\n{'=' * 70}")
        print("  T32 의 Reset Release 는 AXI:0xC81040/0xC81044 에 쓴다.")
        print("  그런데 AXIAP1 은 모든 주소에서 0 이고, 0 은 default slave 라인이")
        print("  **아니다**. (a) 버스가 진짜 0 인가 (b) AP 가 전달을 못 하나?")
        print("  양성대조 = TAR 되읽기 (AP 레지스터라 타깃 버스엔 안 쓴다).")
        print("  (b) 라면 0xC81040 에 써봐야 검증조차 못 한다.\n")
        r0 = session(a, 0)
        if not r0.get('ok'):
            print("---8<---")
            print(f"무효 세션 (AP일치={r0.get('ap_match')}/6) - 다시 실행")
            print("---8<---")
            return 6
        print("---8<---")
        healthy = []
        for r in r0.get('axi', {}).get('aps', []):
            rv = ",".join(f"{k}={v}" for k, v in r['reads'].items())
            ok = r['tar_n'] and r['tar_ok'] == r['tar_n']
            if ok and r['ap'] == 'AXIAP1':
                healthy.append(r['ap'])
            print(f"{r['ap']} IDR={r['IDR']} CFG={r['CFG']} "
                  f"TAR되읽기={r['tar_ok']}/{r['tar_n']}{'(정상)' if ok else '(불일치)'}")
            print(f"  {rv}")
        print("VERDICT:", "AXI_AP_ALIVE" if healthy else "AXI_AP_NOT_DELIVERING")
        print("---8<---")
        return 0 if healthy else 6

    if a.ident:
        print(f"\n{'=' * 70}\n [IDENT] ROM 테이블 전제 검증 + 주소공간 스캔\n{'=' * 70}")
        print("  CID 클래스 9 는 **모든** CoreSight 컴포넌트다 - ROM 만이 아니다.")
        print("  ROM 이라면 DEVARCH.ARCHID = 0x0AF7. 아니면 오프셋0 의 0x81480003 은")
        print("  ROM 엔트리가 아니라 그냥 레지스터 값이고, 'DM 은 0x81480000' 이")
        print("  통째로 무너진다.\n")
        r0 = session(a, 0)
        if not r0.get('ok'):
            print("---8<---")
            print(f"무효 세션 (AP일치={r0.get('ap_match')}/6) - 다시 실행")
            print("---8<---")
            return 6
        ident = r0.get('ident', {})
        print("---8<---")
        roms = 0
        for r in ident.get('aps', []):
            roms += int(r['is_rom'])
            print(f"{r['ap']} cls={r['cls']} DEVARCH={r['DEVARCH']} "
                  f"ARCHID={r['ARCHID']}{' =ROM테이블' if r['is_rom'] else ' *ROM아님*'} "
                  f"DEVTYPE={r['DEVTYPE']} PART={r.get('PART')} "
                  f"DESIGNER={r.get('DESIGNER')}")
        sc = ident.get('scan', [])
        print(f"스캔 {len(sc)}곳 응답: "
              + (", ".join(f"0x{a:08X}={v}" for a, v in sc) if sc else "없음(전부 기본값)"))
        print("VERDICT:", "ROM_CONFIRMED" if roms else "NOT_A_ROM_TABLE")
        print("---8<---")
        return 0 if roms else 6

    if a.prot:
        print(f"\n{'=' * 70}\n [PROT] APB Prot x 양성대조\n{'=' * 70}")
        print("  가설: DM 이 secure 공간이고 우리 접근이 non-secure 면")
        print("        응답 대신 버스 기본값이 온다 - 지금 그림 그대로다.")
        print("  Prot 마다 ROM 의 CIDR0(=0x0D 여야 함)를 같이 읽어 양성대조로 쓴다:")
        print("    CID0=0D 인데 dmstatus 만 기본값 -> Prot 유효, DM 이 없다")
        print("    CID0 도 깨짐                    -> 그 Prot 자체가 무효, 판정불가\n")
        r0 = session(a, 0)
        if not r0.get('ok'):
            print("---8<---")
            print(f"무효 세션 (AP일치={r0.get('ap_match')}/6) - 다시 실행")
            print("---8<---")
            return 6
        info, rows = r0.get('prot2', ({}, []))
        print("---8<---")
        print(f"APBAP1 BASE={info.get('BASE')} CSW={info.get('CSW')} "
              f"현재Prot={info.get('Prot0')}")
        live, testable = [], 0
        for r in rows:
            testable += int(r['ctl_ok'])
            print(f"Prot={r['prot']:5s} CID0={r['cid0']}"
                  f"{'(대조OK)' if r['ctl_ok'] else '(대조깨짐)'} "
                  f"dmstatus={r['dmstatus']} ver={r['ver']}"
                  + ("  *DM살아있음" if r['ver'] in (2, 3) else ""))
            if r['ver'] in (2, 3):
                live.append(r['prot'])
        print("VERDICT:", f"DM_LIVE (Prot={live[0]})" if live else
                          f"PROT_RULED_OUT (유효대조 {testable}/{len(rows)})"
                          if testable else "PROT_UNTESTABLE")
        print("---8<---")
        return 0 if live else 6

    if a.prepare:
        print(f"\n{'=' * 70}\n [PREPARE] attach.cmm 의 순서를 그대로\n{'=' * 70}")
        print("  T32:  DAPSYSPWRUPREQ OFF / DAPDBGPWRUPREQ ON  →  sys.m prepare")
        print("  = 전원요청을 **처음부터** DBG 만. 그리고 prepare 는 CPU 에 안 붙는다.")
        print("  지금까지 우리는 항상 둘 다(0x50000000) + connect 였다.")
        print(f"  dmstatus 를 0x{a.dmaddr + 0x44:08X} 에서 읽는다. 유효 ver = 2 또는 3.")
        print("  ★ DP CTRL/STAT 쓰기뿐 - 타깃 버스에 아무것도 안 쓴다.\n")
        print("---8<---")
        live = []
        for req, rl in ((0x10000000, 'DBG만'), (0x50000000, 'DBG+SYS')):
            for nc, cl in ((True, 'connect없음'), (False, 'connect함')):
                a.pwrreq, a.no_connect, a.dm = req, nc, True
                r = session(a, 0)
                dm = next((x for x in r.get('dm', [])
                           if x['how'] == '리터럴'), None)
                st = (dm or {}).get('regs', {}).get('dmstatus')
                ver = None
                if st and st != '----':
                    ver = int(st, 16) & 0xF
                print(f"{rl:8s} {cl:11s} 최초CTRL={(r.get('CTRL0') or {}).get('raw')} "
                      f"→{(r.get('CTRL') or {}).get('raw')} "
                      f"AP={r.get('ap_match')}/6 dmstatus={st} ver={ver}"
                      + ("  *DM살아있음" if ver in (2, 3) else ""))
                if ver in (2, 3):
                    live.append(f"{rl}/{cl}")
                time.sleep(0.3)
        print("VERDICT:", f"DM_LIVE ({live[0]})" if live else "DM_ABSENT_ALL")
        print("---8<---")
        return 0 if live else 6

    if a.pwr:
        print(f"\n{'=' * 70}\n [PWR] 전원요청 조합 x APB Prot\n{'=' * 70}")
        print("  attach.cmm 은 DAPSYSPWRUPREQ **OFF** 다. 우리는 계속 둘 다 걸었다.")
        print("  DP CTRL/STAT 쓰기만 한다 - 타깃 버스에 아무것도 안 쓴다.")
        print(f"  dmstatus 를 0x{a.dmaddr + 0x44:08X} 에서 읽는다. 유효 ver = 2 또는 3.\n")
        r0 = session(a, 0)
        if not r0.get('ok'):
            print("---8<---")
            print(f"무효 세션 (AP일치={r0.get('ap_match')}/6) - 다시 실행")
            print("---8<---")
            return 6
        print("---8<---")
        live = []
        for r in r0.get('pwr', []):
            print(f"{r['how']:18s} CTRL={r['CTRL']} AP={r['ap']}/6 "
                  f"dmstatus={r['dmstatus']} ver={r['ver']}"
                  + ("  *DM살아있음" if r['ver'] in (2, 3) else ""))
            if r['ver'] in (2, 3):
                live.append(r['how'])
        for r in r0.get('prot', []):
            print(f"Prot={r['prot']:6s} dmstatus={r['dmstatus']} ver={r['ver']}"
                  + ("  *DM살아있음" if r['ver'] in (2, 3) else ""))
            if r['ver'] in (2, 3):
                live.append('prot ' + r['prot'])
        print("VERDICT:", f"DM_LIVE ({live[0]})" if live else "DM_ABSENT_ALL")
        print("---8<---")
        return 0 if live else 6

    if a.dm:
        print(f"\n{'=' * 70}\n [DM] ROM 이 가리키는 곳에 DM 이 응답하나\n{'=' * 70}")
        print("  dmstatus.version 유효값: 2(0.13) 또는 3(1.0).")
        print("  14(0xE) 가 나오면 그건 default slave 라인 0xEAFFFFFE 다 — 부재.\n")
        r0 = session(a, 0)
        if not r0.get('ok'):
            print("---8<---")
            print(f"무효 세션 (AP일치={r0.get('ap_match')}/6) — 다시 실행")
            print("---8<---")
            return 6
        print("---8<---")
        live = []
        for r in r0.get('dm', []):
            g = r['regs']
            v = r.get('ver')
            mark = ('★DM살아있음' if v in (2, 3) else
                    '(default라인)' if r.get('default') else '')
            print(f"{r['ap']} {r['how']:12s} {r['addr']} "
                  f"dmcontrol={g['dmcontrol']} dmstatus={g['dmstatus']} "
                  f"ver={v} sbcs={g['sbcs']} {mark}")
            if v in (2, 3):
                live.append(r)
        print("VERDICT:", f"DM_LIVE ({live[0]['addr']})" if live else "DM_ABSENT")
        print("---8<---")
        return 0 if live else 6

    if a.rom:
        print(f"\n{'=' * 70}\n [ROM] BASE 전체 + ROM 테이블 CIDR\n{'=' * 70}")
        print("  CIDR 이 0D1005B1 이면 진짜 CoreSight ROM → 엔트리를 믿어도 된다.")
        print("  아니면 0x81480003 은 우연히 그렇게 생긴 버스 값일 뿐이다.\n")
        r0 = session(a, 0)
        if not r0.get('ok'):
            print("---8<---")
            print(f"무효 세션 (AP일치={r0.get('ap_match')}/6) — 다시 실행")
            print("---8<---")
            return 6
        print("---8<---")
        for r in r0.get('rom', []):
            if 'rom' not in r:
                print(f"{r['ap']} BASE={r['BASE']} (읽기 실패)")
                continue
            print(f"{r['ap']} BASE={r['BASE']} P={int(r['P'])} rom={r['rom']} "
                  f"CID={r['CID']}{' ★진짜' if r['CID_OK'] else ''} "
                  f"class={r.get('class')} ent={','.join(r['ent'])}")
        good = [r for r in r0.get('rom', []) if r.get('CID_OK')]
        print("VERDICT:", f"ROM_FOUND ({len(good)}개 AP)" if good else "NO_CORESIGHT_ROM")
        print("---8<---")
        return 0 if good else 6

    if a.replay:
        print(f"\n{'=' * 70}\n [REPLAY] f45f0ca 가 기록한 성공 설정 재생"
              f"\n{'=' * 70}")
        print("  mode=0 / TIF=7 / 10MHz / AddAP 0..5 / APBAPToUse=0 / device=RISC-V")
        print("  TAP 스크립트 없음. 핸들 하나로 CoreBase 를 바꿔 2회 시도.")
        print("  당시 실측: DPIDR=6BA0009D, CTRL=F0000000, 2회차에서 connect 성공\n")
        print("---8<---")
        rs = replay(a)
        for r in rs:
            if 'fatal' in r:
                print("FATAL", r['fatal'])
                continue
            print(f"{r['attempt']}) CoreBase={r['corebase']} "
                  f"connect={'O' if r.get('connect') else 'X'} "
                  f"DPIDR={r.get('DPIDR')} CTRL={r.get('CTRL')} "
                  f"AP일치={r.get('ap_match')}/6"
                  + (f"  err={r['err']}" if r.get('err') else ""))
        good = [r for r in rs if r.get('ap_match', 0) >= AP_GATE_MIN]
        conn = [r for r in rs if r.get('connect')]
        print("VERDICT:", "REPLAY_OK" if good else
                          "CONNECT_ONLY" if conn else "REPLAY_FAILED")
        print("---8<---")
        return 0 if good else 6

    if a.link:
        print(f"\n{'=' * 70}\n [LINK] 물리 계층 — 속도를 낮춰본다"
              f"\n{'=' * 70}")
        print("  AP IDR 이 실행마다 몇 개씩 맞았다 안 맞았다 한다.")
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
                rs = [session(a, i) for i in range(min(a.sessions, 3))]
                got = [r.get('ap_match', 0) for r in rs]
                hit = sum(1 for g in got if g >= AP_GATE_MIN)
                print(f"mode={mode} {spd:>5d}kHz  AP일치 "
                      + "/".join(str(g) for g in got) + " (of 6)"
                      + (f"  ★ 통과 {hit}/{len(got)}" if hit else ""))
                if hit and not found:
                    found = f"mode={mode} {spd}kHz"
                time.sleep(0.3)
        print("VERDICT:", f"FOUND ({found})" if found else "LINK_UNSTABLE")
        if not found:
            print(f"  어느 속도에서도 AP IDR 이 {AP_GATE_MIN}개 이상 안 맞는다.")
            print("  → 타깃 전원 사이클 / cJTAG 배선·풀업 / 프로브 케이블 순으로 본다.")
        print("---8<---")
        return 0 if found else 6

    if a.recover:
        print(f"\n{'=' * 70}\n [RECOVER] AP IDR 일치({AP_GATE_MIN}/6 이상) 조건 탐색"
              f"\n{'=' * 70}")
        print("  브링업 이후 바뀐 것을 전부 되돌려 본다:")
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
                    got.append(r.get('ap_match', 0))
                    time.sleep(0.25)
                hit = sum(1 for g in got if g >= AP_GATE_MIN)
                tag = (f"script={'X' if no_script else 'O'} mode={mode} "
                       f"cmds={'full' if full else 'min'} dev={dev}")
                print(f"{tag}  AP일치={'/'.join(str(g) for g in got)}"
                      + (f"   ★ 통과 {hit}/{len(got)}" if hit else ""))
                if len(set(got)) > 1:
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
            print(f"★ AP IDR 이 {AP_GATE_MIN}/6 이상 맞는 세션부터 확보해야 한다.")
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

    bad = [r for r in runs if not r.get('ok')]
    if bad:
        print(f"\n⚠⚠ 무효 세션 {len(bad)}/{a.sessions} (AP IDR 일치 "
              + "/".join(str(r.get('ap_match', 0)) for r in bad)
              + f", 기준 {1 if a.loose else AP_GATE_MIN}/6) — "
              "그 세션의 값은 **전부 무효**다. 해석하지 말 것.")
    print(f"ok={len(ok)}/{a.sessions} AP일치={(last or {}).get('ap_match')}/6 "
          f"DPIDR={(last or {}).get('DPIDR')} "
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
