#!/usr/bin/env python3
"""SF-E76 (RISC-V) cJTAG + ARM DAP 연결 진단 — pylink 판.

배경 (실측):
  - cJTAG 10MHz 에서 TAP 응답 확인: TotalIRLen=4, IRPrint=0x01 (= ARM DAP 서명)
  - 그러나 J-Link 이 IDCODE 0x00000001 을 "Unknown device" 로 보고 →
    "Assuming RISC-V TAP with DTM setup" 오판 → CPU could not be halted
  - 실제 토폴로지: cJTAG → ARM DP → AP → APB → RISC-V DM  (T32 설정 기준)
  - JLinkScript 판(SF_E76_cJTAG_probe.JLinkScript)은 모든 CoreSight 호출이
    0x80000000(= INT_MIN, API 에러)을 반환해 아무것도 알아내지 못했다.
    → 에러가 보이는 pylink 로 다시 시도한다.

목적: "연결"이 아니라 **어느 단계에서 끊기는지** 확정하는 것.

사용법:
  sudo /home/ssd/gdbfuzz/.venv/bin/python3 probe_sfe76_pylink.py
  sudo ... probe_sfe76_pylink.py --tif 7          # TIF 값을 직접 지정
  sudo ... probe_sfe76_pylink.py --speed 10000    # 기본 10MHz (낮추면 cJTAG 실패)
"""

import argparse
import inspect
import sys
import time

try:
    import pylink
except ImportError:
    sys.exit("pylink 없음 →  pip3 install pylink-square\n"
             "  (venv 에 없고 시스템 python3 에 있는 경우가 있다. 둘 다 시도해볼 것)")

if not hasattr(pylink, 'JLink'):
    sys.exit("잘못된 pylink 패키지. PyPI 에 동명이인이 있다 →  pip3 install pylink-square")


# ── T32 스크립트에서 확보한 값 ────────────────────────────────────────
COREDEBUG_BASE_A = 0x81480000   # hcore / CMCore / Fcore0 / QCore
COREDEBUG_BASE_B = 0x81481000   # Ncore

# MEM-AP CSW: 32bit 접근 + DbgSwEnable. 전부 0 이면 다른 값도 시도해볼 것.
CSW_CANDIDATES = [0x80000002, 0x23000052, 0x00000002]

# DP 레지스터 인덱스
DP_IDR_ABORT = 0
DP_CTRL_STAT = 1
DP_SELECT    = 2
DP_RDBUFF    = 3

# 알려진 TIF 값 (pylink JLinkInterfaces). cJTAG 은 여기 없을 수 있다.
KNOWN_TIF = {0: 'JTAG', 1: 'SWD', 2: 'BDM3', 3: 'FINE',
             4: 'ICSP', 5: 'SPI', 6: 'C2'}

BAD = (None, 0x80000000, 0xFFFFFFFF)   # 의미 없는 반환값


def hx(v):
    return "(예외)" if v is None else f"0x{v & 0xFFFFFFFF:08X}"


def head(t):
    print(f"\n{'=' * 62}\n {t}\n{'=' * 62}")


def sub(t):
    print(f"\n--- {t} ---")


# ══════════════════════════════════════════════════════════════════════
# DP / AP 접근 헬퍼 — 모든 호출을 예외로 감싸 어디서 죽는지 보이게 한다
# ══════════════════════════════════════════════════════════════════════
def dp_read(jl, reg):
    try:
        return jl.coresight_read(reg, ap=False)
    except Exception as e:
        print(f"    !! DP read reg={reg} 예외: {e}")
        return None


def dp_write(jl, reg, val):
    try:
        jl.coresight_write(reg, val, ap=False)
        return True
    except Exception as e:
        print(f"    !! DP write reg={reg} 예외: {e}")
        return False


def ap_read(jl, reg):
    try:
        jl.coresight_read(reg, ap=True)      # AP 읽기는 파이프라인 → 첫 값 버림
        return jl.coresight_read(reg, ap=True)
    except Exception as e:
        print(f"    !! AP read reg={reg} 예외: {e}")
        return None


def ap_write(jl, reg, val):
    try:
        jl.coresight_write(reg, val, ap=True)
        return True
    except Exception as e:
        print(f"    !! AP write reg={reg} 예외: {e}")
        return False


def dap_select(jl, apsel, bank):
    return dp_write(jl, DP_SELECT, ((apsel & 0xFF) << 24) | ((bank & 0xF) << 4))


def ap_mem_read32(jl, apsel, addr, csw):
    """MEM-AP 를 통한 32비트 메모리 읽기."""
    if not dap_select(jl, apsel, 0x0):
        return None
    ap_write(jl, 0, csw)      # CSW
    ap_write(jl, 1, addr)     # TAR
    return ap_read(jl, 3)     # DRW


# ══════════════════════════════════════════════════════════════════════
def stage1_tifs(jl, forced):
    """지원 인터페이스 확인 — cJTAG 를 쓸 수 있나?"""
    head("[1] 지원 target interface (cJTAG 가능한가)")

    if forced is not None:
        print(f"  --tif {forced} 로 강제 지정됨")
        return forced

    try:
        mask = jl.supported_tifs()
    except Exception as e:
        print(f"  supported_tifs() 예외: {e}  → JTAG(0) 로 진행")
        return 0

    print(f"  지원 마스크 = 0x{mask:08X}")
    found = []
    for i in range(32):
        if mask & (1 << i):
            name = KNOWN_TIF.get(i, "??? (cJTAG 후보)")
            print(f"    TIF {i:2d} : {name}")
            found.append(i)

    unknown = [i for i in found if i not in KNOWN_TIF]
    if unknown:
        print(f"\n  ★ 이름 없는 TIF: {unknown}")
        print("    JLinkExe 의 'si cJTAG' 가 동작했으므로 이 중 하나가 cJTAG 다.")
        print(f"    → 우선 {unknown[0]} 로 시도. 아니면 --tif 로 바꿔가며 재실행.")
        return unknown[0]

    print("\n  ⚠ 알려진 TIF 밖의 값이 없다 = pylink 로 cJTAG 선택 불가할 수 있음")
    print("    → JLinkScript 경로로 되돌아가야 한다. 일단 JTAG(0) 로 계속 진행.")
    return 0


def stage2_connect(jl, tif, speed):
    head(f"[2] 인터페이스 선택 (TIF={tif}) + 속도 {speed}kHz")
    try:
        jl.set_tif(tif)
        print(f"  ✅ set_tif({tif}) 성공")
    except Exception as e:
        print(f"  ❌ set_tif({tif}) 실패: {e}")
        return False
    try:
        jl.set_speed(speed)
        print(f"  ✅ set_speed({speed}) 성공")
    except Exception as e:
        print(f"  ⚠ set_speed 실패: {e}")
    return True


def stage3_coresight(jl):
    head("[3] CoreSight 초기화")
    try:
        sig = inspect.signature(jl.coresight_configure)
        print(f"  coresight_configure{sig}")
    except Exception:
        pass

    # 단일 TAP, IRLen=4 (실측 TotalIRLen=4)
    for kwargs in ({'ir_pre': 0, 'dr_pre': 0, 'ir_post': 0, 'dr_post': 0, 'ir_len': 4},
                   {}):
        try:
            jl.coresight_configure(**kwargs)
            print(f"  ✅ coresight_configure({kwargs or '기본값'}) 성공")
            return True
        except Exception as e:
            print(f"  ❌ coresight_configure({kwargs or '기본값'}) 실패: {e}")
    return False


def stage4_dp(jl):
    """DPIDR + 디버그 전원 인가. 여기가 J-Link 이 건너뛰던 단계다."""
    head("[4] DP 접근 — ARM DAP 인지 + 디버그 전원")

    sub("DPIDR")
    idr = dp_read(jl, DP_IDR_ABORT)
    print(f"  DPIDR = {hx(idr)}")
    if idr in BAD or idr == 0 or idr == 1:
        print("  ❌ 무효값. DP 와 통신이 안 되고 있다.")
        print("     → cJTAG 스캔 포맷 불일치 의심 (T32: NOKEEPER USEOAC). SEGGER 문의 대상.")
        return False
    print("  ✅ 유효한 DPIDR — ARM DAP 확정")
    print(f"     DESIGNER=0x{(idr >> 12) & 0xFFF:03X}  PARTNO=0x{(idr >> 20) & 0xFF:02X}"
          f"  VERSION={(idr >> 12) & 0xF}")

    sub("sticky 클리어 + 디버그 전원 인가")
    dp_write(jl, DP_IDR_ABORT, 0x0000001E)          # ABORT
    dp_write(jl, DP_CTRL_STAT, 0x50000000)          # CSYSPWRUPREQ|CDBGPWRUPREQ
    print("  CTRL/STAT ← 0x50000000  (기존 ARM 제품의 dpreg 4 0x50000000 과 동일)")

    ctrl = None
    for _ in range(10):
        time.sleep(0.01)
        ctrl = dp_read(jl, DP_CTRL_STAT)
        if ctrl is not None and (ctrl & 0xA0000000) == 0xA0000000:
            break
    print(f"  CTRL/STAT = {hx(ctrl)}")

    if ctrl in BAD:
        print("  ❌ 읽기 실패")
        return False
    if (ctrl & 0xA0000000) == 0xA0000000:
        print("  ✅ 디버그 전원 ACK (CSYSPWRUPACK|CDBGPWRUPACK)")
    else:
        print("  ❌ 전원 ACK 없음 → 디버그 도메인 게이팅/인증 의심. 벤더 문의 대상.")
    if ctrl & 0x000000A0:
        print("  ⚠ STICKYERR/STICKYORUN — 접근이 거부되고 있다")
    return True


def stage5_aps(jl):
    """APSEL 0~7 열거. T32 추론(DP:0xN0000 → AP N) 검증."""
    head("[5] AP 열거 (APSEL 0~7)")
    types = {1: 'AMBA AHB', 2: 'AMBA APB', 4: 'AMBA AXI'}
    live = []
    for ap in range(8):
        if not dap_select(jl, ap, 0xF):     # IDR = 뱅크 0xF, 인덱스 3
            continue
        idr = ap_read(jl, 3)
        if idr in BAD or idr == 0:
            print(f"  APSEL {ap}: (없음)   raw={hx(idr)}")
            continue
        t = types.get(idr & 0xF, f"type=0x{idr & 0xF:X}")
        print(f"  APSEL {ap}: IDR={hx(idr)}  {t}")
        live.append(ap)
    if not live:
        print("\n  ❌ 살아있는 AP 없음 → [4] 전원 단계부터 실패한 것")
    else:
        print(f"\n  ✅ 살아있는 AP: {live}")
        print("     T32 추론(APBAP1=AP1, APBAP2=AP2, AXIAP1=AP3, AHBAP1=AP4,")
        print("     APBAP3=AP5, APBAP4=AP6)과 대조할 것")
    return live


def stage6_mem(jl, live):
    """코어 디버그 블록 접근 — CoreSight ID 로 주소 검증."""
    head("[6] 코어 디버그 블록 (0x81480000 / 0x81481000)")
    if not live:
        print("  살아있는 AP 가 없어 건너뜀")
        return

    for ap in live:
        for name, base in (("A(hcore 등)", COREDEBUG_BASE_A),
                           ("B(Ncore)", COREDEBUG_BASE_B)):
            for csw in CSW_CANDIDATES:
                cid0 = ap_mem_read32(jl, ap, base + 0xFF0, csw)
                if cid0 in BAD or cid0 is None:
                    continue
                dev = ap_mem_read32(jl, ap, base + 0xFCC, csw)
                print(f"  AP{ap} base={name} CSW={hx(csw)}")
                print(f"      CIDR0(+0xFF0)  = {hx(cid0)}")
                print(f"      DEVTYPE(+0xFCC)= {hx(dev)}")
                if (cid0 & 0xFF) == 0x0D:
                    print("      ✅ CoreSight 컴포넌트 확정 — 주소 정확")
                    if dev is not None and (dev & 0xFF) == 0x21:
                        print("      ★ DEVTYPE=0x21 → 트레이스 싱크(버퍼)!")
                break


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tif', type=int, default=None, help='TIF 값 직접 지정 (cJTAG 후보)')
    ap.add_argument('--speed', type=int, default=10000, help='kHz (기본 10000 — 낮추면 cJTAG 실패)')
    args = ap.parse_args()

    head("SF-E76 cJTAG + ARM DAP 진단 (pylink)")
    jl = pylink.JLink()
    try:
        jl.open()
    except Exception as e:
        sys.exit(f"J-Link open 실패: {e}\n  (다른 프로그램이 J-Link 을 점유 중인지 확인)")

    print(f"  J-Link  : {jl.product_name}")
    print(f"  Serial  : {jl.serial_number}")
    try:
        print(f"  Firmware: {jl.firmware_version}")
    except Exception:
        pass

    try:
        tif = stage1_tifs(jl, args.tif)
        if not stage2_connect(jl, tif, args.speed):
            return
        if not stage3_coresight(jl):
            print("\n  CoreSight 초기화 실패 — 이후 단계는 의미 없음. 위 예외 메시지를 보고할 것.")
            return
        if not stage4_dp(jl):
            print("\n  DP 접근 실패 — [5][6] 건너뜀")
            return
        live = stage5_aps(jl)
        stage6_mem(jl, live)
    finally:
        try:
            jl.close()
        except Exception:
            pass

    head("판정 가이드")
    print("  [1] cJTAG TIF 못 찾음 → JLinkScript 경로로 복귀")
    print("  [3] 실패            → pylink API 사용법 문제. 예외 메시지가 핵심")
    print("  [4] DPIDR 무효      → cJTAG 스캔 포맷 (SEGGER 문의)")
    print("  [4] 전원 ACK 없음   → 디버그 도메인 게이팅/인증 (벤더 문의)")
    print("  [5] AP 없음         → 전원 또는 AP 매핑")
    print("  [6] CIDR0 하위=0x0D → CoreSight 확정, 주소 정확 (다음은 RISC-V DM 탐색)")


if __name__ == '__main__':
    main()
