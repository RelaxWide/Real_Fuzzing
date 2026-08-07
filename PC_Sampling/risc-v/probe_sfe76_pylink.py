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

# T32 SYStem.CONFIG 의 AP base — "DP:0x10000" 을 글자 그대로 DP 주소로 해석(ADIv6)
#   APBAP1=0x10000 APBAP2=0x20000 AXIAP1=0x30000 AHBAP1=0x40000
#   APBAP3=0x50000 APBAP4=0x60000
AP_BASES = [("APBAP1", 0x10000), ("APBAP2", 0x20000), ("AXIAP1", 0x30000),
            ("AHBAP1", 0x40000), ("APBAP3", 0x50000), ("APBAP4", 0x60000)]

# DP 레지스터 인덱스
DP_IDR_ABORT = 0
DP_CTRL_STAT = 1
DP_SELECT    = 2
DP_RDBUFF    = 3

# 알려진 TIF 값 (pylink JLinkInterfaces). cJTAG 은 여기 없을 수 있다.
KNOWN_TIF = {0: 'JTAG', 1: 'SWD', 2: 'BDM3', 3: 'FINE',
             4: 'ICSP', 5: 'SPI', 6: 'C2'}



def is_err(v):
    """pylink 가 음수 에러코드를 그대로 반환하는 경우가 있다.
    DPIDR 은 bit0 이 RAO(항상 1) 이므로 0x80000000 같은 값은 데이터일 수 없다."""
    return v is None or v < 0 or v in (0x80000000, 0xFFFFFFFF)


def hx(v):
    if v is None:
        return "(예외)"
    if v < 0:
        return f"0x{v & 0xFFFFFFFF:08X}  [음수 {v} = API 에러]"
    return f"0x{v:08X}"


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
        return [forced]

    try:
        mask = jl.supported_tifs()
    except Exception as e:
        print(f"  supported_tifs() 예외: {e}  → JTAG(0) 로 진행")
        return [0]

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
        print("    → DPIDR 이 읽힐 때까지 후보를 차례로 시도한다.")
        return unknown

    print("\n  ⚠ 알려진 TIF 밖의 값이 없다 = pylink 로 cJTAG 선택 불가할 수 있음")
    print("    → JLinkScript 경로로 되돌아가야 한다. 일단 JTAG(0) 로 계속 진행.")
    return [0]


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


def stage3_coresight(jl, tif_init):
    """CoreSight 초기화.

    perform_tif_init=True 는 인터페이스를 재초기화하는데, 그게 **cJTAG 활성화
    상태를 날릴 수 있다**(2선 모드 → 4선 복귀). 스캔은 도는데 데이터가 전부 0 인
    지금 증상과 부합해서 False 도 시도한다.
    """
    head(f"[3] CoreSight 초기화 (perform_tif_init={tif_init})")
    try:
        sig = inspect.signature(jl.coresight_configure)
        print(f"  coresight_configure{sig}")
    except Exception:
        pass

    base = {'ir_pre': 0, 'dr_pre': 0, 'ir_post': 0, 'dr_post': 0, 'ir_len': 4}
    for kwargs in (dict(base, perform_tif_init=tif_init), base, {}):
        try:
            jl.coresight_configure(**kwargs)
            print(f"  ✅ coresight_configure({kwargs or '기본값'}) 성공")
            return True
        except Exception as e:
            print(f"  ❌ coresight_configure(...) 실패: {e}")
    return False


def stage4_dp(jl):
    """DPIDR + 디버그 전원 인가. 여기가 J-Link 이 건너뛰던 단계다."""
    head("[4] DP 접근 — ARM DAP 인지 + 디버그 전원")

    sub("DPIDR")
    idr = dp_read(jl, DP_IDR_ABORT)
    print(f"  DPIDR = {hx(idr)}")
    if is_err(idr) or idr in (0, 1) or (idr & 1) == 0:
        print("  ❌ 무효값. DP 와 통신이 안 되고 있다.")
        print("     (DPIDR 은 bit0 = RAO 라 항상 1. 짝수면 데이터가 아니다)")
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

    if is_err(ctrl):
        print("  ❌ 읽기 실패")
        return False
    if (ctrl & 0xA0000000) == 0xA0000000:
        print("  ✅ 디버그 전원 ACK (CSYSPWRUPACK|CDBGPWRUPACK)")
    else:
        print("  ❌ 전원 ACK 없음 → 디버그 도메인 게이팅/인증 의심. 벤더 문의 대상.")
    if ctrl & 0x000000A0:
        print("  ⚠ STICKYERR/STICKYORUN — 접근이 거부되고 있다")
    return True


def ap_read_at(jl, ap_addr, offset):
    """ADIv6 방식 — AP 를 '주소'로 지정해 레지스터를 읽는다.

    ADIv6 는 ADIv5 의 APSEL(8비트 선택자)를 버리고 AP 를 시스템 주소로 지정한다.
    T32 의 `APBAP1.Base DP:0x10000` 표기가 바로 이 주소다.
    SELECT[31:4] = ADDR[31:4] 를 쓰고, 레지스터는 offset 의 A[3:2] 로 고른다.
    """
    if not dp_write(jl, DP_SELECT, (ap_addr + offset) & 0xFFFFFFF0):
        return None
    return ap_read(jl, (offset >> 2) & 0x3)


def stage5_aps_adiv6(jl):
    """ADIv6 주소 기반 AP 접근 — T32 base 값을 그대로 사용."""
    head("[5b] AP 접근 — ADIv6 주소 방식 (T32 base 값 사용)")
    types = {1: 'AMBA AHB', 2: 'AMBA APB', 4: 'AMBA AXI', 8: 'AMBA APB4'}
    live = []
    for name, base in AP_BASES:
        idr = ap_read_at(jl, base, 0xFC)          # AP IDR
        if is_err(idr) or idr == 0:
            print(f"  {name} @0x{base:05X}: (없음)  raw={hx(idr)}")
            continue
        t = types.get(idr & 0xF, f"type=0x{idr & 0xF:X}")
        print(f"  {name} @0x{base:05X}: IDR={hx(idr)}  {t}")
        live.append((name, base))
    if live:
        print(f"\n  ✅ ADIv6 주소 방식으로 AP 발견: {[n for n, _ in live]}")
        print("     → T32 의 DP:0xN0000 은 APSEL 이 아니라 AP 주소였다")
    else:
        print("\n  ❌ 주소 방식으로도 AP 없음")
    return live


def stage6_mem_adiv6(jl, live):
    """ADIv6 AP 를 통해 코어 디버그 블록 읽기."""
    head("[6b] 코어 디버그 블록 (ADIv6 경로)")
    if not live:
        print("  살아있는 AP 가 없어 건너뜀")
        return
    for name, base in live:
        for lbl, addr in (("A(hcore 등)", COREDEBUG_BASE_A), ("B(Ncore)", COREDEBUG_BASE_B)):
            for csw in CSW_CANDIDATES:
                if is_err(ap_read_at(jl, base, 0x00)):     # CSW 읽기 확인
                    continue
                dp_write(jl, DP_SELECT, (base + 0x00) & 0xFFFFFFF0)
                ap_write(jl, 0, csw)                        # CSW
                dp_write(jl, DP_SELECT, (base + 0x04) & 0xFFFFFFF0)
                ap_write(jl, 1, addr)                       # TAR
                dp_write(jl, DP_SELECT, (base + 0x0C) & 0xFFFFFFF0)
                cid0 = ap_read(jl, 3)                       # DRW
                if is_err(cid0):
                    continue
                print(f"  {name} base={lbl} CSW={hx(csw)}  CIDR0(+0xFF0) 영역 = {hx(cid0)}")
                break


def stage5_aps(jl):
    """ADIv5 APSEL 0~7 열거."""
    head("[5a] AP 열거 — ADIv5 APSEL 방식")
    types = {1: 'AMBA AHB', 2: 'AMBA APB', 4: 'AMBA AXI'}
    live = []
    for ap in range(8):
        if not dap_select(jl, ap, 0xF):     # IDR = 뱅크 0xF, 인덱스 3
            continue
        idr = ap_read(jl, 3)
        if is_err(idr) or idr == 0:
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
                if is_err(cid0):
                    continue
                dev = ap_mem_read32(jl, ap, base + 0xFCC, csw)
                print(f"  AP{ap} base={name} CSW={hx(csw)}")
                print(f"      CIDR0(+0xFF0)  = {hx(cid0)}")
                print(f"      DEVTYPE(+0xFCC)= {hx(dev)}")
                if (cid0 & 0xFF) == 0x0D:
                    print("      ✅ CoreSight 컴포넌트 확정 — 주소 정확")
                    if not is_err(dev) and (dev & 0xFF) == 0x21:
                        print("      ★ DEVTYPE=0x21 → 트레이스 싱크(버퍼)!")
                break


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tif', type=int, default=None, help='TIF 값 직접 지정 (cJTAG 후보)')
    ap.add_argument('--speed', type=int, default=10000, help='kHz (기본 10000 — 낮추면 cJTAG 실패)')
    ap.add_argument('--device', default='RISC-V', help='connect() 시도용 장치명 (실패해도 무방)')
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
        candidates = stage1_tifs(jl, args.tif)
        ok = None
        # (TIF, perform_tif_init, connect 선행) 조합을 훑는다
        for tif in candidates:
            for tif_init in (True, False):
                for do_conn in (False, True):
                    tag = f"TIF={tif} tif_init={tif_init} connect={do_conn}"
                    print(f"\n{'#' * 62}\n#  {tag}\n{'#' * 62}")
                    if not stage2_connect(jl, tif, args.speed):
                        continue
                    if do_conn:
                        try:
                            jl.connect(args.device)
                            print(f"  ✅ connect('{args.device}') 성공")
                        except Exception as e:
                            print(f"  ⚠ connect('{args.device}') 실패(무시하고 진행): {e}")
                    if not stage3_coresight(jl, tif_init):
                        continue
                    if stage4_dp(jl):
                        ok = tag
                        break
                    print(f"  {tag}: DP 접근 실패")
                if ok:
                    break
            if ok:
                break

        if ok is None:
            print(f"\n  ❌ 모든 조합에서 DP 접근 실패 (후보 TIF {candidates})")
            print("     → DPIDR 이 한 번도 안 읽혔다. SEGGER 문의 단계.")
            return
        print(f"\n  ✅ 성공 조합: {ok}")
        live = stage5_aps(jl)
        if live:
            stage6_mem(jl, live)
        else:
            print("\n  APSEL 방식 실패 → ADIv6 주소 방식으로 재시도")
            live6 = stage5_aps_adiv6(jl)
            stage6_mem_adiv6(jl, live6)
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
    print("  [5a] APSEL 실패 + [5b] 주소 성공 → ADIv6 확정 (T32 DP:0xN0000 = AP 주소)")
    print("  [5a][5b] 둘 다 실패 → AP 주소 자체가 다름. 벤더 문의")
    print("  [6] CIDR0 하위=0x0D → CoreSight 확정, 주소 정확 (다음은 RISC-V DM 탐색)")


if __name__ == '__main__':
    main()
