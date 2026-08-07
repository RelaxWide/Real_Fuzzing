#!/usr/bin/env python3
"""SF-E76 — J-Link 연결 (SEGGER 공식 hybrid DAP 절차).

★ 근거: SEGGER KB "J-Link RISC-V" 가 우리 토폴로지를 그대로 문서화하고 있다.

    JTAG/SWD -> SWJ-DP -> APB-AP -> DMI registers

  그리고 명시적으로:
    "there is no ROM table scan available for RISC-V"
    "J-Link cannot auto-detect the AP location or DMI register positioning
     in hybrid designs"

  → **J-Link 은 이 구성을 자동 검출할 수 없다. 반드시 수동으로 알려줘야 한다.**
    지금까지 자동 검출이 전부 실패한 이유가 이것이다(우리 코드 문제가 아니었다).

  필요한 설정 (J-Link Command Strings):
    CORESIGHT_AddAP = Index=<i> Type=<T> Addr=<base>
    CORESIGHT_SetIndexAPBAPToUse = <i>      ← DMI 가 붙은 APB-AP
    CORESIGHT_SetCoreBaseAddr = <addr>      ← AP 주소공간 내 DMI 레지스터 위치
    SetcJTAGInitMode = <0|1|2>              ← cJTAG 활성화 시퀀스 변형

  Index 는 **J-Link 내부 AP 맵 번호**이지 하드웨어 APSEL 이 아니다.
  Addr 이 실제 CoreSight 주소공간 위치이고, 이게 T32 의
  `APBAP1.Base DP:0x10000` 값과 대응된다.

실측 전제 (앞선 진단에서 확정):
    cJTAG TIF=7, 10MHz  /  DP reg0=0x6BA0009D  /  CTRL/STAT=0xF0000000(ACK)

사용법:
    sudo python3 connect_sfe76.py                  # 전체 조합 탐색
    sudo python3 connect_sfe76.py --device RISC-V  # 장치명 지정
    sudo python3 connect_sfe76.py --cjtag 1        # cJTAG 모드 고정
"""

import argparse
import sys
import time

try:
    import pylink
except ImportError:
    sys.exit("pylink 없음 →  pip3 install pylink-square")

PROBE_VERSION = "2026-08-08.1  SEGGER hybrid-DAP 절차 (AddAP + APBAPToUse + CoreBaseAddr)"

# ── T32 SYStem.CONFIG 에서 가져온 값 ─────────────────────────────────
#   이름 → (CoreSight 주소공간 base, J-Link AP 타입)
AP_MAP = [
    ("APBAP1", 0x10000, "APB-AP"),
    ("APBAP2", 0x20000, "APB-AP"),
    ("AXIAP1", 0x30000, "AXI-AP"),
    ("AHBAP1", 0x40000, "AHB-AP"),
    ("APBAP3", 0x50000, "APB-AP"),
    ("APBAP4", 0x60000, "APB-AP"),
]

# T32 SYStem.CONFIG.COREDEBUG.Base — AP 주소공간 내 DMI 위치 후보
CORE_BASES = [
    ("hcore/CMCore/Fcore0/QCore", 0x81480000),
    ("Ncore", 0x81481000),
]

TIF_CJTAG = 7          # 실측으로 확인된 값
SPEED_KHZ = 10000      # 10MHz. 낮추면 cJTAG 활성화 실패

CJTAG_MODES = {
    0: "LONG_ACT_SEQ (J-Link 기본)",
    1: "SHORT_ACT_SEQ",
    2: "WILIOT_ACT_SEQ",
}


def head(t):
    print(f"\n{'=' * 66}\n {t}\n{'=' * 66}")


def ex(jl, cmd, quiet=False):
    """exec_command — 실패해도 계속 진행하되 결과를 남긴다."""
    try:
        r = jl.exec_command(cmd)
        if not quiet:
            print(f"    ok   {cmd}")
        return True
    except Exception as e:
        print(f"    FAIL {cmd}\n         -> {e}")
        return False


def setup(jl, cjtag_mode, apb_index, core_base):
    """SEGGER hybrid-DAP 절차. connect() 이전에 전부 끝내야 한다."""
    ex(jl, f"SetcJTAGInitMode = {cjtag_mode}", quiet=True)

    jl.set_tif(TIF_CJTAG)
    jl.set_speed(SPEED_KHZ)

    for i, (name, addr, typ) in enumerate(AP_MAP):
        ex(jl, f"CORESIGHT_AddAP = Index={i} Type={typ} Addr=0x{addr:X}", quiet=True)

    ok = ex(jl, f"CORESIGHT_SetIndexAPBAPToUse = {apb_index}")
    ok &= ex(jl, f"CORESIGHT_SetCoreBaseAddr = 0x{core_base:X}")
    return ok


def verify(jl):
    """연결 후 실제로 코어가 잡혔는지 확인."""
    info = []
    try:
        info.append(f"halted={jl.halted()}")
    except Exception as e:
        info.append(f"halted=? ({e})")
    try:
        info.append(f"core_id=0x{jl.core_id():08X}")
    except Exception:
        pass
    try:
        info.append(f"core_name={jl.core_name()}")
    except Exception:
        pass
    return "  ".join(info) if info else "(확인 불가)"


def attempt(jl, device, cjtag_mode, apb_index, core_base, core_label):
    name, addr, typ = AP_MAP[apb_index]
    print(f"\n{'-' * 66}")
    print(f" cJTAG={cjtag_mode}({CJTAG_MODES[cjtag_mode]})  "
          f"APB-AP=Index{apb_index}({name} @0x{addr:X})")
    print(f" CoreBase=0x{core_base:X} ({core_label})  device={device}")
    print(f"{'-' * 66}")

    if not setup(jl, cjtag_mode, apb_index, core_base):
        print("  설정 단계 실패 — 다음 조합")
        return False

    try:
        jl.connect(device, speed=SPEED_KHZ)
    except Exception as e:
        print(f"  connect 실패: {e}")
        return False

    print(f"  ★★★ connect 성공!  {verify(jl)}")
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--device', default='RISC-V',
                    help="J-Link 장치명. 실패하면 다른 이름 시도 (기본 RISC-V)")
    ap.add_argument('--cjtag', type=int, default=None, choices=[0, 1, 2],
                    help="cJTAG 활성화 모드 고정 (기본: 0,1,2 전부 시도)")
    ap.add_argument('--apb', type=int, default=None,
                    help="APB-AP 인덱스 고정 (0~5)")
    ap.add_argument('--first', action='store_true',
                    help="첫 성공에서 중단 (기본: 전수 탐색해 전체 맵을 만든다)")
    ap.add_argument('--harts', type=int, default=5,
                    help="각 성공 조합에서 시도할 하트 수 (기본 5)")
    args = ap.parse_args()

    head("SF-E76 J-Link 연결 — SEGGER hybrid DAP 절차")
    print(f"  version : {PROBE_VERSION}")
    print("\n  SEGGER KB(J-Link RISC-V) 근거:")
    print("    토폴로지  JTAG -> SWJ-DP -> APB-AP -> DMI registers")
    print("    \"no ROM table scan available for RISC-V\"")
    print("    \"cannot auto-detect the AP location or DMI register positioning\"")
    print("    => 수동 설정이 필수. 자동 검출 실패는 우리 코드 문제가 아니었다.")

    print("\n  AP 맵 (T32 SYStem.CONFIG 값):")
    for i, (n, a, t) in enumerate(AP_MAP):
        print(f"    Index={i}  {n:7s} Addr=0x{a:05X}  Type={t}")

    cjtag_list = [args.cjtag] if args.cjtag is not None else [0, 1, 2]
    apb_list = [args.apb] if args.apb is not None else range(len(AP_MAP))

    jl = pylink.JLink()
    try:
        jl.open()
    except Exception as e:
        sys.exit(f"J-Link open 실패: {e}\n  (다른 프로그램이 점유 중인지 확인)")
    print(f"\n  J-Link  : {jl.product_name}  SN={jl.serial_number}")

    # ★ 전수 탐색. 첫 성공에서 멈추면 '다른 코어는 어디 붙어 있나' 를 영영 모른다.
    #   실제로 0x81480000(hcore/CMCore/Fcore0/QCore)은 APBAP1 하나만 시도하고
    #   끝나버렸다 — 나머지 AP 뒤에 있을 수 있다.
    hits = []
    try:
        for cj in cjtag_list:
            for apb in apb_list:
                # APB-AP 로 등록된 것만 DMI 후보
                if AP_MAP[apb][2] != "APB-AP":
                    continue
                for label, base in CORE_BASES:
                    if attempt(jl, args.device, cj, apb, base, label):
                        hits.append((cj, apb, base, label))
                        if args.first:
                            raise StopIteration
                    time.sleep(0.2)
    except StopIteration:
        pass
    finally:
        try:
            jl.close()
        except Exception:
            pass

    head("결과")
    if hits:
        print(f"  ★ 연결 성공 조합 {len(hits)}개:\n")
        for cj, apb, base, label in hits:
            n, a, t = AP_MAP[apb]
            print(f"    cJTAG={cj}  APB=Index{apb}({n} @0x{a:X})  "
                  f"CoreBase=0x{base:X}  [{label}]")

        cj, apb, base, label = hits[0]
        n, a, t = AP_MAP[apb]
        print("\n  첫 조합 기준 v10.0 샘플러 설정:")
        print(f"      SetcJTAGInitMode = {cj}")
        print(f"      set_tif({TIF_CJTAG})   # cJTAG")
        print(f"      set_speed({SPEED_KHZ})")
        for i, (nn, aa, tt) in enumerate(AP_MAP):
            print(f"      CORESIGHT_AddAP = Index={i} Type={tt} Addr=0x{aa:X}")
        print(f"      CORESIGHT_SetIndexAPBAPToUse = {apb}   # {n} @0x{a:X}")
        print(f"      CORESIGHT_SetCoreBaseAddr = 0x{base:X}  # {label}")
        print(f"      connect('{args.device}')")

        # 어느 CoreBase 가 안 붙었는지 명시 — 코어 귀속 판단에 중요
        got = {b for _, _, b, _ in hits}
        for label, base in CORE_BASES:
            if base not in got:
                print(f"\n  ⚠ CoreBase 0x{base:X} ({label}) 은 **어떤 AP 로도 연결 실패**")
                print("     → 그 코어들이 리셋/정지 상태이거나, 주소·AP 가 다르다.")
                print("     NVMe 명령을 처리하는 코어가 여기 있으면 반드시 해결해야 한다.")
    else:
        print("  ✗ 모든 조합 실패.")
        print("\n  다음 확인 사항:")
        print("   1) --device 이름 — J-Link 이 아는 RISC-V 장치명이어야 한다.")
        print("      JLinkExe 에서 connect -> Device> ? 로 목록 확인 후 재시도")
        print("   2) CoreBaseAddr — T32 COREDEBUG.Base 가 DMI 위치가 맞는지")
        print("      (RISC-V 에서는 DM 의 DMI 레지스터 주소여야 한다)")
        print("   3) AP Addr — T32 의 DP:0xN0000 해석이 맞는지")
        print("   4) 멀티하트 — 코어 5개. RISCV_SetHartSel 이 필요할 수 있다")


if __name__ == '__main__':
    main()
