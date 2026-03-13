#!/usr/bin/env python3
"""DP CTRL/STAT CSYSPWRUPREQ 클리어 검증 스크립트.

J-Link SWD 연결 상태에서 ARM SW-DP CTRL/STAT 레지스터의 CSYSPWRUPREQ(bit30)를
소프트웨어로 클리어하여 SSD가 실제 PM 상태(L1/L1.2/D3)에 진입하는지 확인.

PMU 전류 변화로 판단:
  [2] write 직후 전류 하락  → CSYSPWRUPREQ 클리어 효과 있음
  [3] halt() 후에도 유지    → 퍼저 통합 가치 높음 (이상적)
  [3] halt() 후 전류 재상승 → J-Link DLL이 halt() 시 CSYSPWRUPREQ 재설정함
                              (퍼저 통합 효과 제한적 — halt 사이 구간만 PM 진입)

사용:
    sudo python3 dp_ctrl_test.py --device Cortex-R8 --speed 4000
"""
import argparse
import time
import sys

try:
    import pylink
except ImportError:
    print("pylink-square 가 설치되지 않았습니다: pip install pylink-square")
    sys.exit(1)

# DP CTRL/STAT 레지스터 (DP bank 0, address 0x04)
_DP_CTRL_STAT = 4

# CSYSPWRUPREQ=0, CDBGPWRUPREQ=1, ORUNDETECT=1
# bit28=1 (CDBGPWRUPREQ): DAP/CoreSight 전원 유지 → halt()/read_reg() 계속 동작
# bit30=0 (CSYSPWRUPREQ): 시스템 도메인 sleep 허용 → CPU WFI → ASPM idle → PM 진입
_CTRL_CSYS_OFF  = 0x10000001
# CSYSPWRUPREQ=1, CDBGPWRUPREQ=1, ORUNDETECT=1 (원래 J-Link connect 상태)
_CTRL_CSYS_ON   = 0x50000001


def read_dp_ctrl(jl: pylink.JLink) -> int:
    """DP CTRL/STAT 현재 값 읽기."""
    try:
        return jl.coresight_read(_DP_CTRL_STAT, ap=False)
    except Exception as e:
        return -1


def step(msg: str) -> None:
    print(f"\n{msg}")
    input("    PMU 전류 확인 후 Enter ▶ ")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--device', default='Cortex-R8', help='J-Link 타겟 디바이스명')
    p.add_argument('--speed',  type=int, default=4000, help='JTAG/SWD 속도 (kHz)')
    p.add_argument('--auto',   action='store_true',
                   help='Enter 없이 자동 진행 (각 단계 3초 대기)')
    args = p.parse_args()

    wait = (lambda msg: (print(f"\n{msg}"), time.sleep(3))) if args.auto \
          else (lambda msg: step(msg))

    jl = pylink.JLink()
    jl.open()
    jl.set_tif(pylink.enums.JLinkInterfaces.SWD)
    jl.connect(args.device, speed=args.speed)
    print(f"[J-Link] Connected: {args.device} @ {args.speed}kHz")

    ctrl = read_dp_ctrl(jl)
    print(f"[Info] DP CTRL/STAT 초기값: 0x{ctrl:08X}" if ctrl >= 0
          else "[Info] DP CTRL/STAT 읽기 실패 (계속 진행)")

    # ── Step 1: 기준 전류 ─────────────────────────────────────────────────
    wait("[1] 연결 직후 — PMU 전류 기준값 확인 (예상: ~480mA)")

    # ── Step 2: CSYSPWRUPREQ 클리어 ───────────────────────────────────────
    try:
        jl.coresight_write(_DP_CTRL_STAT, _CTRL_CSYS_OFF, ap=False)
        ctrl = read_dp_ctrl(jl)
        print(f"    → CTRL/STAT 기록: 0x{_CTRL_CSYS_OFF:08X}  "
              f"현재값: {'0x{:08X}'.format(ctrl) if ctrl >= 0 else 'READ_FAIL'}")
    except Exception as e:
        print(f"    [ERROR] coresight_write 실패: {e}")
        print("    pylink 버전이 ap= 파라미터를 지원하지 않을 수 있음.")
        print("    DLL 직접 호출로 재시도...")
        try:
            jl._dll.JLINK_CORESIGHT_WriteDP(1, _CTRL_CSYS_OFF)
            print(f"    → DLL JLINK_CORESIGHT_WriteDP(1, 0x{_CTRL_CSYS_OFF:08X}) 성공")
        except Exception as e2:
            print(f"    [ERROR] DLL 직접 호출도 실패: {e2}")

    wait("[2] CSYSPWRUPREQ=0 기록 직후 — PMU 전류 확인\n"
         "    목표: 480mA → 285mA 수준으로 하락 (CDBGPWRUPREQ=1이므로 완전 9mA는 아님)")

    # ── Step 3: halt() 후 전류 변화 확인 ─────────────────────────────────
    try:
        jl._dll.JLINKARM_Halt()
        time.sleep(0.1)
        ctrl_after = read_dp_ctrl(jl)
        print(f"    halt() 완료. CTRL/STAT: {'0x{:08X}'.format(ctrl_after) if ctrl_after >= 0 else 'READ_FAIL'}")
        if ctrl_after >= 0:
            csys = (ctrl_after >> 30) & 1
            print(f"    CSYSPWRUPREQ = {csys}  "
                  + ("← DLL이 halt() 시 재설정함 (PM 효과 제한적)" if csys else
                     "← 유지됨! 퍼저 통합 효과 높음 ✓"))
    except Exception as e:
        print(f"    halt() 예외: {e}")

    wait("[3] halt() 후 — PMU 전류 확인\n"
         "    전류 유지 → DLL halt() 시 CSYSPWRUPREQ 재설정 안함 (이상적)\n"
         "    전류 재상승 → DLL이 재설정함 (NVMe 명령 처리 중엔 효과 있을 수 있음)")

    # ── Step 4: resume + 복원 ─────────────────────────────────────────────
    try:
        jl._dll.JLINKARM_Go()
    except Exception:
        pass
    try:
        jl.coresight_write(_DP_CTRL_STAT, _CTRL_CSYS_ON, ap=False)
        print(f"\n[4] DP CTRL/STAT 복원: 0x{_CTRL_CSYS_ON:08X}")
    except Exception:
        try:
            jl._dll.JLINK_CORESIGHT_WriteDP(1, _CTRL_CSYS_ON)
            print(f"\n[4] DP CTRL/STAT 복원 (DLL): 0x{_CTRL_CSYS_ON:08X}")
        except Exception as e:
            print(f"\n[4] 복원 실패: {e}")

    jl.close()
    print("\n[완료] J-Link 연결 종료.")
    print("\n결과 해석:")
    print("  [2]에서 전류 하락 + [3]에서 halt() 후도 유지 → --pm-dp-ctrl 옵션 퍼저에 통합 권장")
    print("  [2]에서 전류 하락 + [3]에서 halt() 후 재상승 → 통합 효과 제한적, 하드웨어 스위치 검토")
    print("  [2]에서 전류 변화 없음                        → coresight_write API 문제 또는 SSD 특성")


if __name__ == '__main__':
    main()
