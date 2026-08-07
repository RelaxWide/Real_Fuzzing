#!/usr/bin/env python3
"""SF-E76 — 첫 connect 가 실패하는 **근본 원인** 규명.

재시도로 붙는 것은 정상이 아니다. 퍼저는 POR 복구·크래시 후 수백 번 재연결하므로
첫 시도 실패를 전제로 두면 운영 리스크다. 원인을 특정한다.

지금까지 확정된 것:
    A  setup 1회 -> connect 2회   2회차 성공   ← 이것만 됨
    B  setup 2회 -> connect 1회   실패          setup 이중적용 아님
    C  setup -> sleep -> connect  실패          시간(readiness) 아님
=> **connect 시도 자체가 "레지스터를 쓰는 일"을 한다.**

유력 가설 — RISC-V DM 의 dmactive:
    RISC-V Debug Spec 상 dmcontrol.dmactive 를 1 로 쓴 뒤 **되읽어 1이 될 때까지
    기다려야** DM 이 리셋에서 깨어난다. J-Link 이 dmactive=1 을 쓰고 기다리지 않고
    바로 haltreq 를 하면 "Error while halting CPU / Specific core setup failed" 가
    나고, 2차 connect 때는 이미 dmactive=1 이라 성공한다.
    이 가설은 A/B/C 를 전부 설명한다(B: setup 은 DM 미접촉, C: 시간으론 안 됨).

실험:
    D  세션 지속성 — 성공 후 close/reopen 하고 1회 connect
         성공하면 상태가 **타깃**에 남는 것(dmactive 유력)
         실패하면 **DLL** 상태이거나 close 가 타깃을 리셋하는 것
    E  장치명 — 'RISC-V' 제네릭이 문제일 수 있다. 다른 이름으로 1회 connect
    F  하트 선택 — RISCV_SetHartSel 을 connect 前에 지정하면 1회로 붙나

사용법:
    sudo python3 diagnose_connect.py              # D, E, F
    sudo python3 diagnose_connect.py --only D
    sudo python3 diagnose_connect.py --devices "RISC-V,RV32,SiFive-E76"
"""

import argparse
import sys
import time

try:
    import pylink
except ImportError:
    sys.exit("pylink 없음 →  pip3 install pylink-square")

VERSION = "2026-08-07.5  첫 connect 실패 근본원인 (D/E/F)"

TIF_CJTAG  = 7
SPEED_KHZ  = 10000
CJTAG_MODE = 0
APB_INDEX  = 0
BASE       = 0x81480000
DEVICE     = 'RISC-V'

AP_MAP = [
    ("APBAP1", 0x10000, "APB-AP"), ("APBAP2", 0x20000, "APB-AP"),
    ("AXIAP1", 0x30000, "AXI-AP"), ("AHBAP1", 0x40000, "AHB-AP"),
    ("APBAP3", 0x50000, "APB-AP"), ("APBAP4", 0x60000, "APB-AP"),
]


def setup(jl, base, hart=None):
    try:
        jl.exec_command(f"SetcJTAGInitMode = {CJTAG_MODE}")
        jl.set_tif(TIF_CJTAG)
        jl.set_speed(SPEED_KHZ)
        for i, (n, a, t) in enumerate(AP_MAP):
            jl.exec_command(f"CORESIGHT_AddAP = Index={i} Type={t} Addr=0x{a:X}")
        jl.exec_command(f"CORESIGHT_SetIndexAPBAPToUse = {APB_INDEX}")
        jl.exec_command(f"CORESIGHT_SetCoreBaseAddr = 0x{base:X}")
        if hart is not None:
            jl.exec_command(f"RISCV_SetHartSel = {hart}")
        return True
    except Exception as e:
        print(f"      setup 실패: {e}")
        return False


def conn(jl, device, tag=""):
    try:
        jl.connect(device, speed=SPEED_KHZ)
        print(f"      connect{tag} ★ 성공")
        return True
    except Exception as e:
        print(f"      connect{tag} 실패: {e}")
        return False


def safe_resume(jl):
    """halt 로 남기지 않는다 — SSD 컨트롤러가 멈춘 채로 두면 NVMe 가 hang 한다."""
    for fn in ('restart', 'go'):
        try:
            getattr(jl, fn)()
            return
        except Exception:
            continue


def close(jl):
    try:
        if jl.halted():
            safe_resume(jl)
    except Exception:
        safe_resume(jl)
    try:
        jl.close()
    except Exception:
        pass
    time.sleep(0.5)


def fresh():
    jl = pylink.JLink()
    jl.open()
    return jl


# ══════════════════════════════════════════════════════════════════
def exp_d(base, device):
    """세션 지속성 — 상태가 타깃에 남나 DLL 에 남나."""
    print("\n[D] 세션 지속성")
    print("    1단계: 정상 절차(connect 2회)로 성공시킨다")
    jl = fresh()
    ok2 = False
    try:
        if not setup(jl, base):
            return None
        r1 = conn(jl, device, " 1회차")
        ok2 = r1 or conn(jl, device, " 2회차")
        if not ok2:
            print("    1단계 실패 — D 판정 불가")
            return None
    finally:
        close(jl)

    print("\n    2단계: close/reopen 후 **1회만** connect")
    jl = fresh()
    try:
        if not setup(jl, base):
            return None
        r = conn(jl, device, " (재연결 1회차)")
        return r
    finally:
        close(jl)


def exp_e(base, devices):
    """장치명 — 'RISC-V' 제네릭이 CPU setup 을 실패시키는 원인일 수 있다."""
    print("\n[E] 장치명 후보별 1회 connect")
    out = {}
    for dev in devices:
        print(f"\n    device = {dev!r}")
        jl = fresh()
        try:
            if not setup(jl, base):
                out[dev] = None
                continue
            out[dev] = conn(jl, dev, " 1회차")
        except Exception as e:
            print(f"      예외: {e}")
            out[dev] = None
        finally:
            close(jl)
    return out


def exp_f(base, device):
    """하트 선택을 connect 전에 지정하면 1회로 붙나."""
    print("\n[F] RISCV_SetHartSel 을 connect 前에 지정")
    out = {}
    for h in range(5):
        print(f"\n    hart = {h}")
        jl = fresh()
        try:
            if not setup(jl, base, hart=h):
                out[h] = None
                continue
            out[h] = conn(jl, device, " 1회차")
        except Exception as e:
            print(f"      예외: {e}")
            out[h] = None
        finally:
            close(jl)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--only', choices=['D', 'E', 'F'])
    ap.add_argument('--base', type=lambda x: int(x, 0), default=BASE)
    ap.add_argument('--device', default=DEVICE)
    ap.add_argument('--devices',
                    default="RISC-V,RV32,RV32IMAC,SiFive-E76,E76,Unspecified",
                    help='E 실험에서 시도할 장치명 (콤마 구분). '
                         'JLinkExe 의 Device> ? 목록에서 실제 이름을 찾아 넣을 것')
    args = ap.parse_args()

    print(f"\n{'=' * 64}\n 첫 connect 실패 — 근본원인 진단\n{'=' * 64}")
    print(f"  version : {VERSION}")
    print(f"  CoreBase: 0x{args.base:X}")
    print("  ※ 각 시도는 cold handle. halt 로 남기지 않도록 항상 resume 한다.")

    d = e = f = None
    if args.only in (None, 'D'):
        d = exp_d(args.base, args.device)
    if args.only in (None, 'E'):
        e = exp_e(args.base, [x.strip() for x in args.devices.split(',') if x.strip()])
    if args.only in (None, 'F'):
        f = exp_f(args.base, args.device)

    print(f"\n{'=' * 64}\n 판정\n{'=' * 64}")

    if d is not None:
        if d:
            print("  ★ [D] 재연결이 1회로 성공 → 상태가 **타깃**에 남는다.")
            print("      dmactive 가설 지지. 첫 connect 는 타깃 전원 사이클 직후에만 필요.")
            print("      => 퍼저는 세션 시작 시 1회만 예열하면 되고 재연결마다는 불필요.")
        else:
            print("  ★ [D] 재연결도 1회차 실패 → 상태가 **DLL/프로브** 쪽이거나")
            print("      close 가 타깃을 리셋한다. 매 연결마다 예열이 필요하다는 뜻.")

    if e:
        good = [k for k, v in e.items() if v]
        print(f"\n  [E] 1회 connect 성공한 장치명: {good if good else '없음'}")
        if good:
            print("      ★ 장치명이 원인이었다. 제네릭 'RISC-V' 프로파일의 CPU setup 이")
            print("        이 코어와 안 맞았던 것 → 그 이름을 쓰면 재시도 불필요.")
        else:
            print("      시도한 이름 모두 실패. JLinkExe 의 Device> ? 목록에서")
            print("      실제 RISC-V/SiFive 항목을 찾아 --devices 로 다시 시도할 것.")

    if f:
        good = [k for k, v in f.items() if v]
        print(f"\n  [F] 1회 connect 성공한 hart: {good if good else '없음'}")
        if good:
            print("      ★ 하트 선택이 원인이었다. 기본 하트가 halt 불가 상태였던 것.")
        else:
            print("      하트 선택은 원인이 아니다.")

    print("\n  ※ 각 실험을 2~3회 재현할 것. 특히 [D] 는 타깃 전원 사이클 직후와")
    print("     그렇지 않을 때의 결과가 다를 수 있다(그 차이 자체가 정보다).")


if __name__ == '__main__':
    main()
