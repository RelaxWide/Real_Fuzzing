#!/usr/bin/env python3
"""SF-E76 — halt / PC 읽기 / resume 검증 + 하트 열거.

connect 는 이미 성공했다(connect_sfe76.py). 이제 v10.0 샘플러의 실제 요건을 확인한다:

    connect ✅ → halt → dpc(PC) 읽기 → resume

이 넷이 되면 기존 `JLinkHaltSampler` 를 그대로 이식할 수 있고, v10.0 이 돌기 시작한다.

확정된 연결 설정 (connect_sfe76.py 실측):
    SetcJTAGInitMode = 0
    TIF = 7 (cJTAG),  speed = 10000 kHz
    CORESIGHT_AddAP  Index=0..5  (T32 SYStem.CONFIG 값)
    CORESIGHT_SetIndexAPBAPToUse = 0        # APBAP1 @ 0x10000
    CORESIGHT_SetCoreBaseAddr    = 0x81481000
    connect('RISC-V')

★★ 첫 connect() 는 **구조적으로 실패한다** (실측 확정).

  같은 주소를 두 번 시도한 통제 실험에서:
      0x81480000 -> 0x81480000     1회차 실패, 2회차 성공
  주소를 바꿔도 항상 2회차만 성공했다. 즉 "0x81480000 은 연결 안 된다" 는
  **틀린 결론이었고**, 첫 시도가 실패하는 것은 **위치(순서) 때문**이다.
  첫 connect 는 `Error while halting CPU / Specific core setup failed` 로
  실패하면서 예열 역할을 한다.

  → T32 가 SYStem.Up 을 재시도 루프로 감싼 이유가 이것이다.
  → **두 DM 모두 접근 가능**: 0x81480000(4코어) / 0x81481000(Ncore)
  → 샘플러도 반드시 connect 를 2회 이상 시도해야 한다.

사용법:
    sudo python3 verify_halt_pc.py
    sudo python3 verify_halt_pc.py --samples 50      # PC 샘플 수
    sudo python3 verify_halt_pc.py --hart 1          # 특정 하트만
    sudo python3 verify_halt_pc.py --core-base 0x81480000
"""

import argparse
import sys
import time

try:
    import pylink
except ImportError:
    sys.exit("pylink 없음 →  pip3 install pylink-square")

VERSION = "2026-08-08.2  halt/PC/resume 검증 + 하트 열거"

# ── connect_sfe76.py 로 확정된 설정 ──────────────────────────────────
TIF_CJTAG   = 7
SPEED_KHZ   = 10000
CJTAG_MODE  = 0
APB_INDEX   = 0
CORE_BASE   = 0x81480000   # ★ hcore/CMCore/Fcore0/QCore DM. NVMe 프론트엔드 후보
CORE_BASE_N = 0x81481000   # Ncore DM

AP_MAP = [
    ("APBAP1", 0x10000, "APB-AP"),
    ("APBAP2", 0x20000, "APB-AP"),
    ("AXIAP1", 0x30000, "AXI-AP"),
    ("AHBAP1", 0x40000, "AHB-AP"),
    ("APBAP3", 0x50000, "APB-AP"),
    ("APBAP4", 0x60000, "APB-AP"),
]

# 펌웨어 .text 추정 범위 — PC 후보를 거르는 용도(아직 미확정이라 넓게 잡는다)
FW_LO, FW_HI = 0x00000000, 0xFFFFFFFF


def head(t):
    print(f"\n{'=' * 66}\n {t}\n{'=' * 66}")


def ex(jl, cmd):
    try:
        jl.exec_command(cmd)
        return True
    except Exception as e:
        print(f"    FAIL {cmd} -> {e}")
        return False


def _apply(jl, core_base, hart):
    ex(jl, f"SetcJTAGInitMode = {CJTAG_MODE}")
    jl.set_tif(TIF_CJTAG)
    jl.set_speed(SPEED_KHZ)
    for i, (n, a, t) in enumerate(AP_MAP):
        ex(jl, f"CORESIGHT_AddAP = Index={i} Type={t} Addr=0x{a:X}")
    ex(jl, f"CORESIGHT_SetIndexAPBAPToUse = {APB_INDEX}")
    ex(jl, f"CORESIGHT_SetCoreBaseAddr = 0x{core_base:X}")
    if hart is not None:
        ex(jl, f"RISCV_SetHartSel = {hart}")


def connect(jl, core_base, hart=None, tries=3):
    """★ 첫 connect 는 구조적으로 실패한다 — 반드시 재시도한다.

    통제 실험(같은 주소 2회)에서 1회차 실패 / 2회차 성공이 재현됐다.
    첫 시도가 예열이고, 그 상태를 물려받은 두 번째가 붙는다.
    핸들을 중간에 close 하면 예열이 사라지므로 **하나의 핸들로** 반복한다.
    """
    last = None
    for t in range(1, tries + 1):
        _apply(jl, core_base, hart)
        try:
            jl.connect('RISC-V', speed=SPEED_KHZ)
            if t > 1:
                print(f"  (connect 시도 {t}회차에 성공 — 1회차는 예열)")
            return t
        except Exception as e:
            last = e
            print(f"  connect 시도 {t}/{tries} 실패: {e}")
            time.sleep(0.2)
    raise RuntimeError(f"connect {tries}회 모두 실패: {last}")


# ══════════════════════════════════════════════════════════════════
def find_pc_register(jl):
    """PC(dpc) 가 몇 번 레지스터인지 실측으로 찾는다.

    ARM 때 jlink_reg_diag.py 로 했던 것과 같은 문제다. RISC-V 는 보통
    x0~x31 = 0~31 이고 PC 가 그 뒤에 온다. 이름을 주는 API 가 있으면 그걸 쓰고,
    없으면 '값이 실행마다 변하고 코드 주소처럼 보이는' 인덱스를 찾는다.
    """
    head("[A] PC 레지스터 인덱스 탐색")

    # 1) 이름 목록을 주는 API 가 있으면 그게 제일 확실하다
    try:
        names = jl.register_list()
        print(f"  register_list() → {len(names)}개")
        for i, nm in enumerate(names[:64]):
            try:
                label = jl.register_name(nm)
            except Exception:
                label = str(nm)
            if any(k in str(label).lower() for k in ('pc', 'dpc')):
                print(f"    ★ index={nm}  name={label}")
    except Exception as e:
        print(f"  register_list() 불가: {e}")

    # 2) 실측: halt 상태에서 0~47 을 읽어 값을 본다
    print("\n  인덱스별 값 (halt 상태):")
    vals = {}
    for idx in range(48):
        try:
            v = jl.register_read(idx)
        except Exception:
            continue
        vals[idx] = v
        if v not in (0, 0xFFFFFFFF):
            print(f"    [{idx:2d}] = 0x{v & 0xFFFFFFFF:08X}")
    return vals


def sample_pc(jl, pc_idx, n, settle_ms):
    """halt → PC 읽기 → resume 을 반복. 샘플러의 핵심 루프 그대로."""
    head(f"[C] PC 샘플링 {n}회  (register index={pc_idx})")
    pcs = []
    fails = 0
    t0 = time.time()
    for i in range(n):
        try:
            jl.halt()
            pc = jl.register_read(pc_idx)
            jl.restart()                    # resume
            pcs.append(pc & 0xFFFFFFFF)
        except Exception as e:
            fails += 1
            if fails <= 3:
                print(f"    {i}회차 실패: {e}")
        if settle_ms:
            time.sleep(settle_ms / 1000.0)
    dt = time.time() - t0

    uniq = sorted(set(pcs))
    print(f"\n  성공 {len(pcs)}/{n}   실패 {fails}")
    print(f"  소요 {dt:.2f}s → {len(pcs) / dt if dt else 0:.1f} 샘플/초")
    print(f"  고유 PC {len(uniq)}개")
    if uniq:
        print(f"  범위 0x{uniq[0]:08X} ~ 0x{uniq[-1]:08X}")
        for v in uniq[:20]:
            print(f"    0x{v:08X}  x{pcs.count(v)}")
    return pcs, uniq


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--samples', type=int, default=30)
    ap.add_argument('--pc-index', type=int, default=None,
                    help='PC 레지스터 인덱스 직접 지정 (미지정 시 탐색)')
    ap.add_argument('--hart', type=int, default=None, help='RISCV_SetHartSel 값')
    ap.add_argument('--core-base', type=lambda x: int(x, 0), default=CORE_BASE)
    ap.add_argument('--settle-ms', type=float, default=0.0,
                    help='resume 후 대기 (ARM 의 go_settle 대응)')
    ap.add_argument('--enum-harts', action='store_true',
                    help='하트 0~4 를 각각 붙여보고 결과 비교')
    args = ap.parse_args()

    head("SF-E76 halt / PC / resume 검증")
    print(f"  version   : {VERSION}")
    print(f"  CoreBase  : 0x{args.core_base:X}")
    print(f"  hart      : {args.hart if args.hart is not None else '(미지정)'}")

    if args.enum_harts:
        head("[H] 하트 열거 — 코어 5개(hcore/CMCore/Fcore0/QCore/Ncore)")
        # ★ 핸들 하나로 전부 처리한다. 하트마다 close/open 하면 예열이 사라져
        #   전부 실패한다(스윕에서 실측으로 확인됨).
        jl = pylink.JLink()
        try:
            jl.open()
        except Exception as e:
            sys.exit(f"J-Link open 실패: {e}")
        try:
            for h in range(5):
                print(f"\n  ── hart {h} ──")
                try:
                    connect(jl, args.core_base, hart=h)
                except Exception as e:
                    print(f"    connect 실패: {e}")
                    continue
                try:
                    jl.halt()
                    regs = {i: jl.register_read(i) & 0xFFFFFFFF for i in (32, 33)}
                    print(f"    halted={jl.halted()}  "
                          + "  ".join(f"reg{i}=0x{v:08X}" for i, v in regs.items()))
                    jl.restart()
                except Exception as e:
                    print(f"    halt/read 실패: {e}")
        finally:
            try:
                jl.close()
            except Exception:
                pass
        print("\n  하트별 reg 값이 서로 다르면 → 하트 선택이 실제로 동작하는 것")
        return

    jl = pylink.JLink()
    try:
        jl.open()
    except Exception as e:
        sys.exit(f"J-Link open 실패: {e}")
    print(f"  J-Link    : {jl.product_name} SN={jl.serial_number}")

    try:
        head("[1] connect")
        connect(jl, args.core_base, hart=args.hart)
        print("  ✅ connect 성공")
        try:
            print(f"     core_name={jl.core_name()}  core_id=0x{jl.core_id():08X}")
        except Exception:
            pass

        head("[2] halt")
        jl.halt()
        print(f"  ✅ halt 성공   halted={jl.halted()}")

        pc_idx = args.pc_index
        if pc_idx is None:
            find_pc_register(jl)
            print("\n  ※ 위 목록에서 PC 로 보이는 인덱스를 골라 --pc-index 로 재실행.")
            print("     RISC-V 는 보통 x0~x31=0~31, 그 뒤가 pc. 코드 주소처럼 보이고")
            print("     실행마다 값이 변하는 것이 PC 다.")
            pc_idx = 32
            print(f"\n  일단 index={pc_idx} 로 진행")

        head("[3] resume")
        jl.restart()
        print(f"  ✅ resume 성공   halted={jl.halted()}")

        sample_pc(jl, pc_idx, args.samples, args.settle_ms)

    except Exception as e:
        print(f"\n  ❌ 실패: {e}")
    finally:
        try:
            jl.close()
        except Exception:
            pass

    head("판정")
    print("  halt/PC/resume 이 모두 되고 PC 가 여러 값으로 흩어지면")
    print("  → 기존 JLinkHaltSampler 를 그대로 이식할 수 있다 (v10.0 착수 가능)")
    print("  PC 가 한 값에 고정되면 → 코어가 실제로 안 돌거나 잘못된 하트에 붙은 것")


if __name__ == '__main__':
    main()
