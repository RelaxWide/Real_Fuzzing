#!/usr/bin/env python3
"""SF-E76 (RISC-V behind CoreSight DAP) — J-Link 연결 계층. **정식 모듈.**

이 파일이 연결 지식의 단일 출처다. 실험 스크립트도, v10.0 샘플러도 여기를 쓴다.
(이전에는 6개 스크립트가 같은 로직을 각자 복사해 갖고 있었다.)

────────────────────────────────────────────────────────────────────────
실측으로 확정된 사실
────────────────────────────────────────────────────────────────────────
토폴로지    cJTAG → ARM DP → APB-AP → RISC-V DM(DMI) → hart
            SEGGER KB(J-Link RISC-V)가 공식 지원하는 hybrid 구성이다.
            단, **"RISC-V 는 ROM table scan 이 없어 AP 위치와 DMI 위치를
            자동 검출할 수 없다"** 고 명시 → 수동 선언이 필수.

인터페이스  cJTAG, TIF=7, **10MHz**
            1000kHz 로 낮추면 cJTAG 활성화 자체가 실패한다(TDO 상시 high).
            T32 설정도 "USB 연결 시 10MHz" 였다.

DP          reg0 = 0x6BA0009D   (PARTNO 0xBA00 = ARM DAP.
                                 DESIGNER 는 ARM(0x23B) 이 아니다 = 벤더 DAP)
전원        CTRL/STAT ← 0x50000000 → 0xF0000000 (CSYSPWRUPACK|CDBGPWRUPACK)

AP map      T32 SYStem.CONFIG 의 `DP:0xN0000` 이 그대로 `Addr` 이다.
            `CORESIGHT_AddAP` 의 `Index` 는 **J-Link 내부 맵 번호**이지
            하드웨어 APSEL 이 아니다(APSEL 로 착각해 오래 헤맸다).

DMI         APB Index 0 (APBAP1 @0x10000) 로 두 CoreBase 모두
            **J-Link connect 후보로 통과**했다.
              0x81480000  hcore/CMCore/Fcore0/QCore   (4코어 공유)
              0x81481000  Ncore
            ⚠ "접근 가능" 이 아니다. DM register/hart/PC/halt 는 미검증이라
              실제로 올바른 코어에 도달하는지는 아직 모른다.

────────────────────────────────────────────────────────────────────────
⚠ 반드시 지킬 것
────────────────────────────────────────────────────────────────────────
1. **한 handle = 한 설정.**
   조합을 섞으면 (a) 한 번 붙은 뒤 이후가 전부 거짓 성공하거나
   (b) close 로 격리하면 전부 실패한다. 실측으로 둘 다 겪었다.

2. **첫 connect() 는 실패한다.** 2회차에 붙는다.
   통제 실험 결과: setup 이중 적용(B)도, 대기(C)도 아니고
   **connect 시도 자체**가 필요하다(A). 근본 원인은 규명 중 —
   유력 **가설**은 RISC-V DM 의 `dmactive` (아직 직접 관측으로 확정된 것은
   아니다. ARM DP 전원 요청이나 J-Link 내부 CPU module 초기화일 수도 있다).
   → 현재는 bounded retry 가 **임시 workaround** 다.

   범위 제한: 현재 **J-Link DLL/펌웨어 · generic 'RISC-V' device · 현재 명령
   순서 · 현재 보드 상태**에서 일관되게 관측된 현상이다. RISC-V 나 이 SoC
   일반의 성질로 일반화하지 말 것.

4. **APB 메모리 접근 ≠ RISC-V DMI 레지스터 접근.**
   `dmcontrol 0x10`, `dmstatus 0x11` 등은 **DMI register address** 이지
   APB byte offset 이 아니다. DMI aperture 레이아웃과 J-Link 의 변환 방식을
   확보하기 전에 `core_base + 0x10` 식으로 메모리를 읽고 쓰면
   **엉뚱한 장치를 건드릴 수 있다.**

3. **halt 후 반드시 resume.**
   코어를 멈춘 채 두면 SSD 컨트롤러가 멈춰 NVMe 가 hang 한다.
   어떤 경로로 빠져나가든 `safe_resume()` 을 부를 것.

────────────────────────────────────────────────────────────────────────
사용
────────────────────────────────────────────────────────────────────────
    from sfe76_link import Link, CORE_BASE_MAIN

    with Link(core_base=CORE_BASE_MAIN) as lk:
        lk.connect()                 # 재시도 내장
        lk.jl.halt()
        pc = lk.jl.register_read(32)
        lk.resume()

단독 실행 시 연결만 확인한다:
    sudo python3 sfe76_link.py
    sudo python3 sfe76_link.py --core-base 0x81481000 --hart 1
"""

import argparse
import sys
import time

try:
    import pylink
except ImportError:
    sys.exit("pylink 없음 →  pip3 install pylink-square\n"
             "  (venv 가 아니라 시스템 python3 에 있을 수 있다)")

VERSION = "2026-08-07"

# ── 연결 파라미터 (전부 실측값) ──────────────────────────────────────
TIF_CJTAG   = 7          # cJTAG. pylink enum 에 없어 정수로 지정
SPEED_KHZ   = 10000      # 낮추면 cJTAG 활성화 실패
CJTAG_MODE  = 0          # SetcJTAGInitMode: 0=LONG 1=SHORT 2=WILIOT
DEVICE      = 'RISC-V'
APB_INDEX   = 0          # DMI 가 붙은 AP (AddAP 의 Index)

CORE_BASE_MAIN = 0x81480000   # hcore/CMCore/Fcore0/QCore DM
CORE_BASE_N    = 0x81481000   # Ncore DM

# T32 SYStem.CONFIG 의 AP 목록 — (이름, CoreSight 주소, J-Link 타입)
AP_MAP = [
    ("APBAP1", 0x10000, "APB-AP"),
    ("APBAP2", 0x20000, "APB-AP"),
    ("AXIAP1", 0x30000, "AXI-AP"),
    ("AHBAP1", 0x40000, "AHB-AP"),
    ("APBAP3", 0x50000, "APB-AP"),
    ("APBAP4", 0x60000, "APB-AP"),
]

CONNECT_TRIES = 3


class Link:
    """J-Link 연결 1개 = 설정 1개. 조합을 섞지 않는다."""

    def __init__(self, core_base=CORE_BASE_MAIN, hart=None,
                 device=DEVICE, speed=SPEED_KHZ, verbose=True):
        self.core_base = core_base
        self.hart = hart
        self.device = device
        self.speed = speed
        self.verbose = verbose
        self.jl = None
        self.connect_tries_used = 0

    # ── 컨텍스트 매니저 — 어떤 경로로 나가든 resume + close ───────────
    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def _say(self, msg):
        if self.verbose:
            print(msg)

    def open(self):
        self.jl = pylink.JLink()
        self.jl.open()
        self._say(f"  [Link] {self.jl.product_name} SN={self.jl.serial_number}")
        return self

    # ── 설정: connect() 이전에 전부 끝나야 한다 ──────────────────────
    def apply_settings(self):
        jl = self.jl
        try:
            jl.exec_command(f"SetcJTAGInitMode = {CJTAG_MODE}")
            jl.set_tif(TIF_CJTAG)
            jl.set_speed(self.speed)
            for i, (_n, addr, typ) in enumerate(AP_MAP):
                jl.exec_command(f"CORESIGHT_AddAP = Index={i} Type={typ} Addr=0x{addr:X}")
            jl.exec_command(f"CORESIGHT_SetIndexAPBAPToUse = {APB_INDEX}")
            jl.exec_command(f"CORESIGHT_SetCoreBaseAddr = 0x{self.core_base:X}")
            if self.hart is not None:
                jl.exec_command(f"RISCV_SetHartSel = {self.hart}")
            return True
        except Exception as e:
            self._say(f"  [Link] 설정 실패: {e}")
            return False

    def connect(self, tries=CONNECT_TRIES):
        """★ 첫 시도는 실패한다(임시 workaround — 원인 규명 중).

        실패를 숨기지 않고 몇 회차에 붙었는지 남긴다. 그 수치가 커지거나
        매번 달라지면 그 자체가 이상 신호다.
        """
        last = None
        for t in range(1, tries + 1):
            if not self.apply_settings():
                raise RuntimeError("설정 단계 실패")
            try:
                self.jl.connect(self.device, speed=self.speed)
                self.connect_tries_used = t
                if t > 1:
                    self._say(f"  [Link] connect 성공 (시도 {t}/{tries} — "
                              f"1회차 실패는 알려진 현상)")
                else:
                    self._say("  [Link] connect 성공 (1회차) ★ 예상 밖 — 좋은 신호")
                return t
            except Exception as e:
                last = e
                self._say(f"  [Link] connect 시도 {t}/{tries} 실패: {e}")
                time.sleep(0.2)
        raise RuntimeError(f"connect {tries}회 모두 실패: {last}")

    # ── 안전 ─────────────────────────────────────────────────────────
    def resume(self, why=""):
        """halt 로 남기지 않는다 — 멈춘 채 두면 SSD 가 hang 한다."""
        for fn in ('restart', 'go'):
            try:
                getattr(self.jl, fn)()
                return True
            except Exception:
                continue
        self._say(f"  [Link] ⚠ resume 실패 {why} — 코어가 halt 로 남았을 수 있다. "
                  f"nvme list 로 확인할 것")
        return False

    def close(self):
        if self.jl is None:
            return
        try:
            if self.jl.halted():
                self.resume("(종료 전 정리)")
        except Exception:
            self.resume("(halted 확인 불가 — 무조건 시도)")
        try:
            self.jl.close()
        except Exception:
            pass
        self.jl = None
        time.sleep(0.3)


# ══════════════════════════════════════════════════════════════════
def main():
    ap = argparse.ArgumentParser(description="연결만 확인한다")
    ap.add_argument('--core-base', type=lambda x: int(x, 0), default=CORE_BASE_MAIN)
    ap.add_argument('--hart', type=int, default=None)
    ap.add_argument('--device', default=DEVICE)
    ap.add_argument('--tries', type=int, default=CONNECT_TRIES)
    args = ap.parse_args()

    label = {CORE_BASE_MAIN: "hcore/CMCore/Fcore0/QCore",
             CORE_BASE_N: "Ncore"}.get(args.core_base, "?")
    print(f"\n{'=' * 62}\n SF-E76 연결 확인 ({VERSION})\n{'=' * 62}")
    print(f"  CoreBase 0x{args.core_base:X} [{label}]  hart={args.hart}  "
          f"device={args.device!r}")

    with Link(core_base=args.core_base, hart=args.hart, device=args.device) as lk:
        try:
            lk.connect(tries=args.tries)
        except Exception as e:
            print(f"\n  ❌ {e}")
            return 1
        for fn, nm in ((lk.jl.halted, 'halted'), (lk.jl.core_name, 'core_name'),
                       (lk.jl.core_id, 'core_id')):
            try:
                print(f"  {nm:10s} = {fn()}")
            except Exception:
                pass
        print(f"\n  ✅ 연결 성공 (connect 시도 {lk.connect_tries_used}회)")
    return 0


if __name__ == '__main__':
    sys.exit(main())
