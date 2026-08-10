#!/usr/bin/env python3
"""SF-E76 (RISC-V behind CoreSight DAP) — J-Link 연결 계층. **정식 모듈.**

연결 지식의 단일 출처. 실험 스크립트도, v10.0 샘플러도 **반드시 여기를 쓴다.**
raw `jl.halt()` / `jl.restart()` 를 직접 부르지 말 것 — 아래 이유 때문이다.

────────────────────────────────────────────────────────────────────────
★ checked API 를 쓰는 이유
────────────────────────────────────────────────────────────────────────
pylink 의 `halt()` / `restart()` 는 실패나 no-op 상황에서 **예외 대신 False 를
반환**한다. 반환값을 무시하면:

  - `halted == False` 인데 "halt 성공" 으로 기록 → 실행 중인 코어의 일반
    레지스터를 PC 로 읽어 **거짓 성공**
  - resume 실패를 성공으로 기록 → **코어가 멈춘 채 남아 SSD 가 hang**

그래서 이 모듈은 **명령 반환값 + 사후 상태를 모두 확인**하는 API 만 노출한다:

    connect_checked / halt_checked / read_pc / resume_checked

────────────────────────────────────────────────────────────────────────
실측으로 확정된 사실
────────────────────────────────────────────────────────────────────────
토폴로지    cJTAG → ARM DP → APB-AP → RISC-V DM(DMI) → hart
            SEGGER KB(J-Link RISC-V)가 공식 지원하는 hybrid 구성.
            **"RISC-V 는 ROM table scan 이 없어 AP/DMI 위치를 자동 검출할 수
            없다"** 고 명시 → 수동 선언 필수.

인터페이스  cJTAG, TIF=7, **10MHz** (1000kHz 로 낮추면 활성화 자체가 실패)
DP          reg0 = 0x6BA0009D  (PARTNO 0xBA00 = ARM DAP.
                                DESIGNER 는 ARM(0x23B)이 아님 = 벤더 DAP)
전원        CTRL/STAT ← 0x50000000 → 0xF0000000 (CSYSPWRUPACK|CDBGPWRUPACK)
AP map      T32 의 `DP:0xN0000` 이 그대로 `Addr`.
            `CORESIGHT_AddAP` 의 `Index` 는 **J-Link 내부 맵 번호**이지 APSEL 아님.
CoreBase    0x81480000  hcore/CMCore/Fcore0/QCore (4코어 공유)
            0x81481000  Ncore
            ⚠ 둘 다 **J-Link connect 후보로 통과**했을 뿐이다.
              DM register/hart/PC/halt 미검증 — "접근 가능" 이 아니다.

────────────────────────────────────────────────────────────────────────
⚠ 반드시 지킬 것
────────────────────────────────────────────────────────────────────────
1. **한 handle = 한 설정.** 조합을 섞으면 거짓 성공 또는 전체 실패.
   후보(CoreBase/hart/device)를 바꾸려면 **프로세스를 새로** 시작한다.

2. **첫 connect() 는 실패한다.** 2회차에 붙는다.
   통제 실험: setup 이중 적용(B)도 대기(C)도 아니고 connect 시도 자체(A)가 필요.
   유력 **가설**은 RISC-V DM 의 `dmactive` — 직접 관측으로 확정된 것은 아니다
   (ARM DP 전원 요청이나 J-Link 내부 CPU module 초기화일 수도 있다).
   범위 제한: **현재 DLL/펌웨어 · generic 'RISC-V' device · 현재 명령 순서 ·
   현재 보드 상태**에서 관측된 현상. RISC-V 일반의 성질로 일반화하지 말 것.

3. **halt 후 반드시 resume, 그리고 확인.** resume 확인이 실패하면
   다음 실험을 진행하지 말고 `recovery_required` 를 호출자에게 알린다.

4. **APB 메모리 접근 ≠ RISC-V DMI 레지스터 접근.**
   `dmcontrol 0x10` 등은 **DMI register address** 이지 APB byte offset 이 아니다.
   aperture 레이아웃을 확보하기 전에 `core_base + 0x10` 식으로 읽고 쓰면
   **엉뚱한 장치를 건드릴 수 있다.**

────────────────────────────────────────────────────────────────────────
사용
────────────────────────────────────────────────────────────────────────
    from sfe76_link import Link, CORE_BASE_NCORE, LinkError

    lk = Link(core_base=CORE_BASE_NCORE)
    try:
        with lk:
            lk.connect_checked()
            lk.halt_checked()
            pc = lk.read_pc(pc_index)      # 확정된 인덱스만
            lk.resume_checked()
    except LinkError as e:
        ...  # e.exit_code 로 어느 게이트인지 구분
    if lk.recovery_required:
        ...  # 보드 복구(POR) 필요

단독 실행:
    sudo python3 sfe76_link.py --core-base 0x81481000
"""

import argparse
import sys
import time

try:
    import pylink
except ImportError:
    sys.exit("pylink 없음 →  pip3 install pylink-square\n"
             "  (venv 가 아니라 시스템 python3 에 있을 수 있다)")

VERSION = "2026-08-07.2  checked API"

# ── 연결 파라미터 (전부 실측값) ──────────────────────────────────────
TIF_CJTAG   = 7          # cJTAG. pylink enum 에 없어 정수로 지정
SPEED_KHZ   = 10000      # 낮추면 cJTAG 활성화 실패
CJTAG_MODE  = 0          # SetcJTAGInitMode: 0=LONG 1=SHORT 2=WILIOT
DEVICE      = 'RISC-V'
APB_INDEX   = 0          # DMI 가 붙은 AP (AddAP 의 Index)

CORE_BASE_MAIN  = 0x81480000   # hcore/CMCore/Fcore0/QCore DM (4코어 공유)
CORE_BASE_NCORE = 0x81481000   # Ncore DM

CORE_BASE_LABEL = {
    CORE_BASE_MAIN:  "hcore/CMCore/Fcore0/QCore",
    CORE_BASE_NCORE: "Ncore",
}

# ★ hart 매핑 — attach.cmm 실물에서 확정 (추측 아님)
#     SYS.CONFIG CORE <core_idx>. <chip_idx>.
#     SYS.CONFIG HARTINDEX 0. 1. 2. 3.      ← core_idx 순서대로의 hart 번호
#   즉 CORE_BASE_MAIN 하나의 DM 에 **하트가 4개** 달려 있고,
#   Ncore 만 chip 2 = 별도 DM(CORE_BASE_NCORE) 의 hart 0 이다.
#   → hart 를 0..4 로 넘겨짚을 필요가 없다. 아래가 전부다.
CORE_HART = {
    'hcore':  (CORE_BASE_MAIN,  0),   # CORE 1. 1.  ← NVMe 펌웨어 유력
    'cmcore': (CORE_BASE_MAIN,  1),   # CORE 2. 1.
    'fcore':  (CORE_BASE_MAIN,  2),   # CORE 3. 1.
    'qcore':  (CORE_BASE_MAIN,  3),   # CORE 4. 1.
    'ncore':  (CORE_BASE_NCORE, 0),   # CORE 1. 2.  ← 코드 맵에서 제외되는 코어
}

# DMI 레지스터의 APB aperture 매핑 (강한 추론, 미검증)
#   두 DM base 의 간격이 0x1000 = 4KB → DMI 주소 1024개 × 4바이트.
#   ⇒ APB 주소 = CoreBase + (dmi_addr << 2)
#   예: dmcontrol(0x10) → 0x81480040,  dmstatus(0x11) → 0x81480044
DMI_STRIDE_SHIFT = 2
DM_APERTURE_SIZE = 0x1000

# T32 SYStem.CONFIG 의 AP 목록 — (이름, CoreSight 주소, J-Link 타입)
AP_MAP = [
    ("APBAP1", 0x10000, "APB-AP"),
    ("APBAP2", 0x20000, "APB-AP"),
    ("AXIAP1", 0x30000, "AXI-AP"),
    ("AHBAP1", 0x40000, "AHB-AP"),
    ("APBAP3", 0x50000, "APB-AP"),
    ("APBAP4", 0x60000, "APB-AP"),
]

CONNECT_TRIES  = 3
STATE_TIMEOUT  = 2.0     # halt/resume 사후 상태 확인 대기(초)

# ── 종료 코드 — 자동화가 실패를 구분할 수 있게 ──────────────────────
EXIT_OK           = 0
EXIT_CONNECT_FAIL = 2
EXIT_HALT_FAIL    = 3
EXIT_PC_FAIL      = 4
EXIT_RESUME_FAIL  = 5    # ★ 보드 복구 필요
EXIT_INSUFFICIENT = 6


class LinkError(RuntimeError):
    """단계 실패. exit_code 로 어느 게이트에서 깨졌는지 구분한다."""

    def __init__(self, msg, exit_code=EXIT_INSUFFICIENT):
        super().__init__(msg)
        self.exit_code = exit_code


class Link:
    """J-Link 연결 1개 = 설정 1개. 조합을 섞지 않는다."""

    def __init__(self, core_base=CORE_BASE_NCORE, hart=None, device=DEVICE,
                 speed=SPEED_KHZ, serial=None, verbose=True, apb_index=APB_INDEX,
                 ap_count=None):
        self.core_base = core_base
        self.hart = hart
        self.apb_index = apb_index
        # ★ 등록할 AP 개수. 2026-08-10 probe_dap 결과, AP 1개일 때만 DAP 전원이
        #   ACK 됐다(6개는 실패). 실재가 확인된 AP 는 APBAP1 하나뿐이므로
        #   **없는 AP 를 등록하는 것이 해가 될 수 있다.** None = AP_MAP 전부.
        self.ap_count = len(AP_MAP) if ap_count is None else max(1, min(ap_count, len(AP_MAP)))
        self.device = device
        self.speed = speed
        self.serial = serial
        self.verbose = verbose
        self.jl = None

        # 결과 상태와 복구 상태를 분리한다
        self.connect_tries_used = 0
        self.recovery_required = False
        self.cleanup_error = None

    # ── 컨텍스트 매니저 ──────────────────────────────────────────────
    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def _say(self, msg):
        if self.verbose:
            print(msg)

    def meta(self):
        """결과 레코드에 남길 연결 메타데이터."""
        m = {
            'version': VERSION,
            'device': self.device, 'tif': TIF_CJTAG, 'speed_khz': self.speed,
            'cjtag_mode': CJTAG_MODE, 'apb_index': self.apb_index,
            'core_base': f"0x{self.core_base:X}",
            'core_base_label': CORE_BASE_LABEL.get(self.core_base, '?'),
            'hart': self.hart,
            'connect_tries_used': self.connect_tries_used,
        }
        if self.jl is not None:
            for k, fn in (('probe', lambda: self.jl.product_name),
                          ('serial', lambda: self.jl.serial_number),
                          ('firmware', lambda: self.jl.firmware_version)):
                try:
                    m[k] = fn()
                except Exception:
                    pass
        return m

    # ── open / 설정 ──────────────────────────────────────────────────
    def open(self):
        self.jl = pylink.JLink()
        # 여러 probe 가 붙어 있으면 엉뚱한 보드를 잡는다
        if self.serial:
            self.jl.open(serial_no=self.serial)
        else:
            self.jl.open()
        self._say(f"  [Link] {self.jl.product_name} SN={self.jl.serial_number}")
        return self

    def apply_settings(self):
        """connect() 이전에 **1회만** 적용한다.

        retry 마다 다시 부르지 않는다 — 같은 Index 로 `CORESIGHT_AddAP` 를
        반복 등록하면 DLL 버전에 따라 덮어쓰기/중복/오류가 될 수 있고,
        분리 실험 A(setup 1회 + connect 2회)와도 어긋난다.
        """
        jl = self.jl
        try:
            jl.exec_command(f"SetcJTAGInitMode = {CJTAG_MODE}")
            jl.set_tif(TIF_CJTAG)
            jl.set_speed(self.speed)
            for i, (_n, addr, typ) in enumerate(AP_MAP[:self.ap_count]):
                jl.exec_command(f"CORESIGHT_AddAP = Index={i} Type={typ} Addr=0x{addr:X}")
            jl.exec_command(
                f"CORESIGHT_SetIndexAPBAPToUse = {min(self.apb_index, self.ap_count - 1)}")
            jl.exec_command(f"CORESIGHT_SetCoreBaseAddr = 0x{self.core_base:X}")
            if self.hart is not None:
                jl.exec_command(f"RISCV_SetHartSel = {self.hart}")
            return True
        except Exception as e:
            self._say(f"  [Link] 설정 실패: {e}")
            return False

    # ── G1: connect ──────────────────────────────────────────────────
    def connect_checked(self, tries=CONNECT_TRIES):
        """설정 1회 + connect bounded retry. 몇 회차에 붙었는지 남긴다."""
        if not self.apply_settings():
            raise LinkError("설정 단계 실패", EXIT_CONNECT_FAIL)

        last = None
        for t in range(1, tries + 1):
            try:
                self.jl.connect(self.device, speed=self.speed)
                self.connect_tries_used = t
                note = ("★ 1회차 성공 — 예상 밖(좋은 신호)" if t == 1
                        else "(1회차 실패는 현재 도구/보드 조건에서 알려진 현상)")
                self._say(f"  [Link] connect 성공 시도 {t}/{tries} {note}")
                return t
            except Exception as e:
                last = e
                self._say(f"  [Link] connect 시도 {t}/{tries} 실패: {e}")
                time.sleep(0.2)
        raise LinkError(f"connect {tries}회 모두 실패: {last}", EXIT_CONNECT_FAIL)

    # ── 상태 대기 ────────────────────────────────────────────────────
    def _wait_halted(self, expected, timeout=STATE_TIMEOUT):
        end = time.time() + timeout
        last = None
        while time.time() < end:
            try:
                last = bool(self.jl.halted())
            except Exception as e:
                last = None
                self._say(f"  [Link] halted() 예외: {e}")
            if last is expected:
                return True
            time.sleep(0.02)
        self._say(f"  [Link] 상태 대기 실패: halted={last}, 기대={expected}")
        return False

    # ── G2: halt ─────────────────────────────────────────────────────
    def halt_checked(self, timeout=STATE_TIMEOUT):
        """명령 반환값 + 사후 상태를 **둘 다** 확인한다."""
        try:
            r = self.jl.halt()
        except Exception as e:
            raise LinkError(f"halt() 예외: {e}", EXIT_HALT_FAIL)
        if r is False:
            raise LinkError("halt() 가 False 반환 (명령 실패)", EXIT_HALT_FAIL)
        if not self._wait_halted(True, timeout):
            raise LinkError("halt 명령은 받아들여졌으나 halted 상태로 진입하지 않음",
                            EXIT_HALT_FAIL)
        return True

    # ── G3: PC ───────────────────────────────────────────────────────
    def read_pc(self, pc_index):
        """**확정된** 인덱스만 받는다.

        인덱스를 추측해 넘기면 실행 중인 코어의 일반 레지스터를 PC 로 기록해
        G3 를 거짓 통과한다. 확정 근거는 셋 중 하나여야 한다:
          - J-Link register name 이 PC/DPC 로 확인됨
          - T32/벤더 자료로 교차 검증됨
          - 독립적인 PC fingerprint 실험을 통과한 --pc-index
        """
        if pc_index is None:
            raise LinkError("PC 레지스터 인덱스가 확정되지 않았다", EXIT_PC_FAIL)
        if not self._wait_halted(True, 0.2):
            raise LinkError("halt 상태가 아닌데 PC 를 읽으려 함", EXIT_PC_FAIL)
        try:
            return self.jl.register_read(pc_index) & 0xFFFFFFFF   # E76 = RV32
        except Exception as e:
            raise LinkError(f"register_read({pc_index}) 실패: {e}", EXIT_PC_FAIL)

    # ── G4: resume ───────────────────────────────────────────────────
    def resume_checked(self, timeout=STATE_TIMEOUT):
        """실패하면 recovery_required 를 세우고 예외를 던진다.

        ⚠ pylink 에 `go()` 는 없다. `restart()` 뿐이고, 문서상
        **"This is a no-op if the CPU isn't halted"** 라 halt 상태가 아니면
        False 를 반환한다. 따라서 `restart() == False` 자체는 실패가 아니다 —
        **이미 running 이면 성공**이다. (이걸 실패로 오판해 '보드 복구 필요'
        거짓 경보를 냈던 적이 있다.)
        """
        try:
            if not self.jl.halted():
                return True          # 이미 running — 할 일 없음
        except Exception:
            pass                     # 확인 불가 → 아래에서 시도

        try:
            r = self.jl.restart()
        except Exception as e:
            self.recovery_required = True
            raise LinkError(f"restart() 예외: {e}", EXIT_RESUME_FAIL)

        # 반환값이 아니라 **실제 상태**로 판정한다
        if self._wait_halted(False, timeout):
            return True

        self.recovery_required = True
        raise LinkError(
            f"resume 실패 — 코어가 halted 로 남았다 (restart 반환={r}). "
            f"보드 복구(POR) 필요", EXIT_RESUME_FAIL)

    # ── 정리 ─────────────────────────────────────────────────────────
    def close(self):
        """어떤 경로로 나가든 resume 을 시도하고, 실패를 숨기지 않는다."""
        if self.jl is None:
            return
        try:
            try:
                still_halted = bool(self.jl.halted())
            except Exception:
                # 확인 불가 시 억지로 resume 하지 않는다. halt 가 애초에
                # 실패했으면 멈춘 적이 없고, 그때 restart() 는 no-op False 를
                # 돌려줘 '복구 필요' 거짓 경보를 만든다.
                still_halted = False
            if still_halted:
                try:
                    self.resume_checked()
                    self._say("  [Link] 종료 전 resume 완료")
                except LinkError as e:
                    self.cleanup_error = str(e)
                    self.recovery_required = True
                    self._say(f"  [Link] ⚠ 종료 전 resume 실패: {e}")
                    self._say("  [Link] ⚠ 코어가 halt 로 남았다. nvme list 로 확인하고 "
                              "보드 전원 사이클 필요")
        finally:
            try:
                self.jl.close()
            except Exception as e:
                self.cleanup_error = self.cleanup_error or f"close: {e}"
            self.jl = None
            time.sleep(0.3)


# ══════════════════════════════════════════════════════════════════
def add_common_args(ap):
    ap.add_argument('--core-base', type=lambda x: int(x, 0), default=CORE_BASE_NCORE,
                    help='기본 0x81481000 (Ncore — 단일 하트로 추정되어 변수가 적다)')
    ap.add_argument('--hart', type=int, default=None)
    ap.add_argument('--device', default=DEVICE)
    ap.add_argument('--serial', default=None, help='J-Link serial (여러 대 연결 시 필수)')
    ap.add_argument('--tries', type=int, default=CONNECT_TRIES)
    ap.add_argument('--ap-count', type=int, default=None,
                    help='등록할 AP 개수 (1=APBAP1 만). 기본은 AP_MAP 전부(6). '
                         'probe_dap 에서 1개일 때만 DAP 전원이 ACK 됐다')
    return ap


def main():
    ap = add_common_args(argparse.ArgumentParser(description="연결만 확인한다"))
    args = ap.parse_args()

    label = CORE_BASE_LABEL.get(args.core_base, "?")
    print(f"\n{'=' * 62}\n SF-E76 연결 확인 ({VERSION})\n{'=' * 62}")
    print(f"  CoreBase 0x{args.core_base:X} [{label}]  hart={args.hart}  "
          f"device={args.device!r}")

    lk = Link(core_base=args.core_base, hart=args.hart, device=args.device,
              serial=args.serial)
    rc = EXIT_OK
    try:
        with lk:
            lk.connect_checked(tries=args.tries)
            print(f"\n  ✅ connect 성공 (시도 {lk.connect_tries_used}회)")
            print(f"  meta: {lk.meta()}")
    except LinkError as e:
        print(f"\n  ❌ {e}")
        rc = e.exit_code
    if lk.recovery_required:
        print("\n  ⚠⚠ 보드 복구 필요 — 전원 사이클 후 nvme list 확인")
        rc = rc or EXIT_RESUME_FAIL
    return rc


if __name__ == '__main__':
    sys.exit(main())
