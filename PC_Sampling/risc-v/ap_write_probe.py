#!/usr/bin/env python3
"""AP 쓰기 경로 진단 — '--diag 는 LIVE 인데 STATE 읽기(TAR 되읽기 0)는 실패' 를 가른다.

--diag 는 AP IDR **읽기만** 한다. STATE 읽기는 CSW 쓰기 → TAR 쓰기 → TAR 되읽기를 거친다.
이 도구는 AP 마다 그 쓰기를 따로 시험한다.

  - AP 내부 레지스터(CSW·TAR)에만 쓰고 원래 값으로 되돌린다. TAR 쓰기는 메모리에 닿지 않는다.
  - SJTAG 블록은 STATE **읽기** 1회뿐 — 인증 카운터 무소모.
  - 주소는 출력하지 않는다(AP 이름만).

판정:
  IDR 이 AP 마다 같다          → DP SELECT 쓰기부터 안 먹는다(링크 수준 쓰기 문제)
  IDR 은 다른데 TAR 전부 불일치  → AP 쓰기(APACC write)만 안 먹는다
  APBAP3 만 TAR 불일치          → APBAP3 한정 문제
  TAR 전부 일치인데 STATE 실패   → TAR 이후(DRW/APB 버스) 문제

CSW 비트도 풀어 찍는다 — TrInProg(bit7)=1 이면 이전 전송이 끝나지 않고 AP 에 걸려 있다.
--dap-abort: 시험 전에 DP ABORT.DAPABORT(bit0)로 걸린 AP 전송을 취소하고 전후 상태를 찍는다.
  (평소 sticky 클리어는 ABORT=0x1E 로 bit0 을 쓰지 않아 멈춘 전송을 풀지 못한다.)

--watch N: 한 세션을 유지한 채 N 초 동안 --interval 간격으로 AP 마다 TAR 쓰기/되읽기를
  반복하고 한 줄씩 찍는다(전원 ON·부팅 이후 시간에 따라 어떻게 변하는지). 기호:
  O=일치  X=되읽기 불일치(0 등)  E=읽기 실패/0x80000000(링크 수준 에러)
  CTRL/STAT 의 요청(req)·응답(ack) 비트를 따로 찍는다:
    req=1 ack=0 → 요청은 살아 있는데 칩이 디버그 전원을 회수
    req=0       → DP 가 리셋돼 요청이 지워짐(디버그 도메인 리셋/전원 강하)
  ※ CTRL/STAT 이 0x80000000 이면 실제 값이 아니라 J-Link 의 읽기 실패 표식이다(링크 끊김).
--reassert: 매 회 ABORT(0x1E)·전원요청을 다시 써서 회복되는지 본다.
VTref 열 = 프로브가 잰 1번 핀 전압(mV). 링크가 끊길 때 같이 떨어지면 타깃 IO 기준전압/배선 쪽.
tx 열 = watch 시작 후 누적 DP/AP 전송 수. --interval 을 바꿔 돌렸을 때 끊기는 시점이
  같은 '초' 에 맞으면 시간 기반(칩 쪽), 같은 'tx' 에 맞으면 전송 기반(링크 동기 상실)이다.
--speed: cJTAG 속도(kHz). 기본은 sfe76_link 의 값(10000).
--aps: 시험할 AP 만 고른다(예: APBAP3). 시스템 버스 AP(AXI/AHB)를 건드리지 않고 보려는 용도.
--vtref-mv: VTref 고정(mV, 기본 1800, 0=자동). 시작 로그의 '[Link] VTref …' 줄에 고정 성공 여부와
  고정 전 측정값이 찍힌다.

사용: sudo python3 risc-v/ap_write_probe.py [--power both|dbg-only|sys-only] [--dap-abort]
      sudo python3 risc-v/ap_write_probe.py --watch 120 [--interval 2]
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sjtag_unlock as sj                                    # noqa: E402
from sfe76_link import Link, AP_MAP, CORE_BASE_MAIN, SPEED_KHZ  # noqa: E402
from dap_access import (OFF_CSW, OFF_TAR, OFF_IDR,           # noqa: E402
                        DP_ABORT, DP_CTRL_STAT, DP_RDBUF, hx)

TAR_PATTERNS = (0x00000004, 0x00000100, 0xA5A5A5A4)


def jlink_info(jl):
    out = []
    for k, fn in (('probe', lambda: jl.product_name), ('SN', lambda: jl.serial_number),
                  ('FW', lambda: jl.firmware_version), ('DLL', lambda: jl.version),
                  ('DLL 빌드', lambda: jl.compile_date),
                  ('VTref(mV)', lambda: jl.hardware_status.voltage)):
        try:
            out.append(f"{k}={fn()}")
        except Exception as e:
            out.append(f"{k}=?({str(e)[:30]})")
    return "  ".join(out)


def sticky_bits(v):
    if v is None:
        return "CTRL/STAT 읽기 실패"
    bits = [nm for m, nm in ((1 << 7, 'WDATAERR'), (1 << 5, 'STICKYERR'),
                             (1 << 1, 'STICKYORUN')) if v & m]
    return " ".join(bits) if bits else "에러 없음"


def csw_bits(v):
    """CSW 중 상태 판단에 쓰는 비트만."""
    if v is None or v == 0x80000000:
        return "?"
    return f"TrInProg={(v >> 7) & 1} DeviceEn={(v >> 6) & 1} Size={v & 0x7}"


def ap_state(dap, base):
    dap.clear_sticky()
    csw = dap.ap_read(base, OFF_CSW)
    tar = dap.ap_read(base, OFF_TAR)
    return (f"CSW={hx(csw)} ({csw_bits(csw)})  TAR={hx(tar)}  "
            f"sticky={sticky_bits(dap.dp_read(DP_CTRL_STAT))}")


def probe_ap(dap, name, base):
    """AP 하나: IDR, CSW 쓰기/되읽기, TAR 패턴 쓰기/되읽기. 원래 값 복원."""
    dap.clear_sticky()
    idr = dap.ap_read(base, OFF_IDR)
    csw0 = dap.ap_read(base, OFF_CSW)
    tar0 = dap.ap_read(base, OFF_TAR)
    print(f"\n  [{name}] IDR={hx(idr)}  CSW={hx(csw0)} ({csw_bits(csw0)})  TAR(현재)={hx(tar0)}")

    csw_ok = None
    if csw0 is not None and csw0 != 0x80000000:
        # Size 필드(비트 2:0)만 word(2) → byte(0) 로 바꿔 보고 되읽는다
        res = []
        for size in (0x2, 0x0):
            want = (csw0 & ~0x7) | size
            wr = dap.ap_write(base, OFF_CSW, want)
            back = dap.ap_read(base, OFF_CSW)
            res.append(wr and back is not None and (back & 0x7) == size)
            print(f"    CSW.Size<={size}  쓰기={'OK' if wr else '실패'}  되읽기={hx(back)}  "
                  f"→ {'일치' if res[-1] else '불일치'}")
        dap.ap_write(base, OFF_CSW, csw0)                        # 복원
        csw_ok = all(res)

    tar_ok = []
    for pat in TAR_PATTERNS:
        wr = dap.ap_write(base, OFF_TAR, pat)
        dap.dp_read(DP_RDBUF)                                    # posted write flush
        ctrl = dap.dp_read(DP_CTRL_STAT)
        back = dap.ap_read(base, OFF_TAR)
        ok = wr and back == pat
        tar_ok.append(ok)
        print(f"    TAR<={hx(pat)}  쓰기={'OK' if wr else '실패'}  되읽기={hx(back)}  "
              f"sticky={sticky_bits(ctrl)}  → {'일치' if ok else '불일치'}")
        if not ok:
            dap.clear_sticky()
    if tar0 is not None:
        dap.ap_write(base, OFF_TAR, tar0)                        # 복원
    return idr, csw_ok, all(tar_ok), any(tar_ok)


def quick_ap(dap, base):
    """TAR 한 번 쓰고 되읽기 → 'O'/'X'/'E'."""
    dap.clear_sticky()
    dap.ap_write(base, OFF_TAR, 0x00000004)
    dap.dp_read(DP_RDBUF)
    back = dap.ap_read(base, OFF_TAR)
    if back is None or back == 0x80000000:
        return 'E'
    return 'O' if back == 0x00000004 else 'X'


def nvme_state():
    """호스트가 본 컨트롤러 상태(있으면) — 링크 변화와 rescan/드라이버 시점을 맞춰 보기 위함."""
    try:
        names = sorted(os.listdir('/sys/class/nvme'))
        if not names:
            return '-'
        with open(f'/sys/class/nvme/{names[0]}/state') as f:
            return f"{names[0]}:{f.read().strip()}"
    except OSError:
        return '-'


def pwr_bits(ctrl):
    """CTRL/STAT → 'Dr/Da Sr/Sa' (CDBG req/ack, CSYS req/ack)."""
    if ctrl is None:
        return '  ?/? ?/?'
    b = lambda n: (ctrl >> n) & 1
    return f"  {b(28)}/{b(29)} {b(30)}/{b(31)}"


class TxCounter:
    """jl.coresight_read/write 호출 수를 센다(인스턴스 속성으로 감싼다)."""
    def __init__(self, jl):
        self.n = 0
        for name in ('coresight_read', 'coresight_write'):
            fn = getattr(jl, name)
            setattr(jl, name, self._wrap(fn))

    def _wrap(self, fn):
        def call(*a, **k):
            self.n += 1
            return fn(*a, **k)
        return call


def watch(dap, seconds, interval, reassert=False, req=0x50000000, aps=None):
    aps = aps or AP_MAP
    names = [n for n, _b, _k in aps]
    print(f"\n  [watch] {seconds:.0f}초, {interval:.1f}초 간격"
          + (", 매 회 전원요청 재기입" if reassert else "")
          + "  (O=일치 X=불일치 E=링크에러)")
    print("    t(s)      tx  VTref   DPIDR       CTRL/STAT   CDBG CSYS(req/ack)  "
          + " ".join(f"{n:>7}" for n in names) + "   nvme")
    tx = TxCounter(dap.jl)
    t0 = time.monotonic()
    while True:
        t = time.monotonic() - t0
        n0 = tx.n
        if reassert:
            dap.dp_write(DP_ABORT, 0x0000001E)
            dap.dp_write(DP_CTRL_STAT, req)
            dap._select = None
        dpidr = dap.dp_read(0)
        ctrl = dap.dp_read(DP_CTRL_STAT)
        marks = [quick_ap(dap, b) for _n, b, _k in aps]
        try:
            vt = str(int(dap.jl.hardware_status.voltage))      # 프로브가 잰 VTref(mV)
        except Exception:
            vt = '?'
        print(f"    {t:6.1f}  {n0:6d}  {vt:>5}  {hx(dpidr):>10}  {hx(ctrl):>10}  {pwr_bits(ctrl):>16}  "
              + " ".join(f"{m:>7}" for m in marks) + f"   {nvme_state()}", flush=True)
        if t >= seconds:
            return
        time.sleep(interval)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--power", choices=("dbg-only", "both", "sys-only"), default="both",
                    help="DAP 전원요청 (퍼저 기본 both)")
    ap.add_argument("--dap-abort", action="store_true",
                    help="시험 전에 DP ABORT.DAPABORT(bit0)로 AP 에 걸린 전송을 취소")
    ap.add_argument("--watch", type=float, default=0, metavar="SEC",
                    help="한 세션으로 SEC 초 동안 AP 별 TAR 쓰기를 반복해 시간 변화를 본다")
    ap.add_argument("--interval", type=float, default=2.0, metavar="SEC",
                    help="--watch 반복 간격(초)")
    ap.add_argument("--speed", type=int, default=SPEED_KHZ, metavar="KHZ",
                    help=f"cJTAG 속도(kHz, 기본 {SPEED_KHZ})")
    ap.add_argument("--vtref-mv", type=int, default=1800, metavar="MV",
                    help="J-Link VTref 고정값(mV), open 직후·connect 전 적용. 0=자동(측정값 추종)")
    ap.add_argument("--aps", default="", metavar="NAMES",
                    help="시험할 AP 이름만(쉼표 구분, 예: APBAP3 또는 APBAP1,APBAP3). 기본 전부")
    ap.add_argument("--reassert", action="store_true",
                    help="--watch 매 회 ABORT·전원요청을 다시 써서 회복 여부를 본다")
    a = ap.parse_args()

    if not AP_MAP:
        print("AP_MAP 비어 있음 — risc-v/sjtag_addrs.json 확인", file=sys.stderr)
        return 9
    want = {n.strip().upper() for n in a.aps.split(',') if n.strip()}
    aps = [r for r in AP_MAP if not want or r[0].upper() in want]
    if not aps:
        print(f"--aps 에 맞는 AP 없음 (가능: {', '.join(r[0] for r in AP_MAP)})", file=sys.stderr)
        return 9
    lk = Link(core_base=CORE_BASE_MAIN, speed=a.speed, vtref_mv=a.vtref_mv)
    try:
        lk.open(tap_script=False)
    except Exception as e:
        print(f"  J-Link open 실패: {e}")
        return 3
    try:
        print(f"  [J-Link] {jlink_info(lk.jl)}  speed={a.speed}kHz")
        try:
            sj.prepare_session(lk, a.power, "off", tif_init=True, strict=False)
        except sj.SecureJtagError as e:
            print(f"  세션 준비 실패: {e}")
            return e.exit_code
        dap = sj.MemDap(lk.jl)
        print(f"  [DP] DPIDR={hx(dap.dp_read(0))}  CTRL/STAT={hx(dap.dp_read(DP_CTRL_STAT))}")

        if a.dap_abort:
            print(f"\n  [DAPABORT 전] APBAP3 {ap_state(dap, sj.APBAP3_BASE)}")
            ok = dap.dp_write(DP_ABORT, 0x00000001)              # DAPABORT
            dap.clear_sticky()
            print(f"  [DAPABORT] ABORT<=0x1 쓰기={'OK' if ok else '실패'}")
            print(f"  [DAPABORT 후] APBAP3 {ap_state(dap, sj.APBAP3_BASE)}")

        if a.watch:
            req = 0x10000000 if a.power == "dbg-only" else 0x50000000
            watch(dap, a.watch, max(0.2, a.interval), a.reassert, req, aps)
            return 0

        rows = [(name,) + probe_ap(dap, name, base) for name, base, _k in aps]

        # 실제 증상 재현: STATE 1회 읽기(읽기 전용)
        dap.clear_sticky()
        st = None
        if sj.SJTAG_BASE is not None:
            st = dap.mem_read32(sj.APBAP3_BASE, sj.SJTAG_BASE + sj.OFF_STATE)
        if sj.SJTAG_BASE is None:
            print("\n  [STATE 읽기] 건너뜀 — runtime.sjtag_base 미설정")
        else:
            print(f"\n  [STATE 읽기] {hx(st)}"
                  + ("" if st is not None else f"  ({dap.last.get('why')})"))

        print("\n  ── 요약 ──")
        for name, idr, csw_ok, tar_all, tar_any in rows:
            print(f"    {name:8} IDR={hx(idr):>10}  CSW쓰기={'-' if csw_ok is None else ('OK' if csw_ok else '실패')}  "
                  f"TAR쓰기={'OK' if tar_all else ('일부' if tar_any else '실패')}")
        idrs = {r[1] for r in rows if r[1] is not None}
        tars = [r[3] for r in rows]
        if len(rows) > 1 and len(idrs) == 1:
            print("  → IDR 이 AP 마다 같다: DP SELECT 쓰기부터 안 먹는 것으로 보임(링크 수준 쓰기 문제)")
        elif not any(tars):
            print("  → IDR 은 AP 별로 다르지만 TAR 쓰기가 전부 실패: AP 쓰기(APACC write) 경로 문제")
        elif all(tars) and st is None and sj.SJTAG_BASE is not None:
            print("  → TAR 쓰기는 정상인데 STATE 실패: TAR 이후(DRW/APB 버스) 문제")
        elif all(tars):
            print("  → 이번 실행에서는 AP 쓰기 정상"
                  + ("·STATE 정상" if st is not None else ""))
        else:
            bad = [r[0] for r in rows if not r[3]]
            print(f"  → 일부 AP 만 TAR 쓰기 실패: {', '.join(bad)}")
        return 0
    finally:
        try:
            lk.close()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
