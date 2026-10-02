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

사용: sudo python3 risc-v/ap_write_probe.py [--power both|dbg-only|sys-only] [--dap-abort]
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sjtag_unlock as sj                                    # noqa: E402
from sfe76_link import Link, AP_MAP, CORE_BASE_MAIN          # noqa: E402
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


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--power", choices=("dbg-only", "both", "sys-only"), default="both",
                    help="DAP 전원요청 (퍼저 기본 both)")
    ap.add_argument("--dap-abort", action="store_true",
                    help="시험 전에 DP ABORT.DAPABORT(bit0)로 AP 에 걸린 전송을 취소")
    a = ap.parse_args()

    if not AP_MAP:
        print("AP_MAP 비어 있음 — risc-v/sjtag_addrs.json 확인", file=sys.stderr)
        return 9
    lk = Link(core_base=CORE_BASE_MAIN)
    try:
        lk.open(tap_script=False)
    except Exception as e:
        print(f"  J-Link open 실패: {e}")
        return 3
    try:
        print(f"  [J-Link] {jlink_info(lk.jl)}")
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

        rows = [(name,) + probe_ap(dap, name, base) for name, base, _k in AP_MAP]

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
