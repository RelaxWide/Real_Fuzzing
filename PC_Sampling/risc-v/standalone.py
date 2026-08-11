#!/usr/bin/env python3
"""SF-E76 — **단일 파일 진단기.** 다른 파일을 하나도 import 하지 않는다.

════════════════════════════════════════════════════════════════════
왜 단일 파일인가
════════════════════════════════════════════════════════════════════
지금까지 다섯 번, "인자를 못 알아듣는다 / 함수가 없다" 가 전부
**파일 버전이 서로 안 맞아서** 생겼다. `sfe76_link.py` 만 옛것이어도
전 도구가 깨진다. 받아오는 방식이 무엇이든 그 위험이 남는다.

이 파일은 **`pylink` 외에 아무것도 필요 없다.** 복사 한 번이면 끝이고
버전 스큐가 원리적으로 생기지 않는다.

════════════════════════════════════════════════════════════════════
무엇을 재나 (전부 읽기 전용)
════════════════════════════════════════════════════════════════════
  1. J-Link 정보 / cJTAG / DP  — DPIDR, 하드웨어 버전
  2. DAP 전원                   — CTRL/STAT, ACK 비트
  3. AP 6개                     — IDR / CSW / CFG / BASE
  4. DM 후보 읽기               — ROM 엔트리와 그것이 가리키는 곳
  5. DP 오류 비트               — ★ STICKYERR 는 **bit5** (bit7 아님)

★ 쓰기는 CSW/TAR/DP-SELECT/ABORT 뿐이다. **DRW 에 쓰지 않는다** =
  타깃 메모리에 아무것도 쓰지 않는다.

════════════════════════════════════════════════════════════════════
사용
════════════════════════════════════════════════════════════════════
    sudo python3 standalone.py                # 전체
    sudo python3 standalone.py --sessions 3   # 재현성 확인
    sudo python3 standalone.py --json out.json
"""

import argparse
import json
import sys
import time

try:
    import pylink
except ImportError:
    sys.exit("pylink 없음 →  pip3 install pylink-square")

VERSION = "standalone 2026-08-11.7  u1 도 값을 찍는다"

# ★ APBAP3 앞 4워드에 내용이 있다 (유효 세션, DPIDR=0x6BA0009D):
#     0x00=0x00040700  0x04=0x00000010  0x08=0x81592158  0x0C=0x000002C3
#     0x10~0x1C = 0
#   0x08 은 0x81xxxxxx 대역 — DM base(0x81480000/0x81481000)와 같은 계열이다.
#   여기가 **DMI aperture** 라면(stride 4) dmstatus 는 바이트 0x44 다.
#   우리는 0x0~0x1C 만 봤고 **그 자리를 아직 안 봤다.**
#   → 'dmi' 프리셋으로 스펙상 의미 있는 오프셋만 골라 읽는다.

# ★ 결과를 **손으로 옮겨 적는** 환경이다. 그래서 기본 출력을 3줄로 줄인다.
#   전체가 필요하면 --full, 파일이 필요하면 --json.
#   지금 판단에 실제로 필요한 것은 셋뿐이다:
#     ① STICKYERR 가 뜨는가 (비트 수정 후 재측정의 핵심)
#     ② 전송이 어느 단계에서 끝나는가
#     ③ AP 별로 읽은 값이 **몇 종류**인가 (1종 = 변화 없음)

TIF_CJTAG, SPEED_KHZ, CJTAG_MODE, DEVICE = 7, 10000, 1, 'E76'
# ★ **선언값과 읽은 값을 구분한다.** 실측:
#     선언 0x5BA00477 (알려진 ARM DAP) → DPIDR 읽기 = 0x6BA0009D   ← 유효
#     선언 0x6BA0009D (읽은 값 그대로) → DPIDR 읽기 = 0xFFFFFFFF   ← 무효
#   J-Link 은 **선언된 ID 로 어떤 프로토콜로 말할지**를 정한다. 0x5BA00477 은
#   알려진 CoreSight DAP 이라 ARM DAP 경로를 타고, 0x6BA0009D 는 모르는 ID 라
#   다른 처리로 빠져 스캔이 깨진다.
#   ⇒ **선언은 0x5BA00477**, 그 상태에서 읽히는 0x6BA0009D 가 실리콘의 IDCODE.
OBSERVED_TAP_ID = 0x6BA0009D      # 실리콘에서 읽은 값 (선언용 아님)
CHAIN_TAP_ID = 0x5BA00477         # J-Link 에 선언하는 값

AP_MAP = [("APBAP1", 0x10000, "APB-AP"), ("APBAP2", 0x20000, "APB-AP"),
          ("AXIAP1", 0x30000, "AXI-AP"), ("AHBAP1", 0x40000, "AHB-AP"),
          ("APBAP3", 0x50000, "APB-AP"), ("APBAP4", 0x60000, "APB-AP")]

# RISC-V Debug Spec DMI 레지스터 (주소, 이름). 바이트 오프셋 = 주소 << 2
DMI_REGS = [(0x10, 'dmcontrol'), (0x11, 'dmstatus'), (0x12, 'hartinfo'),
            (0x16, 'abstractcs'), (0x17, 'command'), (0x1D, 'nextdm'),
            (0x38, 'sbcs'), (0x04, 'data0')]
DM_VER = {0: '없음', 1: '0.11', 2: '★0.13', 3: '★1.0'}

DP_ABORT, DP_CTRL, DP_SELECT = 0, 1, 2
OFF_CSW, OFF_TAR, OFF_DRW = 0xD00, 0xD04, 0xD0C
OFF_CFG, OFF_BASE, OFF_IDR = 0xDF4, 0xDF8, 0xDFC

TAP_SCRIPT = """void ConfigTargetSettings(void) {
  JTAG_AllowTAPReset = 1;            /* 1 = 자동 검출 OFF */
  JLINK_JTAG_SetDeviceId(0, 0x%08X);
  JLINK_JTAG_IRPre  = 0;
  JLINK_JTAG_DRPre  = 0;
  JLINK_JTAG_IRPost = 0;
  JLINK_JTAG_DRPost = 0;
  JLINK_JTAG_IRLen  = 4;
  return 0;
}
"""


def hx(v):
    return "----" if v is None else f"{v & 0xFFFFFFFF:08X}"


def decode_ctrl(v):
    """★ STICKYERR 는 **bit5**. 이전 코드가 `1 << 5 + 2`(=bit7)로 잘못 봤다."""
    if v is None:
        return {}
    return {'raw': f"0x{v:08X}",
            'STICKYORUN': bool(v & (1 << 1)),
            'STICKYERR': bool(v & (1 << 5)),
            'READOK': bool(v & (1 << 6)),
            'WDATAERR': bool(v & (1 << 7)),
            'CDBGACK': bool(v & (1 << 29)),
            'CSYSACK': bool(v & (1 << 31))}


class Dap:
    def __init__(self, jl):
        self.jl, self.sel = jl, None

    def dpr(self, r):
        try:
            v = self.jl.coresight_read(r, ap=False)
            return None if (v is None or v < 0) else v & 0xFFFFFFFF
        except Exception:
            return None

    def dpw(self, r, v):
        try:
            self.jl.coresight_write(r, v & 0xFFFFFFFF, ap=False)
            return True
        except Exception:
            return False

    def abort(self):
        self.dpw(DP_ABORT, 0x1E)
        self.sel = None

    def _sel(self, addr):
        v = addr & 0xFFFFFFF0
        if self.sel == v:
            return True
        if not self.dpw(DP_SELECT, v):
            return False
        self.sel = v
        try:
            self.jl.coresight_read(0, ap=True)      # priming
        except Exception:
            pass
        return True

    def apr(self, base, off):
        if not self._sel(base + off):
            return None
        try:
            v = self.jl.coresight_read((off >> 2) & 3, ap=True)
            return None if (v is None or v < 0) else v & 0xFFFFFFFF
        except Exception:
            return None

    def apw(self, base, off, val):
        if not self._sel(base + off):
            return False
        try:
            self.jl.coresight_write((off >> 2) & 3, val & 0xFFFFFFFF, ap=True)
            return True
        except Exception:
            return False

    def mem32(self, base, addr, csw0):
        """읽기 전용. CSW/TAR 만 쓰고 **DRW 에는 쓰지 않는다.**"""
        self.abort()
        before = decode_ctrl(self.dpr(DP_CTRL))
        if csw0 is None:
            return None, {'stage': 'no_csw', 'before': before}
        if not self.apw(base, OFF_CSW, (csw0 & ~0x37) | 0x02):
            return None, {'stage': 'csw_write_fail', 'before': before}
        if not self.apw(base, OFF_TAR, addr):
            return None, {'stage': 'tar_write_fail', 'before': before}
        back = self.apr(base, OFF_TAR)
        if back != (addr & 0xFFFFFFFF):
            return None, {'stage': 'tar_mismatch', 'tar_back': hx(back),
                          'before': before, 'after': decode_ctrl(self.dpr(DP_CTRL))}
        v = self.apr(base, OFF_DRW)
        return v, {'stage': 'ok' if v is not None else 'drw_fail',
                   'before': before, 'after': decode_ctrl(self.dpr(DP_CTRL))}


def session(a, idx):
    import os
    import tempfile
    sp = os.path.join(tempfile.gettempdir(), f"sfe76_sa_{os.getpid()}.JLinkScript")
    with open(sp, 'w') as f:
        f.write(TAP_SCRIPT % CHAIN_TAP_ID)

    out = {'session': idx, 'ok': False, 'aps': {}, 'log': []}
    logs = []
    cb = lambda m: logs.append(str(m).rstrip())
    jl = pylink.JLink(log=cb, detailed_log=cb, error=cb, warn=cb)
    try:
        try:
            jl.exec_command(f"ScriptFile = {sp}")
        except Exception:
            pass
        jl.open()
        out['probe'] = f"{jl.product_name} HW={jl.hardware_version} FW={jl.firmware_version}"
        try:
            jl.exec_command(f"ScriptFile = {sp}")
        except Exception:
            pass
        jl.exec_command(f"SetcJTAGInitMode = {CJTAG_MODE}")
        jl.set_tif(TIF_CJTAG)
        jl.set_speed(SPEED_KHZ)
        for i, (_n, addr, typ) in enumerate(AP_MAP):
            jl.exec_command(f"CORESIGHT_AddAP = Index={i} Type={typ} BaseAddr=0x{addr:X}")
        try:
            jl.connect(a.device, speed=SPEED_KHZ)
            out['connect'] = True
        except Exception as e:
            out['connect'] = False
            out['connect_err'] = str(e)[:100]

        d = Dap(jl)
        try:
            jl.coresight_configure(ir_pre=0, dr_pre=0, ir_post=0, dr_post=0,
                                   ir_len=4, perform_tif_init=False)
        except Exception:
            try:
                jl.coresight_configure()
            except Exception as e:
                out['error'] = f"coresight_configure: {e}"
                return out

        dpidr = d.dpr(0)
        out['DPIDR'] = hx(dpidr)
        # ★ DPIDR 이 무효면 그 세션의 AP 값은 **전부 무효**다.
        #   bit0 은 RAO 이므로 짝수이거나 0/0xFFFFFFFF 면 데이터가 아니다.
        out['dpidr_ok'] = (dpidr is not None and (dpidr & 1) == 1
                           and dpidr not in (0x00000001, 0xFFFFFFFF))
        d.dpw(DP_ABORT, 0x1E)
        d.dpw(DP_CTRL, 0x50000000)
        for _ in range(30):
            time.sleep(0.01)
            c = d.dpr(DP_CTRL)
            if c and c & (1 << 29):
                break
        out['CTRL'] = decode_ctrl(d.dpr(DP_CTRL))
        out['ok'] = bool(out['CTRL'].get('CDBGACK')) and out['dpidr_ok']

        for name, base, _t in AP_MAP:
            csw = d.apr(base, OFF_CSW)
            ap = {'IDR': hx(d.apr(base, OFF_IDR)), 'CSW': hx(csw),
                  'CFG': hx(d.apr(base, OFF_CFG)), 'BASE': hx(d.apr(base, OFF_BASE))}
            if csw is not None:
                ap['DeviceEn'] = bool(csw & (1 << 6))
                ap['Prot'] = f"0x{(csw >> 24) & 0x7F:02X}"
            reads = {}
            for addr in a.addrs:
                v, meta = d.mem32(base, addr, csw)
                reads[f"0x{addr:08X}"] = hx(v)
                out['log'].append({'ap': name, 'addr': f"0x{addr:08X}", **meta})
            ap['reads'] = reads
            if csw is not None:
                d.apw(base, OFF_CSW, csw)        # CSW 원복
            out['aps'][name] = ap
    except Exception as e:
        out['error'] = str(e)[:120]
    finally:
        try:
            jl.close()
        except Exception:
            pass
        try:
            os.unlink(sp)
        except OSError:
            pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--device', default=DEVICE)
    ap.add_argument('--sessions', type=int, default=3)
    ap.add_argument('--addrs', default="0x0,0x4,0x81480000,0x81480044,0xC81040,0xC81044",
                    help="콤마 구분 주소. 'dmi' 를 주면 DMI 레지스터 자리를 자동 계산")
    ap.add_argument('--json', default=None)
    ap.add_argument('--ap', default=None,
                    help='이 AP 하나만 읽는다 (예: APBAP3). 기본은 6개 전부')
    ap.add_argument('--tapid', type=lambda x: int(x, 0), default=None,
                    help='선언할 TAP IDCODE (기본: 실측값 0x6BA0009D)')
    ap.add_argument('--full', action='store_true',
                    help='AP 별 상세까지 전부 출력 (기본은 3줄 요약)')
    ap.add_argument('--version', action='store_true')
    a = ap.parse_args()
    if a.version:
        print(VERSION)
        return 0
    if a.addrs.strip() == 'dmi':
        # RISC-V Debug Spec 의 DMI 주소 × stride 4
        a.addrs = [d * 4 for d, _n in DMI_REGS]
        a.dmi_mode = True
    else:
        a.addrs = [int(x, 0) for x in a.addrs.split(',') if x.strip()]
        a.dmi_mode = False
    global CHAIN_TAP_ID, AP_MAP
    if a.tapid is not None:
        CHAIN_TAP_ID = a.tapid
    if a.ap:
        names = [n for n, _b, _t in AP_MAP]
        if a.ap not in names:
            sys.exit(f"--ap 는 {names} 중 하나여야 한다")
        AP_MAP = [x for x in AP_MAP if x[0] == a.ap]

    print(f"\n{'=' * 70}\n {VERSION}   ★ 단일 파일 · 읽기 전용\n{'=' * 70}")
    print(f"  device={a.device}  cJTAG mode={CJTAG_MODE}  {SPEED_KHZ}kHz")
    print(f"  TAP ID 수동 선언 0x{CHAIN_TAP_ID:08X}  (AllowTAPReset=1)")
    print(f"  AP {[n for n, _b, _t in AP_MAP]}")
    print(f"  주소 {[hex(x) for x in a.addrs]}\n")

    runs = [session(a, i) for i in range(a.sessions)]
    ok = [r for r in runs if r.get('ok')]

    last = ok[-1] if ok else (runs[-1] if runs else None)
    stages, errs = {}, {}
    if last:
        for e in last.get('log', []):
            stages[e['stage']] = stages.get(e['stage'], 0) + 1
            for k in ('STICKYERR', 'WDATAERR', 'STICKYORUN'):
                if (e.get('after') or {}).get(k):
                    errs[k] = errs.get(k, 0) + 1

    print(f"\n---8<---")
    bad = [r for r in runs if not r.get('dpidr_ok')]
    if bad:
        print(f"\n⚠⚠ DPIDR 무효 세션 {len(bad)}/{a.sessions} — "
              f"그 세션의 AP 값은 **전부 무효**다. 해석하지 말 것.")
    print(f"ok={len(ok)}/{a.sessions} DPIDR={(last or {}).get('DPIDR')} "
          f"CTRL={((last or {}).get('CTRL') or {}).get('raw')}")
    print("ERR " + (" ".join(f"{k}={v}" for k, v in sorted(errs.items()))
                    if errs else "없음")
          + "  stages=" + ",".join(f"{k}:{v}" for k, v in sorted(stages.items())))
    # AP 별로 **읽은 값의 종류 수**만 낸다 — 1종이면 변화 없음
    parts = []
    for n, apd in ((last or {}).get('aps') or {}).items():
        u = len(set(apd['reads'].values()))
        parts.append(f"{n}:B={apd['BASE'][-1]}/u{u}")
    print(" ".join(parts))
    for n, apd in ((last or {}).get('aps') or {}).items():
        vs = sorted(set(apd['reads'].values()))
        if len(vs) == 1:
            # ★ 전부 같아도 **그 값이 무엇인지**는 찍는다. 이전엔 생략해서
            #   "u1 만 나오고 끝" 이 됐다 — 정보를 버리고 있었다.
            print(f"{n}= 전부 {vs[0]}")
        else:
            if getattr(a, 'dmi_mode', False):
                names = {d * 4: nm for d, nm in DMI_REGS}
                print(" ".join(
                    f"{names.get(int(k, 16), k)}={v}"
                    for k, v in apd['reads'].items()))
            elif len(AP_MAP) == 1:      # AP 하나만 볼 땐 주소별로 낸다
                print(" ".join(f"{k.replace('0x', '')}={v}"
                                for k, v in apd['reads'].items()))
            else:
                print(f"{n}= " + ",".join(vs))
        # dmi 모드면 값이 몇 종이든 dmstatus 를 해석한다
        if getattr(a, 'dmi_mode', False):
            ds = apd['reads'].get(f"0x{0x11 * 4:08X}")
            if ds and ds != '----':
                ver = int(ds, 16) & 0xF
                print(f"  dmstatus={ds} version={ver} ({DM_VER.get(ver, '무효')})"
                      + ("   ★★★ DM 을 찾았다" if ver in (2, 3) else ""))
    print("---8<---")

    if a.full and last:
        print(f"\n{'=' * 70}\n 상세\n{'=' * 70}")
        if last.get('probe'):
            print(f"  {last['probe']}")
        for n, apd in (last.get('aps') or {}).items():
            print(f"  {n} IDR={apd['IDR']} CSW={apd['CSW']} CFG={apd['CFG']} "
                  f"BASE={apd['BASE']} DevEn={apd.get('DeviceEn')} Prot={apd.get('Prot')}")
            for k, v in apd['reads'].items():
                print(f"      {k} = {v}")

    if a.json:
        with open(a.json, 'w') as f:
            json.dump(runs, f, ensure_ascii=False, indent=1)
        print(f"(상세 {a.json})")
    return 0 if ok else 6


if __name__ == '__main__':
    sys.exit(main())
