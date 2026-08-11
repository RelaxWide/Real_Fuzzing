#!/usr/bin/env python3
"""SF-E76 — cJTAG 활성화 시퀀스가 원인인가. **TAP 인식부터 고친다.**

════════════════════════════════════════════════════════════════════
왜 이게 진짜 블로커로 보이는가
════════════════════════════════════════════════════════════════════
E76 으로 connect 했을 때 J-Link 로그:

    JTAG chain detection found 1 devices: #0 Id: 0x00000001, IRLen: 04
    Unknown device, Assuming RISC-V TAP with JTAG-DTM setup
    DTM architecture: RISC-V JTAG-DTM version: 0.11, AddrBits: 0, DataBits: 34
    Error while reading <dmcontrol> debug register
    Connect failed

**`Id: 0x00000001` 은 정상적인 IDCODE 가 아니다.** (bit0 만 1인 사실상 빈 값)
그래서 J-Link 이 TAPId 를 못 알아보고, SEGGER 문서의 규칙:

    · IRLen=4 이고 TAPId 가 **알려진 CoreSight DAP TAP** → RISC-V behind DAP 로 간주
    · 알려진 TAPId 가 없고 TAP 이 하나뿐이면 → 그냥 그걸 쓴다

두 번째 규칙으로 떨어져 **RISC-V JTAG-DTM 으로 오인**한다.
그러면 우리가 준 `CORESIGHT_*` 설정은 애초에 쓰이지 않는다 —
**CoreBase 를 뭘로 바꿔도 결과가 같았던 이유**가 이것이다.
`AddrBits: 0` 도 정상 DTM 이 아니라는 신호다.

════════════════════════════════════════════════════════════════════
★ 그리고 문서에 답이 적혀 있었다
════════════════════════════════════════════════════════════════════
`SetcJTAGInitMode`:

    0 = Long-form activation, JScan0 boot + OScan1 enter        (기본값)
    1 = Short-form activation, OScan1 boot
        → 원문: "**Needed for e.g. SiFive or RISC-V targets**"
    2 = Wiliot 전용

**우리는 브링업 내내 0 을 썼다.** SiFive 타깃에 필요한 건 1 이다.
활성화가 어설프면 TAP 이 부분적으로만 응답한다 — IDCODE 는 쓰레기인데
우리가 직접 한 DP 읽기(`DPIDR=0x11013913`)는 됐던 것도 여기에 부합한다.
우리 경로는 `perform_tif_init=False` 로 **재초기화를 건너뛰었기 때문**이다.

════════════════════════════════════════════════════════════════════
측정
════════════════════════════════════════════════════════════════════
관찰 대상은 **J-Link 자신의 로그**다. 우리가 해석할 필요가 없다:

    · `Id: 0x........`     ← 유효한 IDCODE 가 나오는가
    · `JTAG-DTM` 문구       ← 나오면 여전히 DAP 로 안 보는 것
    · `CoreSight` / `DAP`   ← 나오면 성공
    · `dmcontrol` 오류      ← 사라지는가

사용:
    sudo python3 probe_cjtag_mode.py            # 모드 0/1/2 × device 훑기
    sudo python3 probe_cjtag_mode.py --brief
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time

import pylink

from sfe76_link import require_api, TIF_CJTAG, SPEED_KHZ, EXIT_OK, EXIT_INSUFFICIENT

VERSION = "2026-08-11.18  TIF 스윕 (4선 JTAG 포함)"

# ★★ 한 번도 안 해본 것: **평범한 4선 JTAG**.
#   T32 가 cJTAG 를 쓰기에 우리도 cJTAG 만 썼다. 그런데 커넥터에
#   **TDI/TDO 가 물려 있다**(사용자 확인). 그러면 4선 JTAG 를 쓸 수 있고,
#   cJTAG 활성화 시퀀스라는 **문제의 원인 자체가 사라진다.**
#
#   지금 증상: J-Link 의 스캔이 Id=0x00000001 (쓰레기)을 읽는다
#   → TAP 을 못 알아봄 → JTAG-DTM 오인 → target_connected 가 끝내 False.
#   cJTAG 2선의 활성화가 어설프면 정확히 이렇게 된다.
#   4선 JTAG 는 활성화 시퀀스가 아예 없다.
TIFS = [(0, 'JTAG (4선)  ← 미시도'), (7, 'cJTAG (2선) ← 지금까지')]

# ★ IDCODE 가 어느 활성화 모드에서도 0x00000001 이면 자동 검출로는 안 된다.
#   SEGGER 문서의 TAP 선택 규칙:
#     IRLen=4 이고 TAPId 가 **알려진 CoreSight DAP TAP** → RISC-V behind DAP 로 간주
#   ⇒ TAP ID 를 **수동 선언**해서 그 규칙을 발동시킨다. InitTarget() 의 용도다.
#
#   JTAG_AllowTAPReset = **1** ← 0=자동검출 ON, 1=OFF. 우리는 0 을 쓰면서
#                                 "끈다" 고 착각했다(feedback 지적).
#   JLINK_JTAG_SetDeviceId(0, id)
#
#   ⚠ 전역 CPU 상수 목록에는 **RISC-V 가 없다**(ARM 전용). 그래서 CPU 는 설정하지
#     않고 체인만 선언한다 — device 지정(E76)이 그 역할을 대신하길 기대한다.
KNOWN_DAP_IDS = [
    (None,       '선언 안 함 (현재 동작)'),
    (0x4BA00477, 'ARM CoreSight DAP (A9 계열)'),
    (0x2BA01477, 'ARM CoreSight DAP (M 계열)'),
    (0x5BA00477, 'ARM CoreSight DAP'),
    (0x6BA00477, 'ARM CoreSight DAP'),
]

INIT_TMPL = """/* 자동 생성 — probe_cjtag_mode.py */
int InitTarget(void) {{
  JLINK_SYS_Report("SFE76_INIT_RAN");
  JTAG_AllowTAPReset = 1;      // ★ 1 이 자동 검출 OFF (0 은 ON — 반대로 썼었다)
  JTAG_IRPre  = 0;
  JTAG_DRPre  = 0;
  JTAG_IRPost = 0;
  JTAG_DRPost = 0;
  JTAG_IRLen  = 4;
  JLINK_JTAG_SetDeviceId(0, 0x{devid:08X});
  return 0;
}}
"""

MODES = [(1, 'SHORT/OScan1  ← SiFive 권장'), (0, 'LONG (지금까지 쓰던 것)'),
         (2, 'WILIOT')]
DEVICES = ['E76', 'E76-MC', 'RISC-V']

RE_ID = re.compile(r'Id:\s*(0x[0-9A-Fa-f]{8})')
RE_IRLEN = re.compile(r'IRLen:\s*(\d+)')


def bad_id(v):
    """정상 IDCODE 가 아닌 값. bit0 은 RAO 라 항상 1이어야 한다."""
    if v is None:
        return True
    n = int(v, 16)
    return n in (0x00000000, 0x00000001, 0xFFFFFFFF) or (n & 1) == 0


def tifsweep(a):
    """★ **4선 JTAG 를 처음 시험한다.** 지금 문제는 이 계층이다.

    관찰 대상은 J-Link 자신의 로그 IDCODE 와 `target_connected()` 다.
    `connect()` 무예외 종료는 **더 이상 신호로 쓰지 않는다** —
    그게 `target_connected=False` 인데도 성공으로 세어 온 원인이었다.
    """
    print(f"\n{'=' * 68}\n [TIF] 4선 JTAG vs cJTAG × 속도\n{'=' * 68}")
    print("  J-Link 스캔이 Id=0x00000001(쓰레기)을 읽는다 → TAP 미인식 → 연결 실패.")
    print("  cJTAG 2선 활성화가 어설프면 정확히 이렇게 된다.")
    print("  커넥터에 TDI/TDO 가 있으니 **4선 JTAG 는 활성화 시퀀스가 아예 없다.**\n")
    speeds = [int(x) for x in a.speeds.split(',') if x.strip()]
    rows = []
    for tif, tlabel in TIFS:
        for spd in speeds:
            r = spawn(1, a.device_one, spd, None, tif)
            r['tif'], r['tlabel'] = tif, tlabel
            rows.append(r)
            ok = not bad_id(r.get('idcode'))
            print(f"  {tlabel:22s} {spd:>6d}kHz  Id={r.get('idcode') or '없음':10s}"
                  f" IRLen={r.get('irlen') or '-'}"
                  f"  target={int(bool(r.get('target_connected')))}"
                  f"{'  ★ 유효 IDCODE' if ok else ''}")
            time.sleep(0.4)

    print(f"\nv={VERSION.split()[0]}")
    for r in rows:
        print(f"tif={r['tif']} spd={r['speed']} Id={r.get('idcode') or '-'} "
              f"target={int(bool(r.get('target_connected')))}")
    tgt = [r for r in rows if r.get('target_connected')]
    good = [r for r in rows if not bad_id(r.get('idcode'))]
    print("VERDICT:", "TARGET_CONNECTED" if tgt else
          ("IDCODE_OK_NO_TARGET" if good else "NO_SIGNAL"))
    if tgt:
        r = tgt[0]
        print(f"  ★★★ tif={r['tif']} speed={r['speed']} 에서 **타깃에 붙었다.**")
        print("     sfe76_link 의 TIF/속도를 이 값으로 고정한다.")
    return EXIT_OK if tgt else EXIT_INSUFFICIENT


def write_init_script(devid):
    import tempfile
    p = os.path.join(tempfile.gettempdir(), f"sfe76_init_{os.getpid()}.JLinkScript")
    with open(p, 'w') as f:
        f.write(INIT_TMPL.format(devid=devid))
    return p


def run_one(a):
    rec = {'tif': a.tif, 'mode': a.mode, 'device': a.device, 'speed': a.speed,
           'devid': (f"0x{a.devid:08X}" if a.devid else None), 'connect': False,
           'idcode': None, 'irlen': None, 'dtm': False, 'dap': False,
           'dmcontrol_err': False, 'error': None}
    logs = []
    cb = lambda m: logs.append(str(m))
    jl = pylink.JLink(log=cb, detailed_log=cb, error=cb, warn=cb)
    try:
        sp = write_init_script(a.devid) if a.devid else None
        if sp:
            try:
                jl.exec_command(f"ScriptFile = {sp}")
            except Exception:
                pass
        jl.open()
        jl.exec_command(f"SetcJTAGInitMode = {a.mode}")
        jl.exec_command("EnableRemarks = 1")
        if sp:
            try:
                jl.exec_command(f"ScriptFile = {sp}")
            except Exception:
                pass
        jl.set_tif(a.tif)
        jl.set_speed(a.speed)
        try:
            jl.connect(a.device, speed=a.speed)
            rec['connect'] = True
        except Exception as e:
            rec['error'] = str(e)[:120]
    except Exception as e:
        rec['error'] = str(e)[:120]
    finally:
        blob = "\n".join(logs)
        m = RE_ID.search(blob)
        rec['idcode'] = m.group(1) if m else None
        m2 = RE_IRLEN.search(blob)
        rec['irlen'] = m2.group(1) if m2 else None
        low = blob.lower()
        rec['dtm'] = 'jtag-dtm' in low or 'dtm setup' in low
        rec['dap'] = ('coresight' in low) or ('dap' in low and 'jtag-dtm' not in low)
        rec['dmcontrol_err'] = 'dmcontrol' in low
        rec['log_lines'] = len(logs)
        rec['init_ran'] = 'SFE76_INIT_RAN' in blob
        try:
            rec['target_connected'] = bool(jl.target_connected())
        except Exception:
            rec['target_connected'] = False
        try:
            jl.close()
        except Exception:
            pass
    print("@@JSON@@" + json.dumps(rec, ensure_ascii=False))
    return EXIT_OK if rec['connect'] else EXIT_INSUFFICIENT


def spawn(mode, device, speed, devid, tif=7):
    cmd = [sys.executable, os.path.abspath(__file__), '--single',
           '--mode', str(mode), '--device', device, '--speed', str(speed),
           '--tif', str(tif)]
    if devid:
        cmd += ['--devid', hex(devid)]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout
    except subprocess.TimeoutExpired:
        return {'mode': mode, 'device': device, 'speed': speed, 'error': 'timeout',
                'connect': False, 'idcode': None, 'dtm': False}
    for line in out.splitlines():
        if line.startswith("@@JSON@@"):
            return json.loads(line[len("@@JSON@@"):])
    return {'mode': mode, 'device': device, 'speed': speed, 'error': 'no result',
            'connect': False, 'idcode': None, 'dtm': False}


def main():
    require_api(4, "probe_cjtag_mode.py")
    ap = argparse.ArgumentParser()
    ap.add_argument('--brief', action='store_true')
    ap.add_argument('--devices', default=",".join(DEVICES))
    ap.add_argument('--device-one', default='E76', help='TIF 스윕에서 쓸 device')
    ap.add_argument('--version', action='store_true')
    ap.add_argument('--single', action='store_true', help=argparse.SUPPRESS)
    ap.add_argument('--mode', type=int, default=1, help=argparse.SUPPRESS)
    ap.add_argument('--device', default='E76', help=argparse.SUPPRESS)
    ap.add_argument('--speed', type=int, default=SPEED_KHZ, help=argparse.SUPPRESS)
    ap.add_argument('--devid', type=lambda x: int(x, 0), default=None,
                    help=argparse.SUPPRESS)
    ap.add_argument('--tif', type=int, default=7, help=argparse.SUPPRESS)
    ap.add_argument('--tifsweep', action='store_true',
                    help='★ 4선 JTAG vs cJTAG × 속도. 지금 증상의 계층을 친다')
    ap.add_argument('--speeds', default="10000,4000,1000",
                    help='시험할 JTAG 속도(kHz). IDCODE 가 쓰레기면 신호 무결성일 수도')
    ap.add_argument('--modes', default="1,0")
    a = ap.parse_args()
    if a.version:
        print(f"probe_cjtag_mode {VERSION}")
        return EXIT_OK
    if a.single:
        return run_one(a)

    devs = [x.strip() for x in a.devices.split(',') if x.strip()]
    if not a.brief:
        print(f"\n{'=' * 68}\n cJTAG 활성화 시퀀스 (v{VERSION})\n{'=' * 68}")
        print("  로그의 IDCODE 가 유효해지는 조합을 찾는다.")
        print("  0x00000001 은 IDCODE 가 아니다 — 그래서 J-Link 이 TAP 을 못 알아보고")
        print("  CoreSight DAP 대신 RISC-V JTAG-DTM 으로 오인한다.\n")
        print("  SetcJTAGInitMode 1 = 'Needed for e.g. SiFive or RISC-V targets' (문서)\n")

    if a.tifsweep:
        return tifsweep(a)

    modes = [int(x) for x in a.modes.split(',') if x.strip()]
    speeds = [int(x) for x in a.speeds.split(',') if x.strip()]
    total = len(modes) * len(devs) * len(speeds) * len(KNOWN_DAP_IDS)
    if not a.brief:
        print(f"  총 {total} 조합 (모드 {modes} × device {devs} × "
              f"속도 {speeds} × TAP ID {len(KNOWN_DAP_IDS)}종)\n")

    rows = []
    for devid, idlabel in KNOWN_DAP_IDS:
        for mode in modes:
            for spd in speeds:
                for dev in devs:
                    r = spawn(mode, dev, spd, devid)
                    rows.append(r)
                    ok = not bad_id(r.get('idcode'))
                    if not a.brief and (ok or r.get('connect') or devid is None):
                        print(f"  id={idlabel:28s} mode={mode} {spd:>5d}kHz "
                              f"{dev:8s} Id={r.get('idcode') or '없음'}"
                              f"{'  ★ 유효' if ok else ''}"
                              f"{'  connect O' if r.get('connect') else ''}"
                              f"{'  [DTM 오인]' if r.get('dtm') else ''}")
                    time.sleep(0.3)

    good = [r for r in rows if not bad_id(r.get('idcode'))]
    conn = [r for r in rows if r.get('connect')]
    nodtm = [r for r in rows if not r.get('dtm')]

    print(f"\nv={VERSION.split()[0]}")
    for r in rows:
        if not bad_id(r.get('idcode')) or r.get('connect'):
            print(f"mode={r['mode']} dev={r['device']:8s} spd={r.get('speed')} "
                  f"id={r.get('devid') or '-'} Id={r.get('idcode') or '-'} "
                  f"connect={int(bool(r.get('connect')))} dtm={int(bool(r.get('dtm')))}")
    print(f"init스크립트실행={sum(1 for r in rows if r.get('init_ran'))}/{len(rows)}")
    print(f"유효IDCODE={len(good)}/{len(rows)}  connect={len(conn)}  "
          f"DTM오인아님={len(nodtm)}")
    print("VERDICT:", "IDCODE_OK" if good else
          ("CONNECT_ONLY" if conn else "TAP_NOT_IDENTIFIED"))

    if not a.brief:
        print(f"\n{'=' * 68}")
        if good:
            m = good[0]
            print(f"  ★★ mode={m['mode']} device={m['device']} 에서 IDCODE 가 유효해졌다.")
            print("     → sfe76_link.CJTAG_MODE / DEVICE 를 이 값으로 고정하고")
            print("       try_jlinkscript.py 를 **이 조건에서** 다시 돌린다.")
            print("       (이전 24/24 는 TAP 오인 상태의 결과라 무의미하다)")
        else:
            print("  IDCODE 가 어느 조합에서도 유효하지 않다.")
            print("  → cJTAG 물리 계층 문제일 수 있다: 속도(10MHz)를 낮춰 재시도,")
            print("     TCKC/TMSC 배선·풀업, 타깃 전원 사이클 후 재측정.")
    return EXIT_OK if good else EXIT_INSUFFICIENT


if __name__ == '__main__':
    sys.exit(main())
