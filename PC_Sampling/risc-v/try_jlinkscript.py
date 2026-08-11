#!/usr/bin/env python3
"""SF-E76 — **J-Link 네이티브 경로**로 DM 에 붙인다. JLinkScript + 조합 훑기.

════════════════════════════════════════════════════════════════════
왜 이제 이 길인가
════════════════════════════════════════════════════════════════════
raw DAP 로 DMI 를 직접 읽는 접근은 **소진됐다.** 실측 결론:

    MEM-AP 읽기가 0x0 / 0x4 에서만 실제 값을 준다. 그 밖의 주소는
    주소가 아니라 **32바이트 정렬 여부만 보고** 두 상수로 떨어진다.
    (정렬 → 0x00000001, 비정렬 → 0xEAFFFFFE)
    ⇒ 우리 MEM-AP 메모리 트랜잭션이 성립하지 않는다.

그러니 **DMI 프로토콜을 우리가 구현하지 않는다.** J-Link 이 이미 안다.
우리가 할 일은 **어디인지 알려주는 것**뿐이고, 그 정식 수단이 JLinkScript 다.

★ 예전에 JLinkScript 를 폐기한 건 **훅을 잘못 골랐기 때문**이다.
  `InitTarget()` 은 JTAG 체인과 전역 `CPU` 를 수동으로 다 지정해야 하는데
  안 해서 cJTAG 스캔이 깨졌다(`IRPrint=0x..0000`).
  `ConfigTargetSettings()` 는 SEGGER 문서상 **타깃 통신이 금지**된 훅이라
  **스캔을 깨뜨릴 수가 없다.** SEGGER 의 RISC-V 예제도 이걸 쓴다.

════════════════════════════════════════════════════════════════════
훑는 변수 (전부 근거가 있는 것만)
════════════════════════════════════════════════════════════════════
  AddAP 문법   `Addr=` / `BaseAddr=`   ← SEGGER 문서 두 곳이 서로 다르다
  APB-AP 인덱스 0,1,4,5                ← APB 타입 AP 4개
  CoreBase     0x81480000 (ROM 엔트리가 지목) / 0x0 (SEGGER 예제) / 0x81481000
  device       RISC-V / E76

오라클: connect 성공 + **`halted()` 동작**(DM 이 살아야만 되고 비침습).
조합마다 **별도 프로세스** — 핸들 재사용은 거짓 성공을 만든다(실측 확인됨).

사용:
    sudo python3 try_jlinkscript.py --brief
    sudo python3 try_jlinkscript.py --only-syntax BaseAddr    # 좁혀 볼 때
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

import pylink

from sfe76_link import (require_api, TIF_CJTAG, SPEED_KHZ, CJTAG_MODE,
                        AP_MAP, EXIT_OK, EXIT_INSUFFICIENT)

VERSION = "2026-08-11.14  focus 모드"

# ★ TAP ID 를 선언하면 JTAG-DTM 오인이 사라진다(실측: DTM오인아님 0/9 → 78/90).
#   ⚠ 다만 "유효 IDCODE" 자체는 **우리가 선언한 값을 되돌려받은 것**일 수 있다.
#      의미 있는 신호는 DTM 오인이 사라진 것과, 그 위에서 DM 이 사는지다.
DEVIDS = [0x4BA00477, 0x2BA01477, 0x5BA00477, 0x6BA00477]

SYNTAXES = ['BaseAddr']
AP_INDEXES = [0, 1]                            # ROM 엔트리가 지목한 둘
CORE_BASES = [0x81480000, 0x0]
DEVICES = ['E76']            # ★ 'RISC-V' 는 connect 자체가 안 된다(실측)

MARKER = "SFE76_SCRIPT_RAN"

TEMPLATE = """/* 자동 생성 — try_jlinkscript.py */

/* ── ① 체인 선언 ─────────────────────────────────────────────────
   자동 검출이 Id=0x00000001 을 읽어 TAP 을 못 알아본다. 그러면 SEGGER 규칙
   "IRLen=4 + 알려진 CoreSight DAP TAP → RISC-V behind DAP" 를 못 타고
   JTAG-DTM 으로 오인한다. 그래서 **직접 선언**한다.
   문서: InitTarget 을 구현하면 "JTAG chain has to be specified manually".
   (전역 CPU 는 설정하지 않는다 — 상수 목록에 RISC-V 가 없다. device 로 대신한다) */
int InitTarget(void) {{
  JLINK_SYS_Report("{marker}_INIT");
  JTAG_AllowTAPReset = 0;
  JTAG_IRPre  = 0;
  JTAG_DRPre  = 0;
  JTAG_IRPost = 0;
  JTAG_DRPost = 0;
  JTAG_IRLen  = 4;
  JLINK_JTAG_SetDeviceId(0, 0x{devid:08X});
  return 0;
}}

/* ── ② AP 맵과 DMI 위치 ──────────────────────────────────────────
   타깃 통신이 금지된 훅이라 스캔을 깨뜨리지 않는다. */
void ConfigTargetSettings(void) {{
  // ★ 이 줄이 J-Link 로그에 보이면 스크립트가 **실제로 로드·실행**된 것이다.
  //    JLINK_SYS_Report 는 호스트 측 출력이라 "타깃 통신" 금지 규칙에 걸리지 않는다.
  JLINK_SYS_Report("{marker}");
{aps}
  JLINK_ExecCommand("CORESIGHT_SetIndexAPBAPToUse = {apidx}");
  JLINK_ExecCommand("CORESIGHT_SetCoreBaseAddr = 0x{corebase:X}");
  JLINK_ExecCommand("RISCV_SetHartSel = {hart}");
  return 0;
}}
"""


def gen_script(path, syntax, apidx, corebase, hart, devid=DEVIDS[0]):
    aps = "\n".join(
        f'  JLINK_ExecCommand("CORESIGHT_AddAP = Index={i} Type={t} '
        f'{syntax}=0x{addr:08X}");'
        for i, (_n, addr, t) in enumerate(AP_MAP))
    with open(path, 'w') as f:
        f.write(TEMPLATE.format(marker=MARKER, aps=aps, apidx=apidx,
                                corebase=corebase, hart=hart, devid=devid))
    return path


# ══════════════════════════════════════════════════════════════════
def run_one(a):
    """자식 프로세스 — 조합 하나만."""
    rec = {'syntax': a.syntax, 'ap': a.ap_index, 'base': f"0x{a.core_base:X}",
           'device': a.device, 'script_ok': None, 'connect': False,
           'dm_alive': False, 'error': None, 'script_ran': None}
    sp = os.path.join(tempfile.gettempdir(), f"sfe76_{os.getpid()}.JLinkScript")
    gen_script(sp, a.syntax, a.ap_index, a.core_base, a.hart, a.devid)
    logs = []
    cb = lambda m: logs.append(str(m))
    jl = pylink.JLink(log=cb, detailed_log=cb, error=cb, warn=cb)
    try:
        # ScriptFile 은 open 전에도 먹을 수 있다 — 양쪽 다 시도한다
        try:
            jl.exec_command(f"ScriptFile = {sp}")
            rec['script_set_preopen'] = True
        except Exception:
            rec['script_set_preopen'] = False
        jl.open()
        jl.exec_command(f"SetcJTAGInitMode = {CJTAG_MODE}")   # ★ 1 = SiFive short-form
        jl.set_tif(TIF_CJTAG)
        jl.set_speed(SPEED_KHZ)
        # ★ ScriptFile 은 connect 이전에 지정한다
        try:
            jl.exec_command(f"ScriptFile = {sp}")
            rec['script_ok'] = True
        except Exception as e:
            rec['script_ok'] = False
            rec['error'] = f"ScriptFile: {str(e)[:80]}"

        for t in range(1, a.tries + 1):
            try:
                jl.connect(a.device, speed=SPEED_KHZ)
                rec['connect'] = True
                rec['tries'] = t
                break
            except Exception as e:
                rec['error'] = str(e)[:120]
                time.sleep(0.25)

        rec['script_ran'] = any(MARKER in l for l in logs)
        if rec['connect']:
            # ★ connect 성공 뒤 DM 이 **어디까지** 사는지 단계별로 캔다.
            #   halted() 만 보면 '실패' 로만 남고 왜인지 모른다.
            probes = [('halted', lambda: bool(jl.halted())),
                      ('core_id', lambda: hex(jl.core_id())),
                      ('core_name', lambda: str(jl.core_name())),
                      ('reg0', lambda: hex(jl.register_read(0) & 0xFFFFFFFF)),
                      ('cpu_halt_reasons', lambda: str(jl.cpu_halt_reasons())[:60])]
            rec['probe'] = {}
            for nm, fn in probes:
                try:
                    rec['probe'][nm] = fn()
                except Exception as e:
                    rec['probe'][nm] = f"ERR {str(e)[:70]}"
            rec['dm_alive'] = not str(rec['probe'].get('halted', '')).startswith('ERR')
            # 로그에서 DM/DTM 관련 줄만 뽑아 둔다
            keys = ('dmcontrol', 'debug module', 'dtm', 'coresight', 'ap ', 'hart')
            rec['loglines'] = [l for l in logs
                               if any(k in l.lower() for k in keys)][:8]
    except Exception as e:
        rec['error'] = str(e)[:120]
    finally:
        rec['script_ran'] = any(MARKER in l for l in logs)
        rec['log_lines'] = len(logs)
        try:
            jl.close()
        except Exception:
            pass
        try:
            os.unlink(sp)
        except OSError:
            pass
    print("@@JSON@@" + json.dumps(rec, ensure_ascii=False))
    return EXIT_OK if rec['dm_alive'] else EXIT_INSUFFICIENT


def spawn(syntax, apidx, base, device, hart, tries, devid):
    cmd = [sys.executable, os.path.abspath(__file__), '--single',
           '--syntax', syntax, '--ap-index', str(apidx),
           '--core-base', hex(base), '--device', device, '--devid', hex(devid),
           '--hart', str(hart), '--tries', str(tries)]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=180).stdout
    except subprocess.TimeoutExpired:
        return {'syntax': syntax, 'ap': apidx, 'base': hex(base),
                'connect': False, 'dm_alive': False, 'error': 'timeout'}
    for line in out.splitlines():
        if line.startswith("@@JSON@@"):
            return json.loads(line[len("@@JSON@@"):])
    return {'syntax': syntax, 'ap': apidx, 'base': hex(base),
            'connect': False, 'dm_alive': False, 'error': 'no result'}


def focus(a):
    """connect 가 되는 조합만 깊이 판다. **왜 DM 이 안 사는지**를 본다."""
    print(f"\n{'=' * 68}\n [FOCUS] CoreBase=0x0 × AP{{0,1}} × hart{{0..3}}\n{'=' * 68}")
    print("  connect 는 되는데 halted() 가 예외다. 그 예외 문구와")
    print("  core_id / core_name / reg0 로 **DM 이 어디까지 사는지** 가른다.\n")
    rows = []
    for apidx in (0, 1):
        for hart in (0, 1, 2, 3):
            r = spawn('BaseAddr', apidx, 0x0, 'E76', hart, a.tries, DEVIDS[0])
            r['hart'] = hart
            rows.append(r)
            p = r.get('probe') or {}
            print(f"  AP={apidx} hart={hart}  connect={int(bool(r.get('connect')))}"
                  f"  halted={p.get('halted')}")
            for k in ('core_id', 'core_name', 'reg0'):
                if k in p:
                    print(f"      {k:10s}= {p[k]}")
            for l in (r.get('loglines') or [])[:4]:
                print(f"      log: {l[:96]}")
            if not r.get('connect') and r.get('error'):
                print(f"      err: {str(r['error'])[:96]}")
            time.sleep(0.3)

    ok = [r for r in rows if r.get('dm_alive')]
    print(f"\nv={VERSION.split()[0]}  focus 조합={len(rows)}")
    for r in rows:
        p = r.get('probe') or {}
        print(f"AP={r['ap']} hart={r['hart']} connect={int(bool(r.get('connect')))} "
              f"halted={p.get('halted')} core_id={p.get('core_id')}")
    print("VERDICT:", "DM_REACHED" if ok else "CONNECT_ONLY")
    return EXIT_OK if ok else EXIT_INSUFFICIENT


def main():
    require_api(4, "try_jlinkscript.py")
    ap = argparse.ArgumentParser()
    ap.add_argument('--brief', action='store_true')
    ap.add_argument('--only-syntax', choices=SYNTAXES)
    ap.add_argument('--focus', action='store_true',
                    help='★ connect 되는 조합(CoreBase=0x0)만 깊이 판다 — hart 도 훑는다')
    ap.add_argument('--devices', default=",".join(DEVICES))
    ap.add_argument('--tries', type=int, default=3)
    ap.add_argument('--hart', type=int, default=0)
    ap.add_argument('--version', action='store_true')
    # 자식 전용
    ap.add_argument('--single', action='store_true', help=argparse.SUPPRESS)
    ap.add_argument('--syntax', default='BaseAddr', help=argparse.SUPPRESS)
    ap.add_argument('--ap-index', type=int, default=0, help=argparse.SUPPRESS)
    ap.add_argument('--core-base', type=lambda x: int(x, 0), default=0x81480000,
                    help=argparse.SUPPRESS)
    ap.add_argument('--device', default='E76', help=argparse.SUPPRESS)
    ap.add_argument('--devid', type=lambda x: int(x, 0), default=DEVIDS[0],
                    help=argparse.SUPPRESS)
    a = ap.parse_args()
    if a.version:
        print(f"try_jlinkscript {VERSION}")
        return EXIT_OK
    if a.single:
        return run_one(a)

    if a.focus:
        return focus(a)

    syns = [a.only_syntax] if a.only_syntax else SYNTAXES
    devs = [x.strip() for x in a.devices.split(',') if x.strip()]
    total = len(syns) * len(AP_INDEXES) * len(CORE_BASES) * len(devs) * len(DEVIDS)
    if not a.brief:
        print(f"\n{'=' * 68}\n JLinkScript 네이티브 연결 (v{VERSION})\n{'=' * 68}")
        print("  DMI 프로토콜은 J-Link 이 안다. 우리는 위치만 알려준다.")
        print("  ConfigTargetSettings() 만 쓴다 — 타깃 통신이 금지된 훅이라")
        print("  cJTAG 스캔을 깨뜨릴 수 없다(예전 실패는 InitTarget 탓이었다).")
        print(f"  총 {total} 조합, 조합마다 별도 프로세스.\n")

    hits, rows = [], []
    for devid in DEVIDS:
      for syn in syns:
        for dev in devs:
            for apidx in AP_INDEXES:
                for base in CORE_BASES:
                    r = spawn(syn, apidx, base, dev, a.hart, a.tries, devid)
                    r['devid'] = f"0x{devid:08X}"
                    rows.append(r)
                    mark = ("★★ DM" if r.get('dm_alive')
                            else "connect만" if r.get('connect') else "실패")
                    if not a.brief:
                        print(f"  id=0x{devid:08X} AP={apidx} base=0x{base:08X} "
                              f"{dev:6s}  {mark}")
                        if r.get('error') and not r.get('dm_alive'):
                            print(f"      {str(r['error'])[:100]}")
                    if r.get('dm_alive'):
                        hits.append(r)
                    time.sleep(0.2)

    print(f"\nv={VERSION.split()[0]}  조합={len(rows)}")
    ran = [r for r in rows if r.get('script_ran')]
    conn = [r for r in rows if r.get('connect')]
    print(f"script실행={len(ran)}/{len(rows)}  connect성공={len(conn)}  "
          f"DM살아있음={len(hits)}")
    if not ran:
        print("★★ **스크립트가 한 번도 실행되지 않았다.** 설정이 반영될 리가 없다.")
        print("   → connect 24/24 성공은 스크립트와 무관한 결과였다.")
        print("   → ScriptFile 지정 방식부터 고쳐야 한다 (JLinkExe -jlinkscriptfile 로 교차확인).")
    for r in hits:
        print(f"HIT devid={r.get('devid')} ap={r['ap']} base={r['base']} dev={r['device']}")
    if not hits and conn:
        # connect 는 되는데 DM 이 안 사는 조합만 요약해서 보여준다
        u = sorted({(r['syntax'], r['ap'], r['base']) for r in conn})[:6]
        print("connect만 된 조합:", u)
    print("VERDICT:", "DM_REACHED" if hits else
          ("SCRIPT_NOT_LOADED" if not ran else
           "CONNECT_ONLY" if conn else "NO_CONNECT"))
    return EXIT_OK if hits else EXIT_INSUFFICIENT


if __name__ == '__main__':
    sys.exit(main())
