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

VERSION = "2026-08-11.23  전체 로그 덤프"

# ★ TAP 계층을 넘은 뒤 아직 안 돌린 변수 둘. 둘 다 문서 근거가 있다.
#
#  ① AP 셀렉터 — SEGGER RISC-V 예제 주석 원문:
#       "If RISC-V is behind an APB-AP, use CORESIGHT_SetIndexAPBAPToUse
#        If RISC-V is behind an AHB-AP, use CORESIGHT_SetIndexAHBAPToUse"
#     우리는 **APB 만** 써 왔다. AHB-AP(index 3, 0x40000)도 실재가 확인돼 있다.
#
#  ② device — "RISC-V 는 안 되고 E76 이어야 한다" 는 관측은 **TAP 이 깨진
#     상태**에서 나온 것이다. TAP 이 정상인 지금은 다시 봐야 한다.
SELECTORS = [('APB', 'CORESIGHT_SetIndexAPBAPToUse'),
             ('AHB', 'CORESIGHT_SetIndexAHBAPToUse')]
CPU_DEVICES = ['E76', 'RISC-V', 'E76-MC']

# ★★ 치명적 정정 (feedback 2026-08-11 최우선 절)
#   JTAG_AllowTAPReset 을 **반대로** 썼다. SEGGER 공식 정의:
#       0 = Auto-detection is **enabled**
#       1 = Auto-detection is **disabled**
#   우리는 0 을 쓰면서 주석에 "자동 검출 끔" 이라고 달았다.
#   ⇒ 지금까지의 모든 "수동 체인" 시험은 자동 검출을 **켜 둔 채** 돌았다.
#     로그에 계속 `Id: 0x00000001` 이 나온 게 당연하다 — 우리가 선언한 TAP ID 를
#     자동 검출이 다시 덮었을 수 있다.
#   ⇒ "cJTAG 손잡이를 전부 돌렸다 / 소프트웨어로 더 할 게 없다" 판정을 **철회**한다.
#
#   그리고 훅도 틀렸다. manual chain 은 SEGGER 최신 예제대로
#   **ConfigTargetSettings()** 에 넣는다. InitTarget() 은 전역 CPU 설정을
#   요구하는데 RISC-V 용 CPU 상수가 존재하지 않는다 — 만족시킬 수 없는 조건이었다.
CHAIN_TAP_ID = 0x5BA00477     # SEGGER manual-chain 예제의 알려진 CoreSight DAP ID
                              # (실제 실리콘 ID 주장이 아니라, DLL 이 이 TAP 을
                              #  CoreSight DAP 으로 고르게 하는 선언값이다)

# ★ 게이트를 잘못 걸었었다. pylink 정의:
#     connected()        = self.opened() and JLINKARM_EMU_IsConnected()
#                          → **J-Link 프로브(USB)가 꽂혔는가.** 타깃과 무관하다
#     target_connected() = self.connected() and JLINKARM_IsConnected()
#                          → **타깃에 붙었는가.** 이게 우리가 원하는 것
#   그리고 pylink 의 @connection_required 는
#     if not self.target_connected(): raise "Target is not connected."
#   즉 halted() 가 그 예외를 던진다는 건 **target_connected() 가 False** 라는 뜻이다.
#   `connected` 로 게이트하면 USB 만 확인하는 셈이라 늘 통과한다 —
#   그래서 SESSION_ALIVE_NO_DM 이 나왔다. 잘못된 판정이었다.

# ★ TAP ID 를 선언하면 JTAG-DTM 오인이 사라진다(실측: DTM오인아님 0/9 → 78/90).
#   ⚠ 다만 "유효 IDCODE" 자체는 **우리가 선언한 값을 되돌려받은 것**일 수 있다.
#      의미 있는 신호는 DTM 오인이 사라진 것과, 그 위에서 DM 이 사는지다.
DEVIDS = [0x4BA00477, 0x2BA01477, 0x5BA00477, 0x6BA00477]

SYNTAXES = ['BaseAddr']
AP_INDEXES = [0, 1]                            # ROM 엔트리가 지목한 둘
CORE_BASES = [0x81480000, 0x81481000, 0x0]
DEVICES = ['E76']            # ★ 'RISC-V' 는 connect 자체가 안 된다(실측)

MARKER = "SFE76_SCRIPT_RAN"

TEMPLATE = """/* 자동 생성 — try_jlinkscript.py  (manual chain v2) */
void ConfigTargetSettings(void) {{
  JLINK_SYS_Report("{marker}");

  /* ── 자동 체인 검출을 **끈다** ─────────────────────────────────
     0 = Auto-detection is enabled / 1 = Auto-detection is disabled
     지금까지 0 을 쓰면서 "끔" 이라고 착각했다. 그래서 우리가 선언한 TAP 을
     자동 검출이 덮고 Id=0x00000001 을 계속 읽었다. */
  JTAG_AllowTAPReset = 1;

  /* ── 체인 수동 선언 ──────────────────────────────────────────── */
  {chain}

  /* ── AP 맵과 DMI 위치 ────────────────────────────────────────── */
{aps}
  JLINK_ExecCommand("{selcmd} = {apidx}");
  JLINK_ExecCommand("CORESIGHT_SetCoreBaseAddr = 0x{corebase:X}");
  JLINK_ExecCommand("RISCV_SetHartSel = {hart}");
  return 0;
}}
"""

# 전역 이름 두 갈래. 최신 공식 예제는 JLINK_JTAG_*, 구 매뉴얼은 JTAG_*.
# V9.66 에서 alias 인지 확실치 않으므로 **둘 다 시험한다.**
CHAIN_FORMS = {
    'JLINK_JTAG': """JLINK_JTAG_SetDeviceId(0, 0x{tapid:08X});
  JLINK_JTAG_IRPre  = 0;
  JLINK_JTAG_DRPre  = 0;
  JLINK_JTAG_IRPost = 0;
  JLINK_JTAG_DRPost = 0;
  JLINK_JTAG_IRLen  = 4;""",
    'JTAG': """JLINK_JTAG_SetDeviceId(0, 0x{tapid:08X});
  JTAG_IRPre  = 0;
  JTAG_DRPre  = 0;
  JTAG_IRPost = 0;
  JTAG_DRPost = 0;
  JTAG_IRLen  = 4;""",
}


def gen_script(path, syntax, apidx, corebase, hart, devid=CHAIN_TAP_ID,
               form='JLINK_JTAG', selcmd='CORESIGHT_SetIndexAPBAPToUse'):
    aps = "\n".join(
        f'  JLINK_ExecCommand("CORESIGHT_AddAP = Index={i} Type={t} '
        f'{syntax}=0x{addr:08X}");'
        for i, (_n, addr, t) in enumerate(AP_MAP))
    with open(path, 'w') as f:
        f.write(TEMPLATE.format(
            marker=MARKER, aps=aps, apidx=apidx, corebase=corebase, hart=hart,
            chain=CHAIN_FORMS[form].format(tapid=devid), selcmd=selcmd))
    return path


# ══════════════════════════════════════════════════════════════════
def run_one(a):
    """자식 프로세스 — 조합 하나만."""
    rec = {'syntax': a.syntax, 'ap': a.ap_index, 'base': f"0x{a.core_base:X}",
           'device': a.device, 'script_ok': None, 'connect': False,
           'dm_alive': False, 'error': None, 'script_ran': None}
    sp = os.path.join(tempfile.gettempdir(), f"sfe76_{os.getpid()}.JLinkScript")
    gen_script(sp, a.syntax, a.ap_index, a.core_base, a.hart, a.devid,
               a.form_arg, a.selcmd)
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
        # ★ connect() 가 예외 없이 끝나도 세션이 살아 있다는 뜻이 아니다.
        #   halted() 는 @connection_required 라서 jl.connected() 가 False 면
        #   "Target is not connected" 를 던진다 — 그게 지금 보이는 증상이다.
        for nm, fn in (('connected', lambda: bool(jl.connected())),
                       ('target_connected', lambda: bool(jl.target_connected()))):
            try:
                rec[nm] = fn()
            except Exception as e:
                rec[nm] = f"ERR {str(e)[:40]}"

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
        blob = "\n".join(logs)
        low = blob.lower()
        rec['script_ran'] = MARKER in blob
        rec['log_lines'] = len(logs)
        # ★ 진단 3종 — 이것만 보면 다음 수가 정해진다
        rec['chain_detect'] = ('chain detection' in low)   # 자동 검출이 아직 도는가
        import re as _re
        m = _re.search(r'Id:\s*(0x[0-9A-Fa-f]{8})', blob)
        rec['idcode'] = m.group(1) if m else None
        rec['dtm'] = ('jtag-dtm' in low or 'dtm setup' in low)
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


def spawn(syntax, apidx, base, device, hart, tries, devid, form='JLINK_JTAG',
          selcmd='CORESIGHT_SetIndexAPBAPToUse'):
    cmd = [sys.executable, os.path.abspath(__file__), '--single',
           '--syntax', syntax, '--ap-index', str(apidx),
           '--core-base', hex(base), '--device', device, '--devid', hex(devid),
           '--hart', str(hart), '--tries', str(tries), '--form-arg', form,
           '--selcmd', selcmd]
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


DM_BASES = [0x0, 0x1000, 0x2000, 0x4000, 0x10000, 0x20000]


def dumplog(a):
    """★ **J-Link 자신의 전체 로그**를 받아 적는다. 조합 훑기를 멈추고 이걸 본다.

    지금까지 우리는 로그에서 **몇 개 패턴만** 정규식으로 골라 봤다
    (`Id:`, `JTAG-DTM`, `chain detection`). 그런데 실패 문구가
    `Could not find supported CPU` 로 바뀐 지금 필요한 것은
    **J-Link 이 어떤 AP 를 어떻게 두드렸고 무엇을 읽었는지**다.
    그건 로그 본문에만 있고 우리는 그걸 한 번도 통째로 본 적이 없다.

    파일로 전부 저장하고, 화면에는 **DAP/AP/CPU 탐지 구간만** 추려서 낸다.
    이 로그는 SEGGER 지원에 첨부할 자료이기도 하다.
    """
    print(f"\n{'=' * 68}\n [LOG] J-Link 전체 로그 덤프\n{'=' * 68}")
    print(f"  조합: sel={a.log_sel} AP={a.log_ap} device={a.log_dev} "
          f"CoreBase=0x{a.log_base:X} hart={a.hart}")
    selcmd = dict(SELECTORS)[a.log_sel]

    sp = os.path.join(tempfile.gettempdir(), f"sfe76_dump_{os.getpid()}.JLinkScript")
    gen_script(sp, 'BaseAddr', a.log_ap, a.log_base, a.hart,
               CHAIN_TAP_ID, 'JLINK_JTAG', selcmd)
    logs = []
    cb = lambda m: logs.append(str(m).rstrip())
    jl = pylink.JLink(log=cb, detailed_log=cb, error=cb, warn=cb)
    try:
        jl.exec_command(f"ScriptFile = {sp}")
        jl.open()
        jl.exec_command(f"SetcJTAGInitMode = {CJTAG_MODE}")
        jl.exec_command("EnableRemarks = 1")
        jl.exec_command("SetLogVerbose = 1")
        jl.exec_command(f"ScriptFile = {sp}")
        jl.set_tif(TIF_CJTAG)
        jl.set_speed(SPEED_KHZ)
        try:
            jl.connect(a.log_dev, speed=SPEED_KHZ)
        except Exception as e:
            logs.append(f"[connect 예외] {e}")
    except Exception as e:
        logs.append(f"[예외] {e}")
    finally:
        try:
            jl.close()
        except Exception:
            pass
        try:
            os.unlink(sp)
        except OSError:
            pass

    path = a.logfile or 'jlink_connect.log'
    with open(path, 'w') as f:
        f.write("\n".join(logs))
    print(f"\n  전체 {len(logs)}줄 → {path}\n")

    # 화면에는 진단에 쓰이는 구간만
    keys = ('coresight', 'dap', ' ap', 'ap[', 'apb', 'ahb', 'axi', 'dmi', 'dm ',
            'debug module', 'dmcontrol', 'dmstatus', 'hart', 'riscv', 'risc-v',
            'idcode', 'id:', 'irlen', 'cpu', 'core', 'error', 'fail', 'cannot',
            'could not', 'timeout')
    sel_lines = [l for l in logs if any(k in l.lower() for k in keys)]
    print(f"  {'─' * 64}\n  진단 관련 {len(sel_lines)}줄:")
    for l in sel_lines[-40:]:
        print(f"    {l[:110]}")
    print(f"  {'─' * 64}")
    print("\n  ★ 볼 것: J-Link 이 **어느 AP 를 두드렸고 무엇을 읽었는지**.")
    print("     그게 우리가 준 AP 맵과 맞는지, 아니면 무시하고 다른 걸 봤는지.")
    print(f"  ★ 이 파일({path})은 SEGGER 지원에 그대로 첨부할 자료다.")
    return EXIT_OK


def cpusweep(a):
    """★ TAP 계층을 넘은 뒤 남은 두 변수: **AP 셀렉터**와 **device**.

    실패 문구가 `Could not find supported CPU` 다 — DAP 는 탔는데 그 뒤에서
    코어를 못 찾는다. 그 단계에 영향을 주는 문서화된 변수가 둘 남았다:

      ① APB-AP 용 셀렉터만 써 왔다. AHB-AP 용 셀렉터가 따로 있다
         (SEGGER 예제 주석이 명시). AHB-AP 도 실재가 확인돼 있다(index 3).
      ② "RISC-V 는 안 되고 E76" 이라는 관측은 **TAP 이 깨진 상태**의 것이다.
         지금은 조건이 다르므로 다시 본다.

    CoreBase 는 **T32 값 `0x81480000`** 고정, hart 0 고정.
    (SEGGER 예제의 0x0 은 그쪽 칩 값일 뿐이고, "0x0 에서만 성공" 관측은
     TAP 이 깨진 상태의 무효 측정이었다)
    셀렉터에 맞춰 AP 인덱스도 바꾼다 — APB 는 0, AHB 는 3(0x40000).
    """
    print(f"\n{'=' * 68}\n [CPU] AP 셀렉터 × device\n{'=' * 68}")
    print("  실패 문구가 'Could not find supported CPU' — DAP 는 탔는데 코어를 못 찾는다.")
    print("  APB 셀렉터만 써 왔다. AHB 셀렉터가 따로 있다(SEGGER 예제 주석).")
    print("  'RISC-V 는 안 된다' 는 관측은 TAP 이 깨진 상태의 것이라 재확인한다.\n")
    rows = []
    for sel, selcmd in SELECTORS:
        apidx = 0 if sel == 'APB' else 3          # APBAP1 / AHBAP1
        for dev in a.cpu_devices:
            tgt = conn = 0
            errs = set()
            for _ in range(a.reps):
                r = spawn('BaseAddr', apidx, a.core_base, dev, 0, a.tries,
                          CHAIN_TAP_ID, 'JLINK_JTAG', selcmd)
                conn += bool(r.get('connect'))
                tgt += (r.get('target_connected') is True)
                if r.get('error'):
                    errs.add(str(r['error'])[:60])
                time.sleep(0.25)
            rows.append((sel, apidx, dev, conn, tgt, sorted(errs)))
            print(f"  {sel}(AP={apidx}) dev={dev:8s} connect={conn}/{a.reps} "
                  f"**target={tgt}/{a.reps}**"
                  + ("   ★★" if tgt else ""))
            for e in sorted(errs)[:1]:
                print(f"      {e}")

    print(f"\nv={VERSION.split()[0]}  reps={a.reps}")
    for sel, apidx, dev, conn, tgt, errs in rows:
        print(f"sel={sel} ap={apidx} dev={dev} connect={conn}/{a.reps} "
              f"target={tgt}/{a.reps}" + (f" err={errs[0]}" if errs else ""))
    hit = [r for r in rows if r[4] > 0]
    print("VERDICT:", "TARGET_CONNECTED" if hit else "STILL_NO_TARGET")
    if hit:
        sel, apidx, dev, _c, _t, _e = hit[0]
        print(f"  ★★★ sel={sel} AP={apidx} device={dev} 에서 붙었다. 정본을 이걸로 굳힌다.")
    else:
        print("  둘 다 아니다 → 남은 건 TAP ID 후보 교체(--devid) 와 hart/CoreBase 확대.")
    return EXIT_OK if hit else EXIT_INSUFFICIENT


def v2(a):
    """★ 공식형 최소 manual-chain 시험. **변수를 넓히지 않는다.**

    feedback 이 지정한 단일 조건:
        device E76 / cJTAG / 10MHz / SetcJTAGInitMode=1 / hart 0 /
        APB-AP index 0 / CoreBase 0x0 / 오라클 target_connected()

    앞선 실패의 원인 두 개를 고친 뒤의 첫 시험이다:
      ① JTAG_AllowTAPReset 을 0(=자동검출 켬) 으로 쓰고 있었다 → 1 로 정정
      ② manual chain 을 InitTarget() 에 넣었다 → ConfigTargetSettings() 로 이동
         (InitTarget 은 전역 CPU 설정을 요구하는데 RISC-V 상수가 없다)

    체인 전역 이름은 `JLINK_JTAG_*`(최신 예제) 와 `JTAG_*`(구 매뉴얼) 를
    **둘 다** 시험한다 — V9.66 에서 alias 인지 확실치 않다.
    """
    forms = [a.form] if a.form else list(CHAIN_FORMS)
    print(f"\n{'=' * 68}\n [v2] 공식형 최소 manual-chain — 1조건\n{'=' * 68}")
    print(f"  device=E76  cJTAG  10MHz  cJTAGInitMode=1  hart=0  AP=0  "
          f"CoreBase=0x{a.core_base:X}")
    print(f"  TAP ID=0x{CHAIN_TAP_ID:08X}   체인 전역 이름: {forms}")
    print("  ★ AllowTAPReset=1 (자동 검출 OFF) — 이전엔 0 을 쓰면서 껐다고 착각했다")
    print(f"  반복 {a.reps}회. 오라클은 target_connected().\n")

    out = []
    for form in forms:
        ok = tgt = ran = cd = dtm = 0
        errs, ids = set(), set()
        for _ in range(a.reps):
            r = spawn('BaseAddr', 0, a.core_base, 'E76', 0, a.tries,
                      CHAIN_TAP_ID, form)
            ran += bool(r.get('script_ran'))
            ok += bool(r.get('connect'))
            tgt += (r.get('target_connected') is True)
            cd += bool(r.get('chain_detect'))
            dtm += bool(r.get('dtm'))
            if r.get('idcode'):
                ids.add(r['idcode'])
            if r.get('error'):
                errs.add(str(r['error'])[:70])
            time.sleep(0.3)
        errs, ids = sorted(errs), sorted(ids)
        out.append((form, ran, ok, tgt, cd, dtm, errs, ids))
        print(f"  [{form:10s}] script={ran}/{a.reps} connect={ok}/{a.reps} "
              f"**target={tgt}/{a.reps}**")
        print(f"      자동검출 여전히 돎 = {cd}/{a.reps}"
              f"   DTM오인 = {dtm}/{a.reps}   로그 IDCODE = {ids or '없음'}")
        for e in errs[:2]:
            print(f"      err: {e}")

    print(f"\nv={VERSION.split()[0]}  reps={a.reps}")
    for form, ran, ok, tgt, cd, dtm, errs, ids in out:
        print(f"form={form} script={ran}/{a.reps} connect={ok}/{a.reps} "
              f"target={tgt}/{a.reps} autodetect={cd}/{a.reps} dtm={dtm}/{a.reps} "
              f"id={','.join(ids) or '-'}")
        if errs:
            print(f"  err[{form}]: {errs[0]}")
    hit = [f for f, _r, _o, t, *_ in out if t > 0]
    noscript = all(r == 0 for _f, r, *_ in out)
    still_auto = any(row[4] > 0 for row in out)
    print("VERDICT:", "TARGET_CONNECTED" if hit else
          ("SCRIPT_NOT_LOADED" if noscript else "STILL_NO_TARGET"))
    if hit:
        print(f"  ★★★ form={hit[0]} 에서 **타깃에 붙었다.** 정본 스크립트를 이걸로 굳힌다.")
    elif noscript:
        print("  스크립트가 안 돌았다 — 전역 이름이 거부됐을 수 있다. 로그 확인.")
    else:
        print("  스크립트는 돌았는데 여전히 타깃 미연결.")
        declared = f"0x{CHAIN_TAP_ID:08X}".lower()
        took = any(any(declared == x.lower() for x in row[7]) for row in out)
        if took:
            print(f"  ✅ **체인 선언이 반영됐다** — 로그 IDCODE 가 우리가 선언한 "
                  f"0x{CHAIN_TAP_ID:08X} 다 (이전엔 0x00000001).")
            print("     'chain detection' 문자열이 남는 건 J-Link 이 **수동 선언된**")
            print("     체인을 로그로 찍는 것이므로 자동 검출이 도는 증거가 아니다.")
            print("     DTM 오인도 사라졌다 → **이제 DAP 경로를 탄다.**")
            print("\n  → 남은 실패는 'Could not find supported CPU' 다. 즉 DAP 는 탔는데")
            print("     그 뒤에서 RISC-V 코어를 못 찾는다. 이제서야 아래가 의미를 갖는다:")
            print("        sudo python3 try_jlinkscript.py --dmsweep --reps 3")
            print("     (AP 인덱스 × CoreBase 를 살아있는 세션 기준으로 훑는다)")
        elif still_auto:
            print("  ⚠ 자동 검출이 아직 돌고 IDCODE 도 우리 선언값이 아니다.")
            print("     AllowTAPReset=1 이 안 먹었다 — 전역 이름/훅 위치를 다시 볼 것.")
        else:
            print("  자동 검출은 꺼졌다. err 문구가 다음 단서.")
    return EXIT_OK if hit else EXIT_INSUFFICIENT


def dmsweep(a):
    """★ **살아있는 세션에서만** DM 변수를 훑는다.

    `SESSION_ALIVE_NO_DM` 이 나왔다 = 연결 유지는 되고 DM 만 안 산다.
    그러면 이제 CoreBase/AP/hart 가 다시 의미를 갖는다. 단 조건이 있다:

      · 조합마다 `--reps` 회 반복한다 (1회 결과는 신호가 아니다)
      · **`connected=False` 인 시행은 버린다.** 죽은 세션의 측정은
        '실패' 가 아니라 **무효**다 — raw DAP 때 `require_power` 게이트와 같은 원리다
      · 유효 시행이 하나도 없는 조합은 판정하지 않는다

    출력은 **유효 시행이 있는 행만** 낸다 (손으로 옮겨 적을 수 있게).
    """
    print(f"\n{'=' * 68}\n [DMSWEEP] CoreBase × AP × hart, alive 세션만 집계"
          f"\n{'=' * 68}")
    print(f"  CoreBase {[hex(x) for x in DM_BASES]}")
    print(f"  AP {a.aps}   hart {a.harts}   반복 {a.reps}회")
    print("  죽은 세션(connected=False)은 **무효**로 버린다.\n")

    rows = []
    for base in DM_BASES:
        for apidx in a.aps:
            for hart in a.harts:
                alive = halted = n = 0
                errs = set()
                for _ in range(a.reps):
                    r = spawn('BaseAddr', apidx, base, 'E76', hart, a.tries, CHAIN_TAP_ID)
                    n += 1
                    if r.get('target_connected') is not True:
                        continue          # ← 무효(타깃 미연결). 실패로 세지 않는다
                    alive += 1
                    p = r.get('probe') or {}
                    if isinstance(p.get('halted'), bool):
                        halted += 1
                    else:
                        errs.add(str(p.get('halted'))[:44])
                    time.sleep(0.2)
                if alive:
                    rows.append((base, apidx, hart, alive, n, halted, errs))
                    print(f"  base=0x{base:<7X} AP={apidx} hart={hart}  "
                          f"target={alive}/{n}  halted={halted}/{alive}"
                          + ("   ★★ DM" if halted else ""))
                    for e in sorted(errs)[:1]:
                        print(f"      {e}")

    print(f"\nv={VERSION.split()[0]}  reps={a.reps}")
    if not rows:
        print("**target_connected 가 한 번도 True 가 아니다.**")
        print("연결이 타깃까지 도달하지 못한다 — DM 이전 계층의 문제다.")
        print("VERDICT: TARGET_NEVER_CONNECTED")
        return EXIT_INSUFFICIENT
    for base, apidx, hart, alive, n, halted, _e in rows:
        print(f"base=0x{base:X} AP={apidx} hart={hart} target={alive}/{n} halted={halted}")
    hit = [r for r in rows if r[5] > 0]
    print("VERDICT:", "DM_REACHED" if hit else "ALIVE_BUT_NO_DM")
    if not hit:
        print("  → 살아있는 세션에서도 DM 이 안 산다. CoreBase 후보가 다 틀렸거나")
        print("     DM 접근에 별도 조건이 있다. 오류 문구를 함께 볼 것.")
    return EXIT_OK if hit else EXIT_INSUFFICIENT


def focus(a):
    """connect 되는 조합을 **반복 측정**한다.

    ★ 같은 조합이 실행마다 결과가 달랐다. 그러면 1회 결과는 신호가 아니다
      (STATUS §3.5 원칙 3). 조합마다 `--reps` 회 반복해 **비율**로 본다.

    ★ 그리고 `connect()` 무예외 종료 ≠ 세션 살아있음. `halted()` 는
      `@connection_required` 라 `connected()` 가 False 면
      "Target is not connected" 를 던진다 — 지금 보이는 게 정확히 그것이다.
      그래서 connect 직후 `connected` / `target_connected` 를 따로 기록한다.
    """
    print(f"\n{'=' * 68}\n [FOCUS] CoreBase=0x0 × AP{{0,1}} × hart{{0..3}} × {a.reps}회"
          f"\n{'=' * 68}")
    print("  같은 조합이 실행마다 달랐다 → 비율로 본다. 1회 결과는 신호가 아니다.")
    print("  connect 무예외 ≠ 세션 살아있음. connected/target_connected 를 따로 본다.\n")

    agg = {}
    for apidx in (0, 1):
        for hart in (0, 1, 2, 3):
            k = (apidx, hart)
            agg[k] = {'connect': 0, 'connected': 0, 'tconn': 0, 'halted': 0,
                      'n': 0, 'errs': set()}
            for _ in range(a.reps):
                r = spawn('BaseAddr', apidx, 0x0, 'E76', hart, a.tries, CHAIN_TAP_ID)
                g = agg[k]
                g['n'] += 1
                g['connect'] += bool(r.get('connect'))
                g['connected'] += (r.get('connected') is True)     # USB 프로브
                g['tconn'] += (r.get('target_connected') is True)  # ★ 타깃
                p = r.get('probe') or {}
                h = p.get('halted')
                if isinstance(h, bool):
                    g['halted'] += 1
                elif isinstance(h, str):
                    g['errs'].add(h[:50])
                if r.get('error'):
                    g['errs'].add(str(r['error'])[:50])
                time.sleep(0.25)
            g = agg[k]
            print(f"  AP={apidx} hart={hart}  connect={g['connect']}/{g['n']}"
                  f"  connected={g['connected']}/{g['n']}"
                  f"  target_connected={g['tconn']}/{g['n']}"
                  f"  halted={g['halted']}/{g['n']}")
            for e in sorted(g['errs'])[:2]:
                print(f"      {e}")

    print(f"\nv={VERSION.split()[0]}  reps={a.reps}")
    for (apidx, hart), g in sorted(agg.items()):
        print(f"AP={apidx} hart={hart} conn={g['connect']}/{g['n']} "
              f"target={g['tconn']}/{g['n']} halted={g['halted']}/{g['n']}")
    best = [k for k, g in agg.items() if g['halted'] > 0]
    alive = [k for k, g in agg.items() if g['tconn'] > 0]   # ★ USB 아니라 타깃
    print("VERDICT:", "DM_REACHED" if best else
          ("SESSION_ALIVE_NO_DM" if alive else "SESSION_DIES_AFTER_CONNECT"))
    if not alive:
        print("  → connect 직후 세션이 죽는다. DM 이전에 **연결 유지**가 문제다.")
        print("     속도(10MHz)를 낮춰 재시도, 타깃 전원 사이클 후 재측정.")
    return EXIT_OK if best else EXIT_INSUFFICIENT


def main():
    require_api(4, "try_jlinkscript.py")
    ap = argparse.ArgumentParser()
    ap.add_argument('--brief', action='store_true')
    ap.add_argument('--only-syntax', choices=SYNTAXES)
    ap.add_argument('--reps', type=int, default=3,
                    help='focus 모드에서 조합마다 반복할 횟수')
    ap.add_argument('--dumplog', action='store_true',
                    help='★ J-Link 전체 로그를 파일로 덤프하고 진단 구간을 출력')
    ap.add_argument('--logfile', default=None)
    ap.add_argument('--log-sel', default='APB', choices=[x[0] for x in SELECTORS])
    ap.add_argument('--log-ap', type=int, default=0)
    ap.add_argument('--log-dev', default='E76')
    ap.add_argument('--log-base', type=lambda x: int(x, 0), default=0x81480000)
    ap.add_argument('--cpusweep', action='store_true',
                    help='★ AP 셀렉터(APB/AHB) × device. TAP 통과 후 남은 두 변수')
    ap.add_argument('--cpu-devices', default=",".join(CPU_DEVICES))
    ap.add_argument('--v2', action='store_true',
                    help='★ 공식형 최소 manual-chain 1조건 시험 (feedback P0)')
    ap.add_argument('--form', default=None, choices=list(CHAIN_FORMS),
                    help='체인 전역 이름. 미지정이면 둘 다 시험')
    ap.add_argument('--dmsweep', action='store_true',
                    help='★ 살아있는 세션에서만 CoreBase×AP×hart 를 훑는다')
    ap.add_argument('--aps', default="0,1", help='dmsweep AP 인덱스')
    ap.add_argument('--harts', default="0", help='dmsweep hart')
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
    ap.add_argument('--form-arg', default='JLINK_JTAG', help=argparse.SUPPRESS)
    ap.add_argument('--selcmd', default='CORESIGHT_SetIndexAPBAPToUse',
                    help=argparse.SUPPRESS)
    ap.add_argument('--devid', type=lambda x: int(x, 0), default=CHAIN_TAP_ID,
                    help=argparse.SUPPRESS)
    a = ap.parse_args()
    if a.version:
        print(f"try_jlinkscript {VERSION}")
        return EXIT_OK
    if a.single:
        return run_one(a)

    a.aps = [int(x) for x in a.aps.split(',') if x.strip()]
    a.harts = [int(x) for x in a.harts.split(',') if x.strip()]
    a.cpu_devices = [x.strip() for x in a.cpu_devices.split(',') if x.strip()]
    if a.dumplog:
        return dumplog(a)
    if a.cpusweep:
        return cpusweep(a)
    if a.v2:
        return v2(a)
    if a.dmsweep:
        return dmsweep(a)
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
