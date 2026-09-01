#!/usr/bin/env python3
"""커널 A/B 스윕 하네스 — OS freeze 가 커널 버전에 걸린 문제인지 같은 머신에서 가른다

**왜 같은 머신인가:** 다른 PC 와 비교하면 커널·보드·칩셋·BIOS·슬롯이 **한꺼번에** 바뀐다.
같은 머신에서 커널만 갈아끼우면 변수가 하나로 고정된다 — 이게 유일한 de-confound 경로다.

**이 하네스가 해결하는 것:** 커널 스윕은 부팅→실행→판정→다음 커널 예약을 반복하는데,
프리즈하면 그 시점의 로그가 디스크에 안 남아서 "어디까지 갔는지"가 통째로 날아간다. 그래서
진행 상황을 **주기적으로 fsync** 해 두고, 다음 부팅에서 "running 인 채 남은 엔트리"를 발견하면
그게 곧 **직전 커널이 프리즈했다는 증거**로 자동 판정된다(= 프리즈 순간 로그가 없어도 됨).

    ┌─ boot ─┐
    │ --run  │→ 이전 엔트리가 'running' 이면 FREEZE 로 확정(+ 마지막 fsync 된 exec 기록)
    │        │→ 현재 커널 엔트리를 'running' 으로 찍고 퍼저 실행
    │        │→ exec 이 --threshold 도달하면 PASS, grub-reboot 으로 다음 커널 예약
    └────────┘

사용법:
  # 0) 설치된 커널과 GRUB 엔트리 확인
  sudo python3 kernel_sweep.py --list

  # 1) 스윕 계획 작성 (현재 커널 + 정상 PC 커널 + 사이 버전들)
  sudo python3 kernel_sweep.py --plan 6.8.0-41-generic,6.11.0-9-generic \
      --threshold 1500000 \
      --fuzzer-cmd "/home/ssd/gdbfuzz/.venv/bin/python3 /home/ssd/gdbfuzz/PC_Sampling/pc_sampling_fuzzer_v9.5.py --product P7"

  # 2) 부팅마다 실행 (수동이면 매 부팅 후 직접, 자동이면 --service 로 systemd 등록)
  sudo python3 kernel_sweep.py --run

  # 3) 결과 확인
  sudo python3 kernel_sweep.py --status

  # 자동화(선택): 부팅 시 자동 실행 + 완료 시 자동 재부팅
  sudo python3 kernel_sweep.py --service | sudo tee /etc/systemd/system/kernel-sweep.service
  sudo systemctl enable kernel-sweep
  #   ※ 자동 재부팅은 --plan 에 --arm 을 준 경우에만 동작한다(기본 off — 리그에서 재부팅
  #     루프는 위험하므로 명시적으로 켜야 한다).

전제:
  - GRUB 이 `GRUB_DEFAULT=saved` 여야 `grub-reboot`(1회성 다음 부팅 지정)이 동작한다.
    아니면 `--list` 가 경고한다. `/etc/default/grub` 수정 후 `sudo update-grub`.
  - 프리즈 시 호스트는 스스로 못 살아난다 → 외부 워치독이 없으면 **수동 전원 재투입**이
    필요하다. 그래도 판정은 자동으로 남는다(위 fsync 트릭).

판정 기준(--threshold):
  기존 재현은 30만~48만 명령, 최소 9만. 기하분포라 "살아남았다"를 주장하려면 관측 최대치의
  3배는 필요 → 기본 150만. 반대로 **프리즈는 빨리 나온다**(대개 1~2시간) — 즉 이 스윕은
  '나쁜 커널'은 싸게, '좋은 커널'은 비싸게 판정한다. 이분탐색 시 그 비대칭을 이용할 것.
"""

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import platform

STATE_DIR = '/var/lib/gdbfuzz-kernel-sweep'
STATE_PATH = os.path.join(STATE_DIR, 'state.json')

GRUB_CFGS = ['/boot/grub/grub.cfg', '/boot/grub2/grub.cfg']
GRUB_DEFAULTS = '/etc/default/grub'

_EXEC_RE = re.compile(r'exec[=:]\s*([\d,]+)')


def _p(msg: str) -> None:
    sys.stdout.write(msg + '\n')
    sys.stdout.flush()


# ─────────────────────────────────────────────────────────── state (fsync 필수)

def state_load() -> dict:
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception as e:
        _p(f"[error] state 읽기 실패: {e}")
        return {}


def state_save(st: dict) -> None:
    """프리즈해도 살아남아야 하므로 write→flush→fsync→rename→디렉터리 fsync 까지 한다."""
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = STATE_PATH + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(st, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, STATE_PATH)
    dfd = os.open(STATE_DIR, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


# ─────────────────────────────────────────────────────────── kernel / grub

def installed_kernels() -> list:
    out = []
    for name in sorted(os.listdir('/boot')):
        if name.startswith('vmlinuz-'):
            out.append(name[len('vmlinuz-'):])
    return out


def grub_cfg_path():
    for p in GRUB_CFGS:
        if os.path.exists(p):
            return p
    return None


def grub_entries() -> list:
    """grub.cfg 를 훑어 (엔트리 경로, 제목) 목록. submenu 는 'A>B' 형태로 이어붙인다."""
    path = grub_cfg_path()
    if not path:
        return []
    entries = []
    stack = []
    try:
        with open(path, errors='replace') as f:
            for line in f:
                s = line.strip()
                m = re.match(r"^(submenu|menuentry)\s+'([^']*)'", s)
                if not m:
                    m = re.match(r'^(submenu|menuentry)\s+"([^"]*)"', s)
                if m:
                    kind, title = m.group(1), m.group(2)
                    if kind == 'submenu':
                        stack.append(title)
                    else:
                        entries.append('>'.join(stack + [title]))
                    continue
                if s == '}' and stack and not s.startswith('menuentry'):
                    # submenu 닫힘 추정 — grub.cfg 는 중첩이 얕아 이 정도로 충분
                    pass
    except Exception as e:
        _p(f"[warn] grub.cfg 파싱 실패: {e}")
    return entries


def entry_for_version(ver: str):
    """커널 버전 문자열을 포함하는 GRUB 엔트리 경로. 여러 개면 recovery 아닌 것 우선."""
    cands = [e for e in grub_entries() if ver in e]
    if not cands:
        return None
    normal = [e for e in cands if 'recovery' not in e.lower()]
    return (normal or cands)[0]


def grub_default_is_saved() -> bool:
    try:
        with open(GRUB_DEFAULTS) as f:
            for line in f:
                if line.strip().startswith('GRUB_DEFAULT='):
                    return 'saved' in line
    except Exception:
        pass
    return False


def schedule_next_boot(ver: str) -> bool:
    entry = entry_for_version(ver)
    if not entry:
        _p(f"[error] '{ver}' 에 해당하는 GRUB 엔트리를 못 찾음 — --list 로 확인")
        return False
    tool = shutil.which('grub-reboot') or shutil.which('grub2-reboot')
    if not tool:
        _p("[error] grub-reboot 없음")
        return False
    r = subprocess.run([tool, entry], capture_output=True, text=True)
    if r.returncode != 0:
        _p(f"[error] grub-reboot 실패: {r.stderr.strip()}")
        return False
    _p(f"[grub] 다음 부팅 1회 지정: {entry}")
    return True


# ─────────────────────────────────────────────────────────── 명령

def cmd_list() -> int:
    _p("설치된 커널:")
    cur = platform.release()
    for k in installed_kernels():
        _p(f"  {'* ' if k == cur else '  '}{k}{'   ← 현재 부팅' if k == cur else ''}")
    _p("")
    _p("GRUB 엔트리:")
    for e in grub_entries():
        _p(f"  {e}")
    _p("")
    if not grub_default_is_saved():
        _p("[warn] /etc/default/grub 의 GRUB_DEFAULT 가 'saved' 가 아니다 → grub-reboot(1회성")
        _p("       다음 부팅 지정)이 동작하지 않는다. GRUB_DEFAULT=saved 로 바꾸고 update-grub.")
    else:
        _p("[ok] GRUB_DEFAULT=saved — grub-reboot 사용 가능")
    return 0


def cmd_plan(args) -> int:
    vers = [v.strip() for v in args.plan.split(',') if v.strip()]
    if not vers:
        _p("[error] --plan 에 커널 버전을 콤마로 나열할 것")
        return 1
    missing = [v for v in vers if v not in installed_kernels()]
    if missing:
        _p(f"[error] 설치되지 않은 커널: {', '.join(missing)}")
        _p("        먼저 설치하고 update-grub 할 것 (--list 로 확인)")
        return 1
    st = {
        'threshold': args.threshold,
        'fuzzer_cmd': args.fuzzer_cmd,
        'arm': bool(args.arm),
        'created': time.strftime('%Y-%m-%d %H:%M:%S'),
        'entries': [{'version': v, 'status': 'pending', 'last_exec': 0,
                     'started': None, 'finished': None, 'verdict': None} for v in vers],
    }
    state_save(st)
    _p(f"[plan] {len(vers)} 개 커널, threshold={args.threshold:,} 명령, "
       f"자동재부팅={'ON' if st['arm'] else 'off'}")
    for v in vers:
        _p(f"   - {v}")
    _p("")
    first = vers[0]
    if first == platform.release():
        _p(f"[plan] 첫 대상({first})이 현재 부팅 커널 → 바로 `--run` 하면 된다.")
    else:
        if schedule_next_boot(first):
            _p(f"[plan] 재부팅하면 {first} 로 부팅된다. 부팅 후 `--run`.")
    return 0


def cmd_status() -> int:
    st = state_load()
    if not st:
        _p("[status] 계획 없음 (--plan 먼저)")
        return 1
    _p(f"threshold={st['threshold']:,}  자동재부팅={'ON' if st.get('arm') else 'off'}")
    _p(f"fuzzer: {st['fuzzer_cmd']}")
    _p("")
    _p(f"{'커널':<32}{'판정':<10}{'도달 exec':>14}   기간")
    _p("-" * 78)
    for e in st['entries']:
        dur = ''
        if e['started'] and e['finished']:
            dur = f"{e['started']} → {e['finished']}"
        elif e['started']:
            dur = f"{e['started']} → (미완)"
        verdict = e['verdict'] or e['status']
        _p(f"{e['version']:<32}{verdict:<10}{e['last_exec']:>14,}   {dur}")
    _p("-" * 78)
    _p("PASS   = threshold 까지 무프리즈")
    _p("FREEZE = 실행 중 호스트 정지(다음 부팅에서 자동 판정). 도달 exec = 마지막 fsync 값")
    return 0


def cmd_abort() -> int:
    if os.path.exists(STATE_PATH):
        os.remove(STATE_PATH)
        _p("[abort] 계획 삭제됨. (grub 1회성 지정은 다음 부팅에서 자연 소멸)")
    else:
        _p("[abort] 계획 없음")
    return 0


def cmd_service() -> int:
    _p(f"""[Unit]
Description=gdbfuzz kernel sweep (OS freeze 커널 A/B)
After=multi-user.target

[Service]
Type=oneshot
ExecStart={os.path.abspath(__file__)} --run
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target""")
    return 0


def _run_fuzzer(st: dict, entry: dict) -> str:
    """퍼저를 실행하며 stdout 의 exec= 를 읽어 threshold 에서 끊는다.
    진행은 주기적으로 fsync — 프리즈해도 '어디까지 갔는지'가 남아야 하기 때문."""
    threshold = st['threshold']
    cmd = st['fuzzer_cmd']
    _p(f"[run] {entry['version']}: 퍼저 시작 (threshold={threshold:,})")
    _p(f"[run] cmd: {cmd}")

    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, bufsize=1,
                            preexec_fn=os.setsid)
    last_persist = time.time()
    verdict = 'PASS'
    try:
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            m = _EXEC_RE.search(line)
            if m:
                try:
                    n = int(m.group(1).replace(',', ''))
                except ValueError:
                    continue
                if n > entry['last_exec']:
                    entry['last_exec'] = n
                # 주기적 fsync — 프리즈 대비 (이 값이 곧 '프리즈까지 몇 명령' 이 된다)
                if time.time() - last_persist >= 30:
                    state_save(st)
                    last_persist = time.time()
                if n >= threshold:
                    _p(f"[run] threshold 도달 ({n:,}) → 퍼저 종료")
                    break
        else:
            # 퍼저가 스스로 끝남 = 비정상(크래시/에러). threshold 미달이면 INCONCL.
            if entry['last_exec'] < threshold:
                verdict = 'INCONCL'
                _p(f"[run] 퍼저가 threshold 전에 스스로 종료 (exec={entry['last_exec']:,}) "
                   f"→ INCONCL (커널 판정 아님, 퍼저/장치 문제 확인 필요)")
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGINT)
            proc.wait(timeout=60)
        except Exception:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                pass
    return verdict


def cmd_run(args) -> int:
    st = state_load()
    if not st:
        _p("[error] 계획 없음 — 먼저 --plan")
        return 1

    cur = platform.release()

    # ① 직전 실행 판정: 'running' 인 채 남아 있으면 그 커널에서 호스트가 정지한 것.
    #    (프리즈 순간 로그는 못 남지만, 30초마다 fsync 한 last_exec 는 남아 있다.)
    for e in st['entries']:
        if e['status'] == 'running':
            e['status'] = 'done'
            e['verdict'] = 'FREEZE'
            e['finished'] = time.strftime('%Y-%m-%d %H:%M:%S')
            _p(f"[verdict] {e['version']}: **FREEZE** — 직전 부팅에서 정지 "
               f"(도달 exec≈{e['last_exec']:,})")
            state_save(st)

    # ② 이번에 돌릴 엔트리 = 현재 커널과 일치하는 pending
    target = next((e for e in st['entries']
                   if e['status'] == 'pending' and e['version'] == cur), None)
    if target is None:
        nxt = next((e for e in st['entries'] if e['status'] == 'pending'), None)
        if nxt is None:
            _p("[run] 모든 커널 완료. --status 로 결과 확인.")
            return 0
        _p(f"[run] 현재 커널({cur})은 계획의 다음 대상({nxt['version']})이 아니다.")
        if schedule_next_boot(nxt['version']):
            _p("[run] 재부팅 후 다시 --run 할 것.")
        return 0

    target['status'] = 'running'
    target['started'] = time.strftime('%Y-%m-%d %H:%M:%S')
    state_save(st)          # ← 이 fsync 가 프리즈 판정의 근거

    verdict = _run_fuzzer(st, target)

    target['status'] = 'done'
    target['verdict'] = verdict
    target['finished'] = time.strftime('%Y-%m-%d %H:%M:%S')
    state_save(st)
    _p(f"[verdict] {target['version']}: **{verdict}** (exec={target['last_exec']:,})")

    # ③ 다음 커널 예약
    nxt = next((e for e in st['entries'] if e['status'] == 'pending'), None)
    if nxt is None:
        _p("[run] 스윕 완료. --status 로 결과 확인.")
        return 0
    if not schedule_next_boot(nxt['version']):
        return 1
    if st.get('arm'):
        _p("[run] --arm 이므로 10초 후 재부팅한다. 중단하려면 Ctrl-C.")
        time.sleep(10)
        subprocess.run(['reboot'])
    else:
        _p(f"[run] 다음: {nxt['version']}. **직접 재부팅**한 뒤 --run 할 것.")
        _p("      (자동 재부팅을 원하면 --plan 에 --arm)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description='커널 A/B 스윕 — 같은 머신에서 커널만 바꿔 OS freeze 재현 여부를 판정',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--list', action='store_true', help='설치 커널 + GRUB 엔트리 확인')
    g.add_argument('--plan', metavar='V1,V2,...', help='스윕할 커널 버전 목록')
    g.add_argument('--run', action='store_true', help='부팅 후 실행(판정+퍼저+다음 예약)')
    g.add_argument('--status', action='store_true', help='결과 표')
    g.add_argument('--abort', action='store_true', help='계획 삭제')
    g.add_argument('--service', action='store_true', help='systemd unit 출력')

    ap.add_argument('--threshold', type=int, default=1500000,
                    help='PASS 판정 명령 수 (default: 1500000 = 관측 최대 48만의 3배)')
    ap.add_argument('--fuzzer-cmd',
                    default='/home/ssd/gdbfuzz/.venv/bin/python3 '
                            '/home/ssd/gdbfuzz/PC_Sampling/pc_sampling_fuzzer_v9.5.py --product P7',
                    help='퍼저 실행 명령 (--plan 시 저장됨)')
    ap.add_argument('--arm', action='store_true',
                    help='한 커널이 끝나면 **자동 재부팅**해서 다음으로 넘어간다 (기본 off — '
                         '리그에서 재부팅 루프는 위험하므로 명시적으로 켜야 함)')
    args = ap.parse_args()

    if args.list:
        return cmd_list()
    if args.status:
        return cmd_status()
    if args.abort:
        return cmd_abort()
    if args.service:
        return cmd_service()

    if os.geteuid() != 0:
        _p("[error] root 권한 필요 (grub-reboot / /var/lib 쓰기)")
        return 1
    if args.plan:
        return cmd_plan(args)
    if args.run:
        return cmd_run(args)
    return 1


if __name__ == '__main__':
    sys.exit(main())
