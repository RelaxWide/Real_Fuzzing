#!/usr/bin/env python3
"""퍼저 로그의 [Timing] 줄로 '명령 자체가 느려졌나 / 명령 구성이 바뀌었나'를 가른다 (v11.3).

[Timing] 줄의 '전송 상위' 는 각 창에서 전송 시간을 가장 많이 쓴 명령 3개의 평균 ms × 건수다.
같은 명령의 평균을 초반·후반 창끼리 비교하면 명령 구성과 무관하게 그 명령이 느려졌는지 보인다.
워커 바쁨 비율(SBA 준비+PC 읽기 / 실행 1건 시간)은 SBA 트래픽 세기다 — 이게 초반과 같은데 전송만 늘었으면
SBA 간섭이 '늘어난' 원인은 아니다(처음부터 있던 영향일 수는 있다).

사용: python3 tools/timing_trend.py <퍼저 로그> [--part 0.1]
"""
import argparse
import re
import sys
from collections import defaultdict

_NUM = r'([0-9.]+)'
_RE = {
    'n': re.compile(r'\[Timing\] 실행 (\d+)건'),
    'send': re.compile(r'전송\(명령 실행\) ' + _NUM + 'ms'),
    'stop': re.compile(r'종료 대기 ' + _NUM + 'ms'),
    'rest': re.compile(r'기타\(회계·변이·PM 동작\) ' + _NUM + 'ms'),
    'setup': re.compile(r'SBA 준비 ' + _NUM + 'ms'),
    'read': re.compile(r'PC 읽기 ' + _NUM + 'ms'),
    'spawn': re.compile(r'프로세스 생성 ' + _NUM + 'ms'),
    'rss': re.compile(r'RSS ' + _NUM + 'MB'),
}
_TOP = re.compile(r'전송 상위 (.*?)(?: \| |$)')
_ITEM = re.compile(r'(\S+) ' + _NUM + r'ms×(\d+)')


def parse(lines):
    """[Timing] 줄 → [{'exec': 누적 실행 수(창 끝), 'n', 'send', …, 'top': {명령: (평균ms, 건수)}}]."""
    rows, total = [], 0
    for line in lines:
        if '[Timing]' not in line:
            continue
        m = _RE['n'].search(line)
        if not m:
            continue
        r = {'n': int(m.group(1))}
        for k, rx in _RE.items():
            if k != 'n':
                mm = rx.search(line)
                r[k] = float(mm.group(1)) if mm else None
        t = _TOP.search(line)
        r['top'] = {name: (float(ms), int(c)) for name, ms, c in _ITEM.findall(t.group(1))} if t else {}
        total += r['n']
        r['exec'] = total
        rows.append(r)
    return rows


def _avg(vals):
    vals = [v for v in vals if v is not None]
    return sum(vals) / len(vals) if vals else None


def _wavg(rows, key):
    """건수 가중 평균."""
    num = sum(r[key] * r['n'] for r in rows if r.get(key) is not None)
    den = sum(r['n'] for r in rows if r.get(key) is not None)
    return num / den if den else None


def summarize(rows, part=0.1):
    k = max(1, int(len(rows) * part))
    early, late = rows[:k], rows[-k:]
    out = {'windows': len(rows), 'early': early, 'late': late, 'phase': {}, 'cmds': {}}
    for name, grp in (('early', early), ('late', late)):
        send, stop, rest = (_wavg(grp, x) for x in ('send', 'stop', 'rest'))
        setup, read = _wavg(grp, 'setup'), _wavg(grp, 'read')
        spawn, rss = _wavg(grp, 'spawn'), _avg([r.get('rss') for r in grp])
        per_exec = sum(v for v in (send, stop, rest) if v is not None)
        busy = ((setup or 0) + (read or 0)) / per_exec if per_exec and setup is not None else None
        out['phase'][name] = dict(exec=(grp[0]['exec'], grp[-1]['exec']), send=send, stop=stop, rest=rest,
                                  setup=setup, read=read, per_exec=per_exec, busy=busy, spawn=spawn, rss=rss)
    for name, grp in (('early', early), ('late', late)):
        acc = defaultdict(lambda: [0.0, 0])
        for r in grp:
            for cmd, (ms, c) in r['top'].items():
                acc[cmd][0] += ms * c
                acc[cmd][1] += c
        for cmd, (tot, c) in acc.items():
            out['cmds'].setdefault(cmd, {})[name] = (tot / c, c)
    return out


def _f(v, fmt='{:.1f}'):
    return '-' if v is None else fmt.format(v)


def report(s):
    p = []
    p.append(f"[Timing] 창 {s['windows']}개 — 초반·후반 각 {len(s['early'])}개 비교")
    p.append(f"{'':14}{'초반':>12}{'후반':>12}")
    e, l = s['phase']['early'], s['phase']['late']
    p.append(f"{'실행 구간':14}{e['exec'][0]:>6}~{e['exec'][1]:<6}{l['exec'][0]:>6}~{l['exec'][1]:<6}")
    for key, label in (('send', '전송 ms'), ('stop', '종료 대기 ms'), ('rest', '기타 ms'), ('per_exec', '1건 합계 ms'),
                       ('spawn', '프로세스 생성 ms'), ('rss', 'RSS MB'),
                       ('setup', 'SBA 준비 ms'), ('read', 'PC 읽기 ms')):
        p.append(f"{label:14}{_f(e[key]):>12}{_f(l[key]):>12}")
    p.append(f"{'워커 바쁨 비율':14}{_f(e['busy'], '{:.0%}'):>12}{_f(l['busy'], '{:.0%}'):>12}")
    p.append('')
    p.append('명령별 전송 평균(전송 상위에 나온 창만)')
    p.append(f"{'명령':22}{'초반 ms(건)':>16}{'후반 ms(건)':>16}{'배율':>8}")
    both = []
    for cmd, d in sorted(s['cmds'].items()):
        a, b = d.get('early'), d.get('late')
        ratio = b[0] / a[0] if a and b and a[0] else None
        if ratio is not None:
            both.append(ratio)
        p.append(f"{cmd:22}{(f'{a[0]:.1f} ({a[1]})' if a else '-'):>16}"
                 f"{(f'{b[0]:.1f} ({b[1]})' if b else '-'):>16}{_f(ratio, '{:.2f}x'):>8}")
    p.append('')
    send_ratio = (l['send'] / e['send']) if e['send'] and l['send'] else None
    med = sorted(both)[len(both) // 2] if both else None
    p.append(f"판정 재료: 전송 전체 {_f(send_ratio, '{:.2f}x')}, 양쪽에 나온 명령의 중간 배율 {_f(med, '{:.2f}x')}")
    host = False
    if e['spawn'] is not None and l['spawn'] is not None and e['send'] and l['send'] and l['send'] > e['send']:
        host = (l['spawn'] - e['spawn']) >= 0.5 * (l['send'] - e['send'])
    if send_ratio and med:
        if med >= 0.7 * send_ratio:
            p.append(" → 같은 명령이 비슷한 비율로 느려졌다: 명령 구성 변화는 아니다 — "
                     + ("늘어난 몫 대부분이 nvme-cli 프로세스 생성(호스트, 아래 줄)" if host
                        else "장치·환경 쪽(장치 상태 누적 또는 SBA 영향)"))
        elif med <= 1.3:
            p.append(" → 같은 명령은 그대로인데 전체만 늘었다: 명령 구성(무거운 명령 비중) 변화")
        else:
            p.append(" → 둘 다 섞임: 명령 자체도 느려졌고 구성도 바뀌었다")
    if e['busy'] is not None and l['busy'] is not None:
        p.append(f"워커 바쁨 비율 {e['busy']:.0%} → {l['busy']:.0%}: "
                 + ("SBA 트래픽 세기는 비슷 — SBA 간섭이 '늘어서' 느려진 것은 아니다"
                    if abs(l['busy'] - e['busy']) < 0.15 else "SBA 트래픽 세기가 바뀌었다 — 간섭 변화 가능"))
    if e['spawn'] is not None and l['spawn'] is not None and e['send'] and l['send']:
        d_send, d_spawn = l['send'] - e['send'], l['spawn'] - e['spawn']
        if d_send > 0:
            p.append(f"전송 증가 {d_send:.1f}ms 중 프로세스 생성 증가 {d_spawn:.1f}ms ({d_spawn / d_send:.0%})"
                     + (f", RSS {e['rss']:.0f}→{l['rss']:.0f}MB" if e['rss'] and l['rss'] else '')
                     + (" → 퍼저 메모리 증가로 nvme-cli 생성이 느려진 것(장치 아님)" if d_spawn >= 0.5 * d_send else ''))
    p.append("한계: 전송 = nvme-cli 프로세스 시작~끝(호스트 몫 포함, '프로세스 생성' 이 그중 생성 몫). "
             "SBA 영향 크기 자체는 --no-jlink 비교로만 잰다.")
    return '\n'.join(p)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('log')
    ap.add_argument('--part', type=float, default=0.1, help='초반·후반으로 볼 창 비율(기본 0.1)')
    a = ap.parse_args(argv)
    with open(a.log, encoding='utf-8', errors='replace') as fh:
        rows = parse(fh)
    if len(rows) < 2:
        print('[Timing] 줄이 2개 미만 — 비교 불가', file=sys.stderr)
        return 1
    print(report(summarize(rows, a.part)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
