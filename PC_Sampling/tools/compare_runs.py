#!/usr/bin/env python3
"""compare_runs.py — 여러 실행의 run_record_<run_id>.json 을 모아 LLM ON/OFF(또는 다른 조건)를 비교한다.

퍼저(v11.1+)는 실행마다 output_dir 에 run_record_<run_id>.json 을 남긴다(100명령 스냅샷 중 최소 60초 간격, 종료 시 final).
비교하고 싶은 실행들의 이 파일을 한 폴더에 복사해 두고 이 도구를 돌린다. 장치에 접근하지 않는다.

사용:
  python3 tools/compare_runs.py <폴더|파일...> [--out DIR] [--group llm] [--metric bb_pct]
                                [--x time|exec] [--strict]

  --group   실행을 나눌 조건 키(conditions.<키>). 기본 llm → "LLM ON" / "LLM OFF"
  --metric  bb_pct(기본) | func_pct | bb
  --x       time(기본, 시간) | exec(실행 명령 수)
  --strict  제품·FW·커버리지 분모 등 비교 조건이 다르면 중단(기본은 경고만)

산출물(--out, 기본은 첫 입력 폴더 아래 compare/):
  compare_coverage.png  — 그룹별 커버리지 성장(중앙값 + 최소~최대 음영, 실행별 얇은 선)
  compare_speedup.png   — 커버리지 수준별 도달 시간 비율(기준 그룹 시간 / 비교 그룹 시간)
  compare_llm_share.png — LLM 실행의 효율 배수(명령 1개당 새 BB, LLM ÷ mutation. 1 위 = LLM 이 더 찾음)
  compare_summary.md    — 최종 커버리지 중앙값·범위, 차이, A12, 기준 최종값 도달 시간·배속, 고유 BB

퍼징은 실행마다 편차가 커서 그룹당 3~5회를 권한다. 1회씩이면 표에 그렇게 표시한다.
플롯 텍스트는 ASCII(DejaVu 폰트에 한글 글리프 없음 — 기존 차트 규칙과 같다).
"""
import argparse
import json
import statistics
import sys
import warnings
from pathlib import Path

SCHEMA = 'pcfuzz-run/1'
# 실행마다 다를 수 있는 조건(비교 가능성 검사에서 제외)
_RUN_LEVEL = {'llm', 'llm_module', 'llm_model', 'retrieval', 'config_sha256', 'version'}
# 다르면 커버리지 비교 자체가 무의미한 조건
_MUST_MATCH = ('product', 'commands')


def load_records(inputs):
    files = []
    for arg in inputs:
        p = Path(arg)
        if p.is_dir():
            files += sorted(p.rglob('run_record_*.json'))
        elif p.is_file():
            files.append(p)
        else:
            raise SystemExit(f'[compare] 입력을 찾을 수 없음: {arg}')
    runs = {}
    for f in files:
        try:
            rec = json.loads(f.read_text(encoding='utf-8'))
        except Exception as exc:
            print(f'[compare] 건너뜀(읽기 실패): {f}: {exc}', file=sys.stderr)
            continue
        if rec.get('schema') != SCHEMA:
            print(f'[compare] 건너뜀(형식 다름): {f}', file=sys.stderr)
            continue
        rid = rec.get('run_id') or f.stem
        old = runs.get(rid)
        # 같은 실행의 파일이 여러 개면(중간 복사본 등) 더 오래 돈 것을 쓴다
        if old is None or rec.get('elapsed_s', 0) >= old.get('elapsed_s', 0):
            rec['_file'] = str(f)
            runs[rid] = rec
    if not runs:
        raise SystemExit('[compare] run_record_*.json 이 없습니다')
    return list(runs.values())


def group_label(key, value):
    if key == 'llm':
        return 'LLM ON' if value else 'LLM OFF'
    return f'{key}={value}'


def check_comparable(runs, group_key, strict):
    problems = []
    def fw_id(r):
        fw = (r.get('conditions') or {}).get('fw') or {}
        return json.dumps({k: fw.get(k) for k in ('firmware_rev', 'elf_sha256')}, sort_keys=True)
    checks = [(k, lambda r, k=k: json.dumps((r.get('conditions') or {}).get(k), sort_keys=True))
              for k in _MUST_MATCH if k != group_key]
    checks += [('fw', fw_id),
               ('coverage_unit', lambda r: r.get('coverage_unit')),
               ('bb_total', lambda r: (r.get('totals') or {}).get('bb_total'))]
    for name, fn in checks:
        vals = {}
        for r in runs:
            vals.setdefault(fn(r), []).append(r['run_id'])
        if len(vals) > 1:
            problems.append(f'{name} 가 실행마다 다름: ' +
                            '; '.join(f'{v} ← {", ".join(ids)}' for v, ids in vals.items()))
    other = set()
    for r in runs:
        for k, v in (r.get('conditions') or {}).items():
            if k in _RUN_LEVEL or k == group_key or k in _MUST_MATCH or k == 'fw':
                continue
            other.add(k)
    for k in sorted(other):
        vals = {json.dumps((r.get('conditions') or {}).get(k), sort_keys=True) for r in runs}
        if len(vals) > 1:
            problems.append(f'조건 {k} 가 실행마다 다름: {sorted(vals)}')
    for p in problems:
        print(f'[compare] ⚠ {p}', file=sys.stderr)
    if problems and strict:
        raise SystemExit('[compare] --strict: 비교 조건이 달라 중단')
    return problems


def series_xy(rec, metric, xaxis):
    xs, ys = [], []
    for pt in rec.get('series') or []:
        y = pt.get(metric)
        x = pt.get('t') if xaxis == 'time' else pt.get('exec')
        if y is None or x is None:
            continue
        xs.append(float(x) / (3600.0 if xaxis == 'time' else 1.0))
        ys.append(float(y))
    return xs, ys


def value_at(xs, ys, x):
    """계단식(그 시점까지 도달한 값). 커버리지는 단조 증가."""
    v = None
    for xi, yi in zip(xs, ys):
        if xi > x:
            break
        v = yi
    return v


def time_to(xs, ys, level):
    for xi, yi in zip(xs, ys):
        if yi >= level:
            return xi
    return None


def a12(xs, ys):
    """Vargha-Delaney A12: X 의 한 실행이 Y 의 한 실행보다 클 확률(0.5 = 차이 없음)."""
    if not xs or not ys:
        return None
    gt = sum(1 for x in xs for y in ys if x > y)
    eq = sum(1 for x in xs for y in ys if x == y)
    return (gt + 0.5 * eq) / (len(xs) * len(ys))


def median(v):
    v = [x for x in v if x is not None]
    return statistics.median(v) if v else None


def reach_median(curves, level):
    """도달 시간의 중앙값 — 미도달은 관측 종료 뒤(무한대)로 검열한다.

    도달한 실행만으로 중앙값을 내면 운 좋은 실행만 남아 부풀려진다(생존자 편향). 미도달을 ∞ 로 두면
    **과반이 도달했을 때만** 유한한 중앙값이 나온다(생존 분석의 중앙 도달 시간). 짝수 개면 가운데
    두 값의 평균이라 둘 중 하나라도 ∞ 면 None. 기준 그룹의 목표가 자기 최종값 중앙값이어도 과반이
    도달하므로 값이 나온다(전원 도달을 요구하면 정의상 거의 항상 None 이었다).
    """
    times = [time_to(xs, ys, level) for xs, ys in curves]
    if not times:
        return None, times
    inf = float('inf')
    m = statistics.median([t if t is not None else inf for t in times])
    return (None if m == inf else m), times


def common_budget(data):
    """모든 실행이 관측된 공통 예산에서 잘라 최종값/A12/배속을 비교한다."""
    curves = [curve for group in data.values() for curve in group]
    if any(not xs for xs, _ in curves):
        raise SystemExit('[compare] 시계열이 없는 실행은 비교할 수 없습니다')
    horizon = min(xs[-1] for xs, _ in curves)
    if any(xs[0] > horizon for xs, _ in curves):
        raise SystemExit('[compare] 실행 간 공통 관측 구간이 없습니다')
    limited = {}
    for group, curves in data.items():
        limited[group] = []
        for xs, ys in curves:
            pts = [(x, y) for x, y in zip(xs, ys) if x < horizon]
            pts.append((horizon, value_at(xs, ys, horizon)))
            limited[group].append(([x for x, _ in pts], [y for _, y in pts]))
    return limited, horizon


def compare(runs, group_key='llm', metric='bb_pct', xaxis='time', out_dir=None, strict=False):
    problems = check_comparable(runs, group_key, strict)
    groups = {}
    for r in runs:
        groups.setdefault(group_label(group_key, (r.get('conditions') or {}).get(group_key)), []).append(r)
    if metric not in ('bb_pct', 'func_pct', 'bb'):
        raise SystemExit(f'[compare] 지원하지 않는 metric: {metric}')
    # 기록 점이 없는 실행(첫 기록 전에 죽음 등)은 비교 전체를 막지 않고 빼고 알린다
    skipped = []
    for g in list(groups):
        kept = []
        for r in groups[g]:
            if series_xy(r, metric, xaxis)[0]:
                kept.append(r)
            else:
                skipped.append(r['run_id'])
                print(f"[compare] ⚠ 건너뜀(시계열 없음): {r['run_id']}", file=sys.stderr)
        if kept:
            groups[g] = kept
        else:
            raise SystemExit(f'[compare] {g}: {metric} 시계열이 있는 실행이 없습니다(정적 커버리지 없는 실행?)')
    labels = sorted(groups)
    ref = 'LLM OFF' if 'LLM OFF' in groups else labels[0]
    data = {g: [series_xy(r, metric, xaxis) for r in groups[g]] for g in labels}
    original_data = data
    data, horizon = common_budget(data)
    # 공통 예산을 정한(가장 짧은) 실행 — 하나가 비교 전체를 깎을 수 있으므로 요약에 남긴다
    _ends = [(xs[-1], r['run_id']) for g in labels for r, (xs, _) in zip(groups[g], original_data[g])]
    horizon_run = min(_ends)[1]
    finals = {g: [ys[-1] if ys else None for _, ys in data[g]] for g in labels}
    ref_final = median(finals[ref])

    rows = []
    for g in labels:
        fin = [v for v in finals[g] if v is not None]
        target_t, tt = reach_median(data[g], ref_final)
        reached = [t for t in tt if t is not None]
        ref_t, _ = reach_median(data[ref], ref_final)
        row = dict(group=g, n=len(groups[g]), final_median=median(fin),
                   final_min=min(fin) if fin else None, final_max=max(fin) if fin else None,
                   duration=median([xs[-1] for xs, _ in data[g] if xs]),
                   a12=a12(fin, [v for v in finals[ref] if v is not None]) if g != ref else None,
                   reach_ref_final=target_t,
                   reached=f'{len(reached)}/{len(tt)}',
                   speedup=(ref_t / target_t) if (g != ref and ref_t is not None
                                                   and target_t is not None and target_t > 0) else None)
        rows.append(row)

    # 고유 BB(같은 종류의 커버리지 집합일 때만)
    unique = {}
    kinds = {r.get('covered_kind') for r in runs}
    # 기록된 집합은 실행 종료 시점뿐이다. 잘린 실행의 공통 시점 집합을 추정하지 않는다.
    #   같은 설정으로 돌려도 종료 시각은 몇 초씩 다르다 — 기록 간격(60초)·길이 1% 안이면 같은 종료로 본다.
    _tol = max(60.0 / 3600.0 if xaxis == 'time' else 0.0, 0.01 * horizon)
    same_end = all(xs[-1] - horizon <= _tol for curves in original_data.values() for xs, _ in curves)
    if len(kinds) == 1 and same_end:
        sets = {g: set().union(*(set(r.get('covered') or []) for r in groups[g])) for g in labels}
        for g in labels:
            others = set().union(*(sets[o] for o in labels if o != g)) if len(labels) > 1 else set()
            unique[g] = len(sets[g] - others)

    out = Path(out_dir) if out_dir else Path(runs[0]['_file']).parent / 'compare'
    out.mkdir(parents=True, exist_ok=True)
    _plots(groups, data, labels, ref, ref_final, metric, xaxis, out)
    md = _summary_md(rows, unique, ref, metric, xaxis, problems, groups,
                     horizon=horizon, horizon_run=horizon_run, skipped=skipped)
    (out / 'compare_summary.md').write_text(md, encoding='utf-8')
    print(md)
    print(f'[compare] 산출물: {out}')
    return rows, unique, out


_COLORS = ['#3182bd', '#e6550d', '#31a354', '#756bb1', '#636363']


def _grid(data_g, xaxis):
    end = min(xs[-1] for xs, _ in data_g if xs)
    n = 200
    return [end * i / (n - 1) for i in range(n)]


def _plots(groups, data, labels, ref, ref_final, metric, xaxis, out):
    import matplotlib
    matplotlib.use('Agg')
    matplotlib.rcParams['font.family'] = 'DejaVu Sans'
    warnings.filterwarnings('ignore', message='Glyph .* missing from current font')
    import matplotlib.pyplot as plt

    xl = 'Elapsed time (h)' if xaxis == 'time' else 'Executions'
    yl = {'bb_pct': 'BB coverage (%)', 'func_pct': 'Function coverage (%)', 'bb': 'Covered BBs'}[metric]

    # 1) 성장 곡선
    fig, ax = plt.subplots(figsize=(11, 6))
    for i, g in enumerate(labels):
        c = _COLORS[i % len(_COLORS)]
        for xs, ys in data[g]:
            ax.step(xs, ys, where='post', color=c, alpha=0.25, linewidth=0.8)
        grid = _grid(data[g], xaxis)
        vals = [[value_at(xs, ys, x) for xs, ys in data[g]] for x in grid]
        med = [median(v) for v in vals]
        lo = [min([y for y in v if y is not None], default=None) for v in vals]
        hi = [max([y for y in v if y is not None], default=None) for v in vals]
        ok = [k for k, m in enumerate(med) if m is not None]
        ax.plot([grid[k] for k in ok], [med[k] for k in ok], color=c, linewidth=2.2,
                label=f'{g} (n={len(groups[g])}, median)')
        if len(groups[g]) > 1:
            ax.fill_between([grid[k] for k in ok], [lo[k] for k in ok], [hi[k] for k in ok],
                            color=c, alpha=0.15, linewidth=0)
    if ref_final is not None:
        ax.axhline(ref_final, color='gray', linestyle=':', linewidth=1)
        ax.annotate(f'{ref} common-budget median {ref_final:.2f}', xy=(0, ref_final), xytext=(4, 4),
                    textcoords='offset points', fontsize=8, color='dimgray')
        for i, g in enumerate(labels):
            if g == ref:
                continue
            t, _ = reach_median(data[g], ref_final)
            if t is not None:
                ax.axvline(t, color=_COLORS[i % len(_COLORS)], linestyle='--', linewidth=1)
                ax.annotate(f'{g} reaches it at {t:.2f}' + ('h' if xaxis == 'time' else ''),
                            xy=(t, ref_final), xytext=(4, -14), textcoords='offset points',
                            fontsize=8, color=_COLORS[i % len(_COLORS)])
    ax.set_xlabel(xl)
    ax.set_ylabel(yl)
    ax.set_title('Coverage growth by group (median, band = min..max over runs)')
    ax.grid(True, alpha=0.3)
    ax.legend(loc='upper left', fontsize=8)
    fig.savefig(out / 'compare_coverage.png', dpi=150, bbox_inches='tight')
    plt.close(fig)

    # 2) 배속: 수준별 도달 시간 비율
    fig, ax = plt.subplots(figsize=(11, 4.5))
    if ref_final:
        levels = [ref_final * k / 40 for k in range(1, 41)]
        ref_t = [reach_median(data[ref], L)[0] for L in levels]
        drew = False
        for i, g in enumerate(labels):
            if g == ref:
                continue
            gt = [reach_median(data[g], L)[0] for L in levels]
            pts = [(L, rt / t) for L, rt, t in zip(levels, ref_t, gt) if rt and t and t > 0]
            if pts:
                ax.plot([p[0] for p in pts], [p[1] for p in pts], marker='o', markersize=3,
                        color=_COLORS[i % len(_COLORS)], label=f'{ref} time / {g} time')
                drew = True
        ax.axhline(1.0, color='gray', linewidth=1)
        if drew:
            ax.legend(loc='upper left', fontsize=8)
    ax.set_xlabel(f'Coverage level ({yl}) — up to {ref} common-budget median')
    ax.set_ylabel('Speedup (x)')
    ax.set_title('Time-to-coverage speedup (median reach time; a majority of runs must reach each level)')
    ax.grid(True, alpha=0.3)
    fig.savefig(out / 'compare_speedup.png', dpi=150, bbox_inches='tight')
    plt.close(fig)

    # 3) LLM 효율 배수(LLM 을 쓴 실행만): 명령 1개당 새 BB — LLM ÷ mutation.
    #   퍼징 시작 후 corpus 에서 골라 실행한 명령만(시작 전 보정·LLM 이 패턴만 고른 워크로드 제외).
    #   1 보다 위 = 같은 명령으로 LLM 이 더 찾음. 'sel' 이 없는 옛 기록은 그리지 않는다.
    fig, ax = plt.subplots(figsize=(11, 4.5))
    drew = False
    for g in labels:
        for r in groups[g]:
            if not (r.get('conditions') or {}).get('llm'):
                continue
            xs, ys = [], []
            for pt in r.get('series') or []:
                x = pt.get('t') if xaxis == 'time' else pt.get('exec')
                sel = pt.get('sel') or {}
                (nl, cl), (nm, cm) = sel.get('llm', (0, 0)), sel.get('mutation', (0, 0))
                if x is None or not cl or not cm or not nm:
                    continue
                xs.append(float(x) / (3600.0 if xaxis == 'time' else 1.0))
                ys.append(max((nl / cl) / (nm / cm), 0.01))
            if xs:
                ax.plot(xs, ys, color='#e6550d', alpha=0.75, linewidth=1.3)
                drew = True
    ax.axhline(1.0, color='gray', linewidth=1)
    if drew:
        ax.plot([], [], color='#e6550d', label='LLM / mutation new BB per command (each LLM run)')
        ax.legend(loc='upper left', fontsize=8)
    ax.set_yscale('log')
    ax.set_ylim(0.01, 100)
    ax.set_yticks([0.01, 0.1, 1, 10, 100])
    ax.set_yticklabels(['0.01x', '0.1x', '1x', '10x', '100x'])
    ax.minorticks_off()
    ax.set_xlabel(xl)
    ax.set_ylabel('Efficiency ratio (x)')
    ax.set_title('LLM efficiency vs mutation within LLM runs (above 1 = LLM finds more per command)')
    ax.grid(True, alpha=0.3, which='both')
    fig.savefig(out / 'compare_llm_share.png', dpi=150, bbox_inches='tight')
    plt.close(fig)


def _fmt(v, nd=2):
    return '-' if v is None else (f'{v:.{nd}f}' if isinstance(v, float) else str(v))


def _summary_md(rows, unique, ref, metric, xaxis, problems, groups, horizon=None, horizon_run=None,
                skipped=()):
    unit = 'h' if xaxis == 'time' else 'exec'
    lines = [f'# 실행 비교 — {metric}', '',
             f'기준 그룹: **{ref}**. 배속 = 기준 그룹이 자기 최종 중앙값에 도달한 시간 ÷ 비교 그룹이 같은 값에 도달한 시간.',
             '최종값과 A12는 모든 실행의 공통 예산(가장 짧은 관측 시간 또는 실행 횟수)에서 계산합니다. '
             '도달 시간은 미도달을 무한대로 둔 중앙값이라 그룹의 **과반**이 도달해야 표시됩니다'
             '(도달한 실행만 골라 계산하지 않습니다).', '',
             f'공통 예산: **{_fmt(horizon)} {unit}** — 가장 짧은 실행 `{horizon_run}` 이 정했습니다. '
             '이 실행이 비정상적으로 짧으면(중간에 죽음 등) 빼고 다시 비교하세요.', '',
             'A12 = 비교 그룹의 한 실행이 기준 그룹의 한 실행보다 최종 커버리지가 높을 확률(0.5 = 차이 없음, '
             '0.71 이상이면 통상 "큰 차이").', '',
             f'| 그룹 | 실행 수 | 공통 비교 예산({unit}) | 비교 종료 중앙값 | 최소~최대 | 기준 대비 | A12 | 기준 최종값 도달({unit}) | 도달 실행 | 배속 | 고유 BB |',
             '|---|---|---|---|---|---|---|---|---|---|---|']
    ref_med = next((r['final_median'] for r in rows if r['group'] == ref), None)
    for r in rows:
        diff = (r['final_median'] - ref_med) if (r['final_median'] is not None and ref_med is not None
                                                 and r['group'] != ref) else None
        lines.append(f"| {r['group']} | {r['n']} | {_fmt(r['duration'])} | {_fmt(r['final_median'])} | "
                     f"{_fmt(r['final_min'])}~{_fmt(r['final_max'])} | "
                     f"{'+' if diff and diff > 0 else ''}{_fmt(diff)} | {_fmt(r['a12'])} | "
                     f"{_fmt(r['reach_ref_final'])} | {r['reached']} | "
                     f"{(_fmt(r['speedup']) + 'x') if r['speedup'] else '-'} | {unique.get(r['group'], '-')} |")
    if any(len(v) < 3 for v in groups.values()):
        lines += ['', '> ⚠ 그룹당 실행이 3회 미만입니다. 퍼징은 실행마다 편차가 커서 차이가 우연일 수 있습니다.']
    if not unique:
        lines += ['', '> 고유 BB: 커버리지 집합 종류 또는 종료 예산이 달라 계산하지 않았습니다(공통 시점 집합 없음).']
    if skipped:
        lines += ['', f"> 시계열이 없어 뺀 실행: {', '.join(skipped)}"]
    if problems:
        lines += ['', '## 비교 조건 경고', ''] + [f'- {p}' for p in problems]
    lines += ['', '## 실행 목록', '', '| 그룹 | run_id | 최종 | 실행 시간(h) | LLM 끝까지 활성 | 파일 |', '|---|---|---|---|---|---|']
    for g, rs in sorted(groups.items()):
        for r in rs:
            lines.append(f"| {g} | {r['run_id']} | {'예' if r.get('final') else '진행 중'} | "
                         f"{_fmt((r.get('elapsed_s') or 0) / 3600.0)} | "
                         f"{'예' if (r.get('llm_status') or {}).get('active_at_end') else '아니오'} | "
                         f"{Path(r['_file']).name} |")
    return '\n'.join(lines) + '\n'


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('inputs', nargs='+')
    ap.add_argument('--out')
    ap.add_argument('--group', default='llm')
    ap.add_argument('--metric', default='bb_pct')
    ap.add_argument('--x', dest='xaxis', default='time', choices=('time', 'exec'))
    ap.add_argument('--strict', action='store_true')
    a = ap.parse_args(argv)
    compare(load_records(a.inputs), a.group, a.metric, a.xaxis, a.out, a.strict)
    return 0


if __name__ == '__main__':
    sys.exit(main())
