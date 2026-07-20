#!/usr/bin/env python3
"""coverage_growth_plot.py — v9.4 3축 커버리지 성장 그래프 (fuzzer 와 분리된 오프라인 렌더).

퍼저가 output_dir/coverage_growth.jsonl 에 주기적으로 쓰는 스냅샷을 읽어 그린다.
각 줄(JSON): {exec, elapsed_s, bb_pct, func_pct, sc_count, state_count, by_src:{src:{edge,sc,state}}}

세 축의 성질이 다르다(정직하게 혼합):
  - edge : % (BB/func, Ghidra 정적분석 분모 존재)
  - sc   : discovery-count (안 A — 분모 없이 누적 distinct (cmd,status))
  - state: discovery-count (누적 state_corpus)

산출물(입력 파일과 같은 폴더):
  1) coverage_growth_axes.png       — G1 small-multiples (3단, X 공유)
  2) coverage_growth_normalized.png — G2 self-정규화 겹침(성장 모양/포화 비교)
  3) coverage_growth_by_source.png  — G3 소스 stacked(누가 성장을 만들었나)

사용:
  python3 coverage_growth_plot.py <output_dir | coverage_growth.jsonl> [--x exec|time]
퍼저 프로세스와 분리 실행(인프로세스 matplotlib 반복 렌더가 힙을 손상시킨 전례 회피).
플롯 텍스트는 ASCII 고정(DejaVu 폰트에 한글 글리프 없음 — 기존 차트 규칙과 동일).
"""
import sys
import os
import json
import warnings

import matplotlib
matplotlib.use('Agg')
matplotlib.rcParams['font.family'] = 'DejaVu Sans'
matplotlib.rcParams['axes.unicode_minus'] = False
warnings.filterwarnings('ignore', message='Glyph .* missing from current font')
import matplotlib.pyplot as plt


def _resolve_input(arg):
    if os.path.isdir(arg):
        return os.path.join(arg, 'coverage_growth.jsonl')
    return arg


def load_rows(path):
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue          # 부분 기록/손상 줄 무시
    rows.sort(key=lambda r: r.get('exec', 0))
    return rows


def _xaxis(rows, mode):
    if mode == 'time':
        return [r.get('elapsed_s', 0) for r in rows], 'elapsed (s)'
    return [r.get('exec', 0) for r in rows], 'executions'


def _all_sources(rows):
    srcs = set()
    for r in rows:
        srcs.update((r.get('by_src') or {}).keys())
    # blind 먼저, llm 나중 — 색 일관성
    return sorted(srcs, key=lambda s: (not s.startswith('blind'), s))


def _series_by_src(rows, axis):
    """각 소스의 누적 값 시계열(없으면 0). 반환 {src: [v0, v1, ...]}."""
    srcs = _all_sources(rows)
    out = {s: [] for s in srcs}
    for r in rows:
        bs = r.get('by_src') or {}
        for s in srcs:
            out[s].append((bs.get(s) or {}).get(axis, 0))
    return out


# ── G1: small-multiples ─────────────────────────────────────────────────────
def plot_axes(rows, x, xlabel, outpath):
    fig, axs = plt.subplots(3, 1, figsize=(11, 10), sharex=True)
    bb = [r.get('bb_pct') for r in rows]
    fn = [r.get('func_pct') for r in rows]
    ax = axs[0]
    if any(v is not None for v in bb):
        ax.plot(x, [v if v is not None else float('nan') for v in bb],
                label='BB %', color='#1f77b4')
    if any(v is not None for v in fn):
        ax.plot(x, [v if v is not None else float('nan') for v in fn],
                label='func %', color='#2ca02c')
    ax.set_ylabel('edge-cov (%)')
    ax.set_title('edge coverage: % of static BB/func (Ghidra denominator)')
    ax.legend(loc='lower right'); ax.grid(True, alpha=0.3)
    axs[1].plot(x, [r.get('sc_count', 0) for r in rows], color='#ff7f0e')
    axs[1].set_ylabel('sc discovery (count)')
    axs[1].set_title('sc coverage: cumulative distinct (cmd, status)  [no denominator]')
    axs[1].grid(True, alpha=0.3)
    axs[2].plot(x, [r.get('state_count', 0) for r in rows], color='#9467bd')
    axs[2].set_ylabel('state discovery (count)')
    axs[2].set_title('state coverage: cumulative state_corpus  [no denominator]')
    axs[2].grid(True, alpha=0.3)
    axs[2].set_xlabel(xlabel)
    fig.tight_layout()
    fig.savefig(outpath, dpi=110); plt.close(fig)


# ── G2: self-normalized overlay ─────────────────────────────────────────────
def _norm(vals):
    xs = [v for v in vals if v is not None]
    m = max(xs) if xs else 0
    if m <= 0:
        return [0.0 for _ in vals]
    return [(v / m) if v is not None else float('nan') for v in vals]


def plot_normalized(rows, x, xlabel, outpath):
    fig, ax = plt.subplots(figsize=(11, 6))
    ax.plot(x, _norm([r.get('bb_pct') for r in rows]), label='edge (BB)', color='#1f77b4')
    ax.plot(x, _norm([r.get('sc_count', 0) for r in rows]), label='sc', color='#ff7f0e')
    ax.plot(x, _norm([r.get('state_count', 0) for r in rows]), label='state', color='#9467bd')
    ax.set_ylabel('fraction of each axis final (0..1)')
    ax.set_xlabel(xlabel)
    ax.set_title('growth shape / saturation timing (self-normalized; avoids unknown total)')
    ax.set_ylim(0, 1.02); ax.legend(loc='lower right'); ax.grid(True, alpha=0.3)
    fig.tight_layout(); fig.savefig(outpath, dpi=110); plt.close(fig)


# ── G3: source-stacked ──────────────────────────────────────────────────────
_SRC_COLORS = {
    'blind/cmd': '#4c78a8', 'blind/seq': '#72b7b2', 'blind/iowl': '#54a24b',
    'blind/replay': '#b279a2',
    'llm/cmd': '#f58518', 'llm/seq': '#e45756', 'llm/iowl': '#eeca3b',
    'llm/replay': '#ff9da6',
}


def _stack(ax, x, series, title, ylabel):
    srcs = list(series.keys())
    if not srcs:
        ax.set_title(title + ' (no data)'); return
    ys = [series[s] for s in srcs]
    colors = [_SRC_COLORS.get(s, None) for s in srcs]
    ax.stackplot(x, *ys, labels=srcs, colors=colors, alpha=0.9)
    ax.set_ylabel(ylabel); ax.set_title(title)
    ax.legend(loc='upper left', fontsize=8, ncol=2); ax.grid(True, alpha=0.3)


def plot_by_source(rows, x, xlabel, outpath):
    fig, axs = plt.subplots(2, 1, figsize=(11, 9), sharex=True)
    _stack(axs[0], x, _series_by_src(rows, 'edge'),
           'edge-cov growth: cumulative new BB by source', 'edge (cum new BB)')
    _stack(axs[1], x, _series_by_src(rows, 'sc'),
           'sc-cov growth: cumulative distinct status by source', 'sc (cum distinct)')
    axs[1].set_xlabel(xlabel)
    fig.tight_layout(); fig.savefig(outpath, dpi=110); plt.close(fig)


def main():
    if len(sys.argv) < 2:
        print(__doc__); return 2
    xmode = 'exec'
    if '--x' in sys.argv:
        i = sys.argv.index('--x')
        if i + 1 < len(sys.argv):
            xmode = sys.argv[i + 1]
    path = _resolve_input(sys.argv[1])
    if not os.path.isfile(path):
        print(f"[coverage_growth_plot] input not found: {path}"); return 2
    rows = load_rows(path)
    if not rows:
        print(f"[coverage_growth_plot] empty data: {path}"); return 2
    x, xlabel = _xaxis(rows, xmode)
    outdir = os.path.dirname(os.path.abspath(path))
    p1 = os.path.join(outdir, 'coverage_growth_axes.png')
    p2 = os.path.join(outdir, 'coverage_growth_normalized.png')
    p3 = os.path.join(outdir, 'coverage_growth_by_source.png')
    plot_axes(rows, x, xlabel, p1)
    plot_normalized(rows, x, xlabel, p2)
    plot_by_source(rows, x, xlabel, p3)
    print(f"[coverage_growth_plot] {len(rows)} rows ->\n  {p1}\n  {p2}\n  {p3}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
