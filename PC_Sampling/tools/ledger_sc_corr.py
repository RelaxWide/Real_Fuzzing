#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ledger 로 '응답(status)이 새로우면 새 코드 경로였나' 를 잰다 — v11.4 응답 커버리지 근거 측정.

사용:  python3 tools/ledger_sc_corr.py <출력폴더>/ledger/outcome_ledger_*.jsonl
       python3 tools/ledger_sc_corr.py <출력폴더>            (그 아래 ledger/*.jsonl 전부)

J-Link 연결 실행의 ledger 여야 한다(--no-jlink 면 new_pcs 가 항상 0 이라 잴 게 없다).
ledger 는 새 PC·SC-depth 전진·새 (명령,status)·LLM 실행을 모두 기록하므로 아래 두 비율이 정확히 나온다.
  정밀도 = 새 status 실행 중 새 PC 도 낸 비율      (응답이 새로우면 코드도 새로웠나)
  재현율 = 새 PC 실행 중 새 status 도 낸 비율      (새 코드를 응답으로 알아챘나)
  배율   = 정밀도 / (전체 실행 중 새 PC 를 낸 비율)   (무작위로 고른 실행보다 몇 배 나은가)
마지막 'CODE:' 한 줄만 옮겨 주면 된다.
"""
import json
import sys
from collections import defaultdict
from pathlib import Path


def load(args):
    files = []
    for a in args:
        p = Path(a)
        files += sorted(p.glob('ledger/outcome_ledger_*.jsonl')) + sorted(p.glob('outcome_ledger_*.jsonl')) \
            if p.is_dir() else [p]
    recs, bad = [], 0
    for f in files:
        with open(f, encoding='utf-8', errors='replace') as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                except ValueError:
                    bad += 1
                    continue
                r['_file'] = f.name
                recs.append(r)
    return files, recs, bad


def rates(recs, total_exec, key):
    pc = [r for r in recs if (r.get('new_pcs') or 0) > 0]
    sig = [r for r in recs if r.get(key)]
    both = [r for r in sig if (r.get('new_pcs') or 0) > 0]
    pcs_all = sum(r['new_pcs'] for r in pc)
    pcs_seen = sum(r['new_pcs'] for r in both)
    prec = len(both) / len(sig) if sig else 0.0
    rec = len(both) / len(pc) if pc else 0.0
    base = len(pc) / total_exec if total_exec else 0.0
    return dict(n_pc=len(pc), n_sig=len(sig), n_both=len(both), prec=prec, rec=rec,
                lift=(prec / base if base else 0.0), w_rec=(pcs_seen / pcs_all if pcs_all else 0.0))


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    files, recs, bad = load(sys.argv[1:])
    if not recs:
        sys.exit(f"레코드 없음 (파일 {len(files)}개)")
    # 실행 수 = 파일(=실행)별 마지막 exec 의 합
    last = defaultdict(int)
    for r in recs:
        last[r['_file']] = max(last[r['_file']], int(r.get('exec') or 0))
    total = sum(last.values())
    if not any((r.get('new_pcs') or 0) > 0 for r in recs):
        sys.exit("new_pcs>0 레코드가 없다 — --no-jlink 실행이거나 커버리지가 안 잡힌 실행이다")

    print(f"파일 {len(files)}개 · 레코드 {len(recs):,} · 실행 {total:,}" + (f" · 깨진 줄 {bad}" if bad else ""))
    out = {}
    for key, label in (('sc_new', '새 status'), ('sc_depth_adv', 'SC-depth 전진')):
        for half, sel in (('전체', lambda r: True),
                          ('후반', lambda r: int(r.get('exec') or 0) > last[r['_file']] / 2)):
            sub = [r for r in recs if sel(r)]
            t = total if half == '전체' else total - sum(v // 2 for v in last.values())
            m = rates(sub, t, key)
            out[(key, half)] = m
            print(f"  {label:12} {half}: 정밀도 {m['prec']*100:5.1f}%  재현율 {m['rec']*100:5.1f}% "
                  f"(PC 수 기준 {m['w_rec']*100:5.1f}%)  배율 ×{m['lift']:.0f}  "
                  f"[새PC {m['n_pc']} · 신호 {m['n_sig']} · 겹침 {m['n_both']}]")

    # 새 PC 를 냈는데 status 는 새롭지 않았던 명령 — 다른 축(처리 시간·DW0·직전 명령)이 필요한 곳
    miss = defaultdict(int)
    for r in recs:
        if (r.get('new_pcs') or 0) > 0 and not r.get('sc_new'):
            miss[r.get('cmd')] += r['new_pcs']
    top = sorted(miss.items(), key=lambda kv: -kv[1])[:5]
    print("  status 로 못 잡은 새 PC 상위 명령: " + (", ".join(f"{c}={n}" for c, n in top) or "없음"))

    a, b = out[('sc_new', '전체')], out[('sc_new', '후반')]
    d = out[('sc_depth_adv', '전체')]
    print("CODE: " + " ".join([
        f"N{total}", f"P{a['n_pc']}", f"S{a['n_sig']}", f"B{a['n_both']}",
        f"p{a['prec']*100:.0f}", f"r{a['rec']*100:.0f}", f"w{a['w_rec']*100:.0f}", f"L{a['lift']:.0f}",
        f"hp{b['prec']*100:.0f}", f"hr{b['rec']*100:.0f}",
        f"dp{d['prec']*100:.0f}", f"dr{d['rec']*100:.0f}",
        "M" + ",".join(f"{c}:{n}" for c, n in top[:3])]))


if __name__ == '__main__':
    main()
