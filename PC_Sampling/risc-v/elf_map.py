#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ELF 실행영역 정합성 게이트 + 심볼화 — v10 RISC-V PCSR 커버리지용.

왜 필요한가:
  PCSR 샘플(=런타임 PC)을 ELF 로 심볼화하려면 **런타임 주소와 ELF vaddr 이 같아야**
  한다. 펌웨어가 flash→코드SRAM 으로 복사되는 구조면 런타임 주소가 달라져(offset)
  심볼화가 통째로 어긋나는데, addr2line 은 그래도 그럴듯한 이름을 뱉어서
  **조용히 틀린 커버리지**가 나온다. 그래서 심볼화 **전에** 정합성을 강제 검사한다.

  실측(2026-09): SF-E76 4코어(HCORE/CMCore/Fcore/QCore) 모두 offset=0 으로
  100% 매칭 확인됨. 그래도 제품/빌드가 바뀌면 깨질 수 있으므로 게이트를 상시 둔다.

방식:
  ① readelf -lW 로 실행(PT_LOAD + E) 세그먼트 범위를 읽고
  ② 관측 PC 중 몇 %가 그 범위에 드는지 계산(정합성 게이트, 기본 임계 95%)
  ③ 임계 미만이면 심볼화를 **거부**하고 후보 offset 을 제안한다.

주소 규약:  runtime_pc = elf_vaddr + offset   →  elf_addr = pc - offset
"""
from __future__ import annotations

import bisect
import os
import re
import subprocess

DEFAULT_THRESHOLD = 95.0        # 이 %% 이상 실행영역에 들어야 심볼화 허용
_ADDR_LINE = re.compile(r"^0x[0-9a-fA-F]+$")


# ── ELF 실행영역 ──────────────────────────────────────────────────────
def parse_readelf_l(text):
    """readelf -lW 출력 → 실행(E) PT_LOAD 세그먼트 [(start, end)] (end exclusive).

    LOAD 라인:  LOAD  Offset VirtAddr PhysAddr FileSiz MemSiz <Flg…> Align
    ★ Flg 는 'R E'(공백 포함) / 'RW' / 'RWE' 등 토큰 수가 달라, Align(마지막) 앞의
      토큰을 전부 이어붙여 판정한다(순진한 인덱싱은 깨짐)."""
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("LOAD"):
            continue
        t = s.split()
        if len(t) < 8:                       # LOAD+5필드+flg+align 최소
            continue
        try:
            vaddr = int(t[2], 16)            # VirtAddr
            memsz = int(t[5], 16)            # MemSiz (FileSiz 아님 — .bss 포함)
        except ValueError:
            continue
        flags = "".join(t[6:-1])             # Align 앞까지가 플래그
        if "E" not in flags or memsz <= 0:
            continue
        out.append((vaddr, vaddr + memsz))
    return sorted(out)


def exec_ranges(elf, readelf="readelf", why=None):
    """ELF 의 실행 세그먼트 범위. 실패 시 [].

    why 에 list 를 주면 **실패 이유**를 담아준다 — 그냥 [] 만 돌려주면 호출부가
    'readelf 실패/ELF 아님' 같은 뭉뚱그린 메시지밖에 못 낸다(실기서 원인 파악에 시간을
    버린 지점)."""
    def _note(m):
        if why is not None:
            why.append(m)
    if not os.path.exists(elf):
        _note(f"파일 없음: {elf}  (상대경로면 cwd={os.getcwd()} 기준으로 해석된다)")
        return []
    if not os.path.isfile(elf):
        _note(f"파일이 아님(디렉토리?): {elf}")
        return []
    try:
        with open(elf, "rb") as f:
            magic = f.read(4)
        if magic != b"\x7fELF":
            _note(f"ELF 매직이 아님(앞 4바이트={magic!r}) — 이 파일은 ELF 가 아니다: {elf}")
            return []
    except OSError as e:
        _note(f"읽기 실패: {e}")
        return []
    try:
        r = subprocess.run([readelf, "-lW", elf], capture_output=True,
                           text=True, timeout=60)
    except FileNotFoundError:
        _note(f"'{readelf}' 실행 파일을 못 찾음 — binutils 설치/PATH 확인 "
              f"(sudo 는 secure_path 를 쓰므로 PATH 가 다를 수 있다)")
        return []
    except (OSError, subprocess.SubprocessError) as e:
        _note(f"readelf 실행 실패: {e}")
        return []
    if r.returncode != 0:
        _note(f"readelf rc={r.returncode}: {(r.stderr or '').strip()[:160]}")
        return []
    out = parse_readelf_l(r.stdout)
    if not out:
        _note("readelf 는 성공했으나 실행(PT_LOAD+E) 세그먼트가 없다 "
              "— 링크 스크립트/섹션 구성 확인")
    return out


class Ranges:
    """실행영역 조회(bisect O(log n)) — 샘플 수만 개를 걸러야 하므로."""

    def __init__(self, ranges):
        self.ranges = sorted(ranges)
        self._starts = [a for a, _ in self.ranges]

    def __bool__(self):
        return bool(self.ranges)

    def __contains__(self, addr):
        i = bisect.bisect_right(self._starts, addr) - 1
        return i >= 0 and addr < self.ranges[i][1]

    @property
    def span(self):
        return (self.ranges[0][0], self.ranges[-1][1]) if self.ranges else (0, 0)


# ── 정합성 검사 ───────────────────────────────────────────────────────
def validate_pcs(pcs, ranges, offset=0):
    """관측 PC 가 실행영역에 드는 비율. → dict(total,in_range,pct,pc_min,pc_max,…)"""
    rr = ranges if isinstance(ranges, Ranges) else Ranges(ranges)
    total = len(pcs)
    hit = sum(1 for pc in pcs if (pc - offset) in rr)
    return {
        "total": total,
        "in_range": hit,
        "pct": (100.0 * hit / total) if total else 0.0,
        "pc_min": min(pcs) if pcs else None,
        "pc_max": max(pcs) if pcs else None,
        "elf_span": rr.span,
        "offset": offset,
    }


def suggest_offset(pcs, ranges, align=0x1000):
    """정합성 실패 시 후보 offset 제안 — 관측 최소 PC 를 실행영역 시작에 맞추는 값.
    (align 배수로 반올림한 후보도 함께 평가해 더 나은 쪽을 고른다.)
    → (best_offset, best_pct) 또는 (None, 0.0)"""
    rr = ranges if isinstance(ranges, Ranges) else Ranges(ranges)
    if not pcs or not rr:
        return None, 0.0
    raw = min(pcs) - rr.span[0]
    cands = {0, raw}
    if align:
        cands.add((raw // align) * align)
        cands.add(((raw + align - 1) // align) * align)
    best, best_pct = None, -1.0
    for off in sorted(cands):
        pct = validate_pcs(pcs, rr, off)["pct"]
        if pct > best_pct:
            best, best_pct = off, pct
    return best, best_pct


def check_gate(pcs, elf, offset=0, threshold=DEFAULT_THRESHOLD, label="",
               readelf="readelf", verbose=True):
    """심볼화 전 강제 게이트. → (ok: bool, info: dict)

    ok=False 면 심볼화하지 말 것 — offset 이 틀렸거나 ELF 가 이 코어 것이 아니다."""
    why: list = []
    rr = Ranges(exec_ranges(elf, readelf, why=why))
    tag = f"[{label}] " if label else ""
    if not rr:
        if verbose:
            print(f"  {tag}⚠ 실행영역을 못 읽음 — 정합성 검증 불가, 심볼화 보류")
            for m in why:
                print(f"  {tag}  원인: {m}")
        return False, {"error": "no-exec-ranges", "elf": elf, "why": why}
    info = validate_pcs(pcs, rr, offset)
    info["elf"] = elf
    ok = info["pct"] >= threshold and info["total"] > 0
    if verbose:
        lo, hi = info["elf_span"]
        print(f"  {tag}ELF exec 0x{lo:X}~0x{hi:X} | 관측 PC "
              f"0x{info['pc_min']:X}~0x{info['pc_max']:X} (n={info['total']})"
              if info["total"] else f"  {tag}관측 PC 없음")
        print(f"  {tag}정합성: {info['in_range']}/{info['total']} = "
              f"{info['pct']:.1f}% (offset=0x{offset:X}, 임계 {threshold:.0f}%) "
              f"→ {'✅ 통과' if ok else '❌ 실패'}")
    if not ok and info["total"]:
        cand, cand_pct = suggest_offset(pcs, rr)
        info["suggested_offset"] = cand
        info["suggested_pct"] = cand_pct
        if verbose and cand is not None and cand_pct > info["pct"]:
            print(f"  {tag}→ 후보 offset=0x{cand:X} 이면 {cand_pct:.1f}% "
                  f"(--offset 으로 지정해 재확인)")
        elif verbose:
            print(f"  {tag}→ offset 조정으로도 개선 안 됨 — 이 ELF 가 해당 코어 것이 "
                  f"맞는지 확인(코어↔ELF 매칭 오류 의심)")
    return ok, info


# ── 심볼화 ────────────────────────────────────────────────────────────
def symbolize(elf, pcs, offset=0, chunk=800, addr2line="addr2line", inline=True):
    """addr2line 으로 PC → [(func, file:line), …]. 인라인 체인 포함.

    ★ -a(주소 에코)로 그룹 경계를 만든다 — -i 는 주소당 출력 줄 수가 가변이라
      단순 2줄씩 페어링하면 어긋난다.
    ★ chunk 로 나눠 호출 — 고유 PC 수천 개면 ARG_MAX 초과로 실패한다."""
    res = {}
    pcs = list(pcs)
    if not pcs:
        return res
    flags = ["-a", "-f", "-e", elf] + (["-i"] if inline else [])
    for i in range(0, len(pcs), chunk):
        part = pcs[i:i + chunk]
        args = [addr2line] + flags + ["0x%x" % (p - offset) for p in part]
        try:
            out = subprocess.run(args, capture_output=True, text=True,
                                 timeout=300).stdout
        except (OSError, subprocess.SubprocessError) as e:
            print(f"  [symbolize] addr2line 실패: {e}")
            continue
        cur, pend = None, []
        for line in out.splitlines():
            s = line.strip()
            if not s:
                continue
            if _ADDR_LINE.match(s):                      # 새 주소 그룹 시작
                if cur is not None:
                    res[cur] = pend
                cur, pend = int(s, 16) + offset, []      # 런타임 PC 로 되돌림
            elif cur is not None:
                pend.append(s)
        if cur is not None:
            res[cur] = pend
    # func/file 교대 → 페어로 정리
    paired = {}
    for pc, lines in res.items():
        items = []
        for j in range(0, len(lines) - 1, 2):
            fn, loc = lines[j], lines[j + 1]
            if fn and fn != "??":
                items.append((fn, loc))
        paired[pc] = items
    return paired


def functions(sym):
    """symbolize() 결과 → 함수명 집합(인라인 포함)."""
    out = set()
    for items in sym.values():
        for fn, _ in items:
            out.add(fn)
    return out


# ── CLI ───────────────────────────────────────────────────────────────
def main():
    import argparse
    import json as _json
    ap = argparse.ArgumentParser(
        description="ELF 실행영역 정합성 검사 + 심볼화 (심볼화 전 게이트 강제)")
    ap.add_argument("--elf", required=True, help="대상 코어의 ELF")
    ap.add_argument("--pcs", required=True,
                    help="PC 목록 파일(한 줄에 하나, 0x… 또는 10진) 또는 PCSR JSON")
    ap.add_argument("--offset", type=lambda x: int(x, 0), default=0,
                    help="runtime_pc = elf_vaddr + offset (기본 0)")
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                    help=f"정합성 임계 %% (기본 {DEFAULT_THRESHOLD})")
    ap.add_argument("--force", action="store_true",
                    help="게이트 실패해도 심볼화 강행(권장 안 함)")
    ap.add_argument("--top", type=int, default=20)
    a = ap.parse_args()

    raw = open(a.pcs).read()
    try:                                            # PCSR 샘플러 JSON 지원
        j = _json.loads(raw)
        pcs = j["pcs"] if isinstance(j, dict) else [p for r in j for p in r["pcs"]]
    except (ValueError, KeyError, TypeError):
        pcs = [int(s, 0) for s in raw.split() if s.strip()]
    print(f"  PC {len(pcs)}개 로드: {a.pcs}")

    ok, info = check_gate(pcs, a.elf, a.offset, a.threshold)
    if not ok and not a.force:
        print("  ❌ 게이트 실패 — 심볼화 중단(--force 로 강행 가능). "
              "offset/코어↔ELF 매칭을 확인하라.")
        return 1
    sym = symbolize(a.elf, sorted(set(pcs)), a.offset)
    fns = functions(sym)
    print(f"  ✅ 심볼화: 고유 PC {len(sym)} → 함수 {len(fns)}개")
    from collections import Counter
    cnt = Counter(fn for items in sym.values() for fn, _ in items)
    for fn, c in cnt.most_common(a.top):
        print(f"    {fn[:60]:60} {c}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
