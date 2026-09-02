#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RISC-V(BM9K1) per-core 커버리지 모델 — v10.

퍼저를 import 하지 않는다(순환 회피: SJTAGPCSampler 는 메인 퍼저에 정의).
pylink 도 모듈 레벨에서 import 하지 않는다 → 하드웨어 없이 전부 단위테스트 가능.

입력(Ghidra 산출, 코어별):
  basic_blocks_core<X>.txt   `0xSTART 0xEND`      END = 마지막바이트+1 (exclusive)
  functions_core<X>.txt      `0xENTRY <십진size> <name>`
  callgraph_core<X>.txt      `0xCALLER 0xCALLEE`
  symbols.json               ELF 해시·exec 범위·개수(자가검증용)
"""
from __future__ import annotations

import bisect
import hashlib
import json
import os
import time
from collections import namedtuple

SCHEMA_VERSION = 1

# ── 코어 식별자 ────────────────────────────────────────────────────────
# ★ 한 번 정하면 못 바꾼다 — 저장된 커버리지 키·코퍼스가 이 번호에 묶인다.
#   PCSR 주소도 te_base + stride*id 라 **하드웨어 코어 순서와 일치해야** 한다.
CORE_IDS = {"H": 0, "CM": 1, "F": 2, "Q": 3}
CORE_NAMES = {v: k for k, v in CORE_IDS.items()}

# ── 커버리지 키 = (core, bank, addr) 패킹 ──────────────────────────────
#   bank 는 **코드 오버레이 대비 예약**. 지금은 항상 0.
#   나중에 키 구조를 바꾸면 저장된 커버리지·코퍼스가 전부 무효화되므로 지금 자리를 잡는다.
#   core=0,bank=0 이면 값이 기존 BB 주소와 동일 → 구 데이터와 비교 가능.
_ADDR_BITS, _BANK_BITS = 32, 12
_BANK_SHIFT, _CORE_SHIFT = _ADDR_BITS, _ADDR_BITS + _BANK_BITS
_ADDR_MASK, _BANK_MASK = (1 << _ADDR_BITS) - 1, (1 << _BANK_BITS) - 1


def pack(core: int, bank: int, addr: int) -> int:
    return (core << _CORE_SHIFT) | ((bank & _BANK_MASK) << _BANK_SHIFT) | (addr & _ADDR_MASK)


def unpack(key: int):
    return (key >> _CORE_SHIFT, (key >> _BANK_SHIFT) & _BANK_MASK, key & _ADDR_MASK)


# ── 관측 단위 ──────────────────────────────────────────────────────────
#   버스트는 한 번에 한 코어만 읽으므로, 기존 worker 처럼 '튜플 위치=코어'로
#   유추할 수 없다. 코어를 명시적으로 들고 다닌다.
#     valid : PCSR bit0. False = 그 코어가 잠깐 halt/wfi (링크 장애 아님)
#     fresh : 직전 값의 반복이 아닌가 (last-retired 계열이라 stall 시 같은 PC 가 반복됨)
Observation = namedtuple("Observation", "core_id pc fresh valid")

AccountResult = namedtuple(
    "AccountResult", "interesting new_count seed_keys new_by_core considered dropped")


class CoreMap:
    """한 코어의 BB/함수/콜그래프 조회 구조(bisect)."""

    def __init__(self, core_id, name=""):
        self.core_id, self.name = core_id, name
        self.bb_starts, self.bb_ends = [], []
        self.fn_entries, self.fn_ends, self.fn_names = [], [], []
        self.callees = {}          # caller_entry -> set(callee_entry)
        self.elf_sha256 = ""

    # ── 조회 ──
    def bb_of(self, pc):
        i = bisect.bisect_right(self.bb_starts, pc) - 1
        if i >= 0 and pc < self.bb_ends[i]:
            return self.bb_starts[i]
        return None

    def func_of(self, pc):
        i = bisect.bisect_right(self.fn_entries, pc) - 1
        if i >= 0 and pc < self.fn_ends[i]:
            return self.fn_entries[i]
        return None

    def func_name(self, entry):
        i = bisect.bisect_left(self.fn_entries, entry)
        if i < len(self.fn_entries) and self.fn_entries[i] == entry:
            return self.fn_names[i]
        return None

    @property
    def total_bbs(self):
        return len(self.bb_starts)

    @property
    def total_funcs(self):
        return len(self.fn_entries)


def _read_bb(path):
    starts, ends = [], []
    with open(path) as f:
        for line in f:
            p = line.split()
            if len(p) < 2:
                continue
            try:
                s, e = int(p[0], 16), int(p[1], 16)
            except ValueError:
                continue
            if e > s:                      # END 는 exclusive → 반드시 s < e
                starts.append(s)
                ends.append(e)
    pairs = sorted(zip(starts, ends))
    return [p[0] for p in pairs], [p[1] for p in pairs]


def _read_funcs(path):
    rows = []
    with open(path) as f:
        for line in f:
            p = line.split(None, 2)        # name 은 공백 포함 가능 → 마지막까지
            if len(p) < 2:
                continue
            try:
                entry, size = int(p[0], 16), int(p[1])
            except ValueError:
                continue
            if size <= 0:
                continue
            rows.append((entry, entry + size, p[2].strip() if len(p) > 2
                         else "FUN_%08x" % entry))
    rows.sort()
    return ([r[0] for r in rows], [r[1] for r in rows], [r[2] for r in rows])


def _read_callgraph(path):
    edges = {}
    with open(path) as f:
        for line in f:
            p = line.split()
            if len(p) < 2:
                continue
            try:
                a, b = int(p[0], 16), int(p[1], 16)
            except ValueError:
                continue
            edges.setdefault(a, set()).add(b)
    return edges


class CoverageModel:
    """per-core 커버리지 집계 — 판정의 단일 진입점.

    커버리지 키는 pack(core, bank, addr). `(core,bank,bb)` 이므로 같은 주소를 두 코어가
    실행하면 **서로 다른 커버리지**가 된다(코어별 ELF 라 주소가 겹칠 수 있다)."""

    def __init__(self):
        self.cores: dict[int, CoreMap] = {}
        self.covered_bbs: set[int] = set()          # packed key
        self.entered_funcs: set[int] = set()        # packed key(함수 entry)
        self.loaded = False
        self.product = ""
        self.warnings: list[str] = []

    # ── 로드 ──────────────────────────────────────────────────────────
    @classmethod
    def load(cls, product_dir, product="", core_ids=None):
        """products/<제품>/ 에서 코어별 표를 읽는다. symbols.json 이 있으면 검증도 한다."""
        m = cls()
        m.product = product
        ids = core_ids or CORE_IDS
        sym = {}
        sp = os.path.join(product_dir, "symbols.json")
        if os.path.exists(sp):
            with open(sp) as f:
                sym = json.load(f)
            conv = sym.get("bb_end_convention")
            if conv and conv != "exclusive":
                raise ValueError(
                    f"basic_blocks END 규약이 'exclusive' 가 아니다: {conv!r} — "
                    "판정식이 `pc < end` 라 규약이 다르면 커버리지가 조용히 틀어진다")
        for name, cid in ids.items():
            bb = os.path.join(product_dir, f"basic_blocks_core{name}.txt")
            fn = os.path.join(product_dir, f"functions_core{name}.txt")
            cg = os.path.join(product_dir, f"callgraph_core{name}.txt")
            if not os.path.exists(bb) and not os.path.exists(fn):
                continue
            cm = CoreMap(cid, name)
            if os.path.exists(bb):
                cm.bb_starts, cm.bb_ends = _read_bb(bb)
            if os.path.exists(fn):
                cm.fn_entries, cm.fn_ends, cm.fn_names = _read_funcs(fn)
            if os.path.exists(cg):
                cm.callees = _read_callgraph(cg)
            info = (sym.get("cores") or {}).get(name, {})
            cm.elf_sha256 = info.get("elf_sha256", "")
            m._verify_counts(cm, info)
            m.cores[cid] = cm
        m.loaded = bool(m.cores)
        return m

    def _verify_counts(self, cm, info):
        """symbols.json 의 개수와 실제 로드량 대조 — 파일이 잘렸거나 짝이 안 맞으면 경고."""
        c = info.get("counts") or {}
        # 생산 쪽 오타('funtions') 관용 — 나중에 고쳐도 안 깨지게 양쪽 다 본다
        want_fn = c.get("functions", c.get("funtions"))
        for label, want, got in (("basic_blocks", c.get("basic_blocks"), cm.total_bbs),
                                 ("functions", want_fn, cm.total_funcs)):
            if want is not None and want != got:
                self.warnings.append(
                    f"core{cm.name}: {label} 개수 불일치 symbols.json={want} 실제={got}")

    # ── 판정 ──────────────────────────────────────────────────────────
    def account(self, observations, credit_cores=None) -> AccountResult:
        """관측 → 커버리지 반영 + interesting 판정. 판정의 단일 진입점.

        credit_cores 가 주어지면 그 코어의 신규만 interesting 을 세운다(저duty 코어의
        샘플링 운으로 생기는 노이즈를 배제하고 싶을 때)."""
        cur, considered, dropped = set(), 0, 0
        for ob in observations:
            if not ob.valid or ob.pc is None:
                dropped += 1
                continue
            if not ob.fresh:                 # stale = 직전 값 반복 → 판정에서 제외
                dropped += 1
                continue
            cm = self.cores.get(ob.core_id)
            if cm is None:
                dropped += 1
                continue
            considered += 1
            bb = cm.bb_of(ob.pc)
            if bb is None:
                continue                     # 표에 없는 PC (매핑 실패)
            cur.add(pack(ob.core_id, 0, bb))
            fe = cm.func_of(ob.pc)
            if fe is not None:
                self.entered_funcs.add(pack(ob.core_id, 0, fe))
        new = cur - self.covered_bbs
        self.covered_bbs |= cur
        by_core = {}
        for k in new:
            by_core[unpack(k)[0]] = by_core.get(unpack(k)[0], 0) + 1
        if credit_cores is None:
            interesting = bool(new)
        else:
            interesting = any(c in credit_cores for c in by_core)
        return AccountResult(interesting, len(new), cur, by_core, considered, dropped)

    def update(self, observations):
        """판정 없이 커버리지만 반영(idle/boot/prefill 용)."""
        self.account(observations)

    # ── 통계 / 리포트 ──────────────────────────────────────────────────
    def stats_by_core(self):
        out = {}
        for cid, cm in self.cores.items():
            cb = sum(1 for k in self.covered_bbs if unpack(k)[0] == cid)
            cf = sum(1 for k in self.entered_funcs if unpack(k)[0] == cid)
            out[cid] = {
                "name": cm.name,
                "bb": cb, "bb_total": cm.total_bbs,
                "bb_pct": 100.0 * cb / cm.total_bbs if cm.total_bbs else 0.0,
                "func": cf, "func_total": cm.total_funcs,
                "func_pct": 100.0 * cf / cm.total_funcs if cm.total_funcs else 0.0,
            }
        return out

    def uncovered_functions(self, core_id, limit=None):
        """미도달 함수 (name, size, entry), 큰 것부터."""
        cm = self.cores.get(core_id)
        if cm is None:
            return []
        out = []
        for i, e in enumerate(cm.fn_entries):
            if pack(core_id, 0, e) not in self.entered_funcs:
                out.append((cm.fn_names[i], cm.fn_ends[i] - e, e))
        out.sort(key=lambda t: -t[1])
        return out[:limit] if limit else out

    def frontier_functions(self, core_id, limit=None):
        """★ 도달한 함수가 **직접 호출하는데** 아직 안 간 함수 — 호출자 수 많은 순.
        '가장 큰 미도달'보다 실행 가능하다: 퍼저가 이미 있는 지점에서 한 걸음 거리."""
        cm = self.cores.get(core_id)
        if cm is None or not cm.callees:
            return []
        hit = {unpack(k)[2] for k in self.entered_funcs if unpack(k)[0] == core_id}
        cnt = {}
        for caller in hit:
            for callee in cm.callees.get(caller, ()):
                if pack(core_id, 0, callee) in self.entered_funcs:
                    continue
                cnt[callee] = cnt.get(callee, 0) + 1
        rows = [(cm.func_name(e) or "FUN_%08x" % e, n, e)
                for e, n in cnt.items() if cm.func_name(e)]
        rows.sort(key=lambda t: -t[1])
        return rows[:limit] if limit else rows

    # ── 저장 / 재개 ────────────────────────────────────────────────────
    def save_v2(self, path):
        """resume 의 authoritative source. ELF 해시를 같이 적어 stale 을 검출한다."""
        hdr = {"schema_version": SCHEMA_VERSION, "product": self.product,
               "saved": time.strftime("%Y-%m-%dT%H:%M:%S"),
               "cores": {cm.name: {"id": cid, "elf_sha256": cm.elf_sha256}
                         for cid, cm in self.cores.items()}}
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            f.write(json.dumps({"header": hdr}) + "\n")
            for k in sorted(self.covered_bbs):
                c, b, a = unpack(k)
                f.write(json.dumps({"c": c, "b": b, "a": a}) + "\n")
        os.replace(tmp, path)

    def load_v2(self, path, strict=True):
        """→ (ok, reason). ELF 해시가 다르면 **거부**한다 — 펌웨어가 바뀐 커버리지를
        이어붙이면 조용히 틀린 결과가 누적된다."""
        with open(path) as f:
            lines = f.read().splitlines()
        if not lines:
            return False, "빈 파일"
        hdr = json.loads(lines[0]).get("header", {})
        if hdr.get("schema_version") != SCHEMA_VERSION:
            return False, f"schema_version 불일치 ({hdr.get('schema_version')})"
        for name, info in (hdr.get("cores") or {}).items():
            cid = info.get("id")
            cm = self.cores.get(cid)
            if cm is None:
                continue
            old, new = info.get("elf_sha256", ""), cm.elf_sha256
            if strict and old and new and old != new:
                return False, f"core{name} ELF 해시 불일치 — 펌웨어가 바뀌었다(stale)"
        n = 0
        for ln in lines[1:]:
            if not ln.strip():
                continue
            d = json.loads(ln)
            self.covered_bbs.add(pack(d["c"], d["b"], d["a"]))
            n += 1
        return True, f"{n}개 복원"

    # ── 스냅샷 (차트 서브프로세스용 — plain dict/list/set 만) ───────────
    def snapshot(self):
        return {
            "schema_version": SCHEMA_VERSION, "product": self.product,
            "covered_bbs": set(self.covered_bbs),
            "entered_funcs": set(self.entered_funcs),
            "cores": {cid: {"name": cm.name, "bb_starts": list(cm.bb_starts),
                            "bb_ends": list(cm.bb_ends),
                            "fn_entries": list(cm.fn_entries),
                            "fn_ends": list(cm.fn_ends),
                            "fn_names": list(cm.fn_names)}
                      for cid, cm in self.cores.items()},
        }

    @classmethod
    def from_snapshot(cls, d):
        m = cls()
        m.product = d.get("product", "")
        m.covered_bbs = set(d.get("covered_bbs") or ())
        m.entered_funcs = set(d.get("entered_funcs") or ())
        for cid, c in (d.get("cores") or {}).items():
            cid = int(cid)
            cm = CoreMap(cid, c.get("name", ""))
            cm.bb_starts, cm.bb_ends = list(c["bb_starts"]), list(c["bb_ends"])
            cm.fn_entries = list(c["fn_entries"])
            cm.fn_ends, cm.fn_names = list(c["fn_ends"]), list(c["fn_names"])
            m.cores[cid] = cm
        m.loaded = bool(m.cores)
        return m

    # ── v9.8 호환 뷰 (기존 차트 6종이 그대로 동작하도록) ────────────────
    @property
    def bb_starts(self):
        """전 코어 BB 시작 주소 합집합(정렬). 코어 구분이 없으므로 **집계용일 뿐**
        판정에는 쓰지 않는다 — 판정은 반드시 packed key 로."""
        return sorted({a for cm in self.cores.values() for a in cm.bb_starts})

    @property
    def total_bbs(self):
        return sum(cm.total_bbs for cm in self.cores.values())

    @property
    def total_funcs(self):
        return sum(cm.total_funcs for cm in self.cores.values())


def sha256_of(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest()
