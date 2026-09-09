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
import functools
import hashlib
import json
import os
import random
import shlex
import threading
import time
from collections import namedtuple

SCHEMA_VERSION = 1

# ★ bank 0 은 **비오버레이 본체** 전용이다. 오버레이 N 번은 내부적으로 bank N+1.
#   둘을 같은 0 으로 두면 본체 함수가 오버레이 0 번에서 밟은 커버리지를 자기 것으로
#   센다(실측으로 확인). 파일명(_ovl<N>)과 프로브 표는 **오버레이 순번 N** 을
#   그대로 쓰고, 이 오프셋은 로더에서 한 번만 적용한다.
BANK_BASE = 0            # 비오버레이
OVL_BANK_OFFSET = 1      # 오버레이 순번 → 내부 bank

# 헤더 규약 — 펌웨어가 각 오버레이 앞머리에 심어둔 표식.
#   F/H 코어 실측: base+4 의 워드가 0x4F564C(='OVL') << 8 | 오버레이순번.
#   이 규약이 성립하면 **빌드의 레이아웃 맵만으로** 런타임 판별이 된다
#   (별도 판별표 파일 불필요). 규약이 깨지면 런타임 매직 검사가 즉시
#   불일치를 내고 그 샘플을 버리므로 조용히 틀리지는 않는다.
OVL_HDR_OFFSET = 4
OVL_HDR_MAGIC = 0x4F564C00
OVL_HDR_MASK = 0xFFFFFF00
OVL_HDR_ID_MASK = 0x000000FF


def overlay_layout_candidates(name):
    """코어 <name> 의 빌드 레이아웃 맵 후보 파일명(우선순위 순).

    ★ 코어 문자로 글롭하면 안 된다 — "FW_HCore_overlay_map.json" 에는 FW 의 F 가
    들어 있어 F코어 파일로 오인된다. 명시적 후보만 쓴다.
    """
    return [
        f"overlay_core{name}.json",              # 이 저장소 규약
        f"overlay_map_core{name}.json",          # 구 이름(호환)
        f"FW_{name}Core_overlay_map.json",       # 빌드 산출물 규약
        f"{name}Core_overlay_map.json",
        f"FW_{name}Core.overlay_map.json",
    ]


def overlay_from_layout(doc, offset=OVL_HDR_OFFSET, magic=OVL_HDR_MAGIC,
                        mask=OVL_HDR_MASK, id_mask=OVL_HDR_ID_MASK):
    """빌드 레이아웃 맵(.OVL_REGION_NN: section_index/addr/size) → 런타임 판별 설정.

    레이아웃 맵은 이미 빌드가 내주고 Ghidra 추출에도 쓰이므로, 규약을 아는 이상
    판별표를 따로 생성할 이유가 없다. 순번은 section_index 오름차순이며,
    헤더 ID 가 곧 순번이라는 규약을 쓴다(실측: F 0~3, H 0~34).
    """
    rows = []
    for name, v in (doc or {}).items():
        if not str(name).upper().startswith(".OVL"):
            return None                    # 레이아웃 맵 스키마가 아니다
        try:
            rows.append((int(v["section_index"]), int(v["addr"]), int(v["size"])))
        except (KeyError, TypeError, ValueError):
            return None
    if not rows:
        return None
    rows.sort()
    base = rows[0][1]
    if len({r[1] for r in rows}) != 1:
        return None                        # 주소가 제각각 = 진짜 오버레이가 아니다
    return {
        "base": base,
        "window_end": base + max(r[2] for r in rows),
        "probe_offsets": [offset],
        "magic": magic, "magic_mask": mask, "id_mask": id_mask,
        "bank_sizes": {n + OVL_BANK_OFFSET: r[2] for n, r in enumerate(rows)},
        "probe_to_bank": {(magic | n): n + OVL_BANK_OFFSET
                          for n in range(len(rows))},
        "source": "layout",
    }

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
Observation = namedtuple("Observation", "core_id pc fresh valid bank")
Observation.__new__.__defaults__ = (0,)      # bank 기본 0 = 오버레이 아님/미확정

AccountResult = namedtuple(
    "AccountResult", "interesting new_count seed_keys new_by_core considered dropped")
ProjectionResult = namedtuple(
    "ProjectionResult", "seed_keys func_keys considered dropped")


class CoreMap:
    """한 코어의 BB/함수/콜그래프 조회 구조(bisect)."""

    def __init__(self, core_id, name=""):
        self.core_id, self.name = core_id, name
        self.bb_starts, self.bb_ends = [], []
        self.fn_entries, self.fn_ends, self.fn_names = [], [], []
        self.callees = {}          # caller_entry -> set(callee_entry)
        self.elf_sha256 = ""
        # ── 코드 오버레이 ──
        #   같은 주소에 여러 코드가 번갈아 올라온다(F코어: 0xAE000 에 4개).
        #   overlay: {"base","window_end","probe_offsets","magic","magic_mask","id_mask"}
        #   banks:   {bank: CoreMap 유사 테이블} — 오버레이별 BB/함수.
        self.overlay = None
        self.banks = {}

    # ── 오버레이 ──
    def in_overlay(self, pc):
        o = self.overlay
        return bool(o) and o["base"] <= pc < o["window_end"]

    def overlay_probe_addr(self):
        """런타임에 읽을 주소. 오버레이가 없거나 프로브를 못 찾았으면 None."""
        o = self.overlay
        if not o or not o.get("probe_offsets"):
            return None
        return o["base"] + o["probe_offsets"][0]

    def resolve_bank(self, word):
        """프로브 워드 → bank. 해석 불가면 None(그 버스트는 못 믿는다).

        매직 불일치는 오버레이 미탑재 / 복사 중 / 읽기 실패 중 하나다. 어느 쪽이든
        지금 그 자리에 뭐가 있는지 모른다는 뜻이라 bank 를 찍으면 안 된다.
        """
        o = self.overlay
        if not o or word is None:
            return None
        mm, mg = o.get("magic_mask"), o.get("magic")
        if mm and mg is not None and (word & mm) != mg:
            return None
        return (o.get("probe_to_bank") or {}).get(word)

    def effective_bank(self, pc, bank):
        """키에 쓸 bank. ★ 부풀림 방지 —

        bank 별 BB 테이블이 아직 없는데 bank 를 그대로 키에 넣으면, **같은 BB** 가
        bank 0..3 으로 각각 세어져 covered_bbs 가 최대 4배가 되고 total_bbs 는
        그대로라 커버리지가 100% 를 넘는다. 테이블이 있는 bank 에만 bank 를 쓰고,
        없으면 0 으로 접는다(정보는 잃지만 숫자는 정직하다).
        """
        if not bank or not self.in_overlay(pc):
            return 0
        return bank if bank in self.banks else 0

    def _tbl(self, bank):
        return self.banks.get(bank) if bank else None

    # ── 조회 ──
    def bb_of(self, pc, bank=0):
        t = self._tbl(bank)
        starts, ends = (t["bb_starts"], t["bb_ends"]) if t else (self.bb_starts, self.bb_ends)
        i = bisect.bisect_right(starts, pc) - 1
        if i >= 0 and pc < ends[i]:
            return starts[i]
        return None

    def func_of(self, pc, bank=0):
        t = self._tbl(bank)
        ent, ends = (t["fn_entries"], t["fn_ends"]) if t else (self.fn_entries, self.fn_ends)
        i = bisect.bisect_right(ent, pc) - 1
        if i >= 0 and pc < ends[i]:
            return ent[i]
        return None

    def func_name(self, entry, bank=0):
        """★ bank 를 받아야 한다 — 오버레이는 같은 주소에 다른 함수가 온다.
        bank 를 무시하면 오버레이 함수 이름이 전부 본체 이름으로 나온다."""
        t = self._tbl(bank)
        ent, nms = (t["fn_entries"], t["fn_names"]) if t else (self.fn_entries,
                                                               self.fn_names)
        i = bisect.bisect_left(ent, entry)
        if i < len(ent) and ent[i] == entry:
            return nms[i]
        return None

    def iter_tables(self):
        """(bank, fn_entries, fn_ends, fn_names, bb_starts) — 본체 + 오버레이 전부.
        리포트가 오버레이 함수를 빠뜨리지 않게 한 곳에서 순회한다."""
        yield (0, self.fn_entries, self.fn_ends, self.fn_names, self.bb_starts)
        for b in sorted(self.banks):
            t = self.banks[b]
            yield (b, t["fn_entries"], t["fn_ends"], t["fn_names"], t["bb_starts"])

    @property
    def total_bbs(self):
        # ★ bank 표를 더한다. 안 더하면 covered 에는 bank!=0 키가 들어가는데
        #   분모는 본체뿐이라 커버리지가 100% 를 넘는다(실측 300%).
        return len(self.bb_starts) + sum(len(t["bb_starts"])
                                         for t in self.banks.values())

    @property
    def total_funcs(self):
        return len(self.fn_entries) + sum(len(t["fn_entries"])
                                          for t in self.banks.values())


def _read_bb(path, dropped=None):
    """`0xSTART 0xEND` → (starts, ends). END 는 exclusive.

    dropped 리스트를 주면 **버린 줄의 이유**를 담아준다. 개수 불일치를 볼 때
    "표가 잘렸나 / 형식이 다른가 / 계약이 어긋났나" 를 가르는 유일한 근거다.
    """
    starts, ends = [], []
    n_short = n_parse = n_range = 0
    with open(path) as f:
        for line in f:
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            p = line.split()
            if len(p) < 2:
                n_short += 1
                continue
            try:
                s, e = int(p[0], 16), int(p[1], 16)
            except ValueError:
                n_parse += 1
                continue
            if e > s:                      # END 는 exclusive → 반드시 s < e
                starts.append(s)
                ends.append(e)
            else:
                n_range += 1               # END <= START — 빈 BB 는 조회 불가
    if dropped is not None and (n_short or n_parse or n_range):
        dropped.append((os.path.basename(path), n_short, n_parse, n_range))
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
        self.notes: list[str] = []       # 경고 아닌 정보성(예: 오버레이 counts 규약 차이)

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
            _drop = []
            cm = CoreMap(cid, name)
            if os.path.exists(bb):
                cm.bb_starts, cm.bb_ends = _read_bb(bb, _drop)
            if os.path.exists(fn):
                cm.fn_entries, cm.fn_ends, cm.fn_names = _read_funcs(fn)
            if os.path.exists(cg):
                cm.callees = _read_callgraph(cg)
            # ── 코드 오버레이(있는 코어만) ──
            #   ★ 두 파일을 혼동하지 말 것:
            #     · 빌드의 **레이아웃 맵**(.OVL_REGION_NN: section_index/addr/size)은
            #       "어디에 몇 개" 를 말할 뿐 런타임 판별에 못 쓴다.
            #     · 여기서 읽는 overlay_probe_core<X>.json 은 **판별표**다
            #       (워드값 → bank). ELF 오버레이 섹션의 실제 바이트를 봐야 나오므로
            #       ELF 오버레이 섹션의 바이트를 읽어야 나오므로 정적 추출로는
            #       안 나온다. 지금은 아래 ②(레이아웃 맵 + 헤더 규약)로 충분하다.
            #   bank 별 BB/함수 표는 basic_blocks_core<X>_ovl<N>.txt 규약.
            # ── 오버레이 판별 설정 ──
            #   ① overlay_core<X>.json = **빌드 레이아웃 맵**(.OVL_REGION_NN).
            #      헤더 규약(OVL 매직 + 순번)이 성립하면 이것만으로 충분하다.
            #   ② overlay_probe_core<X>.json = 실측 판별표(수동 작성). 규약이 안 맞는 펌웨어용
            #      탈출구이며, 있으면 ① 보다 우선한다(측정값이 가정을 이긴다).
            cm.overlay = None
            probe_p = os.path.join(product_dir, f"overlay_probe_core{name}.json")
            layout_p = None
            for _cand in overlay_layout_candidates(name):
                _p = os.path.join(product_dir, _cand)
                if os.path.exists(_p):
                    layout_p = _p
                    break
            if os.path.exists(probe_p):
                with open(probe_p, encoding="utf-8") as f:
                    o = json.load(f)
                hdr = o.get("header") or {}
                cm.overlay = {
                    "base": int(o["base"]), "window_end": int(o["window_end"]),
                    "probe_offsets": list(o.get("probe_offsets") or []),
                    "magic": int(hdr.get("magic", "0"), 0) if hdr else None,
                    "magic_mask": int(hdr.get("magic_mask", "0"), 0) if hdr else None,
                    "id_mask": int(hdr.get("id_mask", "0"), 0) if hdr else None,
                    "bank_sizes": {int(k) + OVL_BANK_OFFSET: int(v)
                                   for k, v in (o.get("bank_sizes") or {}).items()},
                    "probe_to_bank": {int(k, 0): int(v) + OVL_BANK_OFFSET
                                      for k, v in (o.get("probe_to_bank") or {}).items()},
                    "source": "probe",
                }
            elif layout_p:
                with open(layout_p, encoding="utf-8") as f:
                    cm.overlay = overlay_from_layout(json.load(f))
                if cm.overlay is None:
                    m.warnings.append(
                        f"core{name}: {os.path.basename(layout_p)} 이 레이아웃 맵"
                        f" 스키마가 아니다(.OVL_REGION_NN: section_index/addr/size 필요)")
                else:
                    cm.overlay["layout_file"] = os.path.basename(layout_p)
            else:
                import glob as _glob
                _orph = _glob.glob(os.path.join(
                    product_dir, f"basic_blocks_core{name}_ovl*.txt"))
                if _orph:
                    # 비슷한 이름이 있으면 같이 알려준다 — 이름만 다른 경우가 많다.
                    _near = sorted(os.path.basename(x) for x in
                                   _glob.glob(os.path.join(product_dir, "*overlay*")) +
                                   _glob.glob(os.path.join(product_dir, "*ovl*.json")))
                    m.warnings.append(
                        f"core{name}: 오버레이 표 {len(_orph)}개가 있는데 레이아웃 맵을"
                        f" 못 찾아 **무시**한다. 찾는 이름: "
                        f"{overlay_layout_candidates(name)[:3]}"
                        + (f" | 디렉토리에 있는 비슷한 파일: {_near[:6]}" if _near else ""))
            if cm.overlay:
                for bank in sorted(cm.overlay["bank_sizes"]):
                    _n = bank - OVL_BANK_OFFSET        # 파일명은 오버레이 순번
                    bb_b = os.path.join(product_dir,
                                        f"basic_blocks_core{name}_ovl{_n}.txt")
                    fn_b = os.path.join(product_dir,
                                        f"functions_core{name}_ovl{_n}.txt")
                    if not os.path.exists(bb_b):
                        continue          # 표 없으면 effective_bank 가 0 으로 접는다
                    bs, be = _read_bb(bb_b, _drop)
                    if not bs:
                        # 0바이트/파싱불가 표를 등록하면 그 오버레이 샘플이 bank N 으로
                        # 태깅된 뒤 BB 를 못 찾아 **조용히 버려진다**. 등록하지 않고
                        # bank 0 으로 접어 최소한 관측이 사라지지는 않게 한다.
                        m.warnings.append(
                            f"core{name}: {os.path.basename(bb_b)} 가 비었다 — "
                            f"bank {_n} 을 등록하지 않는다(추출 실패 가능성)")
                        continue
                    fe, fen, fnm = ([], [], [])
                    if os.path.exists(fn_b):
                        fe, fen, fnm = _read_funcs(fn_b)
                    cm.banks[bank] = {"bb_starts": bs, "bb_ends": be,
                                      "fn_entries": fe, "fn_ends": fen,
                                      "fn_names": fnm}
            info = (sym.get("cores") or {}).get(name, {})
            cm.elf_sha256 = info.get("elf_sha256", "")
            for _fn, _short, _parse, _rng in _drop:
                # 개수가 안 맞을 때 "왜 줄었나" 를 가르는 유일한 근거.
                m.warnings.append(
                    f"core{name}: {_fn} 에서 버린 줄 — "
                    f"토큰부족 {_short} / 16진아님 {_parse} / END<=START {_rng}")
            m._verify_counts(cm, info)
            m.cores[cid] = cm
        m.loaded = bool(m.cores)
        return m

    def _verify_counts(self, cm, info):
        """symbols.json 의 개수와 실제 로드량 대조 — 파일이 잘렸거나 짝이 안 맞는 것을 잡는다.

        ★ counts 는 **본체(비오버레이) 표 기준**이다. 오버레이는 파일이 따로이므로
        추출기가 자연히 세는 단위도 그쪽이다. 총계와 비교하면 오버레이가 있는 코어
        마다 매번 헛경고가 나고, 그러면 사람들이 경고를 무시하게 된다.
        오버레이 개수를 검증하려면 counts.overlay_{basic_blocks,functions} 를 쓴다.
        """
        c = info.get("counts") or {}
        # ★ 추출기가 counts 를 '본체만' 으로 쓰는지 '오버레이 합산 총계' 로 쓰는지
        #   규약이 갈린다. 어느 쪽이든 맞으면 통과시킨다 — 헛경고가 나면 사람이
        #   경고 자체를 무시하게 되어 이 검사의 목적(잘림 탐지)이 사라진다.
        _bb_base, _fn_base = len(cm.bb_starts), len(cm.fn_entries)
        _bb_all = _bb_base + sum(len(t["bb_starts"]) for t in cm.banks.values())
        _fn_all = _fn_base + sum(len(t["fn_entries"]) for t in cm.banks.values())
        for label, want, base_v, all_v in (
                ("basic_blocks", c.get("basic_blocks"), _bb_base, _bb_all),
                ("functions", c.get("functions"), _fn_base, _fn_all)):
            if want is None or want in (base_v, all_v):
                continue
            if cm.banks or cm.overlay:
                # 오버레이가 있는 코어는 symbols.json counts 가 '본체 기준' 인지 '총계 기준'
                # 인지 추출기 규약이 갈린다. 차이가 오버레이에서 오는 것이므로 **잘림이 아니다**
                # — '불일치' 경고가 아니라 정보성 note 로만 남긴다. (실제 파일 잘림은 위 '버린 줄'
                # 경고가, 오버레이 개수는 overlay_* counts 가 따로 검증한다.)
                self.notes.append(
                    f"core{cm.name}: {label} symbols.json={want} vs 본체={base_v}"
                    + (f"(+오버레이 합산={all_v})" if all_v != base_v else "")
                    + " — 오버레이 포함/제외 counts 규약 차이(정상, 잘림 아님)")
            else:
                self.warnings.append(
                    f"core{cm.name}: {label} 개수 불일치 symbols.json={want} "
                    f"실제={base_v} — 표가 잘렸거나 ELF 와 짝이 안 맞는다")
        checks = []
        if cm.banks:
            checks += [
                ("overlay_basic_blocks", c.get("overlay_basic_blocks"),
                 sum(len(t["bb_starts"]) for t in cm.banks.values())),
                ("overlay_functions", c.get("overlay_functions"),
                 sum(len(t["fn_entries"]) for t in cm.banks.values())),
                ("overlay_banks", c.get("overlay_banks"), len(cm.banks)),
            ]
        for label, want, got in checks:
            if want is not None and want != got:
                self.warnings.append(
                    f"core{cm.name}: {label} 개수 불일치 symbols.json={want} 실제={got}")

    # ── 판정 ──────────────────────────────────────────────────────────
    def project(self, observations) -> ProjectionResult:
        """관측을 packed BB/함수 키로 변환하되 전역 커버리지는 변경하지 않는다.

        calibration 처럼 여러 실행의 출현 빈도를 계산한 뒤 한 번만 account 해야 하는
        경로에서 사용한다. raw PC 로 되돌아가면 코어가 사라지고 PC 수와 BB 수가 섞인다.
        """
        cur, funcs, considered, dropped = set(), set(), 0, 0
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
            # 오버레이 창 안이면 관측된 bank 로 조회한다. bank 별 테이블이 없으면
            # effective_bank 가 0 으로 접어 부풀림을 막는다(§오버레이).
            bank = cm.effective_bank(ob.pc, ob.bank)
            bb = cm.bb_of(ob.pc, bank)
            if bb is None:
                continue                     # 표에 없는 PC (매핑 실패)
            cur.add(pack(ob.core_id, bank, bb))
            fe = cm.func_of(ob.pc, bank)
            if fe is not None:
                funcs.add(pack(ob.core_id, bank, fe))
        return ProjectionResult(cur, funcs, considered, dropped)

    def account(self, observations, credit_cores=None) -> AccountResult:
        """관측 → 커버리지 반영 + interesting 판정. 판정의 단일 변경 진입점.

        credit_cores 가 주어지면 그 코어의 신규만 interesting 을 세운다(저duty 코어의
        샘플링 운으로 생기는 노이즈를 배제하고 싶을 때)."""
        p = self.project(observations)
        cur, considered, dropped = p.seed_keys, p.considered, p.dropped
        self.entered_funcs |= p.func_keys
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
    def overlay_stats(self):
        """코어별 오버레이 진행 — {cid: {banks_seen, banks_total, bbs, bbs_total}}.

        주기 통계에 낼 용도. 오버레이는 35개가 한 주소를 공유해 전체 BB% 만 보면
        진행이 안 보인다(본체에 묻힌다). 한 번만 훑는다.
        """
        seen, cov = {}, {}
        for k in self.covered_bbs:
            cid = k >> _CORE_SHIFT
            bank = (k >> _BANK_SHIFT) & _BANK_MASK
            if bank:
                seen.setdefault(cid, set()).add(bank)
                cov[cid] = cov.get(cid, 0) + 1
        out = {}
        for cid, cm in self.cores.items():
            if not cm.banks:
                continue
            out[cid] = {
                "name": cm.name,
                "banks_seen": len(seen.get(cid, ())),
                "banks_total": len(cm.banks),
                "bbs": cov.get(cid, 0),
                "bbs_total": sum(len(t["bb_starts"]) for t in cm.banks.values()),
            }
        return out

    def stats_by_core(self):
        """코어별 집계. ★ 단일 패스 — 코어마다 전체를 훑으면 O(covered × cores) 라
        커버리지가 커질수록 눈에 띄게 느려진다(5만 커버 × 4코어 = 72ms)."""
        bb_by, fn_by = {}, {}
        for k in self.covered_bbs:
            c = k >> _CORE_SHIFT
            bb_by[c] = bb_by.get(c, 0) + 1
        for k in self.entered_funcs:
            c = k >> _CORE_SHIFT
            fn_by[c] = fn_by.get(c, 0) + 1
        out = {}
        for cid, cm in self.cores.items():
            cb, cf = bb_by.get(cid, 0), fn_by.get(cid, 0)
            out[cid] = {
                "name": cm.name,
                "bb": cb, "bb_total": cm.total_bbs,
                "bb_pct": 100.0 * cb / cm.total_bbs if cm.total_bbs else 0.0,
                "func": cf, "func_total": cm.total_funcs,
                "func_pct": 100.0 * cf / cm.total_funcs if cm.total_funcs else 0.0,
            }
        return out

    def uncovered_functions(self, core_id, limit=None):
        """미도달 함수 (name, size, entry), 큰 것부터.

        ★ 오버레이 표(bank>0)까지 순회한다. bank 0 만 보면 오버레이에 있는 코드가
        통째로 빠진다 — H 코어는 471KB 가 오버레이라 미도달 목록이 사실상 반쪽이
        된다. 오버레이는 **우리가 측정하는 방식의 구현 세부사항**이므로 호출자
        (LLM 프롬프트)에는 노출하지 않는다. 이름만 정확하면 된다.
        """
        cm = self.cores.get(core_id)
        if cm is None:
            return []
        out = []
        for bank, fn_entries, fn_ends, fn_names, _bb in cm.iter_tables():
            for i, e in enumerate(fn_entries):
                if pack(core_id, bank, e) not in self.entered_funcs:
                    out.append((fn_names[i], fn_ends[i] - e, e))
        out.sort(key=lambda t: -t[1])
        return out[:limit] if limit else out

    def flat_view(self, core_id=None):
        """한 코어를 기존 차트가 기대하는 _sa_* 모양으로 평탄화한다.

        firmware_map.png 는 _sa_func_entries/_sa_bb_starts 를 직접 읽는데 RISC-V 는
        그 필드가 비어 있어 **차트가 아예 생성되지 않았다**. matplotlib 코드를
        건드리지 않고 데이터만 채워 넣기 위한 어댑터.

        코어를 하나만 쓰는 이유: 코어마다 주소공간이 독립이라 합치면 주소축이
        뒤섞여 지도가 거짓말을 한다. bank 0(비오버레이 본체)만 쓰는 것도 같은
        이유다 — 오버레이는 같은 주소에 여러 코드가 겹쳐 한 축에 못 그린다.
        """
        if core_id is None:
            # 본체(비오버레이) 함수가 **있는** 코어 중에서 고른다. 코드가 가장 많은
            # 코어를 먼저 고르고 나서 비었다고 포기하면, 다른 코어로는 그릴 수
            # 있는데도 지도가 통째로 안 나온다.
            cand = [c for c, m in self.cores.items() if m.fn_entries]
            if not cand:
                return None
            core_id = max(cand, key=lambda c: self.cores[c].total_funcs)
        cm = self.cores.get(core_id)
        if cm is None or not cm.fn_entries:
            return None
        ent = {unpack(k)[2] for k in self.entered_funcs
               if unpack(k)[0] == core_id and unpack(k)[1] == 0}
        cov = {unpack(k)[2] for k in self.covered_bbs
               if unpack(k)[0] == core_id and unpack(k)[1] == 0}
        return {"core_id": core_id, "name": cm.name,
                "fn_entries": list(cm.fn_entries), "fn_ends": list(cm.fn_ends),
                "fn_names": list(cm.fn_names), "entered_funcs": ent,
                "bb_starts": list(cm.bb_starts), "covered_bbs": cov,
                "total_bbs": cm.total_bbs, "total_funcs": cm.total_funcs}

    def reach_ranked_uncovered(self, core_id, max_hops=3):
        """미도달 함수를 **도달한 코드로부터의 콜그래프 거리**로 순위 매긴다.

        이름 패턴(부팅/ISR/...)으로 거르던 방식을 대체한다. 실제 심볼은
        `ARES::IHAL_Fcore::Sync`, `ZEUS::IO::SVBlockConfig::GetIndex` 처럼 생겨서
        문자열 규칙이 통하지 않고, 제품마다 다르다. 반면 "지금 밟은 코드에서
        몇 번 호출을 건너야 닿나" 는 콜그래프로 계산되는 사실이다.

        반환: [(name, size, entry, hops)] — hops 오름차순, 같으면 큰 것 먼저.
              hops=1 이 frontier(직접 호출), None 이면 **도달 경로 없음**.
        ⚠ 콜그래프는 직접 호출만 담는다(함수 포인터 미포함). 그래서 hops=None 은
          '절대 못 감' 이 아니라 '알려진 경로가 없음' 이다 → 제외가 아니라 후순위.
        """
        cm = self.cores.get(core_id)
        if cm is None:
            return []
        reached = {unpack(k)[2] for k in self.entered_funcs if unpack(k)[0] == core_id}
        hops = {}
        frontier = reached
        for d in range(1, max_hops + 1):
            nxt = set()
            for caller in frontier:
                for callee in cm.callees.get(caller, ()):
                    if callee in reached or callee in hops:
                        continue
                    hops[callee] = d
                    nxt.add(callee)
            if not nxt:
                break
            frontier = nxt
        out = []
        for bank, fn_entries, fn_ends, fn_names, _bb in cm.iter_tables():
            for i, e in enumerate(fn_entries):
                if pack(core_id, bank, e) in self.entered_funcs:
                    continue
                out.append((fn_names[i], fn_ends[i] - e, e, hops.get(e)))
        # hops=None 은 맨 뒤로(경로 미상), 나머지는 가까운 것 먼저·큰 것 먼저
        out.sort(key=lambda t: (t[3] if t[3] is not None else 1 << 30, -t[1]))
        return out

    def frontier_functions(self, core_id, limit=None):
        """★ 도달한 함수가 **직접 호출하는데** 아직 안 간 함수 — 호출자 수 많은 순.
        '가장 큰 미도달'보다 실행 가능하다: 퍼저가 이미 있는 지점에서 한 걸음 거리."""
        cm = self.cores.get(core_id)
        if cm is None or not cm.callees:
            return []
        # 도달 판정은 bank 무관 — 어느 오버레이에서든 그 함수에 갔으면 갔다.
        hit = {unpack(k)[2] for k in self.entered_funcs if unpack(k)[0] == core_id}
        reached_addrs = hit
        cnt = {}
        for caller in hit:
            for callee in cm.callees.get(caller, ()):
                if callee in reached_addrs:
                    continue
                cnt[callee] = cnt.get(callee, 0) + 1
        rows = [(cm.func_name(e) or "FUN_%08x" % e, n, e)
                for e, n in cnt.items() if cm.func_name(e)]
        rows.sort(key=lambda t: -t[1])
        return rows[:limit] if limit else rows

    def function_rows(self):
        """리포트용 함수별 BB 커버리지 행.

        반환 행은 주소 정렬이며, ``frontier_callers`` 는 이미 도달한 직접 호출자 수다.
        전체 BB를 함수마다 다시 훑지 않고 코어별 정렬 목록에 bisect 한다.
        """
        covered_by_core = {}
        entered_by_core = {}
        # ★ (core, bank) 로 나눈다. bank 를 버리면 오버레이에서 밟은 BB 가 같은
        #   주소의 **본체 함수** 커버리지로 잘못 들어간다(실측: base 함수가
        #   오버레이 3개분을 자기 것으로 셌다).
        for key in self.covered_bbs:
            cid, bank, addr = unpack(key)
            covered_by_core.setdefault((cid, bank), []).append(addr)
        for key in self.entered_funcs:
            cid, bank, entry = unpack(key)
            entered_by_core.setdefault((cid, bank), set()).add(entry)
        for addrs in covered_by_core.values():
            addrs.sort()

        rows = []
        for cid, cm in sorted(self.cores.items()):
            for bank, fn_entries, fn_ends, fn_names, bb_starts in cm.iter_tables():
                covered = covered_by_core.get((cid, bank), [])
                entered = entered_by_core.get((cid, bank), set())
                frontier = {}
                if bank == 0:          # 콜그래프는 아직 본체만 있다(오버레이별 미제공)
                    for caller in entered:
                        for callee in cm.callees.get(caller, ()):
                            if callee not in entered:
                                frontier[callee] = frontier.get(callee, 0) + 1
                for i, entry in enumerate(fn_entries):
                    end = fn_ends[i]
                    bb_lo = bisect.bisect_left(bb_starts, entry)
                    bb_hi = bisect.bisect_left(bb_starts, end)
                    cov_lo = bisect.bisect_left(covered, entry)
                    cov_hi = bisect.bisect_left(covered, end)
                    total_bbs = bb_hi - bb_lo
                    covered_bbs = cov_hi - cov_lo
                    rows.append({
                        "core_id": cid,
                        "core": cm.name,
                        "bank": bank,
                        "name": fn_names[i],
                        "entry": entry,
                        "end": end,
                        "size": end - entry,
                        "entered": entry in entered,
                        "covered_bbs": covered_bbs,
                        "total_bbs": total_bbs,
                        "bb_pct": (100.0 * covered_bbs / total_bbs
                                   if total_bbs else 0.0),
                        "frontier_callers": frontier.get(entry, 0),
                    })
        return rows

    # ── 스냅샷 (차트 서브프로세스용 — resume 용도가 아님) ──────────────
    def snapshot(self):
        return {
            "schema_version": SCHEMA_VERSION, "product": self.product,
            "covered_bbs": set(self.covered_bbs),
            "entered_funcs": set(self.entered_funcs),
            "cores": {cid: {"name": cm.name, "bb_starts": list(cm.bb_starts),
                            "bb_ends": list(cm.bb_ends),
                            "fn_entries": list(cm.fn_entries),
                            "fn_ends": list(cm.fn_ends),
                            "fn_names": list(cm.fn_names),
                            "callees": {caller: set(callees)
                                        for caller, callees in cm.callees.items()}}
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
            cm.callees = {int(caller): set(callees)
                          for caller, callees in (c.get("callees") or {}).items()}
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


# ══════════════════════════════════════════════════════════════════════
#  버스트 스케줄 — 순서를 고정하지 않는다
# ══════════════════════════════════════════════════════════════════════
class AdaptiveWeights:
    """코어별 샘플 예산을 **최근** 수확률에 맞춰 재배분한다.

    누적 per1k 로는 적응이 안 된다 — 캠페인이 길어질수록 과거가 지배해서, 이미
    포화된 코어의 옛 성과가 계속 예산을 잡고 새로 열린 코어를 못 따라간다.
    그래서 지수감쇠 합(decayed sum)으로 최근 구간의 수확률만 본다.

        rate[c] = decayed_new[c] / decayed_samples[c]

    측정이 배분에 종속된다는 점도 감안한다. 적게 샘플링된 코어는 매 샘플이 새
    코드에 떨어져 rate 가 높게 나오고, 많이 본 코어는 포화돼 낮게 나온다.
    그대로 비례배분하면 매 주기 반대로 튄다 → **step 상한**으로 한 번에 움직일 수
    있는 폭을 묶고, **floor** 로 어떤 코어도 관측이 끊기지 않게 한다(끊기면 그
    코어가 다시 일을 시작해도 영영 모른다).

    총 예산(가중치 합)은 보존한다 — 샘플레이트는 하드웨어가 정하는 상수다.
    """

    def __init__(self, weights, decay=0.995, min_weight=1, max_step=2.0,
                 period=500, prior_samples=2000, exponent=2.0):
        self.weights = {int(c): max(int(min_weight), int(w))
                        for c, w in dict(weights).items()}
        self.total = sum(self.weights.values())
        self.decay = float(decay)
        self.min_weight = int(min_weight)
        self.max_step = float(max_step)
        self.period = int(period)
        # 표본이 적은 코어의 rate 는 노이즈다. 예전엔 min_samples 미만이면 판단에서
        # **제외**했는데, 가중치가 낮은 코어는 그 문턱을 영영 못 넘어 아무리 생산적
        # 이어도 예산을 못 받는 상태로 고정됐다(실측: CM 의 per1k 가 네 코어 중
        # 최고인 갱신에서도 1 에 묶임). → 제외 대신 **전체 평균 쪽으로 수축**한다.
        # 표본이 쌓이면 자기 실제 rate 로 수렴하고, 적으면 평균 대접을 받는다.
        self.prior_samples = float(prior_samples)
        # rate 에 그대로 비례배분하면 저수확 코어로 예산이 샌다. 실측 예: 전체
        # 발견의 7% 뿐인 두 코어가 rate 비례로는 예산의 28% 를 가져갔다. rate**e
        # 로 승자 쪽을 날카롭게 하되, floor 가 있어 관측은 끊기지 않는다.
        self.exponent = float(exponent)
        self.dnew = {c: 0.0 for c in self.weights}
        self.dsamp = {c: 0.0 for c in self.weights}
        self._last_update = 0
        self.updates = 0

    def observe(self, new_by_core, samples_by_core):
        """명령 1건의 결과를 반영. 두 dict 모두 {core_id: count}."""
        d = self.decay
        for c in self.weights:
            self.dnew[c] = self.dnew[c] * d + float((new_by_core or {}).get(c, 0))
            self.dsamp[c] = self.dsamp[c] * d + float((samples_by_core or {}).get(c, 0))

    def rates(self, raw=False):
        """1000 샘플당 신규 BB (감쇠 기준).

        raw=True 면 관측 그대로, 기본은 전체 평균으로 수축한 추정치를 준다.
        수축은 표본이 적은 코어를 배제하지 않으면서 노이즈로 예산이 튀는 것을 막는다.
        """
        if raw:
            return {c: (1000.0 * self.dnew[c] / self.dsamp[c]) if self.dsamp[c] > 0 else 0.0
                    for c in self.weights}
        tot_n = sum(self.dnew.values())
        tot_s = sum(self.dsamp.values())
        pooled = (tot_n / tot_s) if tot_s > 0 else 0.0
        m = self.prior_samples
        return {c: 1000.0 * (self.dnew[c] + m * pooled) / (self.dsamp[c] + m)
                for c in self.weights}

    def should_update(self, executions):
        return (executions - self._last_update) >= self.period

    def compute(self):
        """새 가중치를 계산해 반환. 바꿀 이유가 없으면 None."""
        r = self.rates()
        # ★ 전 코어를 판단한다. 표본 부족은 제외가 아니라 수축으로 다룬다 —
        #   제외하면 저가중치 코어가 문턱을 못 넘어 영원히 후보에서 빠진다.
        judged = [c for c in self.weights if self.dsamp[c] > 0]
        if not judged or sum(r[c] for c in judged) <= 0:
            return None

        pool = sum(self.weights[c] for c in judged)
        sharp = {c: r[c] ** self.exponent for c in judged}
        rsum = sum(sharp.values())
        if rsum <= 0:
            return None
        new = dict(self.weights)
        for c in judged:
            target = pool * sharp[c] / rsum
            lo = self.weights[c] / self.max_step
            hi = self.weights[c] * self.max_step
            new[c] = int(round(min(hi, max(lo, target))))
        for c in new:
            new[c] = max(self.min_weight, new[c])

        # 총 예산 보존 — 반올림/floor 로 어긋난 만큼을 가장 큰 코어에서 정산한다.
        drift = self.total - sum(new.values())
        if drift:
            big = max(new, key=lambda c: new[c])
            new[big] = max(self.min_weight, new[big] + drift)
        return new if new != self.weights else None

    def maybe_update(self, executions):
        """주기가 됐으면 갱신하고 새 가중치를 반환, 아니면 None."""
        if not self.should_update(executions):
            return None
        self._last_update = executions
        new = self.compute()
        if new is None:
            return None
        self.weights = new
        self.updates += 1
        return dict(new)


def build_burst_schedule(weights, rng=None, shuffle=True):
    """가중치를 '버스트 개수'로 펴고 **섞는다**. → [core_id, ...]

    왜 섞는가: 순서를 고정하면(항상 core0 이 윈도우 앞, core3 이 뒤) 명령 처리 단계
    (파싱→DMA→완료)와 코어가 결합돼 **각 코어가 특정 단계만 관측**하는 계통 편향이 생긴다.
    가중치(=관측량)와 순서(=편향)를 분리한다.
      weights: {core_id: 정수 가중치}   예 {0:3, 1:1, 2:1, 3:1}
    """
    seq = []
    for cid, w in sorted(weights.items()):
        seq.extend([cid] * max(0, int(w)))
    if shuffle and seq:
        (rng or random).shuffle(seq)
    return seq


RecoveryResult = namedtuple("RecoveryResult", "ok stage elapsed valid_samples detail")


def _handle_locked(fn):
    """J-Link 핸들 직렬화(플랜 §4 '핸들 독점 계약').

    같은 handle 에 대한 동시 접근은 예외가 아니라 **조용히 틀린 값**을 만든다
    (sba_read_pinned 가 SELECT/TAR 을 재확인하지 않으므로 다른 AP bank 의 DRW 를
    읽는다). 그래서 실패가 로그에 안 남고 커버리지 노이즈로만 보인다.
    """
    @functools.wraps(fn)
    def _w(self, *a, **kw):
        with self.lock:                 # RLock — recover() 가 pin/auth 를 재진입한다
            return fn(self, *a, **kw)
    return _w


class PcsrSession:
    """PCSR 폴링 전송 계층 — 인증·핀·버스트·붕괴복구를 **한 lock 안에** 묶는다.

    ★ 핸들 독점: sba_read_pinned() 는 SELECT/TAR 을 확인하지 않는다(pin 이 맞춰둔 상태를
      신뢰). 버스트 중 같은 J-Link handle 로 다른 DAP 접근이 한 번만 끼어들어도 다른 AP
      bank 의 DRW 를 읽는다. 그래서 샘플링/진단/인증probe/덤프/재연결/코어전환이 전부
      self.lock 을 거친다. (NVMe subprocess 동시 실행은 무관 — 동일 handle 접근이 문제)

    pylink·sjtag_unlock 은 **open() 안에서 지연 import** 한다 → 이 모듈은 하드웨어 없이
    import·테스트된다."""

    def __init__(self, cores, power="both", tap_script=False, auth_wrapper=None,
                 verbose=True, auth_timeout=60.0, word_order=None):
        self.cores = cores            # {core_id: {"name":…, "elf":…, "load_offset":…}}
        self.power, self.tap_script = power, tap_script
        self.auth_wrapper = auth_wrapper
        self.verbose = verbose
        self.lock = threading.RLock()
        self.lk = self.dap = None
        self._ap = self._cb = None
        self._pinned = None           # 현재 핀된 core_id
        self.auth_ms = 0.0
        self.auth_count = 0
        self.auth_fail = 0
        self.auth_timeout = float(auth_timeout)
        self.word_order = word_order or 't32-negative'
        self.last_fail_kind = None    # 'transport' | 'invalid' | None
        self._sj = None               # sjtag_unlock 모듈(지연)

    def _say(self, m):
        if self.verbose:
            print(m)

    # ── 주소 (기밀은 sjtag_addrs.json 에만) ───────────────────────────
    def _pcsr_addr(self, core_id):
        tr = self._sj.RISCV_ADDRS.get("trace", {})
        pc = self._sj.RISCV_ADDRS.get("pcsr", {})
        te = int(str(tr.get("te_base", "0")), 0)
        off = int(str(pc.get("offset", "0")), 0)
        stride = int(str(pc.get("core_stride", "0x1000")), 0)
        return te + stride * core_id + off

    # ── 인증 (SJTAG) ─────────────────────────────────────────────────
    @_handle_locked
    def auth_state(self):
        """SJTAG STATE 레지스터 **read-only** 조회 → (raw, authed).
        읽기만 하므로 인증 카운터를 소모하지 않는다."""
        sj = self._sj
        base = getattr(sj, "SJTAG_BASE", None)
        if base is None or self.dap is None:   # ★ base==0 도 유효 주소다(falsy 검사 금지)
            return None, False
        v = self.dap.mem_read32(sj.APBAP3_BASE, base + sj.OFF_STATE)
        return v, bool(v is not None and (v & sj.AUTH_PASS))

    @_handle_locked
    def _addr_diag(self, key):
        """★ '설정했는데 미설정이라고 나온다'를 한 번에 가르는 자가 진단.
        런타임이 **실제로 읽은 파일과 값 상태**를 보고한다(값 자체는 찍지 않는다).
        별도 도구를 또 돌리지 않아도 이 메시지만으로 원인이 좁혀지도록."""
        sj = self._sj
        try:
            import sfe76_link as _L
            src = os.path.abspath(_L.__file__)
            jpath = os.path.join(os.path.dirname(src), "sjtag_addrs.json")
            real = bool(getattr(_L, "ADDRS_REAL", False))
            addrs = getattr(_L, "RISCV_ADDRS", {}) or {}
        except Exception:
            jpath, real, addrs = "(sfe76_link 미상)", False, {}
        err = addrs.get("_load_error")
        raw = (addrs.get("runtime") or {}).get(key.split(".")[-1], "<키없음>")
        parts = [f"{key} 미설정"]
        parts.append(f"런타임이 읽은 json={jpath}")
        parts.append(f"실제값파일={real} (False 면 example placeholder 사용 중)")
        parts.append(f"원시값: type={type(raw).__name__} len={len(str(raw))} "
                     f"공백={str(raw).strip() == ''}")
        if err:
            parts.append(f"★ JSON 파싱 실패 → {err}")
        if not os.path.exists(jpath):
            parts.append("★ 이 경로에 파일이 없다 — risc-v/ 트리가 둘인지 확인")
        parts.append("점검: sudo python3 tools/check_bm9k1_connect.py")
        return " | ".join(parts)

    @_handle_locked
    def ensure_auth(self, force=False):
        """★ probe-first 인증. → (ok, 사유)

        레지스터가 ground truth다 — 전원이 내려갔으면 AUTH_PASS 가 꺼져 있고, 살아 있으면
        굳이 다시 하지 않는다. unlock() 은 **쓰기**라 인증 카운터를 소모하고, 하드웨어가
        시도를 세거나 anti-hammering 이 있으면 캠페인 도중 자기 디버그 접근을 스스로
        막을 수 있다. 그래서 '필요할 때만' 이 원칙이다.
        (POR 로 전원이 내려가면 자동으로 여기서 재인증된다.)"""
        sj = self._sj
        raw, authed = self.auth_state()
        if authed and not force:
            return True, f"이미 인증됨(STATE={raw:#010x})" if raw is not None else "이미 인증됨"
        # ★ 0 은 유효한 주소일 수 있다(valid_base 가 허용). None 만 '미설정'으로 본다.
        if getattr(sj, "SJTAG_BASE", None) is None:
            return False, self._addr_diag("runtime.sjtag_base")
        if not getattr(sj, "SIGN_TOOL", None):
            return False, self._addr_diag("runtime.sign_tool")

        t0 = time.time()
        try:
            prefix = shlex.split(getattr(sj, "TOOL_PREFIX", "") or "")
            sj.unlock(self.dap, sj.SJTAG_BASE, sj.SIGN_TOOL, self.word_order,
                      timeout=self.auth_timeout, tool_prefix=prefix)
        except Exception as e:
            self.auth_fail += 1
            return False, f"unlock 실패: {str(e)[:120]}"
        self.auth_ms = (time.time() - t0) * 1000.0
        self.auth_count += 1
        raw, authed = self.auth_state()
        if not authed:
            return False, "unlock 은 끝났으나 AUTH_PASS 미확인"
        return True, f"인증 완료 {self.auth_ms:.0f}ms (누적 {self.auth_count}회)"

    # ── 세션 ─────────────────────────────────────────────────────────
    @_handle_locked
    def open(self, power_epoch=0):
        """지연 import → Link.open → prepare_session → 인증 확인."""
        import importlib
        import sys as _sys
        from pathlib import Path as _P
        rv = str(_P(__file__).resolve().parent / "risc-v")
        if rv not in _sys.path:
            _sys.path.insert(0, rv)          # 'risc-v' 는 하이픈이라 패키지 import 불가
        self._sj = importlib.import_module("sjtag_unlock")
        link_mod = importlib.import_module("sfe76_link")
        with self.lock:
            self.lk = link_mod.Link(core_base=link_mod.CORE_BASE_MAIN)
            # README: 첫 connect 는 실패하고 2회차에 붙는다
            for attempt in (1, 2):
                try:
                    self.lk.open(tap_script=self.tap_script)
                    self._sj.prepare_session(self.lk, self.power,
                                             "on" if self.tap_script else "off",
                                             tif_init=True, strict=True)
                    break
                except Exception as e:
                    self._say(f"  [pcsr] open 시도 {attempt} 실패: {str(e)[:80]}")
                    try:
                        self.lk.close()
                    except Exception:
                        pass
                    if attempt == 2:
                        return False
            self.dap = self._sj.MemDap(self.lk.jl)
            # ★ SBA(=DM)는 인증이 통과해야 열린다 → _sba_ready 보다 먼저.
            ok, why = self.ensure_auth()
            self._say(f"  [pcsr] 인증: {why}")
            if not ok:
                self._abort_open()      # ★ 핸들을 남기면 종료 시 DLL 소멸에서 segfault
                return False
            # ★ DM 활성 — SBA(sbcs/sbaddr/sbdata)는 DM 안의 레지스터라, DM 이
            #   dmactive=0(리셋 상태)이면 전부 0 으로 읽혀 'SBA 미구현'처럼 보인다.
            #   동작 체인이 인증 → **DM 활성** → SBA 인데 이 단계가 빠져 있었다.
            #   dmactive write 는 코어를 멈추지 않는 표준 기동(인증 카운터 무관).
            if not self._sj.dm_activate(self.dap, self._sj.CORE_BASE_MAIN):
                self._say("  [pcsr] DM 활성화 실패 — 위 [dm-activate] 로그 참조")
                self._abort_open()
                return False
            sb = self._sj._sba_ready(self.dap)
            if sb is None:
                self._say("  [pcsr] SBA 사용 불가 — DM 은 열렸으나 sbcs 가 0 "
                          "(sbasize=0). DM base/AP 또는 SBA 미구현 확인")
                self._abort_open()
                return False
            self._ap, self._cb = sb
            self._authed_epoch = power_epoch
            return True

    def _abort_open(self):
        """open() 실패 경로 공통 정리. ★ 살아있는 pylink 핸들을 남기면 인터프리터 종료 시
        J-Link DLL 소멸 과정에서 segfault 가 난다(실제 발생). 반드시 닫는다."""
        self.dap = None
        self._pinned = None
        try:
            if self.lk is not None:
                self.lk.close()
        except Exception:
            pass
        self.lk = None

    @_handle_locked
    def close(self):
        with self.lock:
            try:
                if self.dap is not None and self._pinned is not None:
                    self._sj.sba_unpin(self.dap, self._ap, self._cb)
            except Exception:
                pass
            self._pinned = None
            try:
                if self.lk is not None:
                    self.lk.close()
            except Exception:
                pass
            # ★ 닫았으면 비운다 — 남겨두면 'lk is not None' 생존판정이 죽은 세션을
            #   살아있다고 오판해 샘플링 없이 캠페인이 계속된다.
            self.lk = None
            self.dap = None
            self._ap = self._cb = None

    # ── 핀 / 폴링 ────────────────────────────────────────────────────
    @_handle_locked
    def pin(self, core_id):
        with self.lock:
            if self._pinned == core_id:
                return True
            if self._pinned is not None:
                # 마지막 SBDATA0 read 가 다음 SBA read 를 trigger한 상태일 수 있다.
                # 코어 전환은 핫루프 밖이므로 여기서 busy 완료+FIFO off 를 확인한다.
                # 실패한 상태로 새 SBADDR를 쓰면 sbbusyerror가 연쇄되어 이후 모든
                # burst가 빈 리스트가 되므로 fail-closed 한다.
                if not self._sj.sba_unpin(self.dap, self._ap, self._cb):
                    self._pinned = None
                    return False
                self._pinned = None
            ok = self._sj.sba_pin(self.dap, self._ap, self._cb,
                                  self._pcsr_addr(core_id))
            self._pinned = core_id if ok else None
            return ok

    @_handle_locked
    def burst(self, core_id, n, valid_bit=1):
        """한 코어를 n회 연속 폴링 → [Observation].
        ★ 루프 본체에 검사·복구·지연을 넣지 않는다(실측 제약)."""
        obs, raw_fail = [], 0
        with self.lock:
            if not self.pin(core_id):
                self.last_fail_kind = "transport"
                return obs
            read = self._sj.sba_read_pinned
            dap, prev = self.dap, None
            for _ in range(n):
                raw = read(dap)
                if raw is None:
                    raw_fail += 1          # ★ 읽기 자체 실패 = transport
                    obs.append(Observation(core_id, None, False, False))
                    continue
                valid = bool(raw & valid_bit)
                pc = (raw & ~valid_bit) if valid else None
                obs.append(Observation(core_id, pc, pc != prev, valid))
                prev = pc
        # ★ valid=0 은 코어가 halt/wfi 인 **정상** 상태다 — transport 실패가 아니다.
        #   둘을 뭉뚱그리면 정상 WFI 구간에서 불필요한 재연결이 돈다.
        self.last_fail_kind = "transport" if (obs and raw_fail == len(obs)) else None
        return obs

    # ── 복구 ─────────────────────────────────────────────────────────
    @_handle_locked
    def read_word(self, addr):
        """일회성 SBA 읽기(에러검사 있는 경로) — 오버레이 판별용.

        ★ 반드시 **버스트 경계**에서만 부른다. 버스트 핀은 PCSR 주소에 걸려 있어
        여기서 먼저 풀어야 하고, 핫루프(DRW 반복) 안에 넣으면 실측 폴링 제약을 깬다.
        실패는 None 으로 돌려준다 — 호출부가 그 버스트를 버린다.
        """
        if self._pinned is not None:
            if not self._sj.sba_unpin(self.dap, self._ap, self._cb):
                self._pinned = None
                return None
            self._pinned = None
        try:
            return self._sj._sba_read(self.dap, self._ap, self._cb, addr)
        except Exception:
            return None

    @_handle_locked
    def recover(self, core_id, verify_samples=64):
        """붕괴 복구를 **단일 트랜잭션**으로. 재핀·valid 회복까지 통과해야 성공.
        실패 단계(stage)를 남겨야 원인 분석이 된다."""
        t0 = time.time()
        with self.lock:
            self._pinned = None
            dap = self._sj.reopen_session(self.lk, self.power,
                                          tap_script=self.tap_script, strict=True)
            if dap is None:
                return RecoveryResult(False, "open/prepare", time.time() - t0, 0, "")
            self.dap = dap
            ok, why = self.ensure_auth()      # 붕괴 원인이 전원/인증일 수 있다. SBA 보다 먼저
            if not ok:
                return RecoveryResult(False, "auth", time.time() - t0, 0, why)
            if not self._sj.dm_activate(dap, self._sj.CORE_BASE_MAIN):
                return RecoveryResult(False, "dm_activate", time.time() - t0, 0, "")
            sb = self._sj._sba_ready(dap)
            if sb is None:
                return RecoveryResult(False, "sba", time.time() - t0, 0, "")
            self._ap, self._cb = sb
            if not self.pin(core_id):
                return RecoveryResult(False, "pin", time.time() - t0, 0, "")
            obs = self.burst(core_id, verify_samples)
            nv = sum(1 for o in obs if o.valid)
            if nv == 0:
                return RecoveryResult(False, "valid", time.time() - t0, 0,
                                      "재핀은 됐으나 유효 샘플 0")
            return RecoveryResult(True, "ok", time.time() - t0, nv, "")


def sha256_of(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest()
