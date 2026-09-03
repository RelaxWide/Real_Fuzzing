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
import random
import shlex
import threading
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
        for label, want, got in (("basic_blocks", c.get("basic_blocks"), cm.total_bbs),
                                 ("functions", c.get("functions"), cm.total_funcs)):
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


# ══════════════════════════════════════════════════════════════════════
#  버스트 스케줄 — 순서를 고정하지 않는다
# ══════════════════════════════════════════════════════════════════════
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
    def auth_state(self):
        """SJTAG STATE 레지스터 **read-only** 조회 → (raw, authed).
        읽기만 하므로 인증 카운터를 소모하지 않는다."""
        sj = self._sj
        base = getattr(sj, "SJTAG_BASE", None)
        if base is None or self.dap is None:   # ★ base==0 도 유효 주소다(falsy 검사 금지)
            return None, False
        v = self.dap.mem_read32(sj.APBAP3_BASE, base + sj.OFF_STATE)
        return v, bool(v is not None and (v & sj.AUTH_PASS))

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

    # ── 핀 / 폴링 ────────────────────────────────────────────────────
    def pin(self, core_id):
        with self.lock:
            if self._pinned == core_id:
                return True
            ok = self._sj.sba_pin(self.dap, self._ap, self._cb,
                                  self._pcsr_addr(core_id))
            self._pinned = core_id if ok else None
            return ok

    def burst(self, core_id, n, valid_bit=1):
        """한 코어를 n회 연속 폴링 → [Observation].
        ★ 루프 본체에 검사·복구·지연을 넣지 않는다(실측 제약)."""
        obs = []
        with self.lock:
            if not self.pin(core_id):
                self.last_fail_kind = "transport"
                return obs
            read = self._sj.sba_read_pinned
            dap, prev = self.dap, None
            for _ in range(n):
                raw = read(dap)
                if raw is None:
                    obs.append(Observation(core_id, None, False, False))
                    continue
                valid = bool(raw & valid_bit)
                pc = (raw & ~valid_bit) if valid else None
                obs.append(Observation(core_id, pc, pc != prev, valid))
                prev = pc
        self.last_fail_kind = ("transport" if all(o.pc is None and not o.valid for o in obs)
                               and obs else None)
        return obs

    # ── 복구 ─────────────────────────────────────────────────────────
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
