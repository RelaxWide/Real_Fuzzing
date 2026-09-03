#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""riscv_cov 단위테스트.  실행: python3 -m unittest -v test_riscv_cov

하드웨어·실제 ELF 없이 전부 검증된다(합성 표 사용)."""
import json
import os
import tempfile
import unittest
from pathlib import Path

import riscv_cov as rc
from riscv_cov import Observation as Ob


def write_product(d, cores):
    """cores = {name: {bb:[(s,e)], fn:[(entry,size,name)], cg:[(a,b)], sha:str}}"""
    sym = {"generated": "T", "bb_end_convention": "exclusive", "cores": {}}
    for name, c in cores.items():
        Path(d, f"basic_blocks_core{name}.txt").write_text(
            "".join(f"0x{s:x} 0x{e:x}\n" for s, e in c.get("bb", [])))
        Path(d, f"functions_core{name}.txt").write_text(
            "".join(f"0x{e:x} {sz} {nm}\n" for e, sz, nm in c.get("fn", [])))
        Path(d, f"callgraph_core{name}.txt").write_text(
            "".join(f"0x{a:x} 0x{b:x}\n" for a, b in c.get("cg", [])))
        sym["cores"][name] = {
            "elf_sha256": c.get("sha", ""),
            "counts": {"basic_blocks": len(c.get("bb", [])),
                       "functions": len(c.get("fn", []))},
        }
    Path(d, "symbols.json").write_text(json.dumps(sym))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()


class TestKey(unittest.TestCase):
    def test_roundtrip(self):
        for c, b, a in ((0, 0, 0x1000), (3, 0, 0xFFFFFFFF), (2, 5, 0x8000)):
            self.assertEqual(rc.unpack(rc.pack(c, b, a)), (c, b, a))

    def test_core0_bank0_equals_bare_addr(self):
        """core=0,bank=0 이면 기존 BB 주소와 값이 같아야 구 데이터와 비교 가능."""
        self.assertEqual(rc.pack(0, 0, 0x12345678), 0x12345678)

    def test_cores_do_not_collide(self):
        """같은 주소라도 코어가 다르면 다른 키 — 코어별 ELF 라 주소가 겹칠 수 있다."""
        self.assertNotEqual(rc.pack(0, 0, 0x1000), rc.pack(2, 0, 0x1000))

    def test_bank_reserved(self):
        self.assertNotEqual(rc.pack(0, 0, 0x1000), rc.pack(0, 1, 0x1000))


class TestLoad(Base):
    def test_loads_and_maps(self):
        write_product(self.d, {"H": {"bb": [(0x100, 0x110), (0x110, 0x120)],
                                     "fn": [(0x100, 0x20, "main")]}})
        m = rc.CoverageModel.load(self.d)
        self.assertTrue(m.loaded)
        cm = m.cores[rc.CORE_IDS["H"]]
        self.assertEqual(cm.bb_of(0x104), 0x100)
        self.assertEqual(cm.bb_of(0x110), 0x110)      # 경계: START 포함
        self.assertIsNone(cm.bb_of(0x120))            # 경계: END 제외(exclusive)
        self.assertEqual(cm.func_name(0x100), "main")

    def test_rejects_wrong_end_convention(self):
        """END 규약이 inclusive 면 `pc < end` 판정과 어긋나 조용히 틀린다 → 거부."""
        write_product(self.d, {"H": {"bb": [(0x100, 0x110)]}})
        p = Path(self.d, "symbols.json")
        s = json.loads(p.read_text()); s["bb_end_convention"] = "inclusive"
        p.write_text(json.dumps(s))
        with self.assertRaises(ValueError):
            rc.CoverageModel.load(self.d)

    def test_count_mismatch_warns(self):
        write_product(self.d, {"H": {"bb": [(0x100, 0x110)]}})
        p = Path(self.d, "symbols.json")
        s = json.loads(p.read_text()); s["cores"]["H"]["counts"]["basic_blocks"] = 999
        p.write_text(json.dumps(s))
        m = rc.CoverageModel.load(self.d)
        self.assertTrue(any("불일치" in w for w in m.warnings))

    def test_multiword_function_name(self):
        Path(self.d, "basic_blocks_coreH.txt").write_text("0x100 0x110\n")
        Path(self.d, "functions_coreH.txt").write_text("0x100 16 my func with spaces\n")
        m = rc.CoverageModel.load(self.d)
        self.assertEqual(m.cores[0].func_name(0x100), "my func with spaces")


class TestAccount(Base):
    def setUp(self):
        super().setUp()
        write_product(self.d, {
            "H": {"bb": [(0x100, 0x110), (0x110, 0x120)],
                  "fn": [(0x100, 0x20, "hmain")]},
            "F": {"bb": [(0x100, 0x110)],           # ★ H 와 같은 주소대(겹침)
                  "fn": [(0x100, 0x10, "fmain")]},
        })
        self.m = rc.CoverageModel.load(self.d)
        self.H, self.F = rc.CORE_IDS["H"], rc.CORE_IDS["F"]

    def test_new_then_not_new(self):
        r1 = self.m.account([Ob(self.H, 0x104, True, True)])
        self.assertTrue(r1.interesting); self.assertEqual(r1.new_count, 1)
        r2 = self.m.account([Ob(self.H, 0x108, True, True)])   # 같은 블록
        self.assertFalse(r2.interesting); self.assertEqual(r2.new_count, 0)

    def test_same_address_different_core_is_new(self):
        """★ 코어별 ELF 라 주소가 겹칠 수 있다 — 코어가 다르면 별개 커버리지."""
        self.m.account([Ob(self.H, 0x104, True, True)])
        r = self.m.account([Ob(self.F, 0x104, True, True)])
        self.assertTrue(r.interesting, "다른 코어의 같은 주소를 중복으로 보면 안 된다")

    def test_stale_excluded(self):
        """fresh=False(직전 값 반복)는 판정에서 제외 — last-retired 계열이라 stall 시 반복."""
        r = self.m.account([Ob(self.H, 0x104, False, True)])
        self.assertFalse(r.interesting)
        self.assertEqual(r.considered, 0)
        self.assertEqual(r.dropped, 1)

    def test_invalid_excluded(self):
        r = self.m.account([Ob(self.H, None, True, False)])
        self.assertFalse(r.interesting); self.assertEqual(r.dropped, 1)

    def test_unmapped_pc_counted_but_not_covered(self):
        r = self.m.account([Ob(self.H, 0x9999, True, True)])
        self.assertEqual(r.considered, 1)       # 유효 샘플로는 셈
        self.assertEqual(r.new_count, 0)        # 표에 없으니 커버리지 아님

    def test_credit_cores_gates_interesting(self):
        """저duty 코어의 신규는 집계는 하되 interesting 을 세우지 않게 할 수 있다."""
        r = self.m.account([Ob(self.F, 0x104, True, True)], credit_cores={self.H})
        self.assertFalse(r.interesting)
        self.assertEqual(r.new_count, 1)        # 커버리지에는 반영
        self.assertIn(self.F, r.new_by_core)

    def test_function_entered(self):
        self.m.account([Ob(self.H, 0x104, True, True)])
        st = self.m.stats_by_core()[self.H]
        self.assertEqual(st["func"], 1)
        self.assertEqual(st["bb"], 1)
        self.assertAlmostEqual(st["bb_pct"], 50.0)

    def test_uncovered_functions(self):
        self.assertEqual(len(self.m.uncovered_functions(self.H)), 1)
        self.m.account([Ob(self.H, 0x104, True, True)])
        self.assertEqual(self.m.uncovered_functions(self.H), [])


class TestFrontier(Base):
    def test_frontier_is_callee_of_covered(self):
        """도달한 함수가 부르는데 아직 안 간 함수만 frontier."""
        write_product(self.d, {"H": {
            "bb": [(0x100, 0x110), (0x200, 0x210), (0x300, 0x310)],
            "fn": [(0x100, 0x10, "a"), (0x200, 0x10, "b"), (0x300, 0x10, "c")],
            "cg": [(0x100, 0x200)],           # a → b  (c 는 아무도 안 부름)
        }})
        m = rc.CoverageModel.load(self.d)
        m.account([Ob(0, 0x104, True, True)])          # a 도달
        fr = m.frontier_functions(0)
        self.assertEqual([r[0] for r in fr], ["b"], "a 가 부르는 b 만 frontier")
        m.account([Ob(0, 0x204, True, True)])          # b 도 도달
        self.assertEqual(m.frontier_functions(0), [])


class TestPersist(Base):
    def setUp(self):
        super().setUp()
        write_product(self.d, {"H": {"bb": [(0x100, 0x110)], "sha": "AAA"}})
        self.m = rc.CoverageModel.load(self.d)

    def test_save_load_roundtrip(self):
        self.m.account([Ob(0, 0x104, True, True)])
        p = os.path.join(self.d, "coverage_v2.jsonl")
        self.m.save_v2(p)
        m2 = rc.CoverageModel.load(self.d)
        ok, why = m2.load_v2(p)
        self.assertTrue(ok, why)
        self.assertEqual(m2.covered_bbs, self.m.covered_bbs)

    def test_rejects_stale_elf(self):
        """★ 펌웨어가 바뀐 커버리지를 이어붙이면 조용히 틀린다 → 거부해야 한다."""
        self.m.account([Ob(0, 0x104, True, True)])
        p = os.path.join(self.d, "coverage_v2.jsonl")
        self.m.save_v2(p)
        write_product(self.d, {"H": {"bb": [(0x100, 0x110)], "sha": "BBB"}})  # ELF 교체
        m2 = rc.CoverageModel.load(self.d)
        ok, why = m2.load_v2(p)
        self.assertFalse(ok)
        self.assertIn("해시", why)
        self.assertEqual(m2.covered_bbs, set(), "거부했으면 아무것도 안 실려야 한다")


class TestSnapshot(Base):
    def test_snapshot_is_plain_and_faithful(self):
        write_product(self.d, {"H": {"bb": [(0x100, 0x110)],
                                     "fn": [(0x100, 0x10, "m")]}})
        m = rc.CoverageModel.load(self.d)
        m.account([Ob(0, 0x104, True, True)])
        snap = m.snapshot()
        for v in snap["cores"].values():        # 차트 서브프로세스가 pickle 하므로
            self.assertIsInstance(v, dict)      # plain 컨테이너만 있어야 한다
        m2 = rc.CoverageModel.from_snapshot(snap)
        self.assertEqual(m2.covered_bbs, m.covered_bbs)
        self.assertEqual(m2.entered_funcs, m.entered_funcs)
        self.assertEqual(m2.stats_by_core(), m.stats_by_core())


if __name__ == "__main__":
    unittest.main(verbosity=2)


# ══════════════════════════════════════════════════════════════════════
#  버스트 스케줄 / PcsrSession — 하드웨어 없이 검증되는 부분
# ══════════════════════════════════════════════════════════════════════
import random
from types import SimpleNamespace


class TestBurstSchedule(unittest.TestCase):
    def test_weights_become_counts(self):
        sch = rc.build_burst_schedule({0: 3, 1: 1, 2: 1, 3: 1}, shuffle=False)
        self.assertEqual(sch.count(0), 3)
        self.assertEqual(len(sch), 6)

    def test_shuffle_changes_order_but_not_counts(self):
        """★ 순서 고정은 계통 편향(코어↔명령 처리 단계 결합)을 만든다 → 섞어야 한다."""
        w = {0: 3, 1: 1, 2: 1, 3: 1}
        fixed = rc.build_burst_schedule(w, shuffle=False)
        shuf = rc.build_burst_schedule(w, rng=random.Random(1), shuffle=True)
        self.assertEqual(sorted(fixed), sorted(shuf), "가중치(관측량)는 보존")
        orders = {tuple(rc.build_burst_schedule(w, rng=random.Random(s)))
                  for s in range(20)}
        self.assertGreater(len(orders), 1, "매번 같은 순서면 편향이 남는다")

    def test_reproducible_with_seed(self):
        """세션 로그에 seed 를 남기면 샘플링 조건을 재현할 수 있어야 한다."""
        a = rc.build_burst_schedule({0: 2, 1: 2}, rng=random.Random(42))
        b = rc.build_burst_schedule({0: 2, 1: 2}, rng=random.Random(42))
        self.assertEqual(a, b)

    def test_zero_weight_core_excluded(self):
        self.assertNotIn(3, rc.build_burst_schedule({0: 2, 3: 0}, shuffle=False))


class FakeSJ:
    """sjtag_unlock 대역 — 폴링이 실제로 어떤 순서로 호출되는지까지 본다."""

    def __init__(self, reads):
        self._reads = list(reads)
        self.calls = []

    def sba_pin(self, dap, ap, cb, addr):
        self.calls.append(("pin", addr)); return True

    def sba_read_pinned(self, dap):
        self.calls.append(("read",))
        return self._reads.pop(0) if self._reads else None

    def sba_unpin(self, dap, ap, cb):
        self.calls.append(("unpin",))

    RISCV_ADDRS = {"trace": {"te_base": "0x1000000"},
                   "pcsr": {"offset": "0x17C", "core_stride": "0x1000"}}
    # 인증 관련(기본 경로는 '이미 인증됨'을 가정 — 상세는 TestEnsureAuth 에서)
    SJTAG_BASE, SIGN_TOOL, TOOL_PREFIX = 0x1000, "/x/signer.exe", "wine"
    APBAP3_BASE, OFF_STATE, AUTH_PASS = 0x50000, 0x4, 0x100

    def unlock(self, *a, **k):
        self.calls.append(("unlock",))
        return None


def make_session(reads):
    s = rc.PcsrSession(cores={0: {"name": "H"}}, verbose=False)
    s._sj = FakeSJ(reads)
    s.dap, s._ap, s._cb = FakeDapAuth(FakeSJAuth.AUTH_PASS), 0x1000, 0x8000
    return s


class TestPcsrBurst(unittest.TestCase):
    def test_valid_bit_and_mask(self):
        """bit0=valid, PC = value & ~1."""
        s = make_session([0x1235, 0x1234])      # 홀수=valid, 짝수=invalid
        obs = s.burst(0, 2)
        self.assertEqual((obs[0].valid, obs[0].pc), (True, 0x1234))
        self.assertEqual((obs[1].valid, obs[1].pc), (False, None))

    def test_fresh_false_on_repeat(self):
        """같은 PC 반복 = stale. PCSR 이 last-retired 계열이라 stall 시 반복된다."""
        s = make_session([0x1001, 0x1001, 0x2001])
        obs = s.burst(0, 3)
        self.assertTrue(obs[0].fresh)
        self.assertFalse(obs[1].fresh, "직전과 같은 PC 는 stale")
        self.assertTrue(obs[2].fresh)

    def test_read_failure_is_invalid_observation(self):
        s = make_session([None, 0x1001])
        obs = s.burst(0, 2)
        self.assertFalse(obs[0].valid)
        self.assertIsNone(obs[0].pc)

    def test_pins_once_then_reads_only(self):
        """★ 핫루프 계약: 버스트당 pin 1회 + read n회. 그 사이에 아무것도 없어야 한다."""
        s = make_session([0x1001] * 5)
        s.burst(0, 5)
        self.assertEqual(s._sj.calls[0][0], "pin")
        self.assertEqual([c[0] for c in s._sj.calls[1:]], ["read"] * 5)

    def test_repin_skipped_for_same_core(self):
        s = make_session([0x1001] * 4)
        s.burst(0, 2); s.burst(0, 2)
        self.assertEqual(sum(1 for c in s._sj.calls if c[0] == "pin"), 1,
                         "같은 코어 연속 버스트면 재핀 불필요")

    def test_pcsr_address_from_json_only(self):
        """주소는 sjtag_addrs.json 에서만 — 코드에 상수로 박히면 안 된다."""
        s = make_session([])
        self.assertEqual(s._pcsr_addr(0), 0x1000000 + 0x17C)
        self.assertEqual(s._pcsr_addr(2), 0x1000000 + 0x2000 + 0x17C)


class TestRecovery(unittest.TestCase):
    def test_failure_stage_is_reported(self):
        """복구 실패 시 어느 단계에서 막혔는지 남아야 원인 분석이 된다."""
        s = make_session([])
        s._sj.reopen_session = lambda *a, **k: None
        r = s.recover(0)
        self.assertFalse(r.ok)
        self.assertEqual(r.stage, "open/prepare")

    def test_not_ok_without_valid_recovery(self):
        """재핀만 되고 유효 샘플이 안 나오면 복구 성공으로 치면 안 된다."""
        s = make_session([0x1000] * 8)          # 전부 invalid(짝수)
        s._sj.reopen_session = lambda *a, **k: FakeDapAuth(FakeSJAuth.AUTH_PASS)
        s._sj._sba_ready = lambda dap: (0x1000, 0x8000)
        r = s.recover(0, verify_samples=8)
        self.assertFalse(r.ok)
        self.assertEqual(r.stage, "valid")

    def test_ok_when_valid_returns(self):
        s = make_session([0x1001] * 8)
        s._sj.reopen_session = lambda *a, **k: FakeDapAuth(FakeSJAuth.AUTH_PASS)
        s._sj._sba_ready = lambda dap: (0x1000, 0x8000)
        r = s.recover(0, verify_samples=8)
        self.assertTrue(r.ok)
        self.assertEqual(r.stage, "ok")
        self.assertEqual(r.valid_samples, 8)


class FakeDapAuth:
    """STATE 레지스터를 흉내내는 dap — 인증 전/후 값을 바꿔가며 검증."""

    def __init__(self, state=0):
        self.state = state
        self.reads = 0

    def mem_read32(self, ap, addr):
        self.reads += 1
        return self.state


class FakeSJAuth(FakeSJ):
    SJTAG_BASE, SIGN_TOOL, TOOL_PREFIX = 0x1000, "/x/signer.exe", "wine"
    APBAP3_BASE, OFF_STATE, AUTH_PASS = 0x50000, 0x4, 0x100

    def __init__(self, reads=(), unlock_raises=None, state_after=None):
        super().__init__(reads)
        self.unlock_calls = 0
        self._unlock_raises = unlock_raises
        self._state_after = state_after

    def unlock(self, dap, base, tool, word_order, timeout=60.0, tool_prefix=()):
        self.unlock_calls += 1
        if self._unlock_raises:
            raise self._unlock_raises
        if self._state_after is not None:
            dap.state = self._state_after
        return SimpleNamespace(status="ok")


def auth_session(state=0, **kw):
    s = rc.PcsrSession(cores={0: {"name": "H"}}, verbose=False)
    s._sj = FakeSJAuth(**kw)
    s.dap = FakeDapAuth(state)
    s._ap, s._cb = 0x1000, 0x8000
    return s


class TestEnsureAuth(unittest.TestCase):
    """★ probe-first: unlock() 은 쓰기라 인증 카운터를 소모한다. 하드웨어가 시도를 세거나
    anti-hammering 이 있으면 캠페인 도중 자기 디버그 접근을 스스로 막을 수 있다."""

    def test_skips_when_already_authed(self):
        s = auth_session(state=0x100)          # AUTH_PASS 세워짐
        ok, why = s.ensure_auth()
        self.assertTrue(ok)
        self.assertEqual(s._sj.unlock_calls, 0, "이미 인증됐으면 unlock 하지 않는다")

    def test_authenticates_when_cleared(self):
        """POR 로 전원이 내려가면 AUTH_PASS 가 꺼진다 → 자동 재인증."""
        s = auth_session(state=0x000, state_after=0x100)
        ok, why = s.ensure_auth()
        self.assertTrue(ok, why)
        self.assertEqual(s._sj.unlock_calls, 1)
        self.assertEqual(s.auth_count, 1)

    def test_force_reauths_even_if_authed(self):
        s = auth_session(state=0x100, state_after=0x100)
        s.ensure_auth(force=True)
        self.assertEqual(s._sj.unlock_calls, 1)

    def test_unlock_exception_reported(self):
        s = auth_session(state=0, unlock_raises=RuntimeError("서명도구 죽음"))
        ok, why = s.ensure_auth()
        self.assertFalse(ok)
        self.assertIn("unlock 실패", why)
        self.assertEqual(s.auth_fail, 1)

    def test_unlock_without_auth_pass_is_failure(self):
        """unlock 이 끝나도 AUTH_PASS 가 안 서면 성공으로 치면 안 된다."""
        s = auth_session(state=0, state_after=0)
        ok, why = s.ensure_auth()
        self.assertFalse(ok)
        self.assertIn("AUTH_PASS", why)

    def test_zero_base_is_not_treated_as_unset(self):
        """★ '미설정'과 '값이 0'은 다르다. valid_base() 가 0 을 유효 주소로 허용하므로
        falsy 검사로 걸러내면 실제 base 가 0 인 SoC 에서 인증 자체가 불가능해진다."""
        s = auth_session(state=0, state_after=0x100)
        s._sj.SJTAG_BASE = 0
        ok, why = s.ensure_auth()
        self.assertNotIn("미설정", why)
        self.assertEqual(s._sj.unlock_calls, 1, "base=0 이어도 인증을 시도해야 한다")
        self.assertTrue(ok, why)

    def test_none_base_is_unset(self):
        s = auth_session(state=0)
        s._sj.SJTAG_BASE = None
        ok, why = s.ensure_auth()
        self.assertFalse(ok)
        self.assertIn("sjtag_base", why)

    def test_missing_config_gives_clear_reason(self):
        for attr, key in (("SJTAG_BASE", "sjtag_base"), ("SIGN_TOOL", "sign_tool")):
            with self.subTest(attr=attr):
                s = auth_session(state=0)
                setattr(s._sj, attr, None)
                ok, why = s.ensure_auth()
                self.assertFalse(ok)
                self.assertIn(key, why)

    def test_probe_is_read_only(self):
        """probe 는 읽기만 — 카운터 무소모."""
        s = auth_session(state=0x100)
        s.ensure_auth()
        self.assertGreater(s.dap.reads, 0)
        self.assertEqual(s._sj.unlock_calls, 0)


class TestRecoveryAuth(unittest.TestCase):
    def test_auth_checked_before_sba(self):
        """SBA(=DM)는 인증 후에만 열린다 → 인증 실패면 stage='auth' 로 정확히 보고."""
        s = auth_session(state=0, unlock_raises=RuntimeError("no"))
        s._sj.reopen_session = lambda *a, **k: s.dap
        called = {"sba": False}
        def _sba(dap):
            called["sba"] = True; return (0x1000, 0x8000)
        s._sj._sba_ready = _sba
        r = s.recover(0)
        self.assertFalse(r.ok)
        self.assertEqual(r.stage, "auth")
        self.assertFalse(called["sba"], "인증 실패면 SBA 를 시도하지 않는다")
