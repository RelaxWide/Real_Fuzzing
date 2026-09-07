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

    def test_project_preserves_core_and_does_not_account(self):
        """calibration용 projection은 packed BB를 주되 전역 상태를 선점하지 않는다."""
        p = self.m.project([Ob(self.H, 0x104, True, True),
                            Ob(self.F, 0x104, True, True)])
        self.assertEqual(p.seed_keys,
                         {rc.pack(self.H, 0, 0x100), rc.pack(self.F, 0, 0x100)})
        self.assertEqual(self.m.covered_bbs, set())
        self.assertEqual(self.m.entered_funcs, set())

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

    def test_function_rows_reports_partial_and_frontier(self):
        write_product(self.d, {"H": {
            "bb": [(0x100, 0x110), (0x110, 0x120), (0x200, 0x210)],
            "fn": [(0x100, 0x20, "caller"), (0x200, 0x10, "callee")],
            "cg": [(0x100, 0x200)],
        }})
        m = rc.CoverageModel.load(self.d)
        m.account([Ob(0, 0x104, True, True)])
        by_name = {r["name"]: r for r in m.function_rows()}
        self.assertEqual(by_name["caller"]["covered_bbs"], 1)
        self.assertEqual(by_name["caller"]["total_bbs"], 2)
        self.assertAlmostEqual(by_name["caller"]["bb_pct"], 50.0)
        self.assertEqual(by_name["callee"]["frontier_callers"], 1)


class TestSnapshot(Base):
    def test_resume_api_is_not_part_of_runtime_model(self):
        self.assertFalse(hasattr(rc.CoverageModel, "save_v2"))
        self.assertFalse(hasattr(rc.CoverageModel, "load_v2"))

    def test_snapshot_is_plain_and_faithful(self):
        write_product(self.d, {"H": {"bb": [(0x100, 0x110), (0x200, 0x210)],
                                     "fn": [(0x100, 0x10, "m"),
                                            (0x200, 0x10, "next")],
                                     "cg": [(0x100, 0x200)]}})
        m = rc.CoverageModel.load(self.d)
        m.account([Ob(0, 0x104, True, True)])
        snap = m.snapshot()
        for v in snap["cores"].values():        # 차트 서브프로세스가 pickle 하므로
            self.assertIsInstance(v, dict)      # plain 컨테이너만 있어야 한다
        m2 = rc.CoverageModel.from_snapshot(snap)
        self.assertEqual(m2.covered_bbs, m.covered_bbs)
        self.assertEqual(m2.entered_funcs, m.entered_funcs)
        self.assertEqual(m2.stats_by_core(), m.stats_by_core())
        self.assertEqual(m2.frontier_functions(0), m.frontier_functions(0),
                         "차트 자식에서도 callgraph/frontier가 보존돼야 한다")


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
        self.calls.append(("unpin",)); return True

    RISCV_ADDRS = {"trace": {"te_base": "0x1000000"},
                   "pcsr": {"offset": "0x17C", "core_stride": "0x1000"}}
    # 인증 관련(기본 경로는 '이미 인증됨'을 가정 — 상세는 TestEnsureAuth 에서)
    SJTAG_BASE, SIGN_TOOL, TOOL_PREFIX = 0x1000, "/x/signer.exe", "wine"
    APBAP3_BASE, OFF_STATE, AUTH_PASS = 0x50000, 0x4, 0x100

    CORE_BASE_MAIN = 0x8000

    def unlock(self, *a, **k):
        self.calls.append(("unlock",))
        return None

    def dm_activate(self, dap, core_base):
        """DM 활성 — SBA 는 DM 안의 레지스터라 이게 먼저 성공해야 한다."""
        self.calls.append(("dm_activate",))
        return True


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

    def test_core_switch_quiesces_fifo_before_repin(self):
        """A코어 마지막 read가 만든 outstanding SBA read를 정리한 뒤 B코어를 pin."""
        s = make_session([0x1001, 0x2001])
        s.burst(0, 1)
        s.burst(1, 1)
        self.assertEqual([c[0] for c in s._sj.calls],
                         ["pin", "read", "unpin", "pin", "read"])

    def test_core_switch_stops_when_unpin_fails(self):
        """FIFO를 못 끈 상태에서 새 SBADDR를 쓰면 안 된다."""
        s = make_session([0x1001])
        s.burst(0, 1)
        s._sj.sba_unpin = lambda *a: False
        self.assertEqual(s.burst(1, 1), [])
        self.assertIsNone(s._pinned)

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

    def test_dm_activate_failure_reported(self):
        """복구 시 DM 활성이 실패하면 그 단계로 보고해야 한다(SBA 탓으로 오인 금지)."""
        s = make_session([])
        s._sj.reopen_session = lambda *a, **k: FakeDapAuth(FakeSJAuth.AUTH_PASS)
        s._sj.dm_activate = lambda dap, cb: False
        r = s.recover(0)
        self.assertFalse(r.ok)
        self.assertEqual(r.stage, "dm_activate")

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


class TestAdaptiveWeights(unittest.TestCase):
    """예산 재배분 — json 값을 고정하지 않고 최근 수확률로 옮긴다."""

    def setUp(self):
        self.w0 = {0: 8, 1: 1, 2: 4, 3: 1}

    def _run(self, per1k, execs=20000, **kw):
        aw = rc.AdaptiveWeights(dict(self.w0), period=500, **kw)
        for ex in range(1, execs + 1):
            samp = {c: aw.weights[c] * 32 for c in aw.weights}
            new = {c: (samp[c] / 1000.0) * per1k[c] for c in aw.weights}
            aw.observe(new, samp)
            aw.maybe_update(ex)
        return aw

    def test_budget_preserved(self):
        """샘플레이트는 하드웨어 상수 — 총 예산이 늘거나 줄면 안 된다."""
        aw = self._run({0: 1.135, 1: 0.501, 2: 1.346, 3: 0.534})
        self.assertEqual(sum(aw.weights.values()), sum(self.w0.values()))

    def test_shifts_to_higher_rate(self):
        """실측값: F(2) 가 per1k 최고 → F 가 늘고 H(0) 가 준다."""
        aw = self._run({0: 1.135, 1: 0.501, 2: 1.346, 3: 0.534})
        self.assertGreater(aw.weights[2], self.w0[2])
        self.assertLess(aw.weights[0], self.w0[0])

    def test_floor_keeps_every_core_observed(self):
        """0 이 되면 그 코어가 나중에 일을 시작해도 영영 모른다."""
        aw = self._run({0: 5.0, 1: 0.0, 2: 5.0, 3: 0.0})
        for c in self.w0:
            self.assertGreaterEqual(aw.weights[c], 1)

    def test_exponent_sharpens(self):
        """rate 비례(e=1)는 저수확 코어로 예산이 샌다 — 실측서 발견 6.9% 가
        예산 28% 를 가져갔다. e=2 는 그걸 floor 로 눌러야 한다."""
        r = {0: 1.135, 1: 0.501, 2: 1.346, 3: 0.534}
        flat = self._run(r, exponent=1.0)
        sharp = self._run(r, exponent=2.0)
        self.assertGreater(flat.weights[1] + flat.weights[3],
                           sharp.weights[1] + sharp.weights[3])

    def test_no_update_before_period(self):
        aw = rc.AdaptiveWeights(dict(self.w0), period=500)
        aw.observe({0: 10}, {0: 1000})
        self.assertIsNone(aw.maybe_update(499))

    def test_low_sample_core_is_shrunk_not_excluded(self):
        """★ 실측 회귀: 표본 적은 코어를 '판단에서 제외' 하면, 가중치가 낮은 코어는
        문턱을 영영 못 넘어 아무리 생산적이어도 예산을 못 받는다(CM 의 per1k 가
        네 코어 중 최고인 갱신에서도 1 에 묶였다). 제외 대신 수축이어야 한다."""
        aw = rc.AdaptiveWeights({0: 8, 1: 1, 2: 4, 3: 1}, decay=0.999, period=500)
        for ex in range(1, 8001):
            samp = {c: aw.weights[c] * 25 for c in aw.weights}
            r = {0: 0.5, 1: 4.0, 2: 0.5, 3: 0.2}      # CM(1) 만 생산적
            aw.observe({c: (samp[c] / 1000.0) * r[c] for c in aw.weights}, samp)
            aw.maybe_update(ex)
        self.assertGreater(aw.weights[1], 5,
                           "생산적인 저가중치 코어가 예산을 받아야 한다")

    def test_shrinkage_damps_noise(self):
        """표본이 거의 없는 코어의 튀는 rate 가 배분을 흔들면 안 된다."""
        aw = rc.AdaptiveWeights({0: 8, 1: 1}, decay=0.999, period=500)
        for _ in range(200):
            aw.observe({0: 20, 1: 5}, {0: 10000, 1: 5})   # 1번은 표본 5개뿐
        shrunk, raw = aw.rates(), aw.rates(raw=True)
        self.assertLess(shrunk[1], raw[1], "표본 부족 코어는 평균 쪽으로 당겨져야")
        self.assertAlmostEqual(shrunk[0], raw[0], delta=0.2)   # 표본 많으면 거의 그대로

    def test_recent_beats_stale(self):
        """감쇠가 없으면 과거가 지배해 변화를 못 따라간다."""
        aw = rc.AdaptiveWeights({0: 4, 1: 4}, period=500, decay=0.99)
        for ex in range(1, 3001):          # 전반: 0 번만 생산
            aw.observe({0: 5, 1: 0}, {0: 1000, 1: 1000}); aw.maybe_update(ex)
        early = dict(aw.weights)
        for ex in range(3001, 12001):      # 후반: 1 번으로 역전
            aw.observe({0: 0, 1: 5}, {0: 1000, 1: 1000}); aw.maybe_update(ex)
        self.assertGreater(aw.weights[1], early[1])
        self.assertLess(aw.weights[0], early[0])

    def test_none_when_nothing_to_change(self):
        aw = rc.AdaptiveWeights({0: 4, 1: 4}, period=1)
        aw.observe({0: 4, 1: 4}, {0: 1000, 1: 1000})
        aw.maybe_update(1)
        self.assertIsNone(aw.maybe_update(2))


class TestOverlayBanks(unittest.TestCase):
    """코드 오버레이 — 같은 주소에 여러 코드가 번갈아 올라온다(F코어 0xAE000 ×4).

    가장 위험한 실수: bank 별 BB 표가 없는데 bank 를 키에 넣는 것.
    같은 BB 가 bank 0..3 으로 4번 세어져 covered_bbs 가 total_bbs 를 넘는다.
    """
    BASE = 0xAE000
    END = 0xAE000 + 15970

    def _model(self, with_bank_tables=(), tmp=None):
        import json as _json
        d = tmp
        # 베이스 표: 오버레이 창을 덮는 BB 3개
        with open(os.path.join(d, 'basic_blocks_coreF.txt'), 'w') as f:
            f.write(f"0x{self.BASE:x} 0x{self.BASE+16:x}\n")
            f.write(f"0x{self.BASE+16:x} 0x{self.BASE+32:x}\n")
            f.write(f"0x{self.BASE+32:x} 0x{self.BASE+48:x}\n")
        with open(os.path.join(d, 'functions_coreF.txt'), 'w') as f:
            f.write(f"0x{self.BASE:x} 48 ovl_fn\n")
        _json.dump({"core": "F", "base": self.BASE, "window_end": self.END,
                    "probe_offsets": [4],
                    "header": {"magic": "0x4F564C00", "magic_mask": "0xFFFFFF00",
                               "id_mask": "0x000000FF"},
                    "bank_sizes": {"0": 11758, "1": 15970, "2": 10914, "3": 5010}},
                   open(os.path.join(d, 'overlay_map_coreF.json'), 'w'))
        for b in with_bank_tables:
            with open(os.path.join(d, f'basic_blocks_coreF_ovl{b}.txt'), 'w') as f:
                f.write(f"0x{self.BASE:x} 0x{self.BASE+16:x}\n")
        return rc.CoverageModel.load(d, product='BM9K1', core_ids={"F": 2})

    def test_overlay_map_loaded(self):
        with tempfile.TemporaryDirectory() as d:
            m = self._model(tmp=d)
            cm = m.cores[2]
            self.assertIsNotNone(cm.overlay)
            self.assertEqual(cm.overlay['base'], self.BASE)
            self.assertEqual(cm.overlay['magic'], 0x4F564C00)
            self.assertTrue(cm.in_overlay(self.BASE + 8))
            self.assertFalse(cm.in_overlay(self.END))

    def test_no_bank_table_folds_to_zero(self):
        """★ 부풀림 방지의 핵심 — 표가 없으면 bank 를 0 으로 접는다."""
        with tempfile.TemporaryDirectory() as d:
            cm = self._model(tmp=d).cores[2]
            for b in (0, 1, 2, 3):
                self.assertEqual(cm.effective_bank(self.BASE + 4, b), 0)

    def test_bank_used_when_table_exists(self):
        with tempfile.TemporaryDirectory() as d:
            cm = self._model(with_bank_tables=(2,), tmp=d).cores[2]
            self.assertEqual(cm.effective_bank(self.BASE + 4, 2), 2)
            self.assertEqual(cm.effective_bank(self.BASE + 4, 1), 0)  # 표 없는 bank

    def test_outside_window_never_banked(self):
        """오버레이 창 밖 주소는 모호하지 않다 — bank 를 붙이면 안 된다."""
        with tempfile.TemporaryDirectory() as d:
            cm = self._model(with_bank_tables=(2,), tmp=d).cores[2]
            self.assertEqual(cm.effective_bank(0x20000, 2), 0)

    def test_coverage_not_inflated_without_tables(self):
        """★ 회귀 오라클: bank 가 섞인 관측이 들어와도 covered_bbs 가
        total_bbs 를 넘으면 안 된다(넘으면 커버리지 %가 100% 초과)."""
        with tempfile.TemporaryDirectory() as d:
            m = self._model(tmp=d)
            obs = [rc.Observation(2, self.BASE + 4, True, True, b)
                   for b in (0, 1, 2, 3)]
            m.update(obs)
            self.assertEqual(len(m.covered_bbs), 1, "같은 BB 는 한 번만 세어야")
            self.assertLessEqual(len(m.covered_bbs), m.total_bbs)

    def test_distinct_banks_counted_separately_with_tables(self):
        """표가 있으면 같은 주소라도 오버레이별로 **다른 코드**이므로 따로 센다."""
        with tempfile.TemporaryDirectory() as d:
            m = self._model(with_bank_tables=(1, 2), tmp=d)
            m.update([rc.Observation(2, self.BASE + 4, True, True, 1),
                      rc.Observation(2, self.BASE + 4, True, True, 2)])
            self.assertEqual(len(m.covered_bbs), 2)

    def test_observation_bank_defaults_to_zero(self):
        """기존 4인자 호출이 전부 그대로 동작해야 한다."""
        o = rc.Observation(2, 0x1000, True, True)
        self.assertEqual(o.bank, 0)


class TestRuntimeBankResolution(unittest.TestCase):
    """런타임: 프로브 워드 → bank. '오버레이가 바뀌면 같은 PC 를 다른 커버리지로
    센다' 는 목적이 실제로 성립하는지."""

    BASE = 0x56000

    def _cm(self, banks=(0, 1, 2)):
        import tempfile as _tf
        d = self.tmp = _tf.TemporaryDirectory()
        p = d.name
        with open(os.path.join(p, 'basic_blocks_coreH.txt'), 'w') as f:
            f.write(f"0x{self.BASE:x} 0x{self.BASE+16:x}\n")
        json.dump({"core": "H", "base": self.BASE, "window_end": self.BASE + 16214,
                   "probe_offsets": [4],
                   "probe_to_bank": {"0x4F564C00": 0, "0x4F564C01": 1, "0x4F564C02": 2},
                   "header": {"magic": "0x4F564C00", "magic_mask": "0xFFFFFF00",
                              "id_mask": "0x000000FF"},
                   "bank_sizes": {str(b): 4096 for b in (0, 1, 2)}},
                  open(os.path.join(p, 'overlay_map_coreH.json'), 'w'))
        for b in banks:
            with open(os.path.join(p, f'basic_blocks_coreH_ovl{b}.txt'), 'w') as f:
                f.write(f"0x{self.BASE:x} 0x{self.BASE+16:x}\n")
        return rc.CoverageModel.load(p, product='BM9K1', core_ids={"H": 0}).cores[0]

    def tearDown(self):
        if hasattr(self, 'tmp'):
            self.tmp.cleanup()

    def test_probe_addr(self):
        self.assertEqual(self._cm().overlay_probe_addr(), self.BASE + 4)

    def test_resolve_known_words(self):
        cm = self._cm()
        for w, b in ((0x4F564C00, 0), (0x4F564C01, 1), (0x4F564C02, 2)):
            self.assertEqual(cm.resolve_bank(w), b)

    def test_magic_mismatch_is_none(self):
        """미탑재/복사중/읽기실패 — 지금 뭐가 있는지 모르므로 bank 를 찍으면 안 된다."""
        cm = self._cm()
        self.assertIsNone(cm.resolve_bank(0xDEADBEEF))
        self.assertIsNone(cm.resolve_bank(0x00000000))
        self.assertIsNone(cm.resolve_bank(None))

    def test_known_magic_unknown_id_is_none(self):
        """매직은 맞지만 표에 없는 ID → 맵이 이 펌웨어 것이 아니다."""
        self.assertIsNone(self._cm().resolve_bank(0x4F564C09))

    def test_same_pc_different_bank_counts_separately(self):
        """★ 이 기능의 목적 그 자체."""
        cm = self._cm()
        m = rc.CoverageModel()
        m.cores[0] = cm
        m.loaded = True
        m.update([rc.Observation(0, self.BASE + 8, True, True, 0),
                  rc.Observation(0, self.BASE + 8, True, True, 2)])
        self.assertEqual(len(m.covered_bbs), 2,
                         "같은 PC 라도 오버레이가 다르면 다른 커버리지여야 한다")

    def test_same_pc_same_bank_counts_once(self):
        cm = self._cm()
        m = rc.CoverageModel()
        m.cores[0] = cm
        m.loaded = True
        m.update([rc.Observation(0, self.BASE + 8, True, True, 1),
                  rc.Observation(0, self.BASE + 8, True, True, 1)])
        self.assertEqual(len(m.covered_bbs), 1)


class TestFlatView(unittest.TestCase):
    """firmware_map.png 어댑터 — RISC-V 에서 차트가 아예 안 나오던 것을 고친다."""

    def _model(self):
        m = rc.CoverageModel()
        a = rc.CoreMap(0, 'H')
        a.fn_entries = [0x1000, 0x2000]
        a.fn_ends = [0x1100, 0x2100]
        a.fn_names = ['fa', 'fb']
        a.bb_starts = [0x1000, 0x1080, 0x2000]
        a.bb_ends = [0x1080, 0x1100, 0x2100]
        b = rc.CoreMap(2, 'F')
        b.fn_entries = [0x9000]
        b.fn_ends = [0x9100]
        b.fn_names = ['fc']
        b.bb_starts = [0x9000]
        b.bb_ends = [0x9100]
        m.cores = {0: a, 2: b}
        m.loaded = True
        return m

    def test_picks_core_with_most_functions(self):
        self.assertEqual(self._model().flat_view()['name'], 'H')

    def test_explicit_core(self):
        self.assertEqual(self._model().flat_view(2)['name'], 'F')

    def test_only_selected_core_data(self):
        m = self._model()
        m.covered_bbs |= {rc.pack(0, 0, 0x1000), rc.pack(2, 0, 0x9000)}
        fv = m.flat_view(0)
        self.assertEqual(fv['covered_bbs'], {0x1000}, '다른 코어 주소가 섞이면 안 된다')

    def test_excludes_nonzero_bank(self):
        """오버레이는 같은 주소에 여러 코드가 겹쳐 한 축에 못 그린다 → 제외."""
        m = self._model()
        m.covered_bbs |= {rc.pack(0, 0, 0x1000), rc.pack(0, 3, 0x1000)}
        self.assertEqual(m.flat_view(0)['covered_bbs'], {0x1000})

    def test_skips_cores_without_body(self):
        """모든 함수가 오버레이에만 있는 코어를 골라놓고 포기하면 안 된다."""
        m = self._model()
        m.cores[0].fn_entries = []
        m.cores[0].fn_names = []
        m.cores[0].fn_ends = []
        self.assertEqual(m.flat_view()['name'], 'F')

    def test_none_when_no_bodies(self):
        m = self._model()
        for c in m.cores.values():
            c.fn_entries = []
        self.assertIsNone(m.flat_view())
