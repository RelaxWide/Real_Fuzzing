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
                       "funtions": len(c.get("fn", []))},   # ★ 생산 쪽 오타 그대로
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

    def test_tolerates_funtions_typo(self):
        """생산 쪽 'funtions' 오타를 관용 — 나중에 고쳐도 안 깨져야 한다."""
        write_product(self.d, {"H": {"bb": [(0x100, 0x110)],
                                     "fn": [(0x100, 0x10, "f")]}})
        m = rc.CoverageModel.load(self.d)
        self.assertEqual(m.warnings, [])
        p = Path(self.d, "symbols.json")
        s = json.loads(p.read_text())
        s["cores"]["H"]["counts"]["functions"] = s["cores"]["H"]["counts"].pop("funtions")
        p.write_text(json.dumps(s))
        self.assertEqual(rc.CoverageModel.load(self.d).warnings, [])

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
