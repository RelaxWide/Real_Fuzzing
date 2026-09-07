#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""★ 자산 계약 테스트 — Ghidra(사내)가 내는 파일이 이 이름·형식이면 퍼저가 동작한다.

추출 도구를 누가 만들든(Ghidra/objdump/직접) 이 테스트가 통과하는 산출물이면
커버리지가 올바르게 집계된다. 계약이 깨지면 여기서 잡힌다.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import riscv_cov as rc          # noqa: E402

BASE = 0x56000
BODY = 0x10000


def write_assets(d, banks=3, counts=True):
    d = Path(d)
    (d / 'basic_blocks_coreH.txt').write_text(
        f"0x{BODY:08x} 0x{BODY+16:08x}\n0x{BODY+16:08x} 0x{BODY+32:08x}\n")
    (d / 'functions_coreH.txt').write_text(f"0x{BODY:08x} 32 main_loop\n")
    (d / 'callgraph_coreH.txt').write_text(f"0x{BODY:08x} 0x{BODY+16:08x}\n")
    for n in range(banks):
        (d / f'basic_blocks_coreH_ovl{n}.txt').write_text(
            f"0x{BASE:08x} 0x{BASE+16:08x}\n0x{BASE+16:08x} 0x{BASE+32:08x}\n")
        (d / f'functions_coreH_ovl{n}.txt').write_text(f"0x{BASE:08x} 32 ovl{n}_fn\n")
    json.dump({"core": "H", "base": BASE, "window_end": BASE + 16214,
               "probe_offsets": [4],
               "probe_to_bank": {f"0x4F564C{n:02X}": n for n in range(banks)},
               "header": {"magic": "0x4F564C00", "magic_mask": "0xFFFFFF00",
                          "id_mask": "0x000000FF"},
               "bank_sizes": {str(n): 4096 for n in range(banks)}},
              open(d / 'overlay_map_coreH.json', 'w'))
    if counts:
        json.dump({"product": "BM9K1", "bb_end_convention": "exclusive",
                   "cores": {"H": {"counts": {"basic_blocks": 2, "functions": 1,
                                              "overlay_banks": banks,
                                              "overlay_basic_blocks": 2 * banks,
                                              "overlay_functions": banks}}}},
                  open(d / 'symbols.json', 'w'))


class TestAssetContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        write_assets(self.tmp.name)
        self.m = rc.CoverageModel.load(self.tmp.name, product='BM9K1',
                                       core_ids={'H': 0})
        self.cm = self.m.cores[0]

    def tearDown(self):
        self.tmp.cleanup()

    def test_loads_without_warnings(self):
        """counts 는 **본체 기준** — 총계와 비교하면 매번 헛경고가 난다."""
        self.assertTrue(self.m.loaded)
        self.assertEqual(self.m.warnings, [])

    def test_bank_tables_loaded(self):
        """파일명은 _ovl<순번>, 내부 bank 는 순번+1(0은 본체 전용)."""
        self.assertEqual(sorted(self.cm.banks),
                         [n + rc.OVL_BANK_OFFSET for n in range(3)])

    def test_denominator_includes_overlays(self):
        self.assertEqual(self.m.total_bbs, 2 + 3 * 2)
        self.assertEqual(self.m.total_funcs, 1 + 3)

    def test_probe_addr_and_resolution(self):
        self.assertEqual(self.cm.overlay_probe_addr(), BASE + 4)
        for n in range(3):
            self.assertEqual(self.cm.resolve_bank(0x4F564C00 + n),
                             n + rc.OVL_BANK_OFFSET)
        self.assertIsNone(self.cm.resolve_bank(0xDEADBEEF))

    def test_same_pc_different_overlay_counts_separately(self):
        self.m.update([rc.Observation(0, BASE + 4, True, True,
                                      self.cm.resolve_bank(0x4F564C00)),
                       rc.Observation(0, BASE + 4, True, True,
                                      self.cm.resolve_bank(0x4F564C02))])
        self.assertEqual(len(self.m.covered_bbs), 2)

    def test_report_rows_separate_overlays(self):
        rows = self.m.function_rows()
        self.assertEqual({r['name'] for r in rows},
                         {'main_loop', 'ovl0_fn', 'ovl1_fn', 'ovl2_fn'})
        self.assertEqual(len({r['bank'] for r in rows}), 4)

    def test_body_not_polluted_by_overlay(self):
        self.m.update([rc.Observation(0, BASE + 4, True, True,
                                      self.cm.resolve_bank(0x4F564C00))])
        body = [r for r in self.m.function_rows() if r['name'] == 'main_loop'][0]
        self.assertEqual(body['covered_bbs'], 0)

    def test_missing_bank_table_folds_to_zero(self):
        """오버레이 표가 아직 없으면 bank 를 0 으로 접어 분모를 부풀리지 않는다."""
        with tempfile.TemporaryDirectory() as d:
            write_assets(d, banks=0)
            m = rc.CoverageModel.load(d, product='BM9K1', core_ids={'H': 0})
            cm = m.cores[0]
            self.assertEqual(cm.banks, {})
            self.assertEqual(cm.effective_bank(BASE + 4, 2), 0)

    def test_count_mismatch_is_reported(self):
        """파일이 잘리면 잡혀야 한다 — 이 대조가 symbols.json 의 존재 이유다."""
        with tempfile.TemporaryDirectory() as d:
            write_assets(d)
            p = Path(d) / 'symbols.json'
            doc = json.load(open(p))
            doc['cores']['H']['counts']['overlay_basic_blocks'] = 999
            json.dump(doc, open(p, 'w'))
            m = rc.CoverageModel.load(d, product='BM9K1', core_ids={'H': 0})
            self.assertTrue(any('overlay_basic_blocks' in w for w in m.warnings))


if __name__ == '__main__':
    unittest.main(verbosity=2)
