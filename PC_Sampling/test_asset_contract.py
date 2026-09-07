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
              open(d / 'overlay_probe_coreH.json', 'w'))
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


class TestProbeMapRequired(unittest.TestCase):
    """오버레이 설정이 **하나도** 없으면 _ovl 표를 쓸 수 없다 → 소리 내어 알린다.
    표를 35개 넣고도 아무 변화가 없어 원인을 찾는 데 시간을 버리는 상황을 막는다."""

    def test_orphan_tables_warn(self):
        with tempfile.TemporaryDirectory() as d:
            write_assets(d, banks=3)
            Path(d, 'overlay_probe_coreH.json').unlink()      # 판별표도
            self.assertFalse(Path(d, 'overlay_coreH.json').exists())  # 레이아웃도 없음
            m = rc.CoverageModel.load(d, product='BM9K1', core_ids={'H': 0})
            self.assertTrue(any('overlay_coreH.json' in w for w in m.warnings),
                            "오버레이 설정이 없으면 경고해야 한다")
            self.assertEqual(m.cores[0].banks, {})

    def test_denominator_unchanged_without_probe_map(self):
        """판별표가 없으면 분모도 안 부풀어야 한다 — 못 쓰는 표를 분모에만 넣으면
        커버리지가 이유 없이 낮게 보인다."""
        with tempfile.TemporaryDirectory() as d:
            write_assets(d, banks=3)
            Path(d, 'overlay_probe_coreH.json').unlink()
            m = rc.CoverageModel.load(d, product='BM9K1', core_ids={'H': 0})
            self.assertEqual(m.total_bbs, 2)

    def test_no_warning_when_no_overlay_at_all(self):
        with tempfile.TemporaryDirectory() as d:
            write_assets(d, banks=0)
            Path(d, 'overlay_probe_coreH.json').unlink()
            m = rc.CoverageModel.load(d, product='BM9K1', core_ids={'H': 0})
            self.assertEqual(m.warnings, [])


class TestLayoutMapIsEnough(unittest.TestCase):
    """★ 빌드 레이아웃 맵만으로 런타임 판별이 되어야 한다.

    헤더 규약(OVL 매직 + 순번)이 성립하면 필요한 건 base(맵에 있음) + 상수 두 개
    뿐이다. 판별표를 따로 생성하게 만들면 불필요한 단계와 어긋날 위험만 는다.
    """
    LAYOUT = {f".OVL_REGION_{n:02d}": {"section_index": 19 + n, "addr": BASE,
                                       "size": 3370 + n * 100} for n in range(35)}

    def _dir(self, d):
        write_assets(d, banks=35)
        Path(d, 'overlay_probe_coreH.json').unlink()      # 판별표 없음
        json.dump(self.LAYOUT, open(Path(d, 'overlay_coreH.json'), 'w'))
        doc = json.load(open(Path(d, 'symbols.json')))
        doc['cores']['H']['counts'].update(
            {"overlay_banks": 35, "overlay_basic_blocks": 70, "overlay_functions": 35})
        json.dump(doc, open(Path(d, 'symbols.json'), 'w'))

    def test_derives_probe_from_layout(self):
        o = rc.overlay_from_layout(self.LAYOUT)
        self.assertEqual(o['base'], BASE)
        self.assertEqual(o['probe_offsets'], [rc.OVL_HDR_OFFSET])
        self.assertEqual(len(o['bank_sizes']), 35)
        self.assertEqual(o['window_end'], BASE + max(
            v['size'] for v in self.LAYOUT.values()))

    def test_loads_and_resolves(self):
        with tempfile.TemporaryDirectory() as d:
            self._dir(d)
            m = rc.CoverageModel.load(d, product='BM9K1', core_ids={'H': 0})
            cm = m.cores[0]
            self.assertEqual(m.warnings, [])
            self.assertEqual(cm.overlay['source'], 'layout')
            self.assertEqual(len(cm.banks), 35)
            self.assertEqual(cm.overlay_probe_addr(), BASE + rc.OVL_HDR_OFFSET)
            for n in (0, 12, 34):
                self.assertEqual(cm.resolve_bank(rc.OVL_HDR_MAGIC | n),
                                 n + rc.OVL_BANK_OFFSET)

    def test_bad_magic_still_rejected(self):
        """규약이 깨지면 조용히 틀리는 게 아니라 매직 검사에서 걸려야 한다."""
        with tempfile.TemporaryDirectory() as d:
            self._dir(d)
            cm = rc.CoverageModel.load(d, product='BM9K1',
                                       core_ids={'H': 0}).cores[0]
            self.assertIsNone(cm.resolve_bank(0xDEADBEEF))
            self.assertIsNone(cm.resolve_bank(rc.OVL_HDR_MAGIC | 99))   # 범위 밖 ID

    def test_probe_map_overrides_layout(self):
        """실측 판별표가 있으면 그쪽이 이긴다(측정값이 가정을 이긴다)."""
        with tempfile.TemporaryDirectory() as d:
            write_assets(d, banks=3)
            json.dump(self.LAYOUT, open(Path(d, 'overlay_coreH.json'), 'w'))
            cm = rc.CoverageModel.load(d, product='BM9K1',
                                       core_ids={'H': 0}).cores[0]
            self.assertEqual(cm.overlay['source'], 'probe')

    def test_non_layout_schema_warns(self):
        with tempfile.TemporaryDirectory() as d:
            write_assets(d, banks=3)
            Path(d, 'overlay_probe_coreH.json').unlink()
            json.dump({"nonsense": 1}, open(Path(d, 'overlay_coreH.json'), 'w'))
            m = rc.CoverageModel.load(d, product='BM9K1', core_ids={'H': 0})
            self.assertTrue(any('레이아웃 맵 스키마' in w for w in m.warnings))
