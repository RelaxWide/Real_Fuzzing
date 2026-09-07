#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""firmware_map 렌더 테스트.

원래 이 차트는 _generate_all_charts 안에 인라인이라 self._sa_* 만 그릴 수 있었다:
  · RISC-V 는 _sa_* 가 비어 있어 **아예 생성되지 않았고**
  · 코어별로 여러 장을 그릴 수도 없었다
데이터를 인자로 받는 메서드로 분리했으므로, 분리가 렌더를 깨지 않았는지 확인한다.
"""
import importlib.util
import random
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import riscv_cov as rc          # noqa: E402

try:
    import matplotlib
    matplotlib.use('Agg')
    HAVE_MPL = True
except Exception:
    HAVE_MPL = False


def _load_fuzzer():
    spec = importlib.util.spec_from_file_location(
        "fz_map", str(Path(__file__).with_name('pc_sampling_fuzzer_v10.0.py')))
    m = importlib.util.module_from_spec(spec)
    sys.modules['fz_map'] = m
    spec.loader.exec_module(m)
    return m


def _model(cores=((0, 'H', 0x10000, 120), (2, 'F', 0x80000, 60))):
    m = rc.CoverageModel()
    rnd = random.Random(7)
    for cid, nm, base, nf in cores:
        cm = rc.CoreMap(cid, nm)
        a = base
        for i in range(nf):
            sz = rnd.choice([64, 128, 256])
            cm.fn_entries.append(a)
            cm.fn_ends.append(a + sz)
            cm.fn_names.append(f"{nm}_fn_{i}")
            for b in range(0, sz, 32):
                cm.bb_starts.append(a + b)
                cm.bb_ends.append(a + b + 32)
            a += sz
        m.cores[cid] = cm
    m.loaded = True
    for cid, cm in m.cores.items():
        for i, e in enumerate(cm.fn_entries):
            if rnd.random() < 0.5:
                m.entered_funcs.add(rc.pack(cid, 0, e))
                for b in cm.bb_starts:
                    if e <= b < cm.fn_ends[i] and rnd.random() < 0.6:
                        m.covered_bbs.add(rc.pack(cid, 0, b))
    return m


class TestCallSite(unittest.TestCase):
    """호출부 계약(matplotlib 없이도 검증 가능)."""

    def setUp(self):
        self.src = Path(__file__).with_name(
            'pc_sampling_fuzzer_v10.0.py').read_text(encoding='utf-8')

    def test_method_extracted(self):
        self.assertIn('def _render_firmware_map(self, entries, ends, names, entered,',
                      self.src)

    def test_per_core_filenames(self):
        self.assertIn('firmware_map_core{_fv[\'name\']}.png', self.src)

    def test_legacy_path_kept(self):
        """ARM 제품(_sa_*)은 기존 파일명 그대로 나와야 한다."""
        i = self.src.index("elif self._sa_func_entries and self._sa_total_funcs > 0:")
        self.assertIn("'firmware_map.png'", self.src[i:i + 500])

    def test_skips_cores_without_body(self):
        i = self.src.index("_fv = _cov_fm.flat_view(_cid)")
        self.assertIn("not _fv['fn_entries']", self.src[i:i + 240])

    def test_no_stale_graph_dir_in_method(self):
        """분리하면서 남은 graph_dir 참조가 있으면 NameError 로 죽는다."""
        i = self.src.index('def _render_firmware_map')
        j = self.src.index('\n    def ', i + 10)
        self.assertNotIn('graph_dir', self.src[i:j])


@unittest.skipUnless(HAVE_MPL, "matplotlib 필요")
class TestRender(unittest.TestCase):
    """실제로 PNG 가 나오는지 — 분리가 렌더를 깼는지는 그려봐야 안다."""

    @classmethod
    def setUpClass(cls):
        cls.fz = _load_fuzzer()

    def _inst(self):
        return self.fz.NVMeFuzzer.__new__(self.fz.NVMeFuzzer)

    def test_per_core_png_written(self):
        m = _model()
        f = self._inst()
        f.cov = m
        with tempfile.TemporaryDirectory() as d:
            for cid in sorted(m.cores):
                fv = m.flat_view(cid)
                p = Path(d) / f"firmware_map_core{fv['name']}.png"
                f._render_firmware_map(fv['fn_entries'], fv['fn_ends'], fv['fn_names'],
                                       fv['entered_funcs'], fv['bb_starts'],
                                       fv['covered_bbs'], fv['total_bbs'], p,
                                       label=f"  [core {fv['name']}]")
                self.assertTrue(p.exists() and p.stat().st_size > 5000, p.name)

    def test_legacy_sa_style_still_renders(self):
        """ARM 제품 회귀 — 같은 메서드를 _sa_* 모양 데이터로 호출."""
        m = _model(cores=((0, 'H', 0x10000, 80),))
        fv = m.flat_view(0)
        f = self._inst()
        f.cov = None
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'firmware_map.png'
            f._render_firmware_map(fv['fn_entries'], fv['fn_ends'], fv['fn_names'],
                                   fv['entered_funcs'], fv['bb_starts'],
                                   fv['covered_bbs'], fv['total_bbs'], p)
            self.assertTrue(p.exists() and p.stat().st_size > 5000)

    def test_no_bb_data_fallback(self):
        """BB 표가 없으면 진입 여부만으로 0/1 fallback — 죽으면 안 된다."""
        m = _model(cores=((0, 'H', 0x10000, 40),))
        fv = m.flat_view(0)
        f = self._inst()
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'm.png'
            f._render_firmware_map(fv['fn_entries'], fv['fn_ends'], fv['fn_names'],
                                   fv['entered_funcs'], [], set(), 0, p)
            self.assertTrue(p.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
