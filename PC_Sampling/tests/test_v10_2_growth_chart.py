"""Real PNG regression tests for both coverage backends, without device access."""
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

from test_v10_2_learning import fuzzer


class GrowthChartTests(unittest.TestCase):
    def instance(self, folder, riscv):
        inst = fuzzer.NVMeFuzzer.__new__(fuzzer.NVMeFuzzer)
        inst.output_dir = Path(folder)
        inst._sa_loaded = not riscv
        inst._sa_total_bbs = 0 if riscv else 100
        inst._sa_total_funcs = 0 if riscv else 10
        inst._sa_covered_bbs = set()
        inst._sa_entered_funcs = set()
        inst._sa_func_entries = []
        inst._sa_cov_history = [(100, 10, 10, 20), (200, 20, 30, 40)]
        inst.cov = (NS(loaded=True, total_bbs=300, total_funcs=30,
                       covered_bbs=set(), entered_funcs=set(), cores={}) if riscv else None)
        return inst

    def test_riscv_and_arm_render_with_correct_denominators(self):
        import matplotlib.pyplot as plt
        for riscv in (True, False):
            with self.subTest(riscv=riscv), tempfile.TemporaryDirectory() as folder:
                inst = self.instance(folder, riscv)
                original = plt.savefig
                labels = []
                def save(*args, **kwargs):
                    labels.extend(t.get_text() for t in plt.gcf().axes[0].get_legend().get_texts())
                    return original(*args, **kwargs)
                with patch.object(plt, 'savefig', side_effect=save):
                    inst._generate_static_coverage_graphs()
                data = (Path(folder) / 'graphs' / 'coverage_growth.png').read_bytes()
                self.assertTrue(data.startswith(b'\x89PNG\r\n\x1a\n'))
                self.assertGreater(len(data), 1000)
                self.assertIn('Basic Blocks (300)' if riscv else 'Basic Blocks (100)', labels)
                self.assertIn('Functions (30)' if riscv else 'Functions (10)', labels)
                self.assertEqual(plt.get_fignums(), [])

    def test_insufficient_history_explains_skip(self):
        with tempfile.TemporaryDirectory() as folder:
            inst = self.instance(folder, True)
            inst._sa_cov_history = [(100, 10, 10, 20)]
            with self.assertLogs('pcfuzz', level='INFO') as logs:
                inst._generate_static_coverage_graphs()
            self.assertIn('최소 2개 필요', '\n'.join(logs.output))
            self.assertFalse((Path(folder) / 'graphs' / 'coverage_growth.png').exists())
