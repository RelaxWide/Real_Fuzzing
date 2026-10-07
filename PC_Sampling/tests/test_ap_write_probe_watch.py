"""Diagnostic interpretation and watch isolation; no device imports or access."""
import contextlib
import io
from pathlib import Path
import runpy
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SOURCE = Path(__file__).resolve().parents[1] / 'risc-v' / 'ap_write_probe.py'


def load_probe():
    sj = ModuleType('sjtag_unlock')
    link = ModuleType('sfe76_link')
    link.Link = Mock(side_effect=AssertionError('hardware access'))
    link.AP_MAP = [('APBAP3', 123, 'test')]
    link.CORE_BASE_MAIN = 0
    link.SPEED_KHZ = 10000
    dap = ModuleType('dap_access')
    for name, value in dict(OFF_CSW=0, OFF_TAR=4, OFF_IDR=8,
                            DP_ABORT=0, DP_CTRL_STAT=1, DP_RDBUF=3).items():
        setattr(dap, name, value)
    dap.hx = lambda v: 'failed' if v is None else '0x%08X' % v
    with patch.dict(sys.modules, sjtag_unlock=sj, sfe76_link=link, dap_access=dap), \
            patch.object(sys, 'path', list(sys.path)):
        return runpy.run_path(str(SOURCE))


class WatchTests(unittest.TestCase):
    def setUp(self):
        self.mod = load_probe()

    def fake_dap(self, reads):
        jl = SimpleNamespace(coresight_read=Mock(side_effect=reads),
                             coresight_write=Mock(side_effect=AssertionError('write')),
                             hardware_status=SimpleNamespace(voltage=3300))
        return SimpleNamespace(jl=jl,
                               dp_read=lambda reg: jl.coresight_read(reg, ap=False),
                               dp_write=Mock(side_effect=AssertionError('DP write')),
                               ap_read=Mock(side_effect=AssertionError('AP read')),
                               ap_write=Mock(side_effect=AssertionError('AP write')),
                               clear_sticky=Mock(side_effect=AssertionError('ABORT')))

    def test_suspect_raw_values_never_become_power_drop(self):
        for ctrl in (0x80000000, 0, 0xffffffff, None):
            with self.subTest(ctrl=ctrl):
                row = self.mod['dp_sample'](self.fake_dap([0x12345679, ctrl]), None)
                self.assertEqual(row['ctrl'], ctrl)
                self.assertEqual(row['power'], '?/? ?/?')
                self.assertNotEqual(row['state'], 'PLAUSIBLE')
                self.assertEqual(self.mod['pwr_bits'](ctrl), '?/? ?/?')

    def test_bad_or_changed_dpidr_masks_even_plausible_ctrl(self):
        for dpidr in (None, 0, 0x80000000, 0xffffffff, 0x12345678, 0x1234567b):
            row = self.mod['dp_sample'](self.fake_dap([dpidr, 0xf0000000]), 0x12345679)
            self.assertEqual(row['power'], '?/? ?/?')
            self.assertNotEqual(row['state'], 'PLAUSIBLE')

    def test_plausible_values_keep_actual_req_ack(self):
        row = self.mod['dp_sample'](self.fake_dap([0x12345679, 0xa0000000]), 0x12345679)
        self.assertEqual(row['state'], 'PLAUSIBLE')
        self.assertEqual(row['power'], '0/1 0/1')

    def test_dp_only_has_two_reads_no_writes_and_restores_wrappers(self):
        dap = self.fake_dap([0x12345679, 0x80000000])
        original = dap.jl.coresight_read
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch.dict(self.mod['watch'].__globals__, nvme_state=lambda: '-'):
            self.mod['watch'](dap, 0, 1, dp_only=True)
        self.assertEqual(original.call_count, 2)
        self.assertIs(dap.jl.coresight_read, original)
        dap.dp_write.assert_not_called()
        dap.ap_write.assert_not_called()
        dap.clear_sticky.assert_not_called()
        self.assertIn('SUSPECT', output.getvalue())
        self.assertIn('0x80000000', output.getvalue())
        self.assertNotIn('0/0 0/1', output.getvalue())

    def test_ap_mode_records_before_and_after_access(self):
        dap = self.fake_dap([0x12345679, 0xf0000000, 0x12345679, 0x80000000])
        events = []
        def quick(d, base):
            self.assertEqual(original.call_count, 2)
            events.append(base)
            return 'E'
        original = dap.jl.coresight_read
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch.dict(self.mod['watch'].__globals__,
                nvme_state=lambda: '-', quick_ap=quick):
            self.mod['watch'](dap, 0, 1)
        self.assertEqual(events, [123])
        self.assertEqual(original.call_count, 4)
        self.assertIn('phase=post reason=SUSPECT', output.getvalue())
        self.assertIn('APBAP3=E', output.getvalue())

    def test_interrupt_restores_counter_and_prints_summary(self):
        dap = self.fake_dap([KeyboardInterrupt()])
        original = dap.jl.coresight_read
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(KeyboardInterrupt):
            self.mod['watch'](dap, 0, 1, dp_only=True)
        self.assertIs(dap.jl.coresight_read, original)
        self.assertIn('[summary]', output.getvalue())

    def test_invalid_cli_stops_before_opening_hardware(self):
        for args in (['--dp-only'], ['--watch', '1', '--dp-only', '--reassert'],
                     ['--watch', '1', '--dp-only', '--dap-abort'],
                     ['--watch', '1', '--dp-only', '--aps', 'APBAP3'],
                     ['--watch', 'nan'], ['--interval', 'inf']):
            with self.subTest(args=args), patch.object(sys, 'argv', ['probe'] + args), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as cm:
                self.mod['main']()
            self.assertEqual(cm.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
