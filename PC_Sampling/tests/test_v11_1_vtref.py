"""v11.1 — J-Link VTref 를 config(jlink_vtref_mv, 기본 1800) 값으로 open 직후·connect 전에 고정한다.

고정 실패나 확인 불일치는 경고만 남기고 측정값 추종으로 계속한다.
"""
import sys
import unittest
from types import SimpleNamespace as NS

from test_v10_2_learning import ROOT, fuzzer

sys.path.insert(0, str(ROOT / 'risc-v'))
import sfe76_link  # noqa: E402


class FakeJLink:
    def __init__(self, measured=3300, fail=None, follow=True):
        self.mv, self.fail, self.follow = measured, fail, follow
        self.commands = []

    @property
    def hardware_status(self):
        return NS(voltage=self.mv)

    def exec_command(self, cmd):
        self.commands.append(cmd)
        if self.fail:
            raise RuntimeError(self.fail)
        if self.follow:
            self.mv = int(cmd.split('=')[1])


class LinkApplyVtref(unittest.TestCase):
    def test_fixes_and_reports_before_after(self):
        jl = FakeJLink(measured=1750)
        r = sfe76_link.apply_vtref(jl, 1800, say=lambda m: None)
        self.assertEqual(jl.commands, ['VTREF = 1800'])
        self.assertEqual((r['before_mv'], r['after_mv'], r['ok']), (1750, 1800, True))

    def test_auto_sends_nothing(self):
        for mv in (None, 0):
            jl = FakeJLink(measured=1790)
            r = sfe76_link.apply_vtref(jl, mv, say=lambda m: None)
            self.assertEqual(jl.commands, [])
            self.assertEqual((r['before_mv'], r['ok']), (1790, None))

    def test_command_failure_is_reported_not_raised(self):
        jl = FakeJLink(fail='Unknown command')
        r = sfe76_link.apply_vtref(jl, 1800, say=lambda m: None)
        self.assertFalse(r['ok'])
        self.assertIn('Unknown command', r['error'])

    def test_readback_mismatch_is_not_ok(self):
        jl = FakeJLink(measured=3300, follow=False)
        r = sfe76_link.apply_vtref(jl, 1800, say=lambda m: None)
        self.assertFalse(r['ok'])
        self.assertEqual(r['after_mv'], 3300)

    def test_link_default_is_1800(self):
        self.assertEqual(sfe76_link.Link().vtref_mv, 1800)


class HaltSamplerVtref(unittest.TestCase):
    def make(self, mv):
        s = fuzzer.JLinkHaltSampler.__new__(fuzzer.JLinkHaltSampler)
        s.config = NS(jlink_vtref_mv=mv)
        return s

    def test_applies_config_value(self):
        jl = FakeJLink(measured=3300)
        with self.assertLogs(fuzzer.log, 'WARNING') as cm:
            self.make(1800)._apply_vtref(jl)
        self.assertEqual(jl.commands, ['VTREF = 1800'])
        self.assertIn('3300 → 1800', '\n'.join(cm.output))

    def test_failure_warns_and_continues(self):
        jl = FakeJLink(fail='Unknown command')
        with self.assertLogs(fuzzer.log, 'WARNING') as cm:
            self.make(1800)._apply_vtref(jl)
        self.assertIn('고정 실패', '\n'.join(cm.output))

    def test_config_default_is_1800(self):
        self.assertEqual(fuzzer.FuzzConfig.__dataclass_fields__['jlink_vtref_mv'].default, 1800)


if __name__ == '__main__':
    unittest.main()
