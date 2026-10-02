"""v11.1 — 장치 소실(커널이 컨트롤러를 버림)을 일반 errno 실패로 흘리지 않고 불량 캡처로 넘긴다.

2026-10 실측: 'Interrupted system call' → 'No such device' → 'Resource temporarily unavailable'
이 이어지고 퍼저는 같은 실패만 끝없이 찍었다(dmesg: Disabling device after reset failure: -19).
"""
import io
import unittest
from pathlib import Path
from unittest.mock import patch

from test_v10_2_learning import fuzzer

STATE = '/sys/class/nvme/nvme0/state'


def obj():
    o = fuzzer.NVMeFuzzer.__new__(fuzzer.NVMeFuzzer)
    o._ctrl_device = lambda: '/dev/nvme0'
    return o


def fake_open(states):
    it = iter(states)
    real = open

    def _open(path, *a, **k):
        if path == STATE:
            v = next(it)
            if v is None:
                raise FileNotFoundError(path)
            return io.StringIO(v + '\n')
        return real(path, *a, **k)
    return _open


class DeviceLost(unittest.TestCase):
    def check(self, text, states, settle=0.0):
        with patch('builtins.open', fake_open(states)), patch.object(fuzzer.time, 'sleep'):
            return obj()._check_device_lost(text, settle_sec=settle)

    def test_ordinary_errno_does_not_probe(self):
        self.assertIsNone(self.check('msg="Invalid argument"', []))

    def test_live_controller_is_not_lost(self):
        self.assertIsNone(self.check('msg="passthru: Interrupted system call"', ['live']))

    def test_missing_controller_is_lost(self):
        self.assertIn('사라짐', self.check('msg="No such device"', [None]))

    def test_dead_controller_is_lost(self):
        self.assertIn('dead', self.check('msg="Resource temporarily unavailable"', ['dead']))

    def test_transient_reset_recovering_is_not_lost(self):
        self.assertIsNone(self.check('msg="Interrupted system call"',
                                     ['resetting', 'resetting', 'live'], settle=60.0))

    def test_reset_that_never_finishes_is_lost(self):
        r = self.check('msg="Interrupted system call"', ['resetting'] * 1000, settle=0.0)
        self.assertIn('resetting', r)

    def test_send_path_routes_to_crash_capture(self):
        src = Path(fuzzer.__file__).read_text(encoding='utf-8')
        self.assertIn('_lost = self._check_device_lost(_status_info)', src)
        self.assertIn('reason=("device_lost"', src)


if __name__ == '__main__':
    unittest.main()
