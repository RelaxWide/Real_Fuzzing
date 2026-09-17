"""프로브 USB 강제 복구(최후 수단) 시험. 실제 USB 장치를 만지지 않는다.

가짜 sysfs 트리 + ioctl 가로채기로 돈다. 범위를 좁히는 것이 이 기능의 핵심이라
**설정한 vendor id 외의 장치는 건드리지 않는지**를 가장 중요하게 본다.
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from test_v10_2_learning import ROOT, fuzzer      # noqa: F401

sys.path.insert(0, str(ROOT))


def sysfs(root, name, vid, pid, bus, dev):
    d = Path(root) / name
    d.mkdir(parents=True)
    for key, val in (('idVendor', vid), ('idProduct', pid),
                     ('busnum', str(bus)), ('devnum', str(dev))):
        (d / key).write_text(val + '\n', encoding='utf-8')
    return d


def sampler(**over):
    """OpenOCD 샘플러를 __init__ 없이 만들어 복구 메서드만 쓴다."""
    for value in vars(fuzzer).values():
        if isinstance(value, type) and '_probe_usb_recover' in vars(value):
            obj = value.__new__(value)
            return obj
    raise AssertionError('_probe_usb_recover 를 가진 클래스를 찾지 못했습니다')


class FindsOnlyTheConfiguredVendor(unittest.TestCase):
    def test_matches_jlink_and_ignores_everything_else(self):
        with tempfile.TemporaryDirectory() as d:
            sysfs(d, '1-1', '1366', '0101', 1, 5)        # J-Link
            sysfs(d, '1-2', '046d', 'c52b', 1, 6)        # 마우스 — 만지면 안 된다
            sysfs(d, '1-1:1.0', '1366', '0101', 1, 5)    # 인터페이스: busnum 없음
            (Path(d) / '1-1:1.0' / 'busnum').unlink()
            with patch.object(fuzzer, 'PROBE_USB_RESET',
                              {'vendor_ids': ['1366'], 'sysfs_root': d}):
                found = sampler()._probe_usb_devices()
        self.assertEqual([f[1] for f in found], ['1-1'], '다른 장치까지 잡았다')
        self.assertEqual(found[0][0], '/dev/bus/usb/001/005')
        self.assertEqual(found[0][2], '1366:0101')

    def test_missing_sysfs_is_not_fatal(self):
        with patch.object(fuzzer, 'PROBE_USB_RESET',
                          {'vendor_ids': ['1366'], 'sysfs_root': '/nonexistent'}):
            self.assertEqual(sampler()._probe_usb_devices(), [])

    def test_extra_vendor_ids_are_honoured(self):
        with tempfile.TemporaryDirectory() as d:
            sysfs(d, '1-3', '0d28', '0204', 2, 9)        # CMSIS-DAP
            with patch.object(fuzzer, 'PROBE_USB_RESET',
                              {'vendor_ids': ['1366', '0d28'], 'sysfs_root': d}):
                found = sampler()._probe_usb_devices()
        self.assertEqual([f[1] for f in found], ['1-3'])


class ResetsThroughTheIoctl(unittest.TestCase):
    def run_recover(self, d, cfg, ioctl_side_effect=None):
        calls = []

        def fake_ioctl(fd, req, arg):
            calls.append(req)
            if ioctl_side_effect:
                raise ioctl_side_effect
            return 0

        import fcntl
        with patch.object(fuzzer, 'PROBE_USB_RESET', dict(cfg, sysfs_root=d)):
            with patch.object(fcntl, 'ioctl', fake_ioctl), \
                 patch.object(fuzzer.os, 'open', return_value=7), \
                 patch.object(fuzzer.os, 'close'), \
                 patch.object(fuzzer.time, 'sleep'):
                acted = sampler()._probe_usb_recover()
        return acted, calls

    def test_usbdevfs_reset_is_issued_once_per_device(self):
        with tempfile.TemporaryDirectory() as d:
            sysfs(d, '1-1', '1366', '0101', 1, 5)
            sysfs(d, '1-4', '1366', '0101', 1, 7)
            acted, calls = self.run_recover(d, {'enabled': True, 'vendor_ids': ['1366']})
        self.assertTrue(acted)
        self.assertEqual(calls, [0x5514, 0x5514], 'USBDEVFS_RESET 이 아니다')

    def test_disabled_does_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            sysfs(d, '1-1', '1366', '0101', 1, 5)
            acted, calls = self.run_recover(d, {'enabled': False, 'vendor_ids': ['1366']})
        self.assertFalse(acted)
        self.assertEqual(calls, [])

    def test_ioctl_failure_is_reported_not_raised(self):
        with tempfile.TemporaryDirectory() as d:
            sysfs(d, '1-1', '1366', '0101', 1, 5)
            acted, calls = self.run_recover(d, {'enabled': True, 'vendor_ids': ['1366']},
                                            ioctl_side_effect=OSError('EBUSY'))
        self.assertFalse(acted, '실패했는데 복구했다고 보고했다')

    def test_no_probe_found_returns_false(self):
        with tempfile.TemporaryDirectory() as d:
            sysfs(d, '1-2', '046d', 'c52b', 1, 6)
            acted, calls = self.run_recover(d, {'enabled': True, 'vendor_ids': ['1366']})
        self.assertFalse(acted)
        self.assertEqual(calls, [])


class UhubctlOnlyWhenLocationIsGiven(unittest.TestCase):
    """허브 포트 전원을 끊는 것은 위험하다 — 위치를 추측하지 않는다."""

    def recover(self, d, cfg):
        runs = []

        def fake_run(cmd, **kw):
            runs.append(cmd)
            return Mock(returncode=0, stderr=b'')

        with patch.object(fuzzer, 'PROBE_USB_RESET', dict(cfg, sysfs_root=d)):
            with patch.object(fuzzer.subprocess, 'run', fake_run), \
                 patch.object(fuzzer.time, 'sleep'):
                sampler()._probe_usb_recover()
        return runs

    def test_no_location_means_no_uhubctl(self):
        with tempfile.TemporaryDirectory() as d:
            runs = self.recover(d, {'enabled': True, 'vendor_ids': ['1366']})
        self.assertEqual(runs, [], '위치를 안 줬는데 허브 전원을 껐다')

    def test_location_and_port_build_a_cycle_command(self):
        with tempfile.TemporaryDirectory() as d:
            runs = self.recover(d, {'enabled': True, 'vendor_ids': ['1366'],
                                    'uhubctl_location': '1-1', 'uhubctl_port': 2,
                                    'uhubctl_delay_sec': 5})
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0][:8],
                         ['uhubctl', '-l', '1-1', '-p', '2', '-a', 'cycle', '-d'])
        self.assertIn('5', runs[0])

    def test_missing_uhubctl_binary_is_not_fatal(self):
        with tempfile.TemporaryDirectory() as d:
            sysfs(d, '1-1', '1366', '0101', 1, 5)
            with patch.object(fuzzer, 'PROBE_USB_RESET',
                              {'enabled': True, 'vendor_ids': ['1366'], 'sysfs_root': d,
                               'uhubctl_location': '1-1', 'uhubctl_port': 2}):
                with patch.object(fuzzer.subprocess, 'run', side_effect=FileNotFoundError), \
                     patch.object(fuzzer.os, 'open', return_value=7), \
                     patch.object(fuzzer.os, 'close'), \
                     patch.object(fuzzer.time, 'sleep'):
                    import fcntl
                    with patch.object(fcntl, 'ioctl', return_value=0):
                        acted = sampler()._probe_usb_recover()
        self.assertTrue(acted, 'uhubctl 이 없으면 ioctl 로 넘어가야 한다')


class WiredAsTheLastRung(unittest.TestCase):
    def test_reconnect_calls_it_only_after_every_restart_failed(self):
        import ast
        src = (ROOT / 'pc_sampling_fuzzer_v10.3.py').read_text(encoding='utf-8')
        tree = ast.parse(src)
        # _reconnect 는 여러 개다(기반 클래스의 no-op 포함). attempts 를 받는 실물만.
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == '_reconnect'
                  and any(a.arg == 'attempts' for a in n.args.args))
        body = ast.dump(fn)
        self.assertIn('_probe_usb_recover', body, '사다리에 배선되지 않았다')
        # 재시도 루프(For) 뒤에 와야 한다 — 매 시도마다 USB 를 리셋하면 안 된다
        loop = next(i for i, node in enumerate(fn.body) if isinstance(node, ast.For))
        after = ast.dump(ast.Module(body=fn.body[loop + 1:], type_ignores=[]))
        self.assertIn('_probe_usb_recover', after, '루프 안에서 부르고 있다')

    def test_config_ships_the_block_disabled_uhubctl(self):
        import json
        g = json.loads((ROOT / 'fuzzer_config.json').read_text(encoding='utf-8'))['globals']
        blk = g['probe_usb_reset']
        self.assertTrue(blk['enabled'])
        self.assertEqual(blk['vendor_ids'], ['1366'])
        self.assertIsNone(blk['uhubctl_location'], '허브 위치 기본값이 있으면 위험하다')
        self.assertIsNone(blk['uhubctl_port'])


if __name__ == '__main__':
    unittest.main()
