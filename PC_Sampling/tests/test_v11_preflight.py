"""PCIe 5.0-driven preflight, fake sysfs/PMU only. No device operations."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pc_sampling_fuzzer_v11 import ExceptionController, ExceptionFailure, compile_profiles
from pc_sampling_fuzzer_v11 import gpio_value, pci_method_support, subsystem_support
from test_v11_exceptions import options


class Discovery(unittest.TestCase):
    def test_gpio_known_output_and_no_ambiguous_success(self):
        self.assertEqual(gpio_value('[GetGpio][OK]D1] 1\n'), 1)
        self.assertEqual(gpio_value(b'[GetGpio][OK]D1] 0'), 0)
        for value in ('1', '[GetGpio][FAIL]D1] 1', '[GetGpio][OK]D2] 1',
                      '[GetGpio][OK]D1] 1\n[GetGpio][OK]D1] 0'):
            with self.assertRaises(ValueError):
                gpio_value(value)

    def test_flr_not_inferred_from_other_reset_method(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            device = root / '0000:02:00.0'
            device.mkdir()
            (device / 'reset').touch()
            (device / 'reset_method').write_text('bus pm')
            self.assertEqual(pci_method_support(device.name, 'flr', root)[0], 'UNSUPPORTED')
            (device / 'reset_method').write_text('flr bus')
            self.assertEqual(pci_method_support(device.name, 'flr', root)[0], 'AVAILABLE')
            self.assertEqual(pci_method_support(device.name, 'bus', root)[0], 'AVAILABLE')
            (root / '0000:02:00.1').mkdir()
            self.assertEqual(pci_method_support(device.name, 'bus', root)[0], 'UNSUPPORTED')

    def test_nssr_requires_capability_and_single_controller(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ctrl = root / 'nvme0'
            ctrl.mkdir()
            (ctrl / 'address').write_text('0000:02:00.0')
            (ctrl / 'subsysnqn').write_text('nqn.test')
            self.assertEqual(subsystem_support(0, '0000:02:00.0', root)[0], 'UNSUPPORTED')
            self.assertEqual(subsystem_support(1 << 36, '0000:02:00.0', root)[0], 'AVAILABLE')
            other = root / 'nvme1'
            other.mkdir()
            (other / 'address').write_text('0000:03:00.0')
            (other / 'subsysnqn').write_text('nqn.test')
            self.assertEqual(subsystem_support(1 << 36, '0000:02:00.0', root)[0], 'UNSUPPORTED')


class Preflight(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        opts = options()
        opts['profiles'] += [dict(name='flr', body=[dict(action='flr')],
                                 timeout_sec=1, ready_timeout_sec=0.2)]
        self.c = ExceptionController(opts, {}, '/dev/nvme0', 'missing.py', Path(self.tmp.name) / 'events')
        self.c.serial, self.c.bdf = 'SERIAL', '0000:02:00.0'
        self.c.wait_ready = Mock()
        self.c._run_profile = Mock()
        self.c.runner = Mock()
        self.c.runner.run.return_value = (0, b'{"sn":"SERIAL"}', b'')
        self.c.runner.has_pending.return_value = False
        self.before, self.resumed = Mock(), Mock()

    def test_only_passed_profiles_scheduled(self):
        self.c.capability = Mock(side_effect=[('AVAILABLE', 'ok'), ('UNSUPPORTED', 'no flr')])
        self.c.preflight(self.before, self.resumed)
        self.assertEqual([p.name for p in self.c.profiles], ['ctrl'])
        self.assertEqual(self.c.preflight_results['ctrl']['status'], 'PASS')
        self.assertEqual(self.c.preflight_results['flr']['status'], 'UNSUPPORTED')
        self.assertEqual(self.c._run_profile.call_count, 1)
        self.assertEqual(self.resumed.call_count, 1)
        self.assertEqual(self.c.preflight_results['refclk_toggle']['status'], 'UNCONFIGURED')

    def test_active_trial_fault_stops_instead_of_skipping_as_unsupported(self):
        self.c.capability = Mock(return_value=('AVAILABLE', 'ok'))
        self.c._run_profile.side_effect = ExceptionFailure('RDY timeout')
        with self.assertRaisesRegex(ExceptionFailure, 'RDY'):
            self.c.preflight(self.before, self.resumed)
        self.assertEqual(self.c._run_profile.call_count, 1)
        self.assertEqual(self.c.capability.call_count, 1)
        self.assertFalse(self.c.due())
        self.resumed.assert_not_called()
        self.assertEqual(self.c.last_result['outcome'], 'preserved_failure')

    def test_identify_failure_after_rdy_not_pass(self):
        self.c.capability = Mock(return_value=('AVAILABLE', 'ok'))
        self.c.runner.run.return_value = (0, b'{"sn":"OTHER"}', b'')
        with self.assertRaisesRegex(ExceptionFailure, 'Identify'):
            self.c.preflight(self.before, self.resumed)
        self.resumed.assert_not_called()

    def test_sampler_failure_stops_and_preserves(self):
        self.c.capability = Mock(return_value=('AVAILABLE', 'ok'))
        self.resumed.side_effect = ExceptionFailure('OpenOCD unavailable')
        with self.assertRaises(ExceptionFailure):
            self.c.preflight(self.before, self.resumed)
        self.assertNotEqual(self.c.preflight_results['ctrl']['status'], 'PASS')
        self.assertFalse(self.c.due())

    def test_all_unavailable_keeps_fuzzer_without_injection(self):
        self.c.capability = Mock(return_value=('UNSUPPORTED', 'no path'))
        self.c.preflight(self.before, self.resumed)
        self.assertEqual(self.c.profiles, [])
        self.assertFalse(self.c.due())
        self.before.assert_not_called()

    def test_disabled_trial_is_not_labelled_pass(self):
        self.c.options['preflight'] = dict(enabled=False)
        self.c.capability = Mock(return_value=('AVAILABLE', 'path'))
        self.c.preflight(self.before, self.resumed)
        self.assertEqual(self.c.preflight_results['ctrl']['status'], 'UNVERIFIED')
        self.c._run_profile.assert_not_called()

    def test_multiple_trials_run_before_pass(self):
        self.c.options['preflight'] = dict(attempts_per_kind=2)
        self.c.capability = Mock(side_effect=[('AVAILABLE', 'ok'), ('UNSUPPORTED', 'no')])
        self.c.preflight(self.before, self.resumed)
        self.assertEqual(self.c._run_profile.call_count, 2)
        self.assertEqual(self.resumed.call_count, 2)


class HardwareAdapters(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = json.loads((Path(__file__).resolve().parents[1] / 'fuzzer_config.json').read_text())
        self.c = ExceptionController(self.cfg['exceptions'], self.cfg, '/dev/nvme0', 'pmu.py',
                                     Path(self.tmp.name) / 'log')
        self.c.runner = Mock()
        self.c.runner.has_pending.return_value = False
        self.c.bdf = '0000:02:00.0'

    def with_readback(self):
        # 기본 config 에는 readback 이 없다(보드에서 GPIO 읽기 실패 → 링크 다운으로 효과 확인).
        #   adapter 에 명시하면 여전히 엄격하게 확인한다.
        for name, want in (('perst_assert', 0), ('perst_release', 1)):
            self.c.options['adapters'][name]['readback'] = dict(
                argv=['python3', '{pmu_script}', '20', '1', '7'], expected=want)

    def test_default_config_has_no_gpio_readback(self):
        self.assertTrue(all('readback' not in a for a in self.cfg['exceptions']['adapters'].values()))
        self.c.runner.run.return_value = (0, b'', b'')
        self.c._action('perst_assert', self.c.clock() + 1)
        self.assertEqual(self.c.runner.run.call_count, 1)          # 16 만, 20(readback) 없음

    def test_perst_readback_is_verified(self):
        self.with_readback()
        self.c.runner.run.side_effect = [(0, b'', b''), (0, b'[GetGpio][OK]D1] 0', b'')]
        self.c._action('perst_assert', self.c.clock() + 1)
        self.assertTrue(self.c.asserted)
        self.assertEqual(self.c.runner.run.call_args.args[0][-3:], ['20', '1', '7'])

    def test_release_readback_mismatch_retains_cleanup_obligation(self):
        self.with_readback()
        self.c.asserted = True
        self.c.runner.run.side_effect = [(0, b'', b''), (0, b'[GetGpio][OK]D1] 0', b'')]
        with self.assertRaisesRegex(ExceptionFailure, 'mismatch'):
            self.c._action('perst_release', self.c.clock() + 1)
        self.assertTrue(self.c.asserted)

    def test_malformed_release_readback_keeps_asserted_uncertain(self):
        self.with_readback()
        self.c.asserted = True
        self.c.runner.run.side_effect = [(0, b'', b''), (0, b'unrecognized reply', b'')]
        with self.assertRaises(ValueError):
            self.c._action('perst_release', self.c.clock() + 1)
        self.assertTrue(self.c.asserted)

    def test_post_on_rescan_inherits_same_ready_deadline(self):
        from pc_sampling_fuzzer_v11 import Profile
        now = [10.0]
        self.c.clock = lambda: now[0]
        calls = []
        def act(action, deadline):
            calls.append((action, deadline))
            now[0] += 0.1
        self.c._action = act
        self.c.wait_ready = Mock()
        self.c._run_profile(Profile('p', (('power_on', 0), ('pci_rescan', 0)), 60, 2))
        self.assertEqual(calls, [('power_on', 12.0), ('pci_rescan', 12.0)])
        self.assertEqual(self.c.wait_ready.call_args.args[0], 12.0)

    def test_power_on_does_not_release_perst(self):
        self.c.powered, self.c.asserted = False, True
        self.c.runner.run.return_value = (0, b'', b'')
        self.c._action('power_on', self.c.clock() + 1)
        self.assertTrue(self.c.powered)
        self.assertTrue(self.c.asserted)
        self.assertEqual(self.c.runner.run.call_args.args[0][2:], ['4', '1', '3300', '0', '12000', '0', '0'])

    def test_pending_pci_remove_does_not_prevent_supply_only_restore(self):
        from pc_sampling_fuzzer_v11 import CommandRunner
        runner = CommandRunner(Mock())
        runner.pending = [Mock(_exception_supply_control=False, poll=Mock(return_value=None))]
        self.assertTrue(runner.has_pending())
        self.assertFalse(runner.has_pending(supply_only=True))
        runner.pending.append(Mock(_exception_supply_control=True, poll=Mock(return_value=None)))
        self.assertTrue(runner.has_pending(supply_only=True))

    def test_timed_out_custom_adapter_blocks_supply_restore(self):
        from pc_sampling_fuzzer_v11 import CommandRunner
        for argv in (['gpioset', 'gpiochip0', '7=0'], ['helper', '--script=pmu.py']):
            with self.subTest(argv=argv):
                self.c.options['adapters']['custom_assert'] = dict(argv=argv, effect='assert')
                self.c.runner = CommandRunner(Mock())
                proc = Mock(pid=42, poll=Mock(return_value=None))
                proc.wait.side_effect = __import__('subprocess').TimeoutExpired(argv, 1)
                with patch('pc_sampling_fuzzer_v11.subprocess.Popen', return_value=proc) as launch:
                    with self.assertRaises(__import__('subprocess').TimeoutExpired):
                        self.c._action('custom_assert', self.c.clock() + 1)
                    with self.assertRaises(ExceptionFailure):
                        self.c.restore_supply()
                    self.assertEqual(launch.call_count, 1)
                proc.poll.return_value = 0
                self.assertFalse(self.c.runner.has_pending(supply_only=True))

    def test_por_budgets_follow_existing_json(self):
        cfg = copy.deepcopy(self.cfg)
        cfg['power']['por_boot_wait'] = 23
        cfg['power']['por_poweroff_wait'] = 4
        profiles = {p.name: p for p in compile_profiles(cfg['exceptions'], cfg)}
        for name in ('normal_por', 'sudden_por'):
            self.assertEqual(profiles[name].ready_timeout_sec, 23)
            self.assertIn(4, [hold for _, hold in profiles[name].steps])
        self.assertEqual(profiles['normal_por'].steps[0][0], 'pci_remove')
        self.assertEqual(profiles['sudden_por'].steps[0][0], 'power_off')

    def test_exact_pci_reset_method_no_fallback_and_restore_in_child(self):
        self.c.runner.run.return_value = (0, b'', b'')
        with patch('pc_sampling_fuzzer_v11.pci_method_support', return_value=('AVAILABLE', 'ok')):
            self.c._action('flr', self.c.clock() + 1)
        args = self.c.runner.run.call_args.args[0]
        self.assertEqual(args[-1], 'flr')
        self.assertIn('finally: m.write_text(old)', args[2])
        self.assertIn("(p/'reset').write_text('1')", args[2])

    def test_pci_method_disappearance_not_silently_replaced(self):
        with patch('pc_sampling_fuzzer_v11.pci_method_support', return_value=('UNSUPPORTED', 'gone')):
            with self.assertRaisesRegex(ExceptionFailure, 'gone'):
                self.c._action('flr', self.c.clock() + 1)
        self.c.runner.run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
