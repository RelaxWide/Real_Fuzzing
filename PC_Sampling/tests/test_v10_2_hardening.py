"""Deployment/config/window-lifetime/storage regressions, with no device access."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from test_v10_2_learning import ROOT, fuzzer, harness
from llm_learning import LearningState


class DeploymentTests(unittest.TestCase):
    def test_missing_learning_module_exits_with_deployment_hint(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ('pc_sampling_fuzzer_v10.2.py', 'nvme_seeds.py', 'fuzzer_config.json'):
                shutil.copy2(ROOT / name, Path(d) / name)
            result = subprocess.run([sys.executable, str(Path(d) / 'pc_sampling_fuzzer_v10.2.py'), '--help'],
                                    cwd=d, env=dict(os.environ, PYTHONPATH=''),
                                    capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('[FATAL]', result.stderr)
        self.assertIn('llm_learning.py', result.stderr)
        self.assertNotIn('Traceback', result.stderr)

    def test_unknown_config_keys_warn_and_do_not_enter_options(self):
        with self.assertLogs('llm_learning', level='WARNING') as logs:
            state = LearningState({'future_knob': {'enabled': True}, 'evaluation_commands': 3})
        self.assertIn('rag.learning.future_knob', '\n'.join(logs.output))
        self.assertNotIn('future_knob', state.options)
        self.assertEqual(state.options['evaluation_commands'], 3)

    def test_config_errors_name_the_key_and_precede_base_initialization(self):
        for config, key in [({'setup_preserve_ratio': 2}, 'setup_preserve_ratio'),
                            ({'evaluation_commands': 0}, 'evaluation_commands'),
                            ({'enabled': 'yes'}, 'enabled'),
                            ({'snapshot_min_interval_sec': -1}, 'snapshot_min_interval_sec'),
                            ({'snapshot_min_interval_sec': float('nan')}, 'snapshot_min_interval_sec'),
                            ([], 'rag.learning'), (False, 'rag.learning')]:
            with self.subTest(config=config), \
                    patch.object(fuzzer.NVMeFuzzer, '_learning_config', config), \
                    patch.object(fuzzer._V101Fuzzer, '__init__') as initialize:
                with self.assertRaises(SystemExit) as caught:
                    fuzzer.NVMeFuzzer(None)
                self.assertIn('[FATAL]', str(caught.exception))
                self.assertIn(key, str(caught.exception))
                initialize.assert_not_called()

    def test_invalid_config_process_has_no_traceback(self):
        # Import only, then call a deliberately invalid constructor. Base initialization
        # must not run; no actual device configuration is supplied.
        code = ("import runpy,sys; sys.argv=[sys.argv[1]]; "
                "m=runpy.run_path(sys.argv[0]); c=m['NVMeFuzzer']; "
                "c._learning_config={'setup_preserve_ratio':2}; c(None)")
        result = subprocess.run([sys.executable, '-c', code, str(ROOT / 'pc_sampling_fuzzer_v10.2.py')],
                                capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('[FATAL]', result.stderr)
        self.assertIn('rag.learning.setup_preserve_ratio=2', result.stderr)
        self.assertNotIn('Traceback', result.stderr)


class WindowLifetimeTests(unittest.TestCase):
    def make_fuzzer(self):
        obj = harness()
        obj.sampler.start_sampling = Mock()
        obj._learning_attach_sampler()
        seed = fuzzer.Seed(data=b'x', cmd=fuzzer._NAME_TO_CMD['Write'], prov_id=1)
        obj.learning.register(1, 'new_group_seeds', {})
        return obj, seed

    def test_window_without_send_cannot_attribute_failure_to_previous_seed(self):
        obj, seed = self.make_fuzzer()
        obj._learning_last_send = (seed, 1.5)
        obj._learning_account_send = (seed, 1.5)
        obj.sampler.start_sampling()  # Next window does not send a command.
        self.assertIsNone(obj._learning_last_send)
        self.assertIsNone(obj._learning_account_send)
        with patch.object(fuzzer._V101Fuzzer, '_stop_sampling_checked', return_value=(0, False)):
            obj._stop_sampling_checked('command:Write')  # Same prefix/name as old command.
        self.assertEqual(obj.learning.proposals[1]['attempts'], 0)
        self.assertEqual(obj.learning.recent, obj.learning.recent.__class__(maxlen=256))

    def test_repeated_stop_records_a_failed_send_only_once(self):
        obj, seed = self.make_fuzzer()
        obj._learning_last_send = (seed, 1.5)
        with patch.object(fuzzer._V101Fuzzer, '_stop_sampling_checked', return_value=(0, False)):
            obj._stop_sampling_checked('command:Write')
            obj._stop_sampling_checked('command:Write')
        self.assertEqual(obj.learning.proposals[1]['attempts'], 1)
        self.assertEqual(obj.learning.tasks['new_group_seeds']['device_seconds'], 1.5)
        self.assertEqual(obj.learning.tasks['new_group_seeds']['rewards'], [])
        self.assertIsNone(obj._learning_last_send)
        self.assertIsNone(obj._learning_account_send)

    def test_successful_stop_preserves_duration_until_accounting(self):
        obj, seed = self.make_fuzzer()
        obj._learning_last_send = (seed, 1.5)
        with patch.object(fuzzer._V101Fuzzer, '_stop_sampling_checked', return_value=(1, True)):
            obj._stop_sampling_checked('command:Write')
        self.assertIsNone(obj._learning_last_send)
        obj._learning_observe(seed, 0, 0, {100}, 1, 'c1', False)
        self.assertEqual(obj.learning.recent[-1]['device_seconds'], 1.5)
        self.assertIsNone(obj._learning_account_send)

    def test_guard_skip_does_not_create_a_send_for_failure_attribution(self):
        obj, seed = self.make_fuzzer()
        with patch.object(fuzzer._V101Fuzzer, '_send_nvme_command', return_value=obj.RC_SKIP):
            self.assertEqual(obj._send_nvme_command(seed.data, seed), obj.RC_SKIP)
        self.assertIsNone(obj._learning_last_send)
        with patch.object(fuzzer._V101Fuzzer, '_stop_sampling_checked', return_value=(0, False)):
            obj._stop_sampling_checked('command:Write')
        self.assertEqual(obj.learning.proposals[1]['attempts'], 0)

    def test_new_send_clears_previous_record_and_handles_exception(self):
        obj, old = self.make_fuzzer()
        seed = fuzzer.Seed(data=b'y', cmd=fuzzer._NAME_TO_CMD['Read'])
        obj._learning_last_send = (old, 5)
        def send(instance, data, current):
            self.assertIsNone(instance._learning_last_send)
            instance.sampler.start_sampling()
            return 0
        with patch.object(fuzzer._V101Fuzzer, '_send_nvme_command', autospec=True, side_effect=send):
            obj._send_nvme_command(seed.data, seed)
        self.assertIs(obj._learning_last_send[0], seed)
        with patch.object(fuzzer._V101Fuzzer, '_send_nvme_command', side_effect=OSError('test')):
            with self.assertRaises(OSError):
                obj._send_nvme_command(seed.data, seed)
        self.assertIsNone(obj._learning_last_send)


class SnapshotTests(unittest.TestCase):
    def test_throttle_skips_serialization_and_force_keeps_final_data(self):
        obj = harness()
        obj._learning_save = fuzzer.NVMeFuzzer._learning_save.__get__(obj)
        clock = [100.0]
        with tempfile.TemporaryDirectory() as d, \
                patch('llm_learning.time.monotonic', side_effect=lambda: clock[0]), \
                patch.object(obj.learning, 'snapshot', wraps=obj.learning.snapshot) as snapshot:
            obj.output_dir = Path(d)
            self.assertTrue(obj._learning_save())
            obj.learning.counts['latest'] = 7
            clock[0] = 159.0
            self.assertFalse(obj._learning_save())
            self.assertEqual(snapshot.call_count, 1)
            clock[0] = 160.0
            self.assertTrue(obj._learning_save())
            obj.learning.counts['latest'] = 8
            self.assertTrue(obj._learning_save(force=True))
            self.assertEqual(snapshot.call_count, 3)
            saved = json.loads((Path(d) / 'llm/learning_v10.2.json').read_text())
            self.assertEqual(saved['counts']['latest'], 8)

    def test_exit_forces_save_even_after_base_exception(self):
        obj = harness()
        with patch.object(fuzzer._V101Fuzzer, 'run', side_effect=RuntimeError('test')):
            with self.assertRaises(RuntimeError):
                obj.run()
        obj._learning_save.assert_called_once_with(force=True)

    def test_write_failure_does_not_cause_continuous_retry(self):
        obj = harness()
        obj._learning_save = fuzzer.NVMeFuzzer._learning_save.__get__(obj)
        obj.output_dir = Path('/not-used')
        with patch('llm_learning.time.monotonic', return_value=100), \
                patch.object(Path, 'mkdir', side_effect=OSError('disk full')) as mkdir:
            self.assertFalse(obj._learning_save())
            self.assertFalse(obj._learning_save())
            self.assertEqual(mkdir.call_count, 1)

    def test_maximum_generator_coverage_round_trips_and_is_throttled(self):
        obj = harness()
        obj._learning_save = fuzzer.NVMeFuzzer._learning_save.__get__(obj)
        for i in range(128):
            obj.learning.generators[f'g{i}'] = dict(
                rule={}, executions=1, new_coverage=0,
                coverage={(i << 48) + j for j in range(4096)}, coverage_truncated=False)
        with tempfile.TemporaryDirectory() as d:
            obj.output_dir = Path(d)
            started = time.perf_counter()
            self.assertTrue(obj._learning_save())
            elapsed = time.perf_counter() - started
            path = Path(d) / 'llm/learning_v10.2.json'
            saved = json.loads(path.read_text())
            self.assertEqual(sum(len(g['coverage']) for g in saved['generators'].values()), 128 * 4096)
            print(f'\nSnapshot 128x4096: {path.stat().st_size} bytes, {elapsed:.3f}s')
            with patch.object(obj.learning, 'snapshot', side_effect=AssertionError('must throttle')):
                self.assertFalse(obj._learning_save())


if __name__ == '__main__':
    unittest.main()
