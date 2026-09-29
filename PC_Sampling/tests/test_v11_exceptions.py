"""v11: simulated resets only. No NVMe, PMU, sysfs writes or OpenOCD needed."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pc_sampling_fuzzer_v11 import (compile_profiles, csts_ready, ExceptionController,
                               ExceptionFailure, ExceptionFuzzerMixin, CommandRunner)


def options():
    return dict(enabled=True, min_interval_minutes=2, initial_delay_minutes=0,
                profiles=[dict(name='ctrl', body=[dict(action='controller_reset')],
                               timeout_sec=1, ready_timeout_sec=0.2)])


def power_options():
    opts = options()
    opts['adapters'] = {name: dict(argv=['pmu', name], effect=effect) for name, effect in
                       [('off', 'power_off'), ('on', 'power_on'),
                        ('assert', 'assert'), ('release', 'deassert'), ('prepare', 'none')]}
    opts['restore_actions'] = ['on', 'release']
    opts['profiles'] = [dict(name='partial', prefix=[dict(action='prepare')],
                            body=[dict(action='assert'), dict(action='release')], repeat=3,
                            suffix=[dict(action='wait')], timeout_sec=1,
                            ready_timeout_ref='power.por_boot_wait')]
    return opts


class Profiles(unittest.TestCase):
    def test_prefix_suffix_once_only_body_repeated(self):
        profile, = compile_profiles(power_options(), {'power': {'por_boot_wait': 0.1}})
        self.assertEqual([s[0] for s in profile.steps],
                         ['prepare', 'assert', 'release', 'assert', 'release', 'assert', 'release', 'wait'])
        self.assertEqual(profile.ready_timeout_sec, 0.1)

    def test_existing_por_value_is_not_copied_or_extended(self):
        opts = power_options()
        self.assertEqual(compile_profiles(opts, {'power': {'por_boot_wait': 0.05}})[0].ready_timeout_sec, 0.05)
        with self.assertRaises(KeyError):
            compile_profiles(opts, {})

    def test_unconfigured_hardware_rejected(self):
        opts = options()
        opts['profiles'][0]['body'] = [dict(action='perst')]
        with self.assertRaises(ValueError):
            compile_profiles(opts, {})

    def test_invalid_repetition_and_nan_rejected(self):
        for repeat in (0, -1, True, 1.5, 10001):
            opts = options()
            opts['profiles'][0]['repeat'] = repeat
            with self.assertRaises(ValueError):
                compile_profiles(opts, {})
        opts = options()
        opts['profiles'][0]['timeout_sec'] = float('nan')
        with self.assertRaises(ValueError):
            compile_profiles(opts, {})

    def test_power_off_requires_cleanup_and_timeout_reference(self):
        opts = power_options()
        row = opts['profiles'][0]
        row['body'] = [dict(action='off'), dict(action='on')]
        opts['restore_actions'] = []
        with self.assertRaises(ValueError):
            compile_profiles(opts, {'power': {'por_boot_wait': 1}})
        opts['restore_actions'] = ['on']
        row.pop('ready_timeout_ref')
        with self.assertRaises(ValueError):
            compile_profiles(opts, {})

    def test_profile_cannot_end_off_or_asserted(self):
        for action in ('off', 'assert'):
            opts = power_options()
            opts['profiles'][0]['body'] = [dict(action=action)]
            with self.assertRaises(ValueError):
                compile_profiles(opts, {'power': {'por_boot_wait': 1}})

    def test_waits_cannot_consume_entire_budget(self):
        opts = options()
        opts['profiles'][0]['body'][0]['hold_sec'] = 1
        with self.assertRaises(ValueError):
            compile_profiles(opts, {})

    def test_csts_ready_and_fatal_status(self):
        for value, expected in [(0, False), (1, True), (3, False), ('0x1', True), (0xffffffff, False)]:
            self.assertEqual(csts_ready(json.dumps({'csts': value}))[0], expected)
        for value in (None, True, {}, -1):
            with self.assertRaises(ValueError):
                csts_ready(json.dumps({'csts': value}))


class Events(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ctrl = ExceptionController(options(), {}, '/dev/nvme0', 'pmu.py',
                                        Path(self.tmp.name) / 'events.jsonl')
        self.ctrl.next_at = 0
        self.ctrl.runner = Mock()
        self.ctrl.runner.run.return_value = (0, b'', b'')
        self.ctrl.runner.has_pending.return_value = False
        self.ctrl.wait_ready = Mock()
        self.proc = Mock(pid=123, returncode=1)
        self.proc.poll.return_value = None
        self.proc.communicate.return_value = (b'partial response', b'command aborted')
        self.before = Mock()
        self.resumed = Mock()

    def records(self):
        return [json.loads(line) for line in self.ctrl.log_path.read_text().splitlines()]

    def execute(self):
        return self.ctrl.execute(self.proc, {'command': 'FormatNVM'}, self.before, self.resumed)

    def test_any_command_injected_and_aborted_result_preserved(self):
        result = self.execute()
        self.assertEqual(result['outcome'], 'resumed')
        self.assertEqual(self.ctrl.runner.run.call_args.args[0], ['nvme', 'reset', '/dev/nvme0'])
        self.assertEqual(self.resumed.call_count, 1)
        row = next(r for r in self.records() if r['phase'] == 'interrupted_command')
        self.assertEqual(row['rc'], 1)
        self.assertIn('aborted', row['stderr'])
        self.assertFalse(self.ctrl.due())
        self.proc.kill.assert_not_called()

    def test_no_due_has_no_side_effects(self):
        self.ctrl.next_at = float('inf')
        self.assertIsNone(self.execute())
        self.before.assert_not_called()
        self.ctrl.runner.run.assert_not_called()

    def test_finished_command_cancels_late_injection(self):
        self.proc.poll.return_value = 0
        self.assertIsNone(self.execute())
        self.ctrl.runner.run.assert_not_called()
        self.assertFalse(self.ctrl.due())

    def test_completion_during_before_does_not_reset_next_command(self):
        self.proc.poll.side_effect = [None, 0]
        self.assertEqual(self.execute()['outcome'], 'missed_window')
        self.ctrl.runner.run.assert_not_called()

    def test_ready_failure_no_retry_reset_no_resume(self):
        self.ctrl.wait_ready.side_effect = ExceptionFailure('not ready')
        with self.assertRaises(ExceptionFailure):
            self.execute()
        self.assertEqual(self.ctrl.runner.run.call_count, 1)
        self.resumed.assert_not_called()
        self.proc.kill.assert_not_called()
        self.assertIsNone(self.ctrl.active)
        self.assertEqual(self.ctrl.last_result['outcome'], 'preserved_failure')

    def test_failed_reset_not_reported_as_recovered(self):
        self.ctrl.runner.run.return_value = (1, b'', b'ioctl failed')
        with self.assertRaisesRegex(ExceptionFailure, 'ioctl failed'):
            self.execute()
        self.ctrl.wait_ready.assert_not_called()
        self.resumed.assert_not_called()

    def test_original_ioctl_still_pending_stops_campaign(self):
        self.proc.communicate.side_effect = subprocess.TimeoutExpired('nvme', 0.2)
        with self.assertRaisesRegex(ExceptionFailure, 'original command'):
            self.execute()
        self.resumed.assert_not_called()
        self.proc.kill.assert_not_called()

    def test_sampler_failure_is_recorded_without_another_reset(self):
        self.resumed.side_effect = ExceptionFailure('sampler')
        with self.assertRaises(ExceptionFailure):
            self.execute()
        self.assertEqual(self.ctrl.runner.run.call_count, 1)

    def test_ctrl_c_preserved_and_cleanup_attempted(self):
        self.ctrl.runner.run.side_effect = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.execute()
        self.assertEqual(self.ctrl.last_result['outcome'], 'interrupted')
        self.assertIsNone(self.ctrl.active)

    def test_restore_only_on_release_no_off_or_reset(self):
        self.ctrl.options = power_options()
        self.ctrl.powered = False
        self.ctrl.asserted = True
        self.ctrl.restore_supply()
        self.assertEqual([c.args[0] for c in self.ctrl.runner.run.call_args_list],
                         [['pmu', 'on'], ['pmu', 'release']])
        self.ctrl.runner.run.reset_mock()
        self.ctrl.restore_supply()
        self.ctrl.runner.run.assert_not_called()

    def test_pending_hardware_helper_cannot_race_cleanup(self):
        self.ctrl.options = power_options()
        self.ctrl.powered = False
        self.ctrl.runner.has_pending.return_value = True
        with self.assertRaisesRegex(ExceptionFailure, 'still running'):
            self.ctrl.restore_supply()
        self.ctrl.runner.run.assert_not_called()

    def test_por_budget_starts_before_on_helper(self):
        opts = power_options()
        opts['profiles'][0].update(prefix=[], body=[dict(action='off'), dict(action='on')],
                                   suffix=[], repeat=1)
        ticks = [10.0]
        c = ExceptionController(opts, {'power': {'por_boot_wait': 0.2}}, '/dev/nvme0', 'pmu.py',
                                Path(self.tmp.name) / 'power.jsonl', clock=lambda: ticks[0])
        c.next_at = 0
        c.runner = Mock()
        c.runner.has_pending.return_value = False
        def action(argv, deadline, **kwargs):
            if argv[-1] == 'on':
                ticks[0] += 0.1
            return 0, b'', b''
        c.runner.run.side_effect = action
        c.wait_ready = Mock()
        c.execute(self.proc, {}, self.before, self.resumed)
        self.assertAlmostEqual(c.wait_ready.call_args.args[0], 10.2)


class Readiness(unittest.TestCase):
    def test_requires_same_dut_live_and_rdy(self):
        with tempfile.TemporaryDirectory() as d:
            ctrl = ExceptionController(options(), {}, '/dev/nvme0', '', Path(d) / 'log')
            ctrl.sysfs = Path(d)
            ctrl.serial, ctrl.bdf = 'SERIAL', '0000:02:00.0'
            for key, value in [('serial', ctrl.serial), ('address', ctrl.bdf), ('state', 'live')]:
                (Path(d) / key).write_text(value)
            ctrl.runner = Mock()
            ctrl.runner.run.return_value = (0, b'{"csts": 1}', b'')
            with patch('pc_sampling_fuzzer_v11.Path.exists', return_value=True):
                ctrl.wait_ready(ctrl.clock() + 0.2)
            (Path(d) / 'serial').write_text('OTHER')
            with self.assertRaisesRegex(ExceptionFailure, 'identity'):
                ctrl.wait_ready(ctrl.clock() + 0.2)

    def test_rdy_zero_times_out_not_success(self):
        with tempfile.TemporaryDirectory() as d:
            ctrl = ExceptionController(options(), {}, '/dev/nvme0', '', Path(d) / 'log')
            ctrl.sysfs = Path(d)
            ctrl.serial, ctrl.bdf = 'S', 'B'
            for key, value in [('serial', 'S'), ('address', 'B'), ('state', 'live')]:
                (Path(d) / key).write_text(value)
            ctrl.runner = Mock()
            ctrl.runner.run.return_value = (0, b'{"csts":0}', b'')
            with patch('pc_sampling_fuzzer_v11.Path.exists', return_value=True):
                with self.assertRaisesRegex(ExceptionFailure, '준비 시간 초과.*RDY=0.*gate=controller_rdy'):
                    ctrl.wait_ready(ctrl.clock() + 0.01)


class MixinIntegration(unittest.TestCase):
    def harness(self):
        class Base:
            def _account_command(self, *args, **kwargs):
                self.base_accounts += 1
                return False, 0, 'continue'
            def _learning_observe(self, *args, **kwargs):
                self.seen_preserve = self._learning_sequence['preserve']
            def _recover_after_unsupported_skip(self):
                raise AssertionError('must not execute POR')
        class Fuzzer(ExceptionFuzzerMixin, Base):
            pass
        f = Fuzzer.__new__(Fuzzer)
        f._exception_controller = Mock()
        f._exception_sequence_events = []
        f._exception_interrupted = True
        f._exception_preserve = False
        f._learning_sequence = None
        f.executions = f.base_accounts = 0
        f.stats = {}
        f.sampler = Mock(current_trace=set())
        return f

    def test_interrupted_account_not_success_or_seed_failure_next_account_normal(self):
        f = self.harness()
        seed = NS(cmd=NS(name='Sanitize'))
        self.assertEqual(f._account_command(seed, b'', f.RC_EXCEPTION, 0)[2], 'continue')
        self.assertEqual(f.base_accounts, 0)
        self.assertEqual(f.stats['exception_interrupted'], 1)
        f._account_command(seed, b'', 0, 0)
        self.assertEqual(f.base_accounts, 1)

    def test_stale_marker_cannot_swallow_timeout_or_normal_account(self):
        for rc in (-1001, 0):
            f = self.harness()
            f._account_command(NS(cmd=NS(name='Identify')), b'', rc, 0)
            self.assertEqual(f.base_accounts, 1)
            self.assertNotIn('exception_interrupted', f.stats)

    def test_interrupted_stop_drains_worker_and_observations(self):
        f = self.harness()
        f.sampler.current_trace.add(123)
        self.assertEqual(f._stop_sampling_checked(), (0, True))
        f.sampler.stop_sampling.assert_called_once()
        f.sampler._stop_worker.assert_called_once()
        f.sampler.take_observations.assert_called_once()
        self.assertEqual(f.sampler.current_trace, set())

    def test_sequence_preservation_does_not_abort_later_steps(self):
        f = self.harness()
        state = dict(preserve=True, setup_ok=False, exception_events=['e1'])
        f._learning_sequence = state
        f._learning_observe()
        self.assertFalse(f.seen_preserve)
        self.assertTrue(state['preserve'])
        self.assertFalse(state['setup_ok'])

    def test_legacy_por_is_intercepted(self):
        f = self.harness()
        f._exception_capture = Mock()
        self.assertFalse(f._recover_after_unsupported_skip())
        f._exception_capture.assert_called_once()

    def test_failure_skips_old_sampler_recovery(self):
        f = self.harness()
        f._exception_preserve = True
        self.assertEqual(f._stop_sampling_checked(), (0, False))


class Runner(unittest.TestCase):
    def test_timeout_does_not_call_unbounded_communicate_or_assume_kill(self):
        runner = CommandRunner(Mock())
        proc = Mock(pid=42)
        proc.wait.side_effect = subprocess.TimeoutExpired('reset', 0.1)
        proc.poll.return_value = None
        with patch('pc_sampling_fuzzer_v11.subprocess.Popen', return_value=proc):
            with self.assertRaises(subprocess.TimeoutExpired):
                runner.run(['nvme', 'reset', '/dev/nvme0'], __import__('time').monotonic() + 0.1)
        self.assertTrue(runner.has_pending())
        proc.communicate.assert_not_called()
        proc.kill.assert_not_called()



class RealTransportIntegration(unittest.TestCase):
    """Exercise the standalone v11 transport and exception mixin."""
    def setUp(self):
        from test_v10_2_learning import harness
        import pc_sampling_fuzzer_v11 as fuzzer
        from collections import Counter, deque
        self.base = fuzzer
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cls = fuzzer.NVMeFuzzer
        self.f = cls.__new__(cls)
        self.f.__dict__.update(harness().__dict__)
        f = self.f
        f.config = fuzzer.FuzzConfig()
        f.output_dir = Path(self.tmp.name)
        f._exception_controller = ExceptionController(options(), {}, '/dev/nvme0', '', f.output_dir / 'events')
        f._exception_controller.next_at = 0
        f._exception_controller.runner = Mock()
        f._exception_controller.runner.run.return_value = (0, b'', b'')
        f._exception_controller.runner.has_pending.return_value = False
        f._exception_controller.restore_nvme_environment = Mock()
        f._current_combo = fuzzer.POWER_COMBOS[0]
        f._orig_aspm_policy = 'default'
        f.config.pm_inject_prob = 0
        f._shutdown_openocd_for_jlink = Mock()
        f._run_jlink_dump = Mock()
        f._run_debug_tool_dump = Mock()
        f._exception_controller.wait_ready = Mock()
        f._exception_preserve = f._exception_interrupted = False
        f._exception_pm_depth = f._exception_epoch = 0
        f._exception_sequence_events = []
        f._max_xfer_bytes = Mock(return_value=131072)
        f._excluded_opcodes = set()
        f._cmd_history = deque()
        f._nvme_input_path = None
        f.actual_nsid_dist = Counter()
        f.sampler = Mock(INVASIVE=False, current_trace=set())
        f.sampler._reinit_target.return_value = True
        f.executions = 0
        self.proc = Mock(pid=42, returncode=1)
        self.proc.poll.return_value = None
        self.proc.communicate.return_value = (b'', b'aborted')
        self.seed = fuzzer.Seed(data=b'', cmd=next(c for c in fuzzer.NVME_COMMANDS if c.name == 'Identify'))

    def send(self):
        with patch.object(self.base.subprocess, 'Popen', return_value=self.proc):
            return self.f._send_nvme_command(b'', self.seed)

    def test_actual_transport_injects_and_next_normal_timeout_is_restored(self):
        f = self.f
        self.assertEqual(self.send(), f.RC_EXCEPTION)
        self.assertEqual(f._stop_sampling_checked(), (0, True))
        self.assertEqual(f._account_command(self.seed, b'', f.RC_EXCEPTION, 0)[2], 'continue')
        self.proc.communicate.side_effect = subprocess.TimeoutExpired('nvme', 8)
        self.assertEqual(self.send(), f.RC_TIMEOUT)
        self.assertEqual(f._crash_nvme_pid, 42)
        self.proc.kill.assert_not_called()

    def test_real_failure_path_dumps_without_killing_command_or_power_reset(self):
        f = self.f
        f.crashes_dir = f.output_dir / 'crashes'
        f._exception_controller.runner.pending = []
        f._exception_controller.wait_ready.side_effect = ExceptionFailure('RDY deadline')
        f._snapshot_crash_context = Mock()
        f._run_ufas_dump = Mock()
        f.config.enable_ufas = True
        f._handle_timeout_crash = Mock()
        self.assertEqual(self.send(), f.RC_EXCEPTION)
        self.assertTrue(f._exception_preserve)
        self.assertTrue(f._timeout_crash)
        self.assertEqual(f._stop_sampling_checked(), (0, False))
        f._handle_timeout_crash.assert_not_called()
        f._run_ufas_dump.assert_called_once()
        self.proc.kill.assert_not_called()
        self.assertEqual(f._exception_controller.runner.run.call_count, 1)
        evidence = list(f.crashes_dir.glob('*/exception.json'))
        self.assertEqual(len(evidence), 1)
        self.assertIn('RDY deadline', evidence[0].read_text())

    def test_exception_disabled_uses_original_transport(self):
        self.f._exception_controller = None
        self.proc.returncode = 0
        self.assertEqual(self.send(), 0)
        self.assertEqual(self.proc.communicate.call_count, 1)
        self.assertGreater(self.proc.communicate.call_args.kwargs['timeout'], 8)

    def test_pm_transition_does_not_inject(self):
        self.f._exception_pm_depth = 1
        self.proc.returncode = 0
        self.assertEqual(self.send(), 0)
        self.f._exception_controller.runner.run.assert_not_called()

    def test_interrupted_sequence_keeps_remaining_steps_and_setup_not_success(self):
        f = self.f
        remaining = [self.seed, self.seed]
        f._pending_seq_seeds = remaining
        f._learning_sequence = dict(index=0, length=3, preserve=True, setup_ok=True, executed=[])
        f._seq_sink = dict(commands=[], interesting=False, new_pcs=0)
        self.assertEqual(self.send(), f.RC_EXCEPTION)
        f._stop_sampling_checked()
        f._account_command(self.seed, b'', f.RC_EXCEPTION, 0, seq_member=True)
        self.assertIs(f._pending_seq_seeds, remaining)
        self.assertEqual(len(remaining), 2)
        self.assertFalse(f._learning_sequence['setup_ok'])
        self.assertEqual(len(f._learning_sequence['executed']), 1)
        self.assertEqual(len(f._seq_sink['commands']), 1)

    def test_unaccounted_interruption_does_not_leak_to_next_send(self):
        self.assertEqual(self.send(), self.f.RC_EXCEPTION)
        self.f._stop_sampling_checked()
        self.proc.communicate.side_effect = subprocess.TimeoutExpired('nvme', 8)
        self.assertEqual(self.send(), self.f.RC_TIMEOUT)
        self.assertFalse(self.f._exception_interrupted)
        self.assertEqual(self.f._crash_nvme_pid, 42)

    def test_resumed_updates_state_monitor_device(self):
        self.f.state_monitor = self.base.NVMeStateMonitor('/dev/nvme0', [])
        self.f._exception_controller.device = '/dev/nvme1'
        self.f._exception_resumed()
        self.assertEqual(self.f.config.nvme_device, '/dev/nvme1')
        self.assertEqual(self.f.state_monitor._device, '/dev/nvme1')

    def test_completion_after_sampler_stop_is_unobservable_not_zero_reward(self):
        from collections import defaultdict, Counter
        f = self.f
        self.seed.prov_id = 42
        f.learning.register(42, 'new_group_seeds', {})
        f.cmd_stats = defaultdict(lambda: {'exec': 0})
        f.rc_stats = defaultdict(Counter)
        f._fw_commit_reset_pending = False
        f.sampler.openocd_error.is_set.return_value = False
        f.sampler.current_trace = {123}
        self.proc.poll.side_effect = [None, 0]
        self.proc.returncode = 0
        self.assertEqual(self.send(), 0)
        f._exception_controller.runner.run.assert_not_called()
        f._stop_sampling_checked()
        self.assertFalse(f._learning_window_valid)
        self.assertEqual(f.sampler.current_trace, set())
        self.assertEqual(f._account_command(self.seed, b'', 0, 0)[2], 'continue')
        self.assertEqual(f.learning.proposals[42]['evaluated'], 0)
        self.assertFalse(f.learning.recent[-1]['observable'])
        self.assertEqual(f.learning.recent[-1]['submission'], 'completion')
        self.assertEqual(f.stats['coverage_unobserved'], 1)
        self.assertNotIn('exception_interrupted', f.stats)
        label = f._tracking_label(self.seed.cmd, self.seed)
        self.assertEqual(f.cmd_stats[label]['coverage_unobserved'], 1)
        self.assertEqual(f.rc_stats[label][0], 1)
        f.sampler.evaluate_coverage.assert_not_called()
        self.proc.poll.side_effect = None
        self.proc.poll.return_value = 0
        self.assertEqual(self.send(), 0)
        f._stop_sampling_checked()
        self.assertFalse(f._exception_window_truncated)
        self.assertTrue(f._learning_window_valid)

    def test_completion_before_sampler_stop_keeps_valid_window(self):
        self.proc.poll.return_value = 0
        self.proc.returncode = 0
        self.f.sampler.openocd_error.is_set.return_value = False
        self.assertEqual(self.send(), 0)
        self.f._stop_sampling_checked()
        self.assertTrue(self.f._learning_window_valid)
        self.assertFalse(self.f._exception_window_truncated)
        self.f.sampler._stop_worker.assert_not_called()


class CampaignRegression(unittest.TestCase):
    def test_calibration_interruption_then_real_timeout_is_captured(self):
        import pc_sampling_fuzzer_v11 as fuzzer
        with tempfile.TemporaryDirectory() as d:
            cls = fuzzer.NVMeFuzzer
            config = fuzzer.FuzzConfig(no_jlink=True, rag_enabled=False, state_enabled=False,
                                       output_dir=d, calibration_runs=2)
            with patch.object(cls, '_load_static_analysis'), patch.object(cls, '_load_riscv_coverage'):
                f = cls(config)
            seed = fuzzer.Seed(data=b'', cmd=fuzzer._NAME_TO_CMD['Identify'])
            f._send_nvme_command = Mock(side_effect=[f.RC_EXCEPTION, f.RC_TIMEOUT])
            f._stop_sampling_checked = Mock(return_value=(0, True))
            f._handle_timeout_crash = Mock()
            f._learning_observe = Mock()
            f._ledger_write = Mock()
            f._calibrate_seed(seed)
            f._handle_timeout_crash.assert_called_once_with(seed, seed.data)
            self.assertEqual(f._learning_observe.call_count, 1)
            self.assertEqual(f.stats['exception_interrupted'], 1)

    def test_truncated_calibration_excludes_only_incomplete_observation(self):
        import pc_sampling_fuzzer_v11 as fuzzer
        with tempfile.TemporaryDirectory() as d:
            cls = fuzzer.NVMeFuzzer
            config = fuzzer.FuzzConfig(no_jlink=True, rag_enabled=False, state_enabled=False,
                                       output_dir=d, calibration_runs=2)
            with patch.object(cls, '_load_static_analysis'), patch.object(cls, '_load_riscv_coverage'):
                f = cls(config)
            seed = fuzzer.Seed(data=b'', cmd=fuzzer._NAME_TO_CMD['Identify'])
            windows = iter([(True, 123), (False, 456)])
            def send(*args):
                f._exception_window_truncated, pc = next(windows)
                f.sampler.current_trace = {pc}
                f._last_nvme_status = 0
                return 0
            f._send_nvme_command = Mock(side_effect=send)
            f._learning_observe = Mock()
            f._ledger_write = Mock()
            f._calibrate_seed(seed)
            self.assertEqual(seed.covered_pcs, {456})
            self.assertEqual(seed.stable_pcs, {456})
            self.assertEqual(f.stats['coverage_unobserved'], 1)
            self.assertEqual([call.args[3] for call in f._learning_observe.call_args_list],
                             [set(), {456}])
            self.assertTrue(f._learning_window_valid)

    def test_calibration_completion_retires_flags_before_pm(self):
        import pc_sampling_fuzzer_v11 as fuzzer
        for mode in ('interrupted', 'truncated', 'recovery'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d:
                cls = fuzzer.NVMeFuzzer
                config = fuzzer.FuzzConfig(no_jlink=True, rag_enabled=False, state_enabled=False,
                                           output_dir=d, calibration_runs=1)
                with patch.object(cls, '_load_static_analysis'), patch.object(cls, '_load_riscv_coverage'):
                    f = cls(config)
                f._exception_controller = Mock()
                f._exception_recovery_event = 'old-event'
                seed = fuzzer.Seed(data=b'', cmd=fuzzer._NAME_TO_CMD['Identify'])
                def send(*args):
                    f._exception_interrupted = mode == 'interrupted'
                    f._exception_window_truncated = mode == 'truncated'
                    f._exception_recovery_window = mode == 'recovery'
                    f.sampler.current_trace = {123}
                    f._last_nvme_status = 0
                    return f.RC_EXCEPTION if mode == 'interrupted' else 0
                f._send_nvme_command = Mock(side_effect=send)
                f._ledger_write = Mock()
                f._calibrate_seed(seed)
                self.assertFalse(f._exception_interrupted)
                self.assertFalse(f._exception_window_truncated)
                self.assertFalse(f._exception_recovery_window)
                f._exception_controller.emit.reset_mock()
                f.sampler.current_trace = {456}
                f._seq_sink = dict(commands=[], interesting=True)
                f._stop_sampling_checked('pm:combo')
                self.assertEqual(f.sampler.current_trace, {456})
                self.assertNotIn('exception_recovery', f._seq_sink)
                f._exception_controller.emit.assert_not_called()

    def run_ast(self):
        import ast
        import pc_sampling_fuzzer_v11 as fuzzer
        tree = ast.parse(Path(fuzzer.__file__).read_text())
        base = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == '_V101Fuzzer')
        return ast, fuzzer, next(n for n in base.body if isinstance(n, ast.FunctionDef) and n.name == 'run')

    def test_fw_chunk_loop_stops_at_interruption(self):
        ast, module, run = self.run_ast()
        loop = next(n for n in ast.walk(run) if isinstance(n, ast.For)
                    and isinstance(n.target, ast.Name) and n.target.id == '_chunk_seed')
        seed = NS(data=b'firmware')
        f = NS(_fw_chunks=[seed, seed], RC_TIMEOUT=-1001, RC_ERROR=-1002, RC_EXCEPTION=-1011,
               _send_nvme_command=Mock(return_value=-1011))
        for rc, truncated in ((-1011, False), (0, True)):
            f._send_nvme_command = Mock(return_value=rc)
            f._exception_window_truncated = truncated
            env = {'self': f}
            exec(compile(ast.Module(body=[loop], type_ignores=[]), '<actual-fw-loop>', 'exec'), env)
            f._send_nvme_command.assert_called_once()
            self.assertIs(env['_acct_seed'], seed)
            self.assertEqual(env['rc'], rc)

    def test_preflight_interrupt_and_preserved_exit_run_final_cleanup(self):
        from unittest.mock import MagicMock
        ast, module, run = self.run_ast()
        protected = next(n for n in run.body if isinstance(n, ast.Try) and n.finalbody)
        for preserved in (False, True):
            with self.subTest(preserved=preserved), tempfile.TemporaryDirectory() as d:
                f = MagicMock()
                f._wp_held_nsid = None
                f._timeout_crash = preserved
                f._exception_preserve = preserved
                f.output_dir = Path(d)
                f._learning_baseline.side_effect = KeyboardInterrupt
                f._collect_stats.side_effect = RuntimeError('no stats in harness')
                env = dict(vars(module), self=f)
                with patch('signal.signal'):
                    exec(compile(ast.Module(body=[protected], type_ignores=[]), '<actual-run-cleanup>', 'exec'), env)
                f._learning_baseline.assert_called_once_with('fuzz_start')
                f._learning_save.assert_called_with(force=True)
                f.sampler.save_coverage.assert_called_once()
                f.sampler.close.assert_called_once()
                f._monitor_timeout_pc.assert_not_called()
                if preserved:
                    f._apst_restore.assert_not_called()
                    f._keepalive_restore.assert_not_called()
                    f._restore_nvme_timeouts.assert_not_called()
                else:
                    f._apst_restore.assert_called_once()
                    f._keepalive_restore.assert_called_once()
                    f._restore_nvme_timeouts.assert_called_once()

    def test_real_preflight_interrupt_preserves_before_campaign_cleanup(self):
        ast, module, run = self.run_ast()
        protected = next(n for n in run.body if isinstance(n, ast.Try) and n.finalbody)
        class Base:
            def _learning_baseline(self, phase):
                return None
        class Harness(ExceptionFuzzerMixin, Base):
            pass
        f = Harness.__new__(Harness)
        for node in ast.walk(protected):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == 'self'
                    and node.func.attr not in ('_learning_baseline', '_exception_user_interrupt')):
                setattr(f, node.func.attr, Mock())
        f._exception_preserve = f._timeout_crash = False
        f._wp_held_nsid = None
        f._exception_controller = Mock()
        f._exception_controller.preflight.side_effect = KeyboardInterrupt
        f.sampler = Mock()
        f._collect_stats.side_effect = RuntimeError('no stats in harness')
        with tempfile.TemporaryDirectory() as d, patch('signal.signal'):
            f.output_dir = Path(d)
            exec(compile(ast.Module(body=[protected], type_ignores=[]), '<actual-run-cleanup>', 'exec'),
                 dict(vars(module), self=f))
        self.assertTrue(f._exception_preserve)
        self.assertTrue(f._timeout_crash)
        f._exception_controller.restore_supply.assert_called()
        f._log_smart.assert_not_called()
        f._apst_restore.assert_not_called()
        f._keepalive_restore.assert_not_called()
        f._restore_nvme_timeouts.assert_not_called()
        f.sampler.close.assert_called_once()
        f._learning_save.assert_called_with(force=True)
        f.sampler.save_coverage.assert_called_once()

if __name__ == '__main__':
    unittest.main()
