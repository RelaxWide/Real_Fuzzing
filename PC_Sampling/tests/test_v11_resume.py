"""Resume environment, product dumps and event-only recovery observations; no hardware."""
import json
from collections import Counter, defaultdict
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from exception_control import ExceptionController, ExceptionFailure, compile_profiles
import test_v11_exceptions as fixtures


class Environment(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.c = ExceptionController(fixtures.options(), {}, '/dev/nvme1', '', Path(self.tmp.name) / 'log')
        self.c.serial = 'DUT'
        self.c.runner = Mock()
        self.ident = {'sn': 'DUT', 'apsta': 1, 'kas': 10}
        self.values = {12: [1, 0], 15: [500, 0], 2: [3, 0]}
        self.writes = []
        self.deadlines = []
        def command(argv, deadline, **kw):
            self.deadlines.append(deadline)
            if argv[1] == 'id-ctrl':
                return 0, json.dumps(self.ident).encode(), b''
            fid = int(argv[argv.index('-f') + 1], 0)
            if argv[1] == 'get-feature':
                val = self.values[fid].pop(0)
                return 0, f'get-feature:{fid:02x} Current value:{val:08x}\n'.encode(), b''
            self.writes.append(fid)
            if fid == 12:
                self.assertEqual(Path(argv[-1]).read_bytes(), bytes(256))
            return 0, b'', b''
        self.c.runner.run.side_effect = command

    def test_fresh_features_are_disabled_and_read_back_under_one_budget(self):
        self.c.restore_nvme_environment()
        self.assertEqual(self.writes, [12, 15, 2])
        self.assertEqual(len(set(self.deadlines)), 1)
        records = [json.loads(x) for x in self.c.log_path.read_text().splitlines()]
        self.assertEqual([r['status'] for r in records], ['VERIFIED'] * 3)
        self.assertTrue(all(call.args[0][2] == '/dev/nvme1' for call in self.c.runner.run.call_args_list))

    def test_unsupported_features_skip_only_with_identify_evidence(self):
        self.ident.update(apsta=0, kas=0)
        self.values[2] = [0, 0]
        self.c.restore_nvme_environment()
        self.assertEqual(self.writes, [])
        self.assertEqual(len(self.c.runner.run.call_args_list), 3)

    def test_readback_failure_stops_before_next_feature(self):
        self.values[12] = [1, 1]
        with self.assertRaisesRegex(ExceptionFailure, 'readback'):
            self.c.restore_nvme_environment()
        self.assertEqual(self.writes, [12])

    def test_identity_failure_prevents_feature_commands(self):
        self.ident['sn'] = 'OTHER'
        with self.assertRaisesRegex(ExceptionFailure, 'serial'):
            self.c.restore_nvme_environment()
        self.assertEqual(self.c.runner.run.call_count, 1)

    def test_unparseable_feature_is_failure_not_unsupported(self):
        self.c.runner.run.side_effect = [(0, json.dumps(self.ident).encode(), b''), (0, b'unknown', b'')]
        with self.assertRaisesRegex(ExceptionFailure, 'cannot read'):
            self.c.restore_nvme_environment()

    def test_recovery_settings_validate_before_device_use(self):
        for key, value in [('recovery_observation_commands', True),
                           ('recovery_observation_commands', -1),
                           ('recovery_observation_sec', float('nan')),
                           ('resume_timeout_sec', 0)]:
            options = fixtures.options()
            options[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                compile_profiles(options, {})


class Integration(unittest.TestCase):
    def setUp(self):
        self.case = fixtures.RealTransportIntegration()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.f = f = self.case.f
        self.seed = self.case.seed
        f._snapshot_crash_context = Mock()
        f._run_ufas_dump = Mock()
        f.crashes_dir = f.output_dir / 'crashes'
        f._exception_controller.runner.pending = []
        f.sampler.openocd_error.is_set.return_value = False
        f.sampler.take_observations.return_value = []
        f.cmd_stats = defaultdict(lambda: {'exec': 0})
        f.rc_stats = defaultdict(Counter)
        f._fw_commit_reset_pending = False

    def test_environment_failure_preserves_without_sampler_reconnect(self):
        f = self.f
        f._exception_controller.restore_nvme_environment.side_effect = ExceptionFailure('feature failed')
        self.assertEqual(self.case.send(), f.RC_EXCEPTION)
        self.assertTrue(f._exception_preserve)
        f.sampler._reinit_target.assert_not_called()
        f._run_ufas_dump.assert_called_once()

    def test_pm_readback_failure_does_not_claim_baseline(self):
        f = self.f
        old = self.case.base.POWER_COMBOS[-1]
        f._current_combo = old
        f.config.pm_inject_prob = 1
        f._detect_pcie_info = Mock()
        f._set_pcie_l_state = Mock(return_value=True)
        f._set_pcie_d_state = Mock(return_value=True)
        f._pcie_bdf, f._pcie_cap_offset = '0000:01:00.0', 0x40
        f._pcie_root_bdf, f._pcie_root_cap_offset = None, None
        f._setpci_read = Mock(return_value=3)
        with self.assertRaisesRegex(ExceptionFailure, 'L0 readback'):
            f._exception_resumed()
        self.assertIs(f._current_combo, old)
        f._exception_controller.restore_nvme_environment.assert_not_called()

    def test_verified_pm_baseline_replaces_old_tracking_without_overwriting_originals(self):
        f = self.f
        f.config.pm_inject_prob = 1
        f._orig_aspm_policy = 'default'
        f._orig_apst_cdw11 = 0
        f._orig_keepalive_val = 100
        f._current_combo = self.case.base.POWER_COMBOS[-1]
        f._detect_pcie_info = Mock(side_effect=lambda: setattr(f, '_orig_aspm_policy', 'powersave'))
        def set_l0(state):
            self.assertEqual(f._orig_aspm_policy, 'default')
            return True
        f._set_pcie_l_state = Mock(side_effect=set_l0)
        f._set_pcie_d_state = Mock(return_value=True)
        f._pcie_bdf, f._pcie_cap_offset = '0000:01:00.0', 0x40
        f._pcie_root_bdf, f._pcie_root_cap_offset = None, None
        f._setpci_read = Mock(return_value=0)
        f._exception_resumed()
        f._exception_controller.restore_nvme_environment.assert_called_once()
        self.assertEqual(f._current_combo, self.case.base.POWER_COMBOS[0])
        self.assertEqual(f._current_ps, 0)
        self.assertEqual((f._orig_apst_cdw11, f._orig_keepalive_val), (0, 100))

    def test_rediscovery_failure_keeps_original_aspm_policy(self):
        f = self.f
        f.config.pm_inject_prob = 1
        f._orig_aspm_policy = 'performance'
        def detect():
            f._orig_aspm_policy = 'powersave'
            raise RuntimeError('PCI read failed')
        f._detect_pcie_info = Mock(side_effect=detect)
        with self.assertRaisesRegex(RuntimeError, 'PCI read failed'):
            f._exception_resumed()
        self.assertEqual(f._orig_aspm_policy, 'performance')
        f._exception_controller.restore_nvme_environment.assert_not_called()

    def test_preserved_state_never_restores_environment(self):
        self.f._exception_preserve = True
        with self.assertRaises(ExceptionFailure):
            self.f._exception_resumed()
        self.f._exception_controller.restore_nvme_environment.assert_not_called()
        self.f.sampler._reinit_target.assert_not_called()

    def test_product_dump_selection_and_failure_isolation(self):
        f = self.f
        order = Mock()
        for name in ('_shutdown_openocd_for_jlink', '_run_jlink_dump', '_run_ufas_dump', '_run_debug_tool_dump'):
            order.attach_mock(getattr(f, name), name)
        f.config.enable_jlink_dump = f.config.enable_ufas = True
        f.config.enable_debug_tool_dump = False
        f._run_jlink_dump.side_effect = RuntimeError('failed dump')
        f._exception_capture('fault')
        self.assertEqual([c[0] for c in order.mock_calls],
                         ['_shutdown_openocd_for_jlink', '_run_jlink_dump', '_run_ufas_dump'])
        self.assertEqual(f._run_jlink_dump.call_args.kwargs['dest_dir'],
                         f._run_ufas_dump.call_args.kwargs['dest_dir'])

    def test_p9_debug_dump_releases_probe_first(self):
        f = self.f
        f.config.enable_ufas = f.config.enable_jlink_dump = False
        f.config.enable_debug_tool_dump = True
        f.sampler.USES_JLINK_USB = True
        order = Mock()
        order.attach_mock(f.sampler.close, 'close')
        order.attach_mock(f._run_debug_tool_dump, 'dump')
        f._exception_capture('fault')
        self.assertEqual([c[0] for c in order.mock_calls], ['close', 'dump'])
        f._run_ufas_dump.assert_not_called()
        f._run_jlink_dump.assert_not_called()

    def test_unstable_supply_prevents_all_dumps(self):
        f = self.f
        f._exception_controller.runner.has_pending.return_value = True
        f._exception_capture('pending supply helper')
        f._run_ufas_dump.assert_not_called()
        f._run_jlink_dump.assert_not_called()
        f._run_debug_tool_dump.assert_not_called()

    def test_first_post_reset_window_is_logged_without_seed_reward_then_recovers(self):
        f = self.f
        self.assertEqual(self.case.send(), f.RC_EXCEPTION)
        f._stop_sampling_checked()
        f._account_command(self.seed, b'', f.RC_EXCEPTION, 0)
        self.case.proc.returncode = 0
        self.assertEqual(self.case.send(), 0)
        f.sampler.current_trace = {123}
        f._stop_sampling_checked()
        self.assertFalse(f._learning_window_valid)
        f._account_command(self.seed, b'', 0, 1)
        f.sampler.evaluate_coverage.assert_not_called()
        rows = [json.loads(x) for x in f._exception_controller.log_path.read_text().splitlines()]
        row = next(r for r in rows if r['phase'] == 'recovery_observation')
        self.assertEqual(row['pcs'], [123])
        self.assertEqual(row['recovery_event'], 'exception-000001')
        self.assertEqual(self.case.send(), 0)
        f._stop_sampling_checked()
        self.assertTrue(f._learning_window_valid)
        self.assertFalse(f._exception_recovery_window)

    def test_recovery_sequence_is_not_published_after_observation_window(self):
        f = self.f
        f._exception_controller.next_at = float('inf')
        f._exception_recovery_remaining = 1
        f._exception_recovery_event = 'event'
        f._seq_sink = dict(commands=[], interesting=True, new_pcs=10)
        self.case.proc.returncode = 0
        self.assertEqual(self.case.send(), 0)
        f._stop_sampling_checked()
        self.assertTrue(f._seq_sink['exception_recovery'])
        from unittest.mock import patch
        def finalize():
            self.assertFalse(f._seq_sink['interesting'])
        with patch.object(self.case.base.NVMeFuzzer, '_finalize_seq_sink', side_effect=finalize):
            f._finalize_seq_sink()

    def test_time_window_and_guard_do_not_consume_command_quota(self):
        from unittest.mock import patch
        f = self.f
        f._exception_controller.next_at = float('inf')
        f._exception_recovery_remaining = 1
        f._excluded_opcodes = {self.seed.cmd.opcode}
        self.assertEqual(self.case.send(), f.RC_SKIP)
        self.assertEqual(f._exception_recovery_remaining, 1)
        f._excluded_opcodes.clear()
        f._exception_recovery_remaining = 0
        f._exception_recovery_until = 100
        self.case.proc.returncode = 0
        with patch('exception_control.time.monotonic', return_value=99):
            self.assertEqual(self.case.send(), 0)
            self.assertTrue(f._exception_recovery_window)
        with patch('exception_control.time.monotonic', return_value=101):
            self.assertEqual(self.case.send(), 0)
            self.assertFalse(f._exception_recovery_window)

    def assert_clean_command_flags(self):
        for name in ('_exception_interrupted', '_exception_window_truncated', '_exception_recovery_window'):
            self.assertFalse(getattr(self.f, name), name)

    def assert_pm_windows_are_independent(self):
        f = self.f
        self.assert_clean_command_flags()
        log = f._exception_controller.log_path
        before = log.read_text() if log.exists() else ''
        f.sampler.global_coverage = set()
        f._seq_sink = dict(commands=[], interesting=True, new_pcs=0)
        for i, slot in enumerate(('combo', 'pcie-bit', 'clkreq', 'forced-idle')):
            f.sampler.start_sampling()
            f.sampler.current_trace = {0x1000 + i}
            _, ok = f._stop_sampling_checked('pm:' + slot)
            self.assertTrue(ok)
            self.assertEqual(f.sampler.current_trace, {0x1000 + i})
            # Same merge the PM caller performs immediately after stop.
            f.sampler.global_coverage.update(f.sampler.current_trace)
            self.assertNotIn('exception_recovery', f._seq_sink)
        self.assertEqual(len(f.sampler.global_coverage), 4)
        self.assertEqual(log.read_text() if log.exists() else '', before)

    def test_accounted_recovery_window_does_not_consume_later_pm_windows(self):
        f = self.f
        f._exception_controller.next_at = float('inf')
        f._exception_recovery_event = 'event'
        f._exception_recovery_remaining = 2
        self.case.proc.returncode = 0
        self.assertEqual(self.case.send(), 0)
        f._stop_sampling_checked()
        f._account_command(self.seed, b'', 0, 0)
        self.assertEqual(f._exception_recovery_remaining, 1)
        self.assert_pm_windows_are_independent()

    def test_accounted_interruption_does_not_consume_later_pm_windows(self):
        f = self.f
        self.assertEqual(self.case.send(), f.RC_EXCEPTION)
        f._stop_sampling_checked()
        f._account_command(self.seed, b'', f.RC_EXCEPTION, 0)
        self.assert_pm_windows_are_independent()

    def test_accounted_missed_window_does_not_consume_later_pm_windows(self):
        f = self.f
        self.case.proc.poll.side_effect = [None, 0]
        self.case.proc.returncode = 0
        self.assertEqual(self.case.send(), 0)
        f._stop_sampling_checked()
        f._account_command(self.seed, b'', 0, 0)
        self.assert_pm_windows_are_independent()

    def test_guard_has_no_recovery_record_or_sequence_mark(self):
        f = self.f
        f._exception_controller.next_at = float('inf')
        f._exception_recovery_remaining = 2
        f._seq_sink = dict(commands=[], interesting=True)
        f._excluded_opcodes = {self.seed.cmd.opcode}
        self.assertEqual(self.case.send(), f.RC_SKIP)
        self.assert_clean_command_flags()
        f._stop_sampling_checked()
        self.assertEqual(f._exception_recovery_remaining, 2)
        self.assertNotIn('exception_recovery', f._seq_sink)
        self.assertFalse(f._exception_controller.log_path.exists())

    def test_account_failure_retires_flags_without_clearing_preservation(self):
        from unittest.mock import patch
        f = self.f
        f._exception_interrupted = f._exception_window_truncated = f._exception_recovery_window = True
        f._exception_preserve = True
        with patch.object(f, '_exception_account_command', side_effect=RuntimeError('write failed')):
            with self.assertRaises(RuntimeError):
                f._account_command(self.seed, b'', f.RC_EXCEPTION, 0)
        self.assert_clean_command_flags()
        self.assertTrue(f._exception_preserve)

    def test_recovery_window_does_not_mask_real_timeout(self):
        f = self.f
        f._exception_controller.next_at = float('inf')
        f._exception_recovery_remaining = 2
        self.case.proc.communicate.side_effect = subprocess.TimeoutExpired('nvme', 8)
        self.assertEqual(self.case.send(), f.RC_TIMEOUT)
        self.assertEqual(f._crash_nvme_pid, 42)
        # The timeout must go through the existing base crash accounting branch.
        from unittest.mock import patch
        with patch.object(self.case.base.NVMeFuzzer, '_account_command', return_value=(False, 0, 'break')) as base:
            self.assertEqual(f._account_command(self.seed, b'', f.RC_TIMEOUT, 0)[2], 'break')
        base.assert_called_once()


if __name__ == '__main__':
    unittest.main()
