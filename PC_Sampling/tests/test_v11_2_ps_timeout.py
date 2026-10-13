"""Real send path with mocked subprocess; no device access or wall-clock waits."""
import subprocess
import unittest
import test_v11_exceptions as integration


class PowerTimeout(unittest.TestCase):
    setUp = integration.RealTransportIntegration.setUp
    send = integration.RealTransportIntegration.send

    def prepare(self, product='BM9K1', ps=0):
        self.f.config.product = product
        self.f._current_ps = ps
        self.f._exception_controller = None
        # Disable the hook to avoid subtracting real Python call time in exact deadline checks.
        self.f._exception_on_spawn = None
        self.proc.returncode = 0

    def test_actual_wait_by_product_ps_and_json_group(self):
        for product in ('BM9K1', 'PM9M1'):
            for ps in (0, 1, 2):
                for group, base_ms in (('command', 8000), ('command', 1700), ('verify', 22000)):
                    with self.subTest(product=product, ps=ps, group=group, base_ms=base_ms):
                        self.prepare(product, ps)
                        self.seed.cmd = next(c for c in self.base.NVME_COMMANDS
                                             if c.name == 'Identify')
                        # Use a separate command object to avoid mutating global command definitions.
                        import dataclasses
                        self.seed.cmd = dataclasses.replace(self.seed.cmd, timeout_group=group)
                        self.f.config.nvme_timeouts[group] = base_ms
                        self.assertEqual(self.send(), 0)
                        expected = (base_ms * {0: 1, 1: 10, 2: 10}[ps] / 1000
                                    if product == 'BM9K1' else
                                    (base_ms + self.base.PS_ENTRY_EXIT_MARGIN_MS) / 1000 + 2)
                        self.assertAlmostEqual(self.proc.communicate.call_args.kwargs['timeout'], expected)

    def test_timeout_preserves_process_and_logs_tracked_ps(self):
        self.prepare(ps=2)
        self.f.config.nvme_timeouts['command'] = 8000
        self.proc.communicate.side_effect = subprocess.TimeoutExpired('nvme', 80)
        with self.assertLogs('pcfuzz', level='INFO') as logs:
            self.assertEqual(self.send(), self.f.RC_TIMEOUT)
        self.assertIn('tracked_ps=PS2 base=8000ms factor=10', '\n'.join(logs.output))
        self.assertEqual(self.proc.communicate.call_args.kwargs['timeout'], 80)
        self.proc.kill.assert_not_called()

    def test_successful_power_seed_updates_next_command_only(self):
        self.prepare(ps=0)
        self.f.config.nvme_timeouts['command'] = 8000
        self.seed.opcode_override = 0x09  # actual opcode, not original Identify
        self.seed.cdw10, self.seed.cdw11 = 2, 1
        self.assertEqual(self.send(), 0)
        self.assertEqual(self.proc.communicate.call_args.kwargs['timeout'], 8)
        self.assertEqual(self.f._current_ps, 1)
        self.seed.opcode_override = None
        self.assertEqual(self.send(), 0)
        self.assertEqual(self.proc.communicate.call_args.kwargs['timeout'], 80)
        self.seed.opcode_override = 0x09
        self.seed.cdw11 = 2
        self.proc.returncode = 1
        self.assertEqual(self.send(), 1)
        self.assertEqual(self.f._current_ps, 1)

    def test_partial_combo_failure_restores_pre_entry_ps(self):
        import test_v11_2_pm_detach as pm
        from collections import deque
        f, events = pm.engine()
        f.config.product = 'BM9K1'
        f._cmd_history = deque()
        f._pm_nvme_run = unittest.mock.Mock(return_value=pm.OK)
        # Use the real low-level PS setter, including its new tracking update.
        f._pm_set_state = self.base._V101Fuzzer._pm_set_state.__get__(f)
        def partial_entry(combo):
            self.assertTrue(f._pm_set_state(combo.nvme_ps))
            self.assertEqual(f._current_ps, 4)
            return False  # PS succeeded, PCIe transition failed
        f._set_power_combo.side_effect = partial_entry
        self.assertTrue(f._pm_detached_combo(pm.PS4_L12))
        self.assertEqual(f._current_ps, 1)
        self.assertEqual(f._current_combo, pm.OP)
        self.assertIn('--cdw11=0x1', f._pm_nvme_run.call_args.args[0])

    def test_failed_entry_does_not_restore_into_deep_ps(self):
        # Tracked PS can be deep after a fuzzed SetFeatures; never reattach after "restoring" to it.
        import test_v11_2_pm_detach as pm
        for tracked, expected in ((4, 1), (3, 1), (2, 2), (0, 0)):
            with self.subTest(tracked=tracked):
                f, events = pm.engine()
                f._current_ps, f._prev_op_ps = tracked, 1
                f._set_power_combo.side_effect = lambda combo: False
                self.assertTrue(f._pm_detached_combo(pm.OP2))
                f._pm_set_state.assert_called_once_with(expected)
                self.assertEqual(events[-1], 'attach')

    def test_por_recovery_resets_tracked_ps(self):
        from types import SimpleNamespace
        from unittest.mock import MagicMock, patch
        import test_v11_2_pm_detach as pm
        for pm_on in (True, False):
            with self.subTest(pm_on=pm_on):
                f = self.base._V101Fuzzer.__new__(self.base._V101Fuzzer)
                f.config = SimpleNamespace(pmu_script='pmu.py', por_poweroff_wait=0, boot_sweep_s=0,
                                           clkreq_voltage_mv=3300, no_jlink=True,
                                           pm_inject_prob=1 if pm_on else 0)
                f._crash_nvme_pid = None
                f._current_ps, f._current_combo = 2, pm.OP2
                f.sampler = MagicMock()
                for name in ('_probe_device', '_detect_pcie_info', '_set_pcie_l_state',
                             '_apst_disable', '_keepalive_disable'):
                    setattr(f, name, MagicMock())
                f._por_remove_target = MagicMock(return_value=None)
                f._por_pcie_rescan = MagicMock(return_value=True)
                # APST is turned off after the reset, so the tracker must already be PS0 by then.
                f._apst_disable.side_effect = lambda *a, **k: self.assertEqual(f._current_ps, 0)
                done = SimpleNamespace(returncode=0, stderr=b'', stdout=b'')
                with patch.object(self.base.os.path, 'isfile', return_value=True), \
                        patch.object(self.base.subprocess, 'run', return_value=done), \
                        patch.object(self.base.time, 'sleep'):
                    self.assertTrue(f._recover_after_unsupported_skip())
                self.assertEqual(f._current_ps, 0)
                self.assertEqual(f._current_combo,
                                 self.base.POWER_COMBOS[0] if pm_on else pm.OP2)
                f._por_pcie_rescan.return_value = False
                f._current_ps = 2
                with patch.object(self.base.os.path, 'isfile', return_value=True), \
                        patch.object(self.base.subprocess, 'run', return_value=done), \
                        patch.object(self.base.time, 'sleep'):
                    self.assertFalse(f._recover_after_unsupported_skip())
                self.assertEqual(f._current_ps, 2)  # failed recovery: state unknown, keep

    def test_pm_set_state_updates_only_on_success(self):
        self.prepare(ps=2)
        self.f._pm_nvme_run = unittest.mock.Mock(return_value=self.base._StateProc(0, b'', b''))
        self.assertTrue(self.f._pm_set_state(0))
        self.assertEqual(self.f._current_ps, 0)
        self.f._pm_nvme_run.return_value = self.base._StateProc(1, b'', b'failed')
        self.assertFalse(self.f._pm_set_state(1))
        self.assertEqual(self.f._current_ps, 0)


if __name__ == '__main__':
    unittest.main()
