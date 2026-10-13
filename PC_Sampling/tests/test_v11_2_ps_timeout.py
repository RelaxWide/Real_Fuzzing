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
                        expected = (base_ms * {0: 1, 1: 16, 2: 64}[ps] / 1000
                                    if product == 'BM9K1' else
                                    (base_ms + self.base.PS_ENTRY_EXIT_MARGIN_MS) / 1000 + 2)
                        self.assertAlmostEqual(self.proc.communicate.call_args.kwargs['timeout'], expected)

    def test_timeout_preserves_process_and_logs_tracked_ps(self):
        self.prepare(ps=2)
        self.f.config.nvme_timeouts['command'] = 8000
        self.proc.communicate.side_effect = subprocess.TimeoutExpired('nvme', 512)
        with self.assertLogs('pcfuzz', level='INFO') as logs:
            self.assertEqual(self.send(), self.f.RC_TIMEOUT)
        self.assertIn('tracked_ps=PS2 base=8000ms factor=64', '\n'.join(logs.output))
        self.assertEqual(self.proc.communicate.call_args.kwargs['timeout'], 512)
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
        self.assertEqual(self.proc.communicate.call_args.kwargs['timeout'], 128)
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
