"""Reset/POR 판정 경계. 가짜 시계·레지스터·runner만 사용하며 장치에 접근하지 않는다."""
import json
import subprocess
import unittest
from unittest.mock import Mock, patch

from test_v11_timing import v, DUT, RP, controller, FakeMon, FakeSys, profile, ROOT
import test_v11_nssr as nssr
Runner = nssr.Runner


class ConfigAccess(unittest.TestCase):
    def setUp(self):
        self.c = controller(self)
        self.c.root_bdf = RP
        self.now = 0.0
        self.c.clock = lambda: self.now
        self.sleep = patch.object(v.time, 'sleep', side_effect=self.advance)
        self.sleep.start()
        self.addCleanup(self.sleep.stop)

    def advance(self, seconds):
        self.now += seconds

    def test_waits_after_link_up_and_restarts_on_drop(self):
        def link(_):
            return not (self.now < .02 or .07 <= self.now < .09)
        with patch.object(v, '_link_active', side_effect=link):
            self.c._wait_config_access(1)
        self.assertGreaterEqual(self.now, .19)
        self.assertLess(self.now, .21)

    def test_unknown_or_down_never_issues_rescan(self):
        self.c.runner.run = Mock()
        for state in (None, False):
            self.now = 0
            with patch.object(v, '_link_active', return_value=state):
                with self.assertRaises(v.ExceptionFailure):
                    self.c._rescan_until_present(.05)
        self.c.runner.run.assert_not_called()

    def test_monitor_does_not_probe_dut_config_during_reset(self):
        m = v.RecoveryMonitor(DUT, RP, 'SN', bar=Mock())
        m._dllla = Mock(return_value=True)
        m._vendor_ok = Mock(side_effect=AssertionError('early DUT access'))
        m.sample_cfg()
        m._vendor_ok.assert_not_called()
        self.assertIsNone(m.status()['cfg_ok'])

    def test_unsupported_dllla_is_unknown_even_if_status_bit_set(self):
        fs = FakeSys()
        self.addCleanup(fs.tmp.cleanup)
        path = fs.rp_real / 'config'
        cfg = bytearray(path.read_bytes())
        cfg[0x4C:0x50] = bytes(4)
        path.write_bytes(cfg)
        self.assertIsNone(v._link_active(RP, pci=fs.pci))

    def test_cfg_timing_unmeasured_is_not_spec_pass(self):
        m = FakeMon({'link_down': 0, 'link_up': .1, 'cc_en': .2, 'rdy': .21, 'live': .22})
        m.observe_config = False
        self.c._timing_wait(profile('reset'), m, 0, 'reset')
        rows = [json.loads(s) for s in self.c.log_path.read_text().splitlines()]
        cfg = next(r for r in rows[-1]['rows'] if r['key'] == 'cfg_after_ts')
        self.assertEqual(cfg['verdict'], 'N/A')


class FirmwareActivation(unittest.TestCase):
    setUp = nssr.NssrSequence.setUp
    run_nssr = nssr.NssrSequence.run_nssr
    def test_pending_activation_allows_zero_nssro_without_claiming_verification(self):
        r = Runner(self.fs, self.bus, csts_after=0)
        r.fw_log = bytes([0x21]) + bytes(511)
        err, text = self.run_nssr(r)
        self.assertIsNone(err)
        self.assertIn('활성화 예정', text)
        self.assertIn('NSSRO 확인 불가', text)
        self.assertIn('drivers_probe', r.log)

    def test_unknown_activation_does_not_blame_device(self):
        r = Runner(self.fs, self.bus, csts_after=0)
        r.fw_log = b''
        err, text = self.run_nssr(r)
        self.assertIsNone(err)
        self.assertIn('상태 미확인', text)

    def test_cfs_still_fails_with_pending_activation(self):
        r = Runner(self.fs, self.bus, csts_after=2)
        r.fw_log = bytes([0x21]) + bytes(511)
        err, _ = self.run_nssr(r)
        self.assertIn('CFS=1', str(err))
        self.assertNotIn('drivers_probe', r.log)

    def test_firmware_log_timeout_never_unbinds_or_rebinds(self):
        self.c.runner.run = Mock(side_effect=subprocess.TimeoutExpired('nvme get-log', 1))
        with self.assertRaises(subprocess.TimeoutExpired):
            self.c._nssr(self.c.clock() + 1)
        self.assertEqual(self.c.runner.run.call_count, 1)

    def test_nssr_first_config_probe_is_after_gate(self):
        r = Runner(self.fs, self.bus)
        checked = []
        real = self.c._config_valid
        self.c._wait_config_access = lambda deadline: checked.append('gate')
        def read(saved):
            self.assertTrue(checked)
            return real(saved)
        self.c._config_valid = read
        err, _ = self.run_nssr(r)
        self.assertIsNone(err)


class ReadinessAndShutdown(unittest.TestCase):
    def test_npo_rejects_reset_between_shutdown_and_power_cut(self):
        cfg = json.loads((ROOT / 'fuzzer_config.json').read_text())
        p = next(p for p in cfg['exceptions']['profiles'] if p['name'] == 'normal_por')
        p['body'].insert(1, {'action': 'controller_reset'})
        with self.assertRaisesRegex(ValueError, 'invalidates NPO shutdown'):
            v.compile_profiles(cfg['exceptions'], cfg)

    def test_namespace_not_ready_retries_until_success(self):
        c = controller(self)
        now = [0.0]
        c.clock = lambda: now[0]
        c.runner.run = Mock(side_effect=[(1, b'', b'NVMe status: NS_NOT_READY (0x82)'),
                                          (0, b'', b'')])
        with patch.object(v.Path, 'exists', return_value=True), patch.object(
                v.time, 'sleep', side_effect=lambda s: now.__setitem__(0, now[0] + s)):
            t, status = c._io_probe(1)
        self.assertGreater(t, 0)
        self.assertEqual(status, '읽기 성공')
        self.assertEqual(c.runner.run.call_count, 2)

    def test_other_errors_never_mean_io_ready(self):
        for error in ('NS_NOT_READY (0x82)', 'INVALID_NS (0x0b)', 'INTERNAL (0x6)'):
            c = controller(self)
            now = [0.0]
            c.clock = lambda: now[0]
            c.runner.run = Mock(return_value=(1, b'', ('NVMe status: ' + error).encode()))
            with patch.object(v.Path, 'exists', return_value=True), patch.object(
                    v.time, 'sleep', side_effect=lambda s: now.__setitem__(0, now[0] + s)):
                t, status = c._io_probe(.02)
            self.assertIsNone(t, error)
            self.assertIn(error, status)

    def test_completed_read_error_with_dnr_remains_allowed(self):
        c = controller(self)
        c.runner.run = Mock(return_value=(1, b'', b'NVMe status: UNRECOVERED_READ_ERROR (0x4281)'))
        with patch.object(v.Path, 'exists', return_value=True):
            self.assertIsNotNone(c._io_probe(1)[0])

    def test_old_shutdown_does_not_survive_reset(self):
        m = v.RecoveryMonitor(DUT, RP, 'SN', bar=Mock())
        m._on_regs('R', 1, 0x4001, 1)
        m._on_regs('R', 2, 0x4001, 9)
        m._on_regs('R', 3, 0, 0)
        c = controller(self)
        c.emit = Mock()
        c._check_shutdown(m)
        self.assertEqual(c.emit.call_args.kwargs['status'], 'UNOBSERVED')

    def test_lost_observation_is_not_shutdown_failure(self):
        m = v.RecoveryMonitor(DUT, RP, 'SN', bar=Mock())
        m._on_regs('R', 1, 0x4001, 5)
        m._on_regs('X', 2, -7, None)
        c = controller(self)
        c.emit = Mock()
        c._check_shutdown(m)
        self.assertEqual(c.emit.call_args.kwargs['status'], 'UNOBSERVED')


class LinkObservation(unittest.TestCase):
    def controller(self):
        c = controller(self)
        c.root_bdf = RP
        c.clock = v.time.monotonic
        c.emit = Mock()
        c.options['adapters'] = {'assert': dict(argv=['test-helper'], effect='assert'),
                                 'release': dict(argv=['test-helper'], effect='deassert')}
        c.runner.run = Mock(return_value=(0, b'', b''))
        return c

    def test_perst_transitions_and_unknown_baselines(self):
        for before, after, action, expect in ((True, False, 'assert', 'OBSERVED'),
                                              (False, False, 'assert', 'UNVERIFIED'),
                                              (None, None, 'assert', 'UNVERIFIED'),
                                              (False, True, 'release', 'OBSERVED')):
            c = self.controller()
            with patch.object(v, '_link_active', side_effect=[before, after]):
                c._action(action, c.clock() + 1)
            row = next(x.kwargs for x in c.emit.call_args_list if x.args[0] == 'link_check')
            self.assertEqual(row['status'], expect)

    def test_flr_observed_drop_is_preserved_after_successful_helper(self):
        c = self.controller()
        watcher = Mock()
        watcher.start.return_value = watcher
        watcher.finish.return_value = dict(before=True, after=True, down_observed=True, observation_gap=False)
        with patch.object(v, '_ResetLinkWatch', return_value=watcher), patch.object(
                v, 'pci_method_support', return_value=('AVAILABLE', 'ok')):
            with self.assertRaisesRegex(v.ExceptionFailure, 'FLR 중 링크 다운'):
                c._action('flr', c.clock() + 1)
        watcher.finish.assert_called_once()
        row = next(x.kwargs for x in c.emit.call_args_list if x.args[0] == 'reset_link')
        self.assertEqual(row['status'], 'ANOMALY')

    def test_watcher_records_down_even_if_final_state_up(self):
        w = v._ResetLinkWatch(RP)
        # Drive sample deterministically without scheduling a worker.
        with patch.object(v, '_link_active', side_effect=[True, False, True]):
            w.before = w.sample()
            w.sample()
            w.sample()
        self.assertTrue(w.down)

    def test_failed_release_keeps_supply_cleanup_obligation(self):
        c = self.controller()
        now = iter(i * .1 for i in range(100))
        c.clock = lambda: next(now)
        c.asserted = True
        with patch.object(v, '_link_active', return_value=False), patch.object(v.time, 'sleep'):
            with self.assertRaisesRegex(v.ExceptionFailure, '링크 업 기한 초과'):
                c._action('release', 1)
        self.assertTrue(c.asserted)

    def test_link_wait_does_not_move_release_timing_origin(self):
        c = self.controller()
        c.clock = Mock(return_value=0.4)
        def action(*_):
            c._supply_return_at = 0.1  # helper finished before link-up wait
        c._action = action
        c._timing_wait = Mock()
        mon = Mock()
        mon.start.return_value = mon
        c._new_monitor = Mock(return_value=mon)
        c._run_profile(v.Profile('warm', (('release', 0),), 30, 30))
        self.assertEqual(c._timing_wait.call_args.args[2], 0.1)

    def test_helper_failure_still_closes_watcher(self):
        c = self.controller()
        c.runner.run.side_effect = subprocess.TimeoutExpired('reset', 1)
        watcher = Mock()
        watcher.start.return_value = watcher
        watcher.finish.return_value = dict(before=True, after=True, down_observed=False, observation_gap=False)
        with patch.object(v, '_ResetLinkWatch', return_value=watcher), patch.object(
                v, 'pci_method_support', return_value=('AVAILABLE', 'ok')):
            with self.assertRaises(subprocess.TimeoutExpired):
                c._action('flr', c.clock() + 1)
        watcher.finish.assert_called_once()


if __name__ == '__main__':
    unittest.main()
