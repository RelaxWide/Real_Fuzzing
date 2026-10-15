"""v11.3 — 디버그 링크 재연결이 끝내 실패하면(컨트롤러는 정상) POR 후 재연결로 이어간다(riscv.link_fail_por, 기본 꺼짐).

BM9K1: 복구 시퀀스 실패 뒤 DM AP(APBAP1)가 POR 전까지 응답하지 않는 상태가 있다. 컨트롤러가 응답하지 않으면
펌웨어 행이라 기존대로 POR 없이 증거를 남긴다. 횟수 상한 없음.
"""
import json
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import MagicMock

from fuzzer_target import fuzzer as v


def fuzzer(enabled=True, ctrl_ok=True, por_ok=True, reconnect_ok=True):
    o = v.NVMeFuzzer.__new__(v.NVMeFuzzer)
    o.config = NS(riscv={'link_fail_por': enabled},
                  nvme_device='/dev/nvme0', no_jlink=False)
    o.stats = {}
    o._nvme_id_dict = MagicMock(return_value=({'sn': 'x'}, '', 0) if ctrl_ok else ({}, 'EAGAIN', 11))

    def por():
        o._por_reconnect_ok = reconnect_ok if por_ok else None
        return por_ok
    o._recover_after_unsupported_skip = MagicMock(side_effect=por)
    return o


class LinkFailPor(unittest.TestCase):
    def test_disabled_does_nothing(self):
        o = fuzzer(enabled=False)
        self.assertFalse(o._link_fail_por('command'))
        o._recover_after_unsupported_skip.assert_not_called()
        o._nvme_id_dict.assert_not_called()

    def test_por_and_reconnect(self):
        o = fuzzer()
        with self.assertLogs(v.log, 'WARNING') as cm:
            self.assertTrue(o._link_fail_por('command'))
        o._recover_after_unsupported_skip.assert_called_once()
        self.assertEqual(o.stats['link_fail_por'], 1)
        self.assertIn('POR 후 재연결 (#1', '\n'.join(cm.output))

    def test_controller_dead_keeps_evidence(self):
        o = fuzzer(ctrl_ok=False)
        with self.assertLogs(v.log, 'ERROR'):
            self.assertFalse(o._link_fail_por('command'))
        o._recover_after_unsupported_skip.assert_not_called()

    def test_por_done_but_reconnect_failed_is_failure(self):
        # 기존 POR 루틴은 재연결 실패여도 True(퍼징 계속)를 돌려준다 — 링크 복구로 치면 안 된다
        o = fuzzer(reconnect_ok=False)
        with self.assertLogs(v.log, 'ERROR'):
            self.assertFalse(o._link_fail_por('command'))

    def test_por_failure(self):
        o = fuzzer(por_ok=False)
        with self.assertLogs(v.log, 'ERROR'):
            self.assertFalse(o._link_fail_por('command'))

    def test_no_cap(self):
        o = fuzzer()
        with self.assertLogs(v.log, 'WARNING'):
            for k in range(10):
                self.assertTrue(o._link_fail_por(str(k)))
        self.assertEqual(o._recover_after_unsupported_skip.call_count, 10)
        self.assertEqual(o.stats['link_fail_por'], 10)

    def test_exception_campaign_blocks_por(self):
        # 예외 주입 캠페인에서는 override 가 POR 을 막는다(False) → 링크 복구 실패로 끝난다
        o = fuzzer()
        o._recover_after_unsupported_skip = MagicMock(return_value=False)
        with self.assertLogs(v.log, 'ERROR'):
            self.assertFalse(o._link_fail_por('command'))


class Wiring(unittest.TestCase):
    def stop_checked(self, por_result):
        o = fuzzer()
        err = threading.Event()
        err.set()
        o.sampler = NS(stop_sampling=lambda: 5, openocd_error=err, LINK_LABEL='[cJTAG/SBA]',
                       _reinit_target=lambda: False, _reconnect=lambda: False, close=MagicMock())
        o._prepare_sjtag_reauth = MagicMock()
        o._link_fail_por = MagicMock(return_value=por_result)
        o._capture_firmware_hang_if_stuck = MagicMock(return_value=False)
        with self.assertLogs(v.log, 'WARNING'):
            r = v._V101Fuzzer._stop_sampling_checked(o, 'command')   # 공통 복구 지점(믹스인은 그대로 위임)
        return o, r

    def test_stop_checked_uses_por_after_reconnect_fails(self):
        o, r = self.stop_checked(True)
        self.assertEqual(r, (5, True))
        self.assertFalse(o._sampler_recovery_failed)
        o._capture_firmware_hang_if_stuck.assert_not_called()

    def test_stop_checked_falls_through_when_por_fails(self):
        o, r = self.stop_checked(False)
        self.assertEqual(r, (5, False))
        self.assertTrue(o._sampler_recovery_failed)
        o._capture_firmware_hang_if_stuck.assert_called_once()

    def pm_attach(self, por_result):
        o = fuzzer()
        o._pm_detached = True
        o._pm_detach_stats = {'reattach_s': 0.0, 'reattach_fail': 0, 'count': 1, 'reauth': 0}
        o._pm_reattach = MagicMock(return_value=(False, False))
        o._link_fail_por = MagicMock(return_value=por_result)
        o.sampler = NS(session=None)
        o._sampler_recovery_failed = False
        with self.assertLogs(v.log, 'INFO'):
            r = o._pm_sampler_attach('ps4')
        return o, r

    def test_pm_attach_uses_por(self):
        o, r = self.pm_attach(True)
        self.assertTrue(r)
        self.assertFalse(o._pm_detached)
        self.assertFalse(o._sampler_recovery_failed)

    def test_pm_attach_fails_without_por(self):
        o, r = self.pm_attach(False)
        self.assertFalse(r)
        self.assertTrue(o._sampler_recovery_failed)

    def test_config_default_off(self):
        cfg = json.loads((Path(v.__file__).parent / 'fuzzer_config.json').read_text(encoding='utf-8'))
        rv = cfg['products']['BM9K1']['riscv']
        self.assertIs(rv['link_fail_por'], False)
        self.assertNotIn('link_fail_por_max', rv)


class PorRoutineRecordsReconnect(unittest.TestCase):
    """실제 POR 루틴이 샘플러 재연결 결과를 _por_reconnect_ok 에 남기는지(전원·PCIe 단계는 가짜)."""
    def run_por(self, reconnect):
        from unittest.mock import patch
        o = v._V101Fuzzer.__new__(v._V101Fuzzer)
        o.config = NS(pmu_script='/x/pmu.py', por_poweroff_wait=0, clkreq_voltage_mv=0, boot_sweep_s=0,
                      pm_inject_prob=0, no_jlink=False)
        o._crash_nvme_pid = None
        o._probe_device = MagicMock()
        o._por_remove_target = MagicMock(return_value=None)
        o._por_pcie_rescan = MagicMock(return_value=True)
        o._apst_disable = MagicMock()
        o._keepalive_disable = MagicMock()
        o.sampler = NS(_stop_worker=MagicMock(), _reconnect=MagicMock(return_value=reconnect))
        with patch.object(v.os.path, 'isfile', return_value=True), \
                patch.object(v.subprocess, 'run', return_value=NS(returncode=0, stderr=b'')), \
                patch.object(v.time, 'sleep'), self.assertLogs(v.log, 'WARNING'):
            ok = o._recover_after_unsupported_skip()
        return ok, o._por_reconnect_ok

    def test_reconnect_ok(self):
        self.assertEqual(self.run_por(True), (True, True))

    def test_reconnect_failed_still_returns_true_but_recorded(self):
        self.assertEqual(self.run_por(False), (True, False))


if __name__ == '__main__':
    unittest.main()
