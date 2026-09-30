"""리셋/전원 복귀 타이밍 — 구간별 측정·스펙 판정·초과 측정 후 불량 보고.

가짜 sysfs 트리(루트 포트 설정 공간, DUT 설정 공간, BAR0 파일, nvme 클래스)로 관측 스레드의
기록 규칙과 컨트롤러의 판정을 검증한다. 장치 조작은 하지 않는다.
"""
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
with patch.object(sys, 'argv', ['pc_sampling_fuzzer_v11.py']):
    import pc_sampling_fuzzer_v11 as v                     # noqa: E402

from test_v11_exceptions import options                    # noqa: E402

DUT, RP = '0000:02:00.0', '0000:00:1c.0'
BM9K1 = dict(cfg_after_ts_ms=200, en_to_rdy_ms=100, rdy_to_admin_ms=100,
             npo_io_ready_ms=500, spo_io_ready_ms=20000, overrun_wait_sec=60)


class FakeSys:
    """/sys/bus/pci/devices + /sys/class/nvme 흉내. 루트 포트 PCIe cap 은 0x40."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        r = Path(self.tmp.name)
        self.pci = r / 'bus_pci_devices'
        self.nvme = r / 'class_nvme'
        self.rp_real = r / 'devices' / 'pci0000:00' / RP
        self.dut_real = self.rp_real / DUT
        self.pci.mkdir(parents=True)
        self.nvme.mkdir()
        self.rp_real.mkdir(parents=True)
        cfg = bytearray(256)
        cfg[6] = 0x10                    # status: capability list
        cfg[0x34] = 0x40
        cfg[0x40] = 0x10                 # PCI Express cap
        (self.rp_real / 'config').write_bytes(bytes(cfg))
        (self.pci / RP).symlink_to(self.rp_real)
        self.add_dut()
        self.ctrl = self.nvme / 'nvme0'
        self.ctrl.mkdir()
        for k, val in (('serial', 'SN1'), ('address', DUT), ('state', 'live')):
            (self.ctrl / k).write_text(val)
        self.link(True)
        self.regs(cc=1, csts=1)

    def add_dut(self, vendor=0x144D):
        self.dut_real.mkdir(parents=True, exist_ok=True)
        (self.dut_real / 'config').write_bytes(struct.pack('<H', vendor) + bytes(62))
        (self.dut_real / 'resource0').write_bytes(bytes(0x1000))
        if not (self.pci / DUT).exists():
            (self.pci / DUT).symlink_to(self.dut_real)

    def remove_dut(self):
        (self.pci / DUT).unlink()
        for f in self.dut_real.iterdir():
            f.unlink()
        self.dut_real.rmdir()

    def vendor(self, value):
        with open(self.dut_real / 'config', 'r+b') as f:
            f.write(struct.pack('<H', value))

    def link(self, up):
        p = self.rp_real / 'config'
        b = bytearray(p.read_bytes())
        b[0x52:0x54] = struct.pack('<H', (1 << 13) if up else 0)
        p.write_bytes(bytes(b))

    def regs(self, cc, csts):
        with open(self.dut_real / 'resource0', 'r+b') as f:
            f.seek(0x14)
            f.write(struct.pack('<I', cc))
            f.seek(0x1C)
            f.write(struct.pack('<I', csts))

    def state(self, st):
        (self.ctrl / 'state').write_text(st)


class Monitor(unittest.TestCase):
    def setUp(self):
        self.fs = FakeSys()
        self.addCleanup(self.fs.tmp.cleanup)
        self.now = 0.0
        self.m = v.RecoveryMonitor(DUT, RP, 'SN1', clock=lambda: self.now,
                                   pci=self.fs.pci, nvme=self.fs.nvme)
        self.addCleanup(self.m._close_bar)

    def at(self, t):
        self.now = t
        self.m.sample()

    def test_controller_reset_transitions(self):
        self.at(0.000)                                        # 이벤트 전: 켜져 있음 → 기록 안 함
        self.assertEqual(self.m.marks, {})
        self.fs.state('resetting'); self.fs.regs(cc=0, csts=0); self.at(0.010)
        self.fs.regs(cc=1, csts=0); self.at(0.020)
        self.fs.regs(cc=1, csts=1); self.at(0.060)
        self.fs.state('live'); self.at(0.090)
        self.assertEqual(self.m.marks, {'cc_en': 0.020, 'rdy': 0.060, 'live': 0.090})

    def test_link_and_config_completion(self):
        self.at(0.0)
        self.fs.link(False); self.fs.vendor(0xFFFF); self.at(0.1)
        self.fs.link(True); self.at(0.3)
        self.fs.vendor(0x144D); self.at(0.45)
        self.assertEqual((self.m.marks['link_down'], self.m.marks['link_up'], self.m.marks['cfg_ok']),
                         (0.1, 0.3, 0.45))

    def test_removed_device_closes_bar_and_reopens(self):
        self.at(0.0)
        self.fs.remove_dut(); self.fs.state('deleting'); self.at(0.1)
        self.assertIsNone(self.m._mv)
        self.fs.add_dut(); self.fs.regs(cc=0, csts=0); self.at(0.2)
        self.fs.regs(cc=1, csts=1); self.at(0.25)
        self.fs.state('live'); self.at(0.3)
        self.assertEqual((self.m.marks['cc_en'], self.m.marks['rdy'], self.m.marks['live']),
                         (0.25, 0.25, 0.3))

    def test_pcie_cap_parser(self):
        cfg = (self.fs.rp_real / 'config').read_bytes()
        self.assertEqual(v._pcie_cap_offset(cfg), 0x40)
        self.assertIsNone(v._pcie_cap_offset(bytes(256)))


class FakeMon:
    def __init__(self, marks):
        self.marks = marks

    def snapshot(self):
        return dict(self.marks)


def controller(tc, timing=BM9K1):
    tmp = tempfile.TemporaryDirectory()
    tc.addCleanup(tmp.cleanup)
    c = v.ExceptionController(options(), {}, '/dev/nvme0', '', Path(tmp.name) / 'ev.jsonl',
                              clock=Mock(return_value=0.0), timing=timing)
    c.serial, c.bdf = 'SN1', DUT
    c.wait_ready = Mock()
    return c


def profile(timing):
    return v.Profile('p', (('controller_reset', 0.0),), 30, 30, timing)


class Judgement(unittest.TestCase):
    def test_within_spec_passes(self):
        c = controller(self)
        mon = FakeMon({'cc_en': 0.02, 'rdy': 0.06, 'live': 0.12})
        c._timing_wait(profile('reset'), mon, 0.0, 'controller_reset 시작')
        row = [json.loads(l) for l in c.log_path.read_text().splitlines() if '"timing"' in l][-1]
        self.assertEqual([r['verdict'] for r in row['rows']], ['OK', 'OK'])

    def test_over_spec_reports_measured_and_fails(self):
        c = controller(self)
        mon = FakeMon({'cc_en': 0.02, 'rdy': 0.06, 'live': 0.21})       # RDY→live 150ms > 100ms
        with self.assertRaisesRegex(v.ExceptionFailure, r'복귀 스펙 초과: RDY→admin 가능\(live\) 150ms > 스펙 100ms'):
            c._timing_wait(profile('reset'), mon, 0.0, 'controller_reset 시작')

    def test_waits_up_to_overrun_then_reports_missing(self):
        now = [0.0]
        c = controller(self)
        c.clock = lambda: now[0]
        mon = FakeMon({'cc_en': 0.02, 'rdy': 0.06})                      # live 가 끝내 안 옴
        with patch.object(v.time, 'sleep', side_effect=lambda t: now.__setitem__(0, now[0] + 1.0)):
            with self.assertRaisesRegex(v.ExceptionFailure, '60s 추가 대기에도 미완료'):
                c._timing_wait(profile('reset'), mon, 0.0, 'controller_reset 시작')
        self.assertGreaterEqual(now[0], 0.3 + 60)                         # 스펙(0.3s)+60s 까지 기다림

    def test_missing_start_transition_is_not_a_failure(self):
        c = controller(self)
        mon = FakeMon({'rdy': 0.06, 'live': 0.1})                        # CC.EN 전환을 못 봄
        c._timing_wait(profile('reset'), mon, 0.0, 'x')
        row = [json.loads(l) for l in c.log_path.read_text().splitlines() if '"timing"' in l][-1]
        self.assertEqual(row['rows'][0]['verdict'], 'N/A')

    def test_link_segment_only_when_link_went_down(self):
        c = controller(self)
        segs = [s[0] for s in c._timing_segments(profile('reset'), {'rdy': 1})]
        self.assertNotIn('cfg_after_ts', segs)
        segs = [s[0] for s in c._timing_segments(profile('reset'), {'link_down': 0.1})]
        self.assertIn('cfg_after_ts', segs)

    def test_npo_io_ready_against_power_on(self):
        c = controller(self)
        c._io_probe = Mock(return_value=0.62)
        mon = FakeMon({'cc_en': 0.3, 'rdy': 0.32, 'live': 0.40})
        prof = v.Profile('normal_por', (('power_on', 0.0),), 60, 30, 'npo')
        with self.assertRaisesRegex(v.ExceptionFailure, r'전원 ON→I/O 가능 \(NPO\) 620ms > 스펙 500ms'):
            c._timing_wait(prof, mon, 0.0, 'power_on 반환')

    def test_human_table_has_no_json(self):
        c = controller(self)
        mon = FakeMon({'cc_en': 0.02, 'rdy': 0.06, 'live': 0.21})
        with self.assertLogs('pcfuzz', level='WARNING') as logs:
            with self.assertRaises(v.ExceptionFailure):
                c._timing_wait(profile('reset'), mon, 0.0, 'controller_reset 시작')
        text = '\n'.join(logs.output)
        self.assertIn('[timing] 기준: controller_reset 시작', text)
        self.assertIn('✗ 초과', text)
        self.assertNotIn('{', text)


class T0AndProfiles(unittest.TestCase):
    def run_steps(self, steps, timing):
        c = controller(self)
        c._action = Mock()
        c._timing_wait = Mock()
        with patch.object(v, 'RecoveryMonitor') as RM:
            RM.return_value.start.return_value = RM.return_value
            c._run_profile(v.Profile('x', steps, 60, 30, timing))
        return c._timing_wait.call_args[0][3]

    def test_t0_reference(self):
        self.assertEqual(self.run_steps((('controller_reset', 0.0),), 'reset'), 'controller_reset 시작')
        self.assertEqual(self.run_steps((('power_off', 0.0), ('power_on', 0.0),
                                         ('pci_rescan_wait', 0.0)), 'npo'), 'power_on 반환')

    def test_without_timing_uses_legacy_path(self):
        c = controller(self, timing=None)
        c._run_profile_timed = Mock()
        c._action = Mock()
        c.wait_ready = Mock()
        c._run_profile(v.Profile('x', (('controller_reset', 0.0),), 30, 30))
        c._run_profile_timed.assert_not_called()

    def test_profile_timing_validation(self):
        opts = dict(options(), profiles=[{'name': 'bad', 'body': [{'action': 'controller_reset'}],
                                          'timing': 'npo'}])
        with self.assertRaisesRegex(ValueError, 'requires a power_on'):
            v.compile_profiles(opts, {})
        opts['profiles'][0]['timing'] = 'weird'
        with self.assertRaisesRegex(ValueError, "timing must be"):
            v.compile_profiles(opts, {})

    def test_spec_parse(self):
        s = v.TimingSpec.parse(BM9K1)
        self.assertEqual((s.cfg_after_ts, s.en_to_rdy, s.npo_io_ready, s.overrun_wait), (0.2, 0.1, 0.5, 60))
        with self.assertRaisesRegex(ValueError, 'rdy_to_admin_ms'):
            v.TimingSpec.parse({k: val for k, val in BM9K1.items() if k != 'rdy_to_admin_ms'})
        self.assertIsNone(v.TimingSpec.parse(None))


class RescanLoop(unittest.TestCase):
    def test_rescans_until_device_appears(self):
        fs = FakeSys()
        self.addCleanup(fs.tmp.cleanup)
        fs.remove_dut()
        c = controller(self)
        calls = []

        def run(argv, deadline, **kw):
            calls.append(argv)
            if len(calls) == 3:
                fs.add_dut()
            return 0, b'', b''
        c.runner.run = run
        with patch.object(v, '_PCI_DEVICES', fs.pci), patch.object(v.time, 'sleep'):
            c._rescan_until_present(10.0)
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[0], ['sh', '-c', 'echo 1 > /sys/bus/pci/rescan'])


class ProductConfig(unittest.TestCase):
    def test_products(self):
        cfg = json.loads((ROOT / 'fuzzer_config.json').read_text(encoding='utf-8-sig'))
        spec = {n: v.TimingSpec.parse(p.get('exception_timing')) for n, p in cfg['products'].items()}
        self.assertEqual(spec['BM9K1'], v.TimingSpec(0.2, 0.1, 0.1, 0.5, 20.0, 60))
        for n in ('PM9M1', 'PM9M1_LNB', 'PM9M1_HP'):
            self.assertEqual(spec[n], v.TimingSpec(0.1, 10.0, 10.0, 10.0, 10.0, 60), n)
        for n in ('P7', 'P9'):
            self.assertEqual(spec[n], v.TimingSpec(30.0, 30.0, 30.0, 30.0, 30.0, 60), n)
        self.assertIsNone(spec['BM9H1'])
        profs = {p.name: p for p in v.compile_profiles(cfg['exceptions'], cfg)}
        self.assertEqual((profs['normal_por'].timing, profs['sudden_por'].timing), ('npo', 'spo'))
        for n in ('normal_por', 'sudden_por', 'warm_reset_perst'):
            acts = [a for a, _ in profs[n].steps]
            self.assertEqual(acts[-1], 'pci_rescan_wait', n)
            self.assertEqual(dict(profs[n].steps).get('power_on', dict(profs[n].steps).get('perst_release')),
                             0.0, f'{n}: 전원 ON/PERST 해제 뒤 고정 대기가 없어야 한다')


if __name__ == '__main__':
    unittest.main()
