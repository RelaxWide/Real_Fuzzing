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


class FakeBar:
    """BarWatcher 대역 — 자식 프로세스 대신 파일을 그대로 읽어 같은 이벤트를 낸다."""

    def __init__(self, path, clock):
        self.path, self.clock, self.mapped, self.last = Path(path), clock, False, None

    def poll(self):
        t, out = self.clock(), []
        if not self.path.exists():
            if self.mapped:
                out.append(('U', t, None, None))
            self.mapped, self.last = False, None
            return out
        if not self.mapped:
            self.mapped = True
            out.append(('M', t, None, None))
        b = self.path.read_bytes()
        cur = struct.unpack_from('<I', b, 0x14)[0], struct.unpack_from('<I', b, 0x1C)[0]
        if cur != self.last:
            out.append(('R', t, cur[0], cur[1]))
            self.last = cur
        return out

    def close(self):
        pass


class Monitor(unittest.TestCase):
    def setUp(self):
        self.fs = FakeSys()
        self.addCleanup(self.fs.tmp.cleanup)
        self.now = 0.0
        clock = lambda: self.now
        self.m = v.RecoveryMonitor(DUT, RP, 'SN1', clock=clock, pci=self.fs.pci, nvme=self.fs.nvme,
                                   bar=FakeBar(self.fs.pci / DUT / 'resource0', clock))

    def at(self, t):
        self.now = t
        self.m.sample()

    def test_controller_reset_transitions(self):
        self.at(0.000)                                        # 이벤트 전: 켜져 있음 → 기록 안 함
        self.m.begin_cycle(0.0)
        self.assertEqual(self.m.marks, {})
        self.fs.state('resetting'); self.fs.regs(cc=0, csts=0); self.at(0.010)
        self.fs.regs(cc=1, csts=0); self.at(0.020)
        self.fs.regs(cc=1, csts=1); self.at(0.060)
        self.fs.state('live'); self.at(0.090)
        self.assertEqual(self.m.marks, {'cc_en': 0.020, 'rdy': 0.060, 'live': 0.090})

    def test_link_and_config_completion(self):
        self.at(0.0)
        self.m.begin_cycle(0.0)
        self.fs.link(False); self.fs.vendor(0xFFFF); self.at(0.1)
        self.fs.link(True); self.at(0.3)
        self.fs.vendor(0x144D); self.at(0.45)
        self.assertEqual((self.m.marks['link_down'], self.m.marks['link_up'], self.m.marks['cfg_ok']),
                         (0.1, 0.3, 0.45))

    def test_removed_device_closes_bar_and_reopens(self):
        self.at(0.0)
        self.m.begin_cycle(0.0)
        self.fs.remove_dut(); self.fs.state('deleting'); self.at(0.1)
        self.assertIsNone(self.m.status()['cc_en'])            # 매핑 해제 → 모름
        self.fs.add_dut(); self.fs.regs(cc=0, csts=0); self.at(0.2)
        self.fs.regs(cc=1, csts=1); self.at(0.25)
        self.fs.state('live'); self.at(0.3)
        self.assertEqual((self.m.marks['cc_en'], self.m.marks['rdy'], self.m.marks['live']),
                         (0.25, 0.25, 0.3))

    def test_first_value_after_mapping_is_not_a_transition(self):
        # 새 매핑 직후 이미 EN=1 이면 언제 켜졌는지 모른다 — 전환으로 기록하지 않는다.
        self.fs.remove_dut(); self.at(0.0)
        self.m.begin_cycle(0.0)
        self.fs.add_dut(); self.fs.regs(cc=1, csts=1); self.at(0.2)
        self.assertNotIn('cc_en', self.m.marks)
        self.assertTrue(self.m.status()['rdy'])

    def test_repeated_cycles_are_separate(self):
        self.at(0.0)
        self.m.begin_cycle(0.0)
        self.fs.regs(cc=0, csts=0); self.at(0.01)
        self.fs.regs(cc=1, csts=0); self.at(0.02)
        self.fs.regs(cc=1, csts=1); self.at(0.06)               # 1회차: 40ms
        self.m.begin_cycle(1.0)
        self.fs.regs(cc=0, csts=0); self.at(1.01)
        self.fs.regs(cc=1, csts=0); self.at(1.02)
        self.fs.regs(cc=1, csts=1); self.at(1.51)               # 2회차: 490ms
        self.assertEqual((self.m.marks['cc_en'], self.m.marks['rdy']), (1.02, 1.51))
        self.assertEqual(self.m.history[0]['rdy'], 0.06)

    def test_late_events_from_previous_cycle_are_ignored(self):
        # 재리뷰 재현: 이전 주기 이벤트가 파이프에 남았다가 새 주기 시작 뒤에 전달돼도
        #   현재 주기의 전환 기록을 선점하지 않는다.
        q = []

        class QueueBar:
            def poll(self_inner):
                out, q[:] = list(q), []
                return out

            def close(self_inner):
                pass
        m = v.RecoveryMonitor(DUT, RP, 'SN1', clock=lambda: self.now, pci=self.fs.pci,
                              nvme=self.fs.nvme, bar=QueueBar())
        q += [('M', 0.0, None, None), ('R', 0.0, 1, 1)]
        self.now = 0.0; m.sample(); m.begin_cycle(0.0)
        self.now = 0.1; m.sample()
        m.begin_cycle(1.0)                                     # 2회차 시작
        q += [('R', 0.01, 0, 0), ('R', 0.02, 1, 0), ('R', 0.06, 1, 1)]   # 1회차 이벤트가 늦게 도착
        self.now = 1.005; m.sample()
        q += [('R', 1.01, 0, 0), ('R', 1.02, 1, 0), ('R', 1.51, 1, 1)]   # 2회차 실제 이벤트
        self.now = 1.6; m.sample()
        self.assertEqual((m.marks['cc_en'], m.marks['rdy']), (1.02, 1.51))

    def test_pcie_cap_parser(self):
        cfg = (self.fs.rp_real / 'config').read_bytes()
        self.assertEqual(v._pcie_cap_offset(cfg), 0x40)
        self.assertIsNone(v._pcie_cap_offset(bytes(256)))


class FakeMon:
    def __init__(self, marks, status=None):
        self.marks, self._status, self.gaps, self.history = marks, status or {}, [], []

    def snapshot(self):
        return dict(self.marks)

    def status(self):
        return dict(self._status)


def controller(tc, timing=BM9K1):
    tmp = tempfile.TemporaryDirectory()
    tc.addCleanup(tmp.cleanup)
    c = v.ExceptionController(options(), {}, '/dev/nvme0', '', Path(tmp.name) / 'ev.jsonl',
                              clock=Mock(return_value=0.0), timing=timing)
    c.serial, c.bdf = 'SN1', DUT
    c.wait_ready = Mock()
    c._smart_counts = Mock(return_value=None)          # 실제 nvme smart-log 를 부르지 않는다
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
        with self.assertRaisesRegex(v.ExceptionFailure, r'복귀 스펙 위반: \[장치\+호스트 측\(커널 초기화 포함\)\] RDY→admin 가능\(live\) 150ms > 스펙 100ms'):
            c._timing_wait(profile('reset'), mon, 0.0, 'controller_reset 시작')

    def test_waits_up_to_overrun_then_reports_missing(self):
        now = [0.0]
        c = controller(self)
        c.clock = lambda: now[0]
        mon = FakeMon({'cc_en': 0.02, 'rdy': 0.06})                      # live 가 끝내 안 옴
        with patch.object(v.time, 'sleep', side_effect=lambda t: now.__setitem__(0, now[0] + 1.0)):
            with self.assertRaisesRegex(v.ExceptionFailure, r'\[호스트 측 — RDY 이후 드라이버 초기화\(live\)가 끝나지 않음\].*60s 추가 대기에도 미완료'):
                c._timing_wait(profile('reset'), mon, 0.0, 'controller_reset 시작')
        self.assertGreaterEqual(now[0], 0.3 + 60)                         # 스펙(0.3s)+60s 까지 기다림

    def test_missing_start_transition_is_not_a_failure(self):
        c = controller(self)
        mon = FakeMon({'rdy': 0.06, 'live': 0.1})                        # CC.EN 전환을 못 봄
        c._timing_wait(profile('reset'), mon, 0.0, 'x')
        row = [json.loads(l) for l in c.log_path.read_text().splitlines() if '"timing"' in l][-1]
        self.assertEqual(row['rows'][0]['verdict'], 'N/A')

    def test_en_transition_missed_but_ready_now_is_not_failure(self):
        # 리뷰 재현: EN=0 구간을 놓쳐 cc_en/rdy 기록이 없어도, 지금 RDY·live 면 복귀는 된 것이다.
        c = controller(self)
        mon = FakeMon({}, status={'rdy': True, 'live': True, 'cc_en': True})
        c._timing_wait(profile('reset'), mon, 0.0, 'controller_reset 시작')
        row = [json.loads(l) for l in c.log_path.read_text().splitlines() if '"timing"' in l][-1]
        self.assertEqual([r['verdict'] for r in row['rows']], ['N/A', 'N/A'])

    def test_second_cycle_over_spec_is_judged(self):
        fs = FakeSys()
        self.addCleanup(fs.tmp.cleanup)
        now = [0.0]
        clock = lambda: now[0]
        m = v.RecoveryMonitor(DUT, RP, 'SN1', clock=clock, pci=fs.pci, nvme=fs.nvme,
                              bar=FakeBar(fs.pci / DUT / 'resource0', clock))
        def at(t):
            now[0] = t
            m.sample()
        at(0.0); m.begin_cycle(0.0)
        fs.regs(cc=0, csts=0); fs.state('resetting'); at(0.01)
        fs.regs(cc=1, csts=0); at(0.02); fs.regs(cc=1, csts=1); at(0.06); fs.state('live'); at(0.08)
        m.begin_cycle(1.0)
        fs.regs(cc=0, csts=0); fs.state('resetting'); at(1.01)
        fs.regs(cc=1, csts=0); at(1.02); fs.regs(cc=1, csts=1); at(1.51); fs.state('live'); at(1.55)
        c = controller(self)
        c.clock = clock
        with self.assertRaisesRegex(v.ExceptionFailure, r'CC\.EN→RDY 490ms > 스펙 100ms'):
            c._timing_wait(profile('reset'), m, 1.0, 'controller_reset 시작', cycles=2)

    def test_read_error_completion_counts_as_io_available(self):
        c = controller(self)
        c.runner.run = Mock(return_value=(1, b'', b'NVMe status: UNRECOVERED_READ_ERROR: '
                                                  b'The read data could not be recovered(0x281)\n'))
        with patch.object(v.Path, 'exists', return_value=True):
            t, how = c._io_probe(5.0)
        self.assertEqual(t, 0.0)
        self.assertIn('오류 상태로 완료', how)
        self.assertIn('UNRECOVERED_READ_ERROR', how)

    def test_no_response_is_not_io_available(self):
        now = [0.0]
        c = controller(self)
        c.clock = lambda: now[0]
        c.runner.run = Mock(return_value=(1, b'', b'read: Interrupted system call\n'))
        with patch.object(v.Path, 'exists', return_value=True), \
             patch.object(v.time, 'sleep', side_effect=lambda s: now.__setitem__(0, now[0] + 0.5)):
            t, how = c._io_probe(2.0)
        self.assertIsNone(t)
        self.assertIn('Interrupted', how)

    def test_missing_cc_en_after_device_back_is_host_side(self):
        c = controller(self)
        mon = FakeMon({'link_down': 0.0, 'link_up': 0.2, 'cfg_ok': 0.3},
                      status={'cfg_ok': True, 'link_up': True, 'cc_en': False, 'rdy': False, 'live': False})
        now = [0.0]
        c.clock = lambda: now[0]
        with patch.object(v.time, 'sleep', side_effect=lambda s: now.__setitem__(0, now[0] + 5)):
            with self.assertRaisesRegex(v.ExceptionFailure, '호스트 측 — 드라이버가 CC.EN 을 다시 켜지 않음'):
                c._timing_wait(profile('reset'), mon, 0.0, 'nssr 시작')

    def test_reader_gap_but_confirmed_ready_is_not_failure(self):
        # 재리뷰 재현: BAR 자식이 죽어 관측 상태 rdy=None 이어도 wait_ready() 가 실제 RDY·identity 를
        #   확인했으면 복귀는 된 것 — 전환 시각만 '측정 불가'.
        c = controller(self)
        mon = FakeMon({}, status={'rdy': None, 'cc_en': None, 'live': True})
        mon.gaps = [('reader_died', 0.05, -7)]
        c._timing_wait(profile('reset'), mon, 0.0, 'controller_reset 시작')
        c.wait_ready.assert_called_once()
        row = [json.loads(l) for l in c.log_path.read_text().splitlines() if '"timing"' in l][-1]
        self.assertEqual([r['verdict'] for r in row['rows']], ['N/A', 'N/A'])
        self.assertEqual(row['reader_gaps'], 1)

    def test_link_segment_only_when_link_went_down(self):
        c = controller(self)
        segs = [s[0] for s in c._timing_segments(profile('reset'), {'rdy': 1})]
        self.assertNotIn('cfg_after_ts', segs)
        segs = [s[0] for s in c._timing_segments(profile('reset'), {'link_down': 0.1})]
        self.assertIn('cfg_after_ts', segs)

    def test_npo_io_ready_against_power_on(self):
        c = controller(self)
        c._io_probe = Mock(return_value=(0.62, '읽기 성공'))
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
        mon = Mock()
        mon.start.return_value = mon
        mon.shutdown = {}
        c._new_monitor = Mock(return_value=mon)
        c._run_profile(v.Profile('x', steps, 60, 30, timing))
        self.cycles = mon.begin_cycle.call_count
        return c._timing_wait.call_args[0][3]

    def test_each_reset_opens_a_cycle(self):
        self.run_steps((('controller_reset', 0.0), ('controller_reset', 0.0)), 'reset')
        self.assertEqual(self.cycles, 2)

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


class BarReaderIsolation(unittest.TestCase):
    """리뷰 재현: 매핑된 BAR 가 사라지면 SIGBUS — 자식 프로세스에서만 나야 한다."""

    def test_sigbus_in_reader_does_not_kill_fuzzer(self):
        import os, time as _t
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'resource0'
            path.write_bytes(bytes(0x1000))
            w = v.BarWatcher(path, period=0.001)
            self.addCleanup(w.close)
            events, deadline = [], _t.monotonic() + 10
            while not any(e[0] == 'R' for e in events) and _t.monotonic() < deadline:
                events += w.poll(); _t.sleep(0.01)
            self.assertTrue(any(e[0] == 'R' for e in events), '자식이 첫 값을 못 냈다')
            os.truncate(path, 0)                              # 매핑 무효화 → 자식에서 SIGBUS
            while not any(e[0] == 'X' for e in events) and _t.monotonic() < deadline:
                events += w.poll(); _t.sleep(0.01)
            died = [e for e in events if e[0] == 'X']
            self.assertTrue(died, '자식이 죽지 않았다')
            self.assertEqual(died[0][2], -7)                  # SIGBUS
            # 퍼저 본체(이 프로세스)는 살아 있고, 감시자는 다시 띄울 준비가 돼 있다
            self.assertIsNone(w.proc)
            self.assertEqual(w.deaths, [-7])

    def test_repeated_mmap_failure_does_not_leak_fds(self):
        import os, time as _t
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'resource0'
            path.mkdir()                                      # open 은 되고 mmap 은 실패하는 경로
            w = v.BarWatcher(path, period=0.002)
            self.addCleanup(w.close)
            w.poll()
            pid = w.proc.pid
            _t.sleep(0.3)

            def peak():
                # 재시도 중 잠깐 열린 fd 가 찍힐 수 있다 — 여러 번 본 최대값으로 비교(누수면 계속 는다)
                n = 0
                for _ in range(20):
                    n = max(n, len(os.listdir(f'/proc/{pid}/fd')))
                    _t.sleep(0.005)
                return n
            first = peak()
            _t.sleep(0.5)                                     # 그사이 수백 번 재시도
            self.assertIsNone(w.proc.poll(), '자식이 살아 있어야 한다')
            # 부하가 크면 첫 측정이 자식 기동 중(루프 진입 전)이라 1개 적게 잡힌다. 누수라면 재시도
            #   수백 번만큼 늘어난다 — 증가 폭으로 판정
            self.assertLess(peak() - first, 3)


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
        for n in ('PM9M1', 'PM9M1_LNB', 'PM9M1_HP', 'BM9H1'):
            self.assertEqual(spec[n], v.TimingSpec(0.1, 10.0, 10.0, 10.0, 10.0, 60), n)
        for n in ('P7', 'P9'):
            self.assertEqual(spec[n], v.TimingSpec(30.0, 30.0, 30.0, 30.0, 30.0, 60), n)
        profs = {p.name: p for p in v.compile_profiles(cfg['exceptions'], cfg)}
        self.assertEqual((profs['normal_por'].timing, profs['sudden_por'].timing), ('npo', 'spo'))
        for n in ('normal_por', 'sudden_por', 'warm_reset_perst'):
            acts = [a for a, _ in profs[n].steps]
            self.assertEqual(acts[-1], 'pci_rescan_wait', n)
            steps = dict(profs[n].steps)
            self.assertEqual(steps['perst_release'], 0.0, f'{n}: PERST 해제 뒤 고정 대기가 없어야 한다')
            if n != 'warm_reset_perst':
                # PCIe 5.0 §6.6.1 Tpvperl: 전원 ON 뒤 PERST# 를 100ms 유지하고 해제
                acts = [a for a, _ in profs[n].steps]
                self.assertEqual(steps['power_on'], 0.1, n)
                self.assertEqual(acts[acts.index('power_on') + 1], 'perst_release', n)
                self.assertLess(acts.index('perst_assert'), acts.index('power_on'), n)
        acts = [a for a, _ in profs['normal_por'].steps]
        self.assertEqual(acts[:3], ['pci_remove', 'perst_assert', 'power_off'])   # 정상 종료 → PERST → OFF
        acts = [a for a, _ in profs['sudden_por'].steps]
        self.assertEqual(acts[:2], ['power_off', 'perst_assert'])                  # 급차단 → PERST (Tfail)


if __name__ == '__main__':
    unittest.main()
