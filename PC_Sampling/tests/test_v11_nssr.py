"""NSSR 절차 — 드라이버 개입 없이 호스트가 스펙대로 복구한다.

unbind → BAR0 NSSR 쓰기(t0) → 링크 다운 → remove → 링크 업 → rescan → CSTS.NSSRO 확인 → probe.
가짜 sysfs 와 가짜 runner 로 순서·판정·정리를 보고, BAR0 도우미 스크립트는 일반 파일에 대고
실제로 실행한다. 장치 조작은 하지 않는다.
"""
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_v11_timing import DUT, RP, FakeSys, v
from test_v11_exceptions import options

NSSRS = 1 << 36


class FakeBus:
    """/sys/bus/pci 의 drivers_autoprobe · drivers_probe · drivers/nvme/unbind."""

    def __init__(self, fs):
        self.fs = fs
        self.root = Path(fs.tmp.name) / 'bus_pci'
        (self.root / 'drivers' / 'nvme').mkdir(parents=True)
        (self.root / 'drivers' / 'nvme' / 'unbind').write_text('')
        (self.root / 'drivers_autoprobe').write_text('1\n')
        (self.root / 'drivers_probe').write_text('')
        self.bind()

    def bind(self):
        link = self.fs.dut_real / 'driver'
        if not link.exists():
            link.symlink_to(self.root / 'drivers' / 'nvme')


class Runner:
    """sysfs 쓰기·rescan·BAR0 도우미를 흉내 내며 호출 순서를 남긴다."""

    def __init__(self, fs, bus, csts_after=0x10, arm_out=None, link_drops=True):
        self.fs, self.bus, self.log = fs, bus, []
        self.csts_after, self.link_drops = csts_after, link_drops
        self.arm_out = arm_out or f'CMD 6\nCAP {NSSRS | 0xFF}\nCSTS 1\nARMED\nWROTE\n'
        self.pending = []

    def has_pending(self, **_):
        return False

    def run(self, argv, deadline, **_):
        if argv[:2] == ['sh', '-c']:
            self.log.append('rescan')
            self.fs.add_dut()
            return 0, b'', b''
        prog = argv[2]
        if prog == v.ExceptionController._SYSFS_WRITE:
            path, value = Path(argv[3]), argv[4]
            name = path.name if path.name != 'enable' else 'enable=' + value
            self.log.append(name)
            if name == 'unbind':
                (self.fs.dut_real / 'driver').unlink()
            elif name == 'remove':
                self.fs.remove_dut()
                self.fs.link(True)                       # 링크 재학습
                return 0, b'', b''
            elif name == 'drivers_probe':
                self.bus.bind()
            if path.parent.exists():
                path.write_text(value)
            return 0, b'', b''
        if prog == v._NSSR_HELPER:
            mode = argv[3]
            self.log.append('helper:' + mode)
            if mode == 'arm':
                if 'ARMED' in self.arm_out and self.link_drops:
                    self.fs.link(False)
                return (0 if 'ARMED' in self.arm_out else 5), self.arm_out.encode(), b''
            return 0, f'CMD 6\nCAP {NSSRS}\nCSTS {self.csts_after}\n'.encode(), b''
        raise AssertionError(argv)


class NssrSequence(unittest.TestCase):
    def setUp(self):
        self.fs = FakeSys()
        self.addCleanup(self.fs.tmp.cleanup)
        self.bus = FakeBus(self.fs)
        self.c = v.ExceptionController(options(), {}, '/dev/nvme0', '',
                                       Path(self.fs.tmp.name) / 'events')
        self.c.serial, self.c.bdf, self.c.root_bdf = 'SN1', DUT, RP
        for target, value in (('_PCI_DEVICES', self.fs.pci), ('_PCI_BUS', self.bus.root)):
            p = patch.object(v, target, value)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(v.time, 'sleep')
        p.start()
        self.addCleanup(p.stop)

    def run_nssr(self, runner):
        self.c.runner = runner
        with self.assertLogs('pcfuzz', level='WARNING') as logs:
            try:
                self.c._nssr(self.c.clock() + 30)
                err = None
            except v.ExceptionFailure as exc:
                err = exc
        return err, '\n'.join(logs.output)

    def test_spec_sequence(self):
        r = Runner(self.fs, self.bus)
        order = []
        self.c._nssr_trigger = lambda t: order.append(('t0', list(r.log)))
        err, text = self.run_nssr(r)
        self.assertIsNone(err, text)
        self.assertEqual(r.log, ['drivers_autoprobe', 'unbind', 'enable=1', 'helper:arm', 'remove', 'rescan',
                                 'enable=1', 'helper:csts', 'enable=0',
                                 'drivers_autoprobe', 'drivers_probe'])
        # t0 는 unbind 뒤, NSSR 을 쓰기 직전
        self.assertEqual(order, [('t0', ['drivers_autoprobe', 'unbind', 'enable=1'])])
        self.assertEqual((self.bus.root / 'drivers_autoprobe').read_text(), '1')
        self.assertTrue((self.fs.dut_real / 'driver').exists())
        self.assertIn('NSSRO=1', text)
        self.assertIn('OK', text)
        self.assertTrue(self.c._reenumerated)
        self.assertNotIn('subsystem-reset', text)

    def test_nssro_clear_is_device_spec_violation_and_preserved(self):
        r = Runner(self.fs, self.bus, csts_after=0x0)
        err, text = self.run_nssr(r)
        self.assertRegex(str(err), r'\[장치 측\] NSSR 스펙 위반.*NSSRO=0')
        self.assertNotIn('drivers_probe', r.log)                  # 현상 보존: 드라이버 붙이지 않음
        self.assertEqual((self.bus.root / 'drivers_autoprobe').read_text(), '1')   # 전역 설정은 복원

    def test_cfs_after_reset_fails(self):
        r = Runner(self.fs, self.bus, csts_after=0x12)
        err, _ = self.run_nssr(r)
        self.assertIn('CFS=1', str(err))

    def test_not_issued_rebinds_driver(self):
        r = Runner(self.fs, self.bus, arm_out='CMD 6\nCAP 255\nCSTS 1\nERR CAP.NSSRS=0\n')
        err, text = self.run_nssr(r)
        self.assertIn('NSSR 미실행', str(err))
        self.assertIn('CAP.NSSRS=0', str(err))
        self.assertEqual(r.log[-3:], ['enable=0', 'drivers_probe', 'drivers_autoprobe'])
        self.assertTrue((self.fs.dut_real / 'driver').exists())
        self.assertEqual((self.bus.root / 'drivers_autoprobe').read_text(), '1')

    def test_link_never_returns_is_device_side(self):
        r = Runner(self.fs, self.bus)
        orig = r.run

        def run(argv, deadline, **kw):
            rc = orig(argv, deadline, **kw)
            if argv[2:3] == [v.ExceptionController._SYSFS_WRITE] and argv[3].endswith('/remove'):
                self.fs.link(False)                      # remove 뒤에도 링크가 안 올라옴
            return rc
        r.run = run
        clock = iter(i * 0.5 for i in range(10 ** 6))
        self.c.clock = lambda: next(clock)
        err, _ = self.run_nssr(r)
        self.assertIn('[장치 측] NSSR 뒤 링크가', str(err))
        self.assertNotIn('rescan', r.log)

    def test_capability_needs_root_port(self):
        self.c.runner = Runner(self.fs, self.bus)
        self.c.runner.run = lambda argv, deadline, **kw: (0, b'{"cap": "%d"}' % NSSRS, b'')
        profile = v.Profile('nssr', (('nssr', 0.0),), 30, 30)
        with patch.object(v, 'subsystem_support', return_value=('AVAILABLE', 'ok')):
            self.assertEqual(self.c.capability(profile)[0], 'AVAILABLE')
            self.c.root_bdf = None
            self.assertEqual(self.c.capability(profile)[0], 'UNCONFIGURED')


class TimedT0(unittest.TestCase):
    """타이밍 측정 기준(t0)은 nssr **시작**이 아니라 unbind 뒤 NSSR 을 쓰는 순간이다."""

    def test_t0_is_nssr_write(self):
        c = v.ExceptionController(options(), {}, '/dev/nvme0', '', Path(tempfile.mkdtemp()) / 'ev')
        c.timing = v.TimingSpec(0.2, 0.1, 0.1, 0.5, 20.0, 60)
        now = [0.0]
        c.clock = lambda: now[0]
        cycles = []

        class Mon:
            def start(self):
                return self

            def begin_cycle(self, t):
                cycles.append(t)

            def stop(self):
                pass
        c._new_monitor = Mon
        def action(name, deadline):
            now[0] = 1.5                                   # unbind(정상 종료)에 걸린 시간
            c._nssr_trigger(now[0])
            now[0] = 2.0
        c._action = action
        seen = {}
        c._timing_wait = lambda profile, mon, t0, what, n=1: seen.update(t0=t0, what=what, n=n)
        c._run_profile_timed(v.Profile('nssr', (('nssr', 0.0),), 30, 30))
        self.assertEqual(cycles, [1.5])
        self.assertEqual(seen, dict(t0=1.5, what='NSSR 쓰기', n=1))
        self.assertIsNone(c._nssr_trigger)


class Helper(unittest.TestCase):
    """_NSSR_HELPER 를 일반 파일(설정 공간·BAR0 흉내)에 대고 실제로 실행한다."""

    def dev(self, cmd, cap, csts):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        d = Path(tmp.name)
        (d / 'config').write_bytes(bytes(4) + struct.pack('<H', cmd) + bytes(58))
        bar = bytearray(0x1000)
        struct.pack_into('<Q', bar, 0, cap)
        struct.pack_into('<I', bar, 0x1C, csts)
        (d / 'resource0').write_bytes(bytes(bar))
        return d

    def run_helper(self, mode, d):
        p = subprocess.run([sys.executable, '-c', v._NSSR_HELPER, mode, str(d)],
                           capture_output=True, timeout=10)
        return p.returncode, p.stdout.decode()

    def test_arm_clears_nssro_then_writes_magic(self):
        d = self.dev(cmd=0x6, cap=NSSRS, csts=0x11)
        rc, out = self.run_helper('arm', d)
        self.assertEqual(rc, 0, out)
        self.assertIn('ARMED', out)
        bar = (d / 'resource0').read_bytes()
        self.assertEqual(struct.unpack_from('<I', bar, 0x20)[0], 0x4E564D65)
        self.assertIn('CLEARED', out)                  # NSSRO(RW1C) 에 1 을 썼다

    def test_refuses_without_nssrs_or_memory_decode(self):
        rc, out = self.run_helper('arm', self.dev(cmd=0x6, cap=0, csts=1))
        self.assertEqual(rc, 5)
        self.assertNotIn('ARMED', out)
        d = self.dev(cmd=0x0, cap=NSSRS, csts=1)
        rc, out = self.run_helper('arm', d)
        self.assertEqual(rc, 3)
        self.assertIn('Command.MSE=0', out)
        self.assertEqual(struct.unpack_from('<I', (d / 'resource0').read_bytes(), 0x20)[0], 0)

    def test_csts_read_only(self):
        d = self.dev(cmd=0x6, cap=NSSRS, csts=0x10)
        rc, out = self.run_helper('csts', d)
        self.assertEqual(rc, 0)
        self.assertIn('CSTS 16', out)
        self.assertEqual(struct.unpack_from('<I', (d / 'resource0').read_bytes(), 0x20)[0], 0)


if __name__ == '__main__':
    unittest.main()
