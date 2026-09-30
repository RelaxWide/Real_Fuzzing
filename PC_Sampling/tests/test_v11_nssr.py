"""NSSR 절차 — 드라이버 개입 없이 호스트가 스펙대로 복구한다.

unbind → BAR0 NSSR 쓰기(t0) → 링크 다운·업 → 설정 응답 → 설정 공간 복원 → CSTS.NSSRO 확인
→ probe. remove/rescan 은 하지 않는다(재열거하면 드라이버가 먼저 붙어 NSSRO 를 지운다).
가짜 sysfs 와 가짜 runner 로 순서·판정·정리를 보고, BAR0 도우미 스크립트는 일반 파일에 대고
실제로 실행한다. 장치 조작은 하지 않는다.
"""
import json
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
    """/sys/bus/pci 의 drivers_probe · drivers/nvme/unbind."""

    def __init__(self, fs):
        self.fs = fs
        self.root = Path(fs.tmp.name) / 'bus_pci'
        (self.root / 'drivers' / 'nvme').mkdir(parents=True)
        (self.root / 'drivers' / 'nvme' / 'unbind').write_text('')
        (self.root / 'drivers_probe').write_text('')
        self.bind()

    def bind(self):
        link = self.fs.dut_real / 'driver'
        if not link.exists():
            link.symlink_to(self.root / 'drivers' / 'nvme')


BAR0 = 0xA9200004                  # 64비트 메모리 BAR (하위 4비트는 유형)
CONFIG = (struct.pack('<HHH', 0x144D, 0xA80A, 0x0006) + bytes(10)
          + struct.pack('<II', BAR0, 0) + bytes(40))


class Runner:
    """sysfs 쓰기·BAR0 도우미를 흉내 내며 호출 순서를 남긴다. 설정 공간 복원 도우미는 가짜
    설정 공간 파일에 대고 **실제로** 실행한다. NSSR 을 쓰면 링크가 내려가고 설정 공간이
    초기화(Vendor FFFF, BAR 0)되며, 다음 sleep 에서 링크·설정 응답이 돌아온다."""

    def __init__(self, fs, bus, csts_after=0x10, arm_out=None, hotplug=False):
        self.fs, self.bus, self.log = fs, bus, []
        self.csts_after, self.hotplug = csts_after, hotplug
        self.arm_out = arm_out or f'CMD 6\nCAP {NSSRS | 0xFF}\nCSTS 1\nARMED\nWROTE\n'
        self.pending = []
        self.down = False
        (fs.dut_real / 'config').write_bytes(CONFIG)

    def has_pending(self, **_):
        return False

    def tick(self, *_):
        """time.sleep 대역 — NSSR 뒤 첫 대기에서 장치가 돌아온다."""
        if self.down:
            self.down = False
            self.fs.link(True)
            if self.hotplug:                             # pciehp 재열거 + 드라이버 자동 연결
                self.fs.add_dut()
                (self.fs.dut_real / 'config').write_bytes(CONFIG)
                self.bus.bind()
            else:                                         # 초기화된 설정 공간(BAR 0)
                (self.fs.dut_real / 'config').write_bytes(CONFIG[:0x10] + bytes(len(CONFIG) - 0x10))

    def run(self, argv, deadline, **_):
        if argv[:2] == ['sh', '-c']:
            self.log.append('rescan')
            return 0, b'', b''
        prog = argv[2]
        if prog == v.ExceptionController._SYSFS_WRITE:
            path, value = Path(argv[3]), argv[4]
            name = path.name if path.name != 'enable' else 'enable=' + value
            self.log.append(name)
            if name == 'unbind':
                (self.fs.dut_real / 'driver').unlink()
            elif name == 'drivers_probe':
                self.bus.bind()
            return 0, b'', b''
        if prog == v._CFG_RESTORE:
            self.log.append('cfg_restore')
            p = subprocess.run(argv, capture_output=True, timeout=10)
            return p.returncode, p.stdout, p.stderr
        if prog == v._NSSR_HELPER:
            mode = argv[3]
            self.log.append('helper:' + mode)
            if mode == 'arm':
                if 'ARMED' not in self.arm_out:
                    return 5, self.arm_out.encode(), b''
                self.fs.link(False)
                self.down = True
                if self.hotplug:
                    self.fs.remove_dut()
                else:
                    (self.fs.dut_real / 'config').write_bytes(b'\xff' * len(CONFIG))
                return 0, self.arm_out.encode(), b''
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

    def run_nssr(self, runner):
        self.c.runner = runner
        with patch.object(v.time, 'sleep', side_effect=runner.tick):
            with self.assertLogs('pcfuzz', level='WARNING') as logs:
                try:
                    self.c._nssr(self.c.clock() + 30)
                    err = None
                except v.ExceptionFailure as exc:
                    err = exc
        return err, '\n'.join(logs.output)

    def test_spec_sequence_without_reenumeration(self):
        r = Runner(self.fs, self.bus)
        order = []
        self.c._nssr_trigger = lambda t: order.append(list(r.log))
        err, text = self.run_nssr(r)
        self.assertIsNone(err, text)
        self.assertEqual(r.log, ['unbind', 'enable=1', 'helper:arm', 'cfg_restore', 'helper:csts',
                                 'enable=0', 'drivers_probe'])
        self.assertNotIn('remove', r.log)
        self.assertNotIn('rescan', r.log)                          # 재열거 = 드라이버 자동 연결
        self.assertEqual(order, [['unbind', 'enable=1']])         # t0: unbind 뒤 NSSR 쓰기 직전
        # 설정 공간이 NSSR 전 값으로 돌아왔다(BAR0·Command)
        self.assertEqual((self.fs.dut_real / 'config').read_bytes(), CONFIG)
        self.assertTrue((self.fs.dut_real / 'driver').exists())
        self.assertIn('NSSRO=1', text)
        self.assertIn('설정 응답', text)
        self.assertTrue(self.c._reenumerated)                      # nvmeN 재해석
        self.assertNotIn('subsystem-reset', text)

    def test_nssro_clear_is_device_spec_violation_and_preserved(self):
        r = Runner(self.fs, self.bus, csts_after=0x0)
        err, text = self.run_nssr(r)
        self.assertRegex(str(err), r'\[장치 측\] NSSR 스펙 위반.*NSSRO=0')
        self.assertNotIn('drivers_probe', r.log)                  # 현상 보존: 드라이버 붙이지 않음

    def test_cfs_after_reset_fails(self):
        r = Runner(self.fs, self.bus, csts_after=0x12)
        err, _ = self.run_nssr(r)
        self.assertIn('CFS=1', str(err))

    def test_hotplug_reenumeration_is_unverified_not_failure(self):
        r = Runner(self.fs, self.bus, hotplug=True)
        err, text = self.run_nssr(r)
        self.assertIsNone(err, text)
        self.assertIn('NSSRO 확인 불가', text)
        self.assertNotIn('cfg_restore', r.log)
        self.assertNotIn('helper:csts', r.log)
        self.assertNotIn('enable=0', r.log)                      # 드라이버가 붙은 장치엔 쓰지 않음(EBUSY)
        self.assertNotIn('drivers_probe', r.log)

    def test_not_issued_restores_driver(self):
        r = Runner(self.fs, self.bus, arm_out='CMD 6\nCAP 255\nCSTS 1\nERR CAP.NSSRS=0\n')
        err, text = self.run_nssr(r)
        self.assertIn('NSSR 미실행', str(err))
        self.assertIn('CAP.NSSRS=0', str(err))
        self.assertEqual(r.log[-2:], ['enable=0', 'drivers_probe'])
        self.assertTrue((self.fs.dut_real / 'driver').exists())

    def test_link_never_returns_is_device_side(self):
        r = Runner(self.fs, self.bus)
        r.tick = lambda *_: None                                 # 링크가 끝내 안 올라옴
        clock = iter(i * 0.5 for i in range(10 ** 6))
        self.c.clock = lambda: next(clock)
        err, _ = self.run_nssr(r)
        self.assertIn('[장치 측] NSSR 뒤 링크가', str(err))
        self.assertNotIn('cfg_restore', r.log)

    def test_config_never_answers_is_device_side(self):
        r = Runner(self.fs, self.bus)

        def tick(*_):                                            # 링크는 오는데 설정은 FFFF
            r.down = False
            self.fs.link(True)
        r.tick = tick
        clock = iter(i * 0.5 for i in range(10 ** 6))
        self.c.clock = lambda: next(clock)
        err, _ = self.run_nssr(r)
        self.assertIn('[장치 측] NSSR 뒤 설정 요청에 응답하지 않음', str(err))

    def test_crs_vendor_is_not_ready(self):
        self.fs.vendor(0x0001)
        m = v.RecoveryMonitor(DUT, RP, 'SN1', pci=self.fs.pci, nvme=self.fs.nvme, bar=object())
        self.assertFalse(m._vendor_ok())
        self.fs.vendor(0x144D)
        self.assertTrue(m._vendor_ok())

    def test_capability_needs_root_port(self):
        self.c.runner = Runner(self.fs, self.bus)
        self.c.runner.run = lambda argv, deadline, **kw: (0, b'{"cap": "%d"}' % NSSRS, b'')
        profile = v.Profile('nssr', (('nssr', 0.0),), 30, 30)
        with patch.object(v, 'subsystem_support', return_value=('AVAILABLE', 'ok')):
            self.assertEqual(self.c.capability(profile)[0], 'AVAILABLE')
            self.c.root_bdf = None
            self.assertEqual(self.c.capability(profile)[0], 'UNCONFIGURED')


class CfgRestore(unittest.TestCase):
    """_CFG_RESTORE 를 일반 파일에 실제로 실행 — PCIe cap 제어 레지스터까지 되쓴다."""

    def test_restores_header_and_pcie_control(self):
        cfg = bytearray(256)
        struct.pack_into('<HHH', cfg, 0, 0x144D, 0xA80A, 0x0006)
        cfg[6] = 0x10                                            # status: cap list
        struct.pack_into('<II', cfg, 0x10, BAR0, 0x1)
        cfg[0x34] = 0x70
        cfg[0x70] = 0x10
        struct.pack_into('<H', cfg, 0x78, 0x2950)                # DevCtl (MPS/MRRS)
        struct.pack_into('<H', cfg, 0x80, 0x0042)                # LnkCtl (ASPM 등)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'config'
            wiped = bytearray(cfg)
            wiped[4:6] = bytes(2)
            wiped[0x10:0x18] = bytes(8)
            wiped[0x78:0x7A] = bytes(2)
            wiped[0x80:0x82] = bytes(2)
            path.write_bytes(bytes(wiped))
            p = subprocess.run([sys.executable, '-c', v._CFG_RESTORE, str(path), bytes(cfg).hex()],
                               capture_output=True, timeout=10)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            rep = json.loads(p.stdout)
            rows = {r['name']: r for r in rep['rows']}
            self.assertTrue(all(r['ok'] for r in rep['rows']))
            self.assertEqual((rows['BAR0']['reset'], rows['BAR0']['after']), (0, BAR0))
            self.assertEqual(rows['PCIe DevCtl']['after'], 0x2950)
            self.assertEqual(path.read_bytes(), bytes(cfg))


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
