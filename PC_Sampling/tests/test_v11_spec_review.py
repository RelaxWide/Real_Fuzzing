"""리셋·POR 스펙 재검토 — 관측 시각, 판정 예외, 전원 시퀀스, 정상 종료, 설정 공간 복원 비교.

1) 관측 시각은 읽기가 끝난 뒤 찍는다(FLR/hot reset 중 설정 읽기가 막혀 live 가 RDY 보다 앞서던 음수).
2) 음수 구간은 '관측 순서 역전', FLR/hot reset 의 설정 응답 구간은 커널 잠금으로 '측정 불가'.
3) 전원 ON 뒤 PERST 해제(Tpvperl)는 NPO/SPO 기준(t0=전원 ON)을 바꾸지 않는다.
4) NPO: 전원 차단 전 CC.SHN → CSTS.SHST=10b 확인.
5) PERST assert·전원 OFF 는 링크 다운으로 효과 확인(GPIO readback 대신).
6) NSSR 설정 공간 복원: AER·LTR·L1SS 까지 되쓰고 저장본과 비교한 결과를 낸다.
"""
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from test_v11_timing import DUT, RP, FakeSys, FakeBar, FakeMon, controller, v


class StampAfterRead(unittest.TestCase):
    def setUp(self):
        self.fs = FakeSys()
        self.addCleanup(self.fs.tmp.cleanup)
        self.now = [0.0]
        clock = lambda: self.now[0]
        self.m = v.RecoveryMonitor(DUT, RP, 'SN1', clock=clock, pci=self.fs.pci, nvme=self.fs.nvme,
                                   bar=FakeBar(self.fs.pci / DUT / 'resource0', clock))

    def test_blocked_config_read_does_not_backdate_marks(self):
        self.m.sample()
        self.m.begin_cycle(0.0)
        self.fs.state('resetting')
        self.m.sample()
        real = self.m._vendor_ok

        def blocked():                     # 커널이 설정 접근을 잠근 동안 드라이버가 live 로 감
            self.now[0] += 0.2
            self.fs.state('live')
            return real()
        self.m._vendor_ok = blocked
        self.now[0] = 1.0
        self.m.sample_cfg()
        self.m.sample_fast()
        self.assertEqual(self.m.marks['live'], 1.2)      # 예전: 읽기 전 시각 1.0 으로 기록

    def test_two_threads_and_lock_not_held_while_reading(self):
        entered = []

        def slow():
            entered.append(self.m._lock.acquire(blocking=False))
            if entered[-1]:
                self.m._lock.release()
            return True
        self.m._vendor_ok = slow
        self.m.sample_cfg()
        self.assertEqual(entered, [True])                 # 읽는 동안 잠금을 쥐지 않음
        self.m.start()
        self.addCleanup(self.m.stop)
        self.assertEqual(sorted(t.name for t in self.m._threads), ['recovery-cfg', 'recovery-regs'])


class JudgementExceptions(unittest.TestCase):
    def rows(self, c):
        return [json.loads(l) for l in c.log_path.read_text().splitlines() if '"timing"' in l][-1]['rows']

    def test_negative_segment_is_observation_error_not_ok(self):
        c = controller(self)
        mon = FakeMon({'cc_en': 0.02, 'rdy': 0.06, 'live': 0.03})
        with self.assertLogs('pcfuzz', level='WARNING') as logs:
            c._timing_wait(v.Profile('p', (('controller_reset', 0.0),), 30, 30), mon, 0.0, 'x')
        row = [r for r in self.rows(c) if r['key'] == 'rdy_to_admin'][0]
        self.assertEqual(row['verdict'], 'N/A')
        self.assertIn('관측 순서 역전', row['side'])
        self.assertIn('측정 불가', '\n'.join(logs.output))

    def test_kernel_locked_reset_cfg_row_is_not_judged(self):
        for action, expect in (('flr', 'N/A'), ('hot_reset', 'N/A'), ('nssr', 'OVER')):
            with self.subTest(action=action):
                c = controller(self)
                c._t0_action = action
                mon = FakeMon({'link_down': 0.0, 'link_up': 0.1, 'cfg_ok': 0.5,
                               'cc_en': 0.6, 'rdy': 0.62, 'live': 0.7})
                try:
                    c._timing_wait(v.Profile('p', ((action, 0.0),), 30, 30), mon, 0.0, 'x')
                except v.ExceptionFailure:
                    pass
                row = [r for r in self.rows(c) if r['key'] == 'cfg_after_ts'][0]
                self.assertEqual(row['verdict'], expect)


class PowerSequenceT0(unittest.TestCase):
    def run_steps(self, steps, timing):
        c = controller(self)
        c.options['adapters'] = {'perst_assert': dict(argv=['x'], effect='assert'),
                                 'perst_release': dict(argv=['x'], effect='deassert')}
        c._action = Mock()
        c._timing_wait = Mock()
        mon = Mock()
        mon.start.return_value = mon
        mon.shutdown = {'shn': 1.0, 'shst': 1.2, 'shn_type': 1}
        c._new_monitor = Mock(return_value=mon)
        c._run_profile(v.Profile('x', steps, 60, 30, timing))
        return c, mon

    def test_perst_release_after_power_on_keeps_power_on_t0(self):
        c, mon = self.run_steps((('pci_remove', 0.0), ('perst_assert', 0.0), ('power_off', 0.0),
                                 ('power_on', 0.0), ('perst_release', 0.0), ('pci_rescan_wait', 0.0)), 'npo')
        self.assertEqual(c._timing_wait.call_args[0][3], 'power_on 반환')
        self.assertEqual(mon.begin_cycle.call_count, 1)

    def test_warm_perst_t0_is_release(self):
        c, _ = self.run_steps((('perst_assert', 0.0), ('pci_remove', 0.0), ('perst_release', 0.0),
                               ('pci_rescan_wait', 0.0)), 'reset')
        self.assertEqual(c._timing_wait.call_args[0][3], 'perst_release 반환')


class NormalShutdown(unittest.TestCase):
    def test_monitor_records_shn_and_shst(self):
        m = v.RecoveryMonitor(DUT, RP, 'SN1', clock=lambda: 0.0, bar=Mock())
        m._on_regs('R', 1.0, 0x464001, 0x1)            # EN=1, SHN(15:14)=01b
        m._on_regs('R', 1.3, 0x464001, 0x9)            # SHST(3:2)=10b
        self.assertEqual(m.shutdown['shn'], 1.0)
        self.assertEqual(m.shutdown['shst'], 1.3)
        self.assertEqual(m.shutdown['shn_type'], 1)

    def test_check(self):
        c = controller(self)
        with self.assertLogs('pcfuzz', level='WARNING') as logs:
            c._check_shutdown(Mock(shutdown={'shn': 1.0, 'shst': 1.25, 'shn_type': 1}))
        self.assertIn('정상 종료 확인: CC.SHN 정상(01b) → CSTS.SHST=10b 250ms', '\n'.join(logs.output))
        with self.assertLogs('pcfuzz', level='WARNING'):
            with self.assertRaisesRegex(v.ExceptionFailure, r'\[장치 측\] 정상 종료 미완료'):
                c._check_shutdown(Mock(shutdown={'shn': 1.0, 'shn_type': 1, 'last_shst': 1}))
            c._check_shutdown(Mock(shutdown={}))          # 관측 못함 = 판정 생략


class EffectByLink(unittest.TestCase):
    def setUp(self):
        self.fs = FakeSys()
        self.addCleanup(self.fs.tmp.cleanup)
        cfg = json.loads((Path(__file__).resolve().parents[1] / 'fuzzer_config.json')
                         .read_text(encoding='utf-8-sig'))
        self.c = v.ExceptionController(cfg['exceptions'], cfg, '/dev/nvme0', 'pmu.py',
                                       Path(self.fs.tmp.name) / 'log')
        self.c.bdf, self.c.root_bdf = DUT, RP
        self.c.runner = Mock()
        self.c.runner.run.return_value = (0, b'', b'')
        now = [0.0]

        def clock():
            now[0] += 0.05
            return now[0]
        self.c.clock = clock
        p = patch.object(v, '_PCI_DEVICES', self.fs.pci)
        p.start()
        self.addCleanup(p.stop)

    def test_command_ok_but_link_stays_up_fails(self):
        with patch.object(v.time, 'sleep'), self.assertLogs('pcfuzz', level='WARNING'):
            with self.assertRaisesRegex(v.ExceptionFailure, r'\[호스트 측\] perst_assert 명령은 성공했지만'):
                self.c._action('perst_assert', self.c.clock() + 30)
        self.assertTrue(self.c.asserted)                  # 정리 때 해제해야 함

    def test_link_down_confirms_effect(self):
        self.fs.link(False)
        with patch.object(v.time, 'sleep'), self.assertLogs('pcfuzz', level='WARNING') as logs:
            self.c._action('power_off', self.c.clock() + 30)
        self.assertIn('링크 다운 확인', '\n'.join(logs.output))

    def test_no_root_port_skips_check(self):
        self.c.root_bdf = None
        with patch.object(v.time, 'sleep'):
            self.c._action('perst_assert', self.c.clock() + 30)


def ext_cfg():
    """PCIe cap(0x70) + 확장 cap: AER(0x100) → LTR(0x140) → L1SS(0x150)."""
    cfg = bytearray(4096)
    struct.pack_into('<HHH', cfg, 0, 0x144D, 0xA80A, 0x0006)
    cfg[6] = 0x10
    struct.pack_into('<I', cfg, 0x10, 0xA9200004)
    cfg[0x34] = 0x70
    cfg[0x70] = 0x10
    struct.pack_into('<H', cfg, 0x78, 0x2950)
    struct.pack_into('<H', cfg, 0x80, 0x0042)
    struct.pack_into('<H', cfg, 0x98, 0x0400)                   # DevCtl2: LTR enable
    struct.pack_into('<I', cfg, 0x100, 0x0001 | (1 << 16) | (0x140 << 20))
    struct.pack_into('<I', cfg, 0x108, 0x00400000)             # UE mask
    struct.pack_into('<I', cfg, 0x10C, 0x00462030)             # UE severity
    struct.pack_into('<I', cfg, 0x114, 0x00002000)             # CE mask
    struct.pack_into('<I', cfg, 0x118, 0x00000140 | 0x5)       # ECRC 설정 + First Error Ptr(ROS)
    struct.pack_into('<I', cfg, 0x140, 0x0018 | (1 << 16) | (0x150 << 20))
    struct.pack_into('<HH', cfg, 0x144, 0x1003, 0x1003)
    struct.pack_into('<I', cfg, 0x150, 0x001E | (1 << 16))
    struct.pack_into('<I', cfg, 0x158, 0x4064000F)             # L1SS Ctl1 (enable 비트 포함)
    struct.pack_into('<I', cfg, 0x15C, 0x00000028)
    cfg[0x06] = 0x10                                           # status: cap list
    struct.pack_into('<H', cfg, 0x7A, 0x0004)                  # DevSta: 오류 비트(복원 대상 아님)
    return cfg


class CfgRestoreCompare(unittest.TestCase):
    def run_restore(self, saved, wiped, writes=None):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'config'
            path.write_bytes(bytes(wiped))
            p = subprocess.run([sys.executable, '-c', v._CFG_RESTORE, str(path), bytes(saved).hex()],
                               capture_output=True, timeout=10)
            return p.returncode, json.loads(p.stdout), path.read_bytes()

    def test_restores_aer_ltr_l1ss_and_reports_comparison(self):
        saved = ext_cfg()
        wiped = bytearray(saved)
        for off, n in ((0x04, 2), (0x10, 4), (0x78, 2), (0x80, 2), (0x98, 2), (0x108, 4), (0x10C, 4),
                       (0x114, 4), (0x118, 4), (0x144, 4), (0x158, 4), (0x15C, 4), (0x7A, 2)):
            wiped[off:off + n] = bytes(n)
        rc, rep, final = self.run_restore(saved, wiped)
        self.assertEqual(rc, 0, rep)
        rows = {r['name']: r for r in rep['rows']}
        for name in ('AER UE Mask', 'AER UE Severity', 'AER CE Mask', 'AER Cap/Ctl', 'LTR MaxSnoop',
                     'LTR MaxNoSnoop', 'L1SS Ctl1', 'L1SS Ctl2', 'PCIe DevCtl2', 'BAR0', 'Command'):
            self.assertIn(name, rows)
            self.assertTrue(rows[name]['ok'], name)
        self.assertEqual(rows['L1SS Ctl1']['after'], 0x4064000F)
        self.assertEqual(rows['BAR0']['reset'], 0)
        self.assertEqual([c['name'] for c in rep['caps'] if c['start'] >= 0x100], ['AER', 'LTR', 'L1SS'])
        # 복원 대상 외 차이(DevSta 오류 비트)는 영역 이름으로 보고
        self.assertEqual([(o['region'], o['off']) for o in rep['other']], [('PCIe', 0x7A)])
        # 순서: L1SS(ASPM 설정)가 LnkCtl 보다 먼저, Command 는 마지막
        names = [r['name'] for r in rep['rows']]
        self.assertLess(names.index('L1SS Ctl1'), names.index('PCIe LnkCtl'))
        self.assertLess(names.index('LTR MaxSnoop'), names.index('PCIe DevCtl2'))
        self.assertEqual(names[-1], 'Command')

    def test_bar_mismatch_fails(self):
        saved = ext_cfg()
        rc, rep, _ = self.run_restore(saved, saved)
        self.assertEqual(rc, 0)
        # 되읽기가 다른 값이 되는 상황: 저장본 BAR 을 '쓸 수 없는' 값처럼 흉내 — 파일은 그대로 쓰이므로
        #   컨트롤러 쪽 판정만 확인한다
        c = controller(self)
        with self.assertLogs('pcfuzz', level='WARNING') as logs:
            c.emit('cfg_restore', rows=[dict(name='BAR0', off=0x10, size=4, saved=0xA9200004, reset=0,
                                             after=0x4, ok=False)], other=[], ext=[])
        text = '\n'.join(logs.output)
        self.assertIn('✗ 불일치', text)
        self.assertIn('불일치 1', text)


if __name__ == '__main__':
    unittest.main()


def root_cfg():
    """루트 포트: PCIe cap 0x40(DevCtl2 LTR enable, LnkCtl ASPM L1) + AER 0x100."""
    cfg = bytearray(4096)
    cfg[6] = 0x10
    cfg[0x34] = 0x40
    cfg[0x40] = 0x10
    struct.pack_into('<H', cfg, 0x40 + 0x10, 0x0042)            # LnkCtl: ASPM L1 + CCC
    struct.pack_into('<H', cfg, 0x40 + 0x12, 1 << 13)           # LnkSta: DLLLA
    struct.pack_into('<H', cfg, 0x40 + 0x28, 0x0400)            # DevCtl2: LTR enable
    struct.pack_into('<I', cfg, 0x100, 0x0001 | (1 << 16))
    struct.pack_into('<I', cfg, 0x108, 0x00100000)              # UE mask (Surprise Down 안 가림)
    return cfg


class RootPort(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'config'
        self.path.write_bytes(bytes(root_cfg()))

    def rd(self, off, n):
        return int.from_bytes(self.path.read_bytes()[off:off + n], 'little')

    def test_guard_sequence(self):
        g = v._RootPortGuard(self.path)
        self.assertTrue(g.mask_surprise_down())
        self.assertEqual(self.rd(0x108, 4), 0x00100020)
        # NSSR 링크 다운: 하드웨어가 루트 DevCtl2 LTR enable 을 끄고 Surprise Down 을 기록
        b = bytearray(self.path.read_bytes())
        struct.pack_into('<H', b, 0x68, 0x0000)
        struct.pack_into('<I', b, 0x104, (1 << 5) | (1 << 20))   # Surprise Down + UR
        self.path.write_bytes(bytes(b))
        self.assertEqual(g.restore_ltr(), (0x0000, 0x0400))
        self.assertEqual(self.rd(0x68, 2), 0x0400)
        self.assertTrue(g.aspm_l1_off())
        self.assertEqual(self.rd(0x50, 2), 0x0040)
        g.aspm_restore()
        self.assertEqual(self.rd(0x50, 2), 0x0042)
        aer = g.collect_aer()
        self.assertEqual(aer, dict(surprise_down=True, ue_other=1 << 20, ce=0))
        self.assertEqual(self.rd(0x104, 4), 1 << 5)              # RW1C 로 Surprise Down 만 씀
        g.unmask()
        self.assertEqual(self.rd(0x108, 4), 0x00100000)

    def test_already_masked_is_left_alone(self):
        b = root_cfg()
        struct.pack_into('<I', b, 0x108, 1 << 5)
        self.path.write_bytes(bytes(b))
        g = v._RootPortGuard(self.path)
        self.assertFalse(g.mask_surprise_down())
        g.unmask()
        self.assertEqual(self.rd(0x108, 4), 1 << 5)


class NssrWithRootPort(unittest.TestCase):
    """_nssr 전체 흐름에서 루트 포트 처리 순서: 마스크 → (링크 복귀) LTR·ASPM → 장치 복원 → 원복."""

    def test_order_and_cleanup(self):
        from test_v11_nssr import FakeBus, Runner
        fs = FakeSys()
        self.addCleanup(fs.tmp.cleanup)
        rp = fs.rp_real / 'config'
        rp.write_bytes(bytes(root_cfg()))
        bus = FakeBus(fs)
        c = v.ExceptionController(__import__('test_v11_exceptions').options(), {}, '/dev/nvme0', '',
                                  Path(fs.tmp.name) / 'events')
        c.serial, c.bdf, c.root_bdf = 'SN1', DUT, RP
        r = Runner(fs, bus)
        rd = lambda off, n: int.from_bytes(rp.read_bytes()[off:off + n], 'little')
        seen = {}
        orig_run, orig_tick = r.run, r.tick

        def run(argv, deadline, **kw):
            if argv[2:3] == [v._NSSR_HELPER] and argv[3] == 'arm':
                seen['mask_at_arm'] = rd(0x108, 4)
            if argv[2:3] == [v._CFG_RESTORE]:
                seen['root_at_restore'] = (rd(0x68, 2), rd(0x50, 2))
            return orig_run(argv, deadline, **kw)

        def tick(*a):
            if r.down:                                           # DL_Down 효과
                b = bytearray(rp.read_bytes())
                struct.pack_into('<H', b, 0x68, 0)
                struct.pack_into('<I', b, 0x104, 1 << 5)
                rp.write_bytes(bytes(b))
            orig_tick(*a)
        r.run, r.tick = run, tick
        c.runner = r
        with patch.object(v, '_PCI_DEVICES', fs.pci), patch.object(v, '_PCI_BUS', bus.root), \
                patch.object(v.time, 'sleep', side_effect=tick):
            with self.assertLogs('pcfuzz', level='WARNING') as logs:
                c._nssr(c.clock() + 30)
        self.assertEqual(seen['mask_at_arm'] & (1 << 5), 1 << 5)
        self.assertEqual(seen['root_at_restore'], (0x0400, 0x0040))   # LTR 먼저 켬, ASPM L1 꺼 둠
        self.assertEqual(rd(0x108, 4), 0x00100000)                    # 마스크 원복
        self.assertEqual(rd(0x50, 2) & 0x2, 0x2)                       # ASPM L1 원복
        text = '\n'.join(logs.output)
        self.assertIn('Surprise Down 기록 있음(예상된 이벤트 — 지움)', text)
        self.assertIn('LTR enable 해제돼 있었음', text)


class RegionLabels(unittest.TestCase):
    def test_offset_outside_caps_and_duplicate_vsec(self):
        cfg = bytearray(4096)
        struct.pack_into('<HHH', cfg, 0, 0x144D, 0xA80A, 0x0006)
        cfg[6] = 0x10
        cfg[0x34] = 0x70
        cfg[0x70], cfg[0x71] = 0x10, 0xB0                        # PCIe → MSI-X
        cfg[0xB0], cfg[0xB1] = 0x11, 0x00                        # MSI-X (12B: 0xB0~0xBB)
        struct.pack_into('<I', cfg, 0x100, 0x000B | (1 << 16) | (0x148 << 20))   # VSEC len 0x18
        struct.pack_into('<I', cfg, 0x104, 0x018 << 20)
        struct.pack_into('<I', cfg, 0x148, 0x000B | (1 << 16) | (0x178 << 20))   # VSEC#2 len 0x20
        struct.pack_into('<I', cfg, 0x14C, 0x020 << 20)
        struct.pack_into('<I', cfg, 0x178, 0x001E | (1 << 16))                   # L1SS (16B)
        final = bytearray(cfg)
        final[0xE4] ^= 1                                         # MSI-X 뒤, 캡 밖
        final[0x160] ^= 1                                        # 두 번째 VSEC 안
        final[0x349] ^= 1                                        # L1SS(0x178~0x187) 밖
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'config'
            path.write_bytes(bytes(final))
            p = subprocess.run([sys.executable, '-c', v._CFG_RESTORE, str(path), bytes(cfg).hex()],
                               capture_output=True, timeout=10)
        rep = json.loads(p.stdout)
        self.assertEqual([(o['region'], o['off']) for o in rep['other']],
                         [('캡 밖', 0xE4), ('VSEC', 0x160), ('캡 밖', 0x349)])


class PowerLossCounter(unittest.TestCase):
    def run_check(self, timing, base, now):
        c = controller(self)
        c._smart_base = base
        c._smart_counts = Mock(return_value=now)
        prof = v.Profile('p', (('power_on', 0.0),), 60, 30, timing)
        with self.assertLogs('pcfuzz', level='WARNING') as logs:
            try:
                c._check_power_loss(prof)
                err = None
            except v.ExceptionFailure as exc:
                err = exc
        rows = [json.loads(l) for l in c.log_path.read_text().splitlines() if 'power_loss_check' in l]
        return rows[-1]['status'], err, '\n'.join(logs.output), c

    def test_spor_must_increment_npor_must_not(self):
        b = dict(unsafe=5, cycles=10)
        self.assertEqual(self.run_check('spo', b, dict(unsafe=6, cycles=11))[0], 'OK')
        self.assertEqual(self.run_check('npo', b, dict(unsafe=5, cycles=11))[0], 'OK')
        st, err, text, _ = self.run_check('npo', b, dict(unsafe=6, cycles=11))
        self.assertEqual(st, 'MISMATCH')
        self.assertRegex(str(err), r'\[장치 측\] NPOR: SMART Unexpected Power Losses \+1 \(기대 \+0\)')
        st, err, _, _ = self.run_check('spo', b, dict(unsafe=5, cycles=11))
        self.assertIn('증가하지 않음', str(err))

    def test_other_power_cycle_or_missing_is_not_judged(self):
        b = dict(unsafe=5, cycles=10)
        st, err, _, c = self.run_check('spo', b, dict(unsafe=7, cycles=12))
        self.assertEqual((st, err), ('SKIPPED', None))
        self.assertEqual(c._smart_base, dict(unsafe=7, cycles=12))   # 다음 기준 갱신
        self.assertEqual(self.run_check('npo', None, dict(unsafe=5, cycles=11))[:2], ('UNAVAILABLE', None))

    def test_json_keys_old_and_new_names(self):
        c = controller(self)
        del c._smart_counts
        c.runner = Mock()
        for key in ('unsafe_shutdowns', 'unexpected_power_losses'):
            c.runner.run.return_value = (0, json.dumps({key: 3, 'power_cycles': '0x10'}).encode(), b'')
            self.assertEqual(c._smart_counts(1e9), dict(unsafe=3, cycles=16))
