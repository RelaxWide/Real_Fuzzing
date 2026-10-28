"""v11.5 [Device Info] 추가 항목 + 캠페인 끝 [QTMGR] 보고.

[Device Info] 는 Serial 다음에 Density·FW Revision·Application·CTRL·FormFactor·OEM·RBUF 를 찍는다.
RBUF 는 VU 명령 2개(json qtmgr.rbuf)를 시작 시 한 번만 보내 얻는다. [QTMGR] 는 crash 면 덤프·crash 폴더
수집 뒤, crash 없이 끝나면 종료 요약 뒤 한 번 찍는다. 실제 메서드(_log_device_info, _query_rbuf,
_qtmgr_report, _run_dump_collected, _log_smart)를 장치 호출만 가짜로 바꿔 태운다.
"""
import logging
import os
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

from fuzzer_target import fuzzer as v

CTRL = {'mn': 'SAMSUNG MZVL4512HBLU', 'sn': 'S6XXNX0T123456', 'fr': 'BXV7401Q',
        'vid': 0x144d, 'ssvid': 0x144d, 'ieee': 0x002538, 'ver': 0x10400, 'nn': 1, 'mdts': 9}
NS = {'nsze': 1000215216, 'ncap': 1000215216, 'nuse': 1000, 'flbas': 0, 'lbafs': [{'ds': 9}]}


def make(product='BM9K1_HP', family='BM9K1', pm=False):
    f = v.NVMeFuzzer.__new__(v.NVMeFuzzer)
    f.config = v.FuzzConfig(product=product, product_family=family, nvme_device='/dev/nvme0',
                            pm_inject_prob=1.0 if pm else 0.0)
    f._pcie_bdf = '0000:01:00.0'
    f._pcie_root_bdf = None
    f._pcie_lnkcap = None
    f._nvme_id_dict = lambda cmd: ((dict(CTRL), '', 0) if cmd[1] == 'id-ctrl' else (dict(NS), '', 0))
    return f


def vu_ok(argv, **kw):
    if '-w' in argv:
        return Mock(returncode=0, stdout=b'', stderr=b'')
    return Mock(returncode=0, stdout=bytes.fromhex('10282026') + b'\x00' * 508, stderr=b'')


class Helpers(unittest.TestCase):
    def test_density(self):
        for lbas, lba, want in ((1000215216, 512, ('512GB', '512 GB')),
                                (1953525168, 512, ('1TB', '1 TB')),
                                (3907029168, 512, ('2TB', '2 TB')),
                                (500118192, 512, ('256GB', '256 GB')),
                                (976754646, 4096, ('4TB', '4 TB')),
                                (0, 512, ('', ''))):
            with self.subTest(lbas=lbas, lba=lba):
                self.assertEqual(v._density_nominal(lbas * lba), want)

    def test_oem(self):
        for product, family, want in (('PM9M1_HP', 'PM9M1', 'HP'), ('PM9M1_LENOVO', 'PM9M1', 'LENOVO'),
                                      ('BM9K1_LENOVO', 'BM9K1', 'LENOVO'), ('BM9K1', 'BM9K1', 'BRAND'),
                                      ('P9', 'P9', 'BRAND'), ('PM9M1', '', 'BRAND')):
            with self.subTest(product=product):
                self.assertEqual(v._product_oem(product, family), want)

    def test_ttf(self):
        self.assertEqual(v._fmt_ttf(45 * 60), '45 min')
        self.assertEqual(v._fmt_ttf(3 * 3600 + 12 * 60), '3.2 hours')

    def test_smart_temperature_formats(self):
        for text, want in (('temperature\t\t\t\t: 35 °C (308 K)\n', 35),
                           ('temperature : 36 C (309 Kelvin)\n', 36),
                           ('critical_warning : 0\ntemperature : 310 K\n', 37),
                           ('Temperature Sensor 1 : 40 °C\n', None),
                           ('', None)):
            with self.subTest(text=text):
                self.assertEqual(v._smart_temp_c(text), want)

    def test_shipped_json(self):
        self.assertEqual((v.QTMGR['tester'], v.QTMGR['board'], v.QTMGR['slot'], v.QTMGR['port']),
                         ('RS0000-0', '0', '0', '0'))
        self.assertEqual(v.QTMGR['ctrl'], {'BM9K1': 'PALAU', 'PM9M1': 'SM2504XT', 'BM9H1': 'SM2269XT',
                                           'P7': 'PS2251_U21', 'P9': 'PS2251_U21'})
        rb = v.QTMGR['rbuf']
        self.assertEqual((rb['write'], rb['read'], rb['digits'], rb['sig_file']),
                         ({'opcode': 0xC1, 'cdw10': 4, 'cdw12': 0x1, 'data_len': 16},
                          {'opcode': 0xC2, 'cdw10': 4, 'cdw12': 0x23000003, 'data_len': 512}, 8, 'sig2.bin'))
        self.assertIn('PM9M1_LENOVO', v.PRODUCT_CONFIGS)
        self.assertNotIn('PM9M1_LNB', v.PRODUCT_CONFIGS)

    def test_bad_config_fails_loudly(self):
        for bad in ([], {'tester': 3}, {'ctrl': {'BM9K1': 1}}, {'rbuf': {'write': {'opcode': 'x'}}},
                    {'rbuf': {'digits': 0}}, {'rbuf': {'digits': 7}}, {'rbuf': {'digits': 2000}},
                    {'tester': 'TestPC01'}, {'tester': 'RS000-1'}, {'board': 'NA'}, {'slot': '0000:01:00.0'}):
            with self.subTest(bad=bad), self.assertRaises(SystemExit):
                v._parse_qtmgr(bad)

    def test_terminal_filter_passes_new_tags(self):
        flt = v._FuzzingTerminalFilter()
        for msg in ('[Device Info] RBUF : 1', '[QTMGR] SN : x'):
            rec = logging.LogRecord('pcfuzz', logging.WARNING, __file__, 1, msg, None, None)
            self.assertTrue(flt.filter(rec), msg)


class DeviceInfo(unittest.TestCase):
    def setUp(self):
        self.sig = tempfile.NamedTemporaryFile(suffix='.bin', delete=False)
        self.sig.write(b'\x01' * 16)
        self.sig.close()
        self.addCleanup(os.unlink, self.sig.name)
        p = patch.dict(v.QTMGR['rbuf'], sig_file=self.sig.name)
        p.start()
        self.addCleanup(p.stop)

    def lines(self, f):
        with patch.object(v, '_run_nvme_state_cmd', side_effect=vu_ok) as run, \
                self.assertLogs('pcfuzz', level='WARNING') as logs:
            f._log_device_info()
        return [l.split(':', 2)[2] for l in logs.output], run

    def test_order_and_values(self):
        out, run = self.lines(make())
        self.assertTrue(all(l.startswith('[Device Info] ') for l in out), out)
        body = [l[len('[Device Info] '):] for l in out]
        i = next(n for n, l in enumerate(body) if l.strip().startswith('Serial'))
        self.assertTrue(body[i - 1].strip().startswith('Model'))
        self.assertEqual(body[i + 1:i + 8], [
            '  Density     : eDensity_512GB', '  FW Revision : BXV7401Q', '  Application : ePC',
            '  CTRL        : ePALAU', '  FormFactor  : eM_2', '  OEM         : eHP', '  RBUF        : 20261028'])
        # 기존 줄과 같은 들여쓰기·': ' 위치
        self.assertEqual({l.index(': ') for l in body[i - 1:i + 9]}, {14})
        self.assertTrue(body[i + 8].strip().startswith('Firmware'), '나머지 정보가 이어서 나와야 한다')
        self.assertTrue(any('NSZE' in l for l in body))

    def test_ctrl_and_oem_per_product(self):
        for product, family, ctrl, oem in (('PM9M1', 'PM9M1', 'eSM2504XT', 'eBRAND'),
                                           ('PM9M1_LENOVO', 'PM9M1', 'eSM2504XT', 'eLENOVO'),
                                           ('BM9H1', '', 'eSM2269XT', 'eBRAND'),
                                           ('P7', '', 'ePS2251_U21', 'eBRAND'),
                                           ('BM9K1', 'BM9K1', 'ePALAU', 'eBRAND')):
            with self.subTest(product=product):
                out, _ = self.lines(make(product, family))
                self.assertIn(f'[Device Info]   CTRL        : {ctrl}', out)
                self.assertIn(f'[Device Info]   OEM         : {oem}', out)

    def test_vu_commands_sent_once(self):
        f = make()
        _, run = self.lines(f)
        self.assertEqual(run.call_count, 2)
        w, r = (c.args[0] for c in run.call_args_list)
        self.assertEqual(w[:3], ['nvme', 'admin-passthru', '/dev/nvme0'])
        for a in ('--opcode=0xc1', '--cdw10=0x4', '--cdw12=0x1', '--data-len=16', '--timeout=30000',
                  f'--input-file={self.sig.name}', '-w'):
            self.assertIn(a, w)
        for a in ('--opcode=0xc2', '--cdw10=0x4', '--cdw12=0x23000003', '--data-len=512', '-r', '-b'):
            self.assertIn(a, r)
        out, run2 = self.lines(f)                     # 주기 재출력
        run2.assert_not_called()
        self.assertIn('[Device Info]   RBUF        : 20261028', out)

    def test_rbuf_is_bcd_hex_of_first_four_bytes(self):
        """실기 응답(2026-10-28): 버퍼 10 23 20 26 00 00 00 00 …(MMDD YYYY) → 연도 먼저 '20261023'.
        글자(ASCII)로 읽으면 안 된다."""
        def read(argv, **kw):
            if '-w' in argv:
                return Mock(returncode=0, stdout=b'', stderr=b'')
            return Mock(returncode=0, stdout=bytes.fromhex('1023202600000000') + b'\x00' * 504, stderr=b'')
        with patch.object(v, '_run_nvme_state_cmd', side_effect=read):
            self.assertEqual(make()._query_rbuf(), '20261023')

    def test_rbuf_blank_on_failure(self):
        cases = {
            'write fails': lambda a, **k: Mock(returncode=1, stdout=b'', stderr=b'err'),
            'read fails': lambda a, **k: (Mock(returncode=0, stdout=b'', stderr=b'') if '-w' in a
                                          else Mock(returncode=2, stdout=b'', stderr=b'INVALID')),
            'short read': lambda a, **k: Mock(returncode=0, stdout=b'\x10\x28\x20', stderr=b''),
            'timeout': lambda a, **k: Mock(returncode=-1, stdout=b'', stderr=b'timeout'),
        }
        for name, side in cases.items():
            with self.subTest(name), patch.object(v, '_run_nvme_state_cmd', side_effect=side), \
                    self.assertLogs('pcfuzz', level='WARNING'):
                self.assertEqual(make()._query_rbuf(), '')

    def test_timeout_returns_even_if_child_never_exits(self):
        """D-state nvme-cli: kill 이 안 먹고 wait() 는 영원히 — 호출이 무기한 대기 없이 빈칸으로 돌아와야 한다."""
        proc = Mock()
        proc.communicate.side_effect = v.subprocess.TimeoutExpired('nvme', 35)
        proc.wait.side_effect = AssertionError('timeout 뒤 무기한 wait()')
        with patch.object(v.subprocess, 'Popen', return_value=proc) as popen, \
                patch.object(v.subprocess, 'run', side_effect=AssertionError('subprocess.run')), \
                self.assertLogs('pcfuzz', level='WARNING') as logs:
            self.assertEqual(make()._query_rbuf(), '')
        popen.assert_called_once()                       # write 가 시간 초과 → read 는 보내지 않는다
        self.assertEqual(proc.communicate.call_args.kwargs['timeout'], 35)
        proc.kill.assert_called_once()
        proc.wait.assert_not_called()
        self.assertIn('rc=-1', '\n'.join(logs.output))

    def test_missing_sig_file_sends_nothing(self):
        with patch.dict(v.QTMGR['rbuf'], sig_file='/nonexistent/sig2.bin'), \
                patch.object(v, '_run_nvme_state_cmd') as run, self.assertLogs('pcfuzz', level='WARNING'):
            self.assertEqual(make()._query_rbuf(), '')
        run.assert_not_called()

    def test_relative_sig_file_is_next_to_fuzzer(self):
        with patch.dict(v.QTMGR['rbuf'], sig_file='sig2.bin'), \
                patch.object(v.Path, 'is_file', return_value=True), \
                patch.object(v, '_run_nvme_state_cmd', side_effect=vu_ok) as run:
            make()._query_rbuf()
        self.assertIn(f"--input-file={Path(v.__file__).parent / 'sig2.bin'}", run.call_args_list[0].args[0])


class Qtmgr(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def report(self, f, crash_dir=None):
        with self.assertLogs('pcfuzz', level='WARNING') as logs:
            f._qtmgr_report(crash_dir)
        return [l.split(':', 2)[2] for l in logs.output]

    def device(self, **kw):
        f = make(**kw)
        f._devinfo = {'mn': CTRL['mn'], 'sn': CTRL['sn'], 'fr': CTRL['fr'], 'density': '512 GB',
                      'density_tag': '512GB', 'rbuf': '10282026'}
        f._last_smart_temp = 41
        f.start_time = datetime.now() - timedelta(hours=3, minutes=12)
        f.output_dir = Path(self.tmp.name)
        return f

    def test_crash_report(self):
        f = self.device(product='PM9M1_HP', family='PM9M1', pm=True)
        cd = Path(self.tmp.name) / 'crash_20261028_101010'
        cd.mkdir()
        for n in ('dmesg_20261028_101010_at_crash.txt', 'dmesg_20261028_101010.txt', 'pcfuzz.log'):
            (cd / n).write_text('x')
        f._dump_outputs = [('JLINK', str(cd / 'jlink_mem.bin')), ('UFAS', str(cd / 'ufas_dump.bin')),
                           ('UFAS', '/elsewhere/old.bin')]
        out = self.report(f, cd)
        sep = '=' * 52
        self.assertEqual(out, [
            sep, '[QTMGR] Tester : RS0000-0', '[QTMGR] Slot : 0',
            sep, '[QTMGR] Test Item : Fuzzer', '[QTMGR] Test Case : Fuzzing with PM',
            sep, '[QTMGR] Product : ePM9M1', '[QTMGR] OEM : HP', '[QTMGR] Density : 512 GB',
            '[QTMGR] Form Factor : M_2', '[QTMGR] FW Rev : BXV7401Q', '[QTMGR] FW Build : 10282026',
            f"[QTMGR] MN : {CTRL['mn']}", f"[QTMGR] SN : {CTRL['sn']}",
            sep, '[QTMGR] TTF : 3.2 hours', "[QTMGR] Temp ('C) : 41 (saved value from last SMART CHECK)",
            "[QTMGR] Chamber ('C) : Not Chamber",
            sep, f'[QTMGR] Dmesg Path : {os.path.abspath(cd)}/dmesg_20261028_101010.txt',
            f'[QTMGR] Dmesg Path : {os.path.abspath(cd)}/dmesg_20261028_101010_at_crash.txt',
            f'[QTMGR] UFAS Path : {cd}/jlink_mem.bin', f'[QTMGR] UFAS Path : {cd}/ufas_dump.bin',
            sep])

    def test_ttf_excludes_dump_time(self):
        """10분에 장애 → 덤프 20분 → 보고. TTF 는 장애 감지 시각까지(10 min)."""
        f = self.device()
        crash_at = datetime(2026, 10, 28, 10, 10)
        f.start_time = crash_at - timedelta(minutes=10)
        cd = Path(self.tmp.name) / 'crash_t'
        cd.mkdir()
        with patch.object(v, 'datetime', Mock(now=Mock(return_value=crash_at + timedelta(minutes=20)))), \
                self.assertLogs('pcfuzz', level='WARNING') as logs:
            f._qtmgr_report(cd, crash_at)
        self.assertIn('[QTMGR] TTF : 10 min', '\n'.join(logs.output))

    def test_normal_end_uses_run_end_time(self):
        f = self.device()
        f._run_end_time = f.start_time + timedelta(minutes=45)
        self.assertIn('[QTMGR] TTF : 45 min', self.report(f))

    def test_once_only(self):
        f = self.device()
        self.report(f)
        with patch.object(v.log, 'warning') as warn:
            f._qtmgr_report(None)
        warn.assert_not_called()

    def test_normal_end_has_no_paths(self):
        f = self.device()
        f._last_smart_temp = None
        out = self.report(f)
        self.assertIn('[QTMGR] Test Case : Fuzzing', out)
        self.assertIn('[QTMGR] Product : eBM9K1', out)
        self.assertIn('[QTMGR] OEM : HP', out)
        self.assertIn('[QTMGR] Dmesg Path : N/A', out)
        self.assertIn('[QTMGR] UFAS Path : N/A', out)
        self.assertIn("[QTMGR] Temp ('C) : N/A (saved value from last SMART CHECK)", out)

    def test_many_dump_files_print_folders(self):
        f = self.device()
        cd = Path(self.tmp.name) / 'crash_x'
        (cd / 'SnapShot').mkdir(parents=True)
        f._dump_outputs = [('UFAS', str(cd / 'SnapShot' / f'b{i}.bin')) for i in range(30)]
        out = self.report(f, cd)
        self.assertEqual([l for l in out if 'UFAS Path' in l], [f'[QTMGR] UFAS Path : {cd}/SnapShot'])


class CrashFolderContents(unittest.TestCase):
    """crash 폴더: 로그 사본에 [QTMGR] 가 들어 있고(보고가 로그 복사 전), dmesg 는 _at_crash 하나,
    crash_<명령>_*.json 은 없다. 실제 crash 경로(_capture_firmware_hang_if_stuck, _pm_preflight_fail)를 태운다."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(__import__('shutil').rmtree, self.tmp)
        self.f = f = make()
        f.crashes_dir = self.tmp / 'crashes'
        f.crashes_dir.mkdir()
        f.output_dir = self.tmp
        f._log_file = str(self.tmp / 'pcfuzz.log')
        h = logging.FileHandler(f._log_file, encoding='utf-8')
        v.log.addHandler(h)
        self.addCleanup(v.log.removeHandler, h)
        self.addCleanup(h.close)
        f._bg = False
        f._fw_hang_captured = False
        f._pm_unresponsive = None
        f.sampler = Mock(USES_JLINK_USB=False)
        f._generate_replay_sh = Mock()
        f._capture_dmesg = Mock(return_value='kernel: nvme0 ...')
        f._dump_snapshot = Mock(return_value={})
        f._copy_new_dump_files = Mock(return_value=[])
        f._shutdown_openocd_for_jlink = Mock()
        f._devinfo = {'mn': CTRL['mn'], 'sn': CTRL['sn'], 'fr': CTRL['fr'], 'rbuf': '10282026'}
        f.start_time = datetime.now() - timedelta(minutes=5)
        for k in ('enable_jlink_dump', 'enable_ufas', 'enable_debug_tool_dump'):
            setattr(f.config, k, False)

    def crash_dir(self):
        (d,) = [p for p in self.f.crashes_dir.iterdir() if p.is_dir()]
        return d

    def check(self, d):
        names = sorted(p.name for p in d.iterdir())
        self.assertEqual([n for n in names if n.startswith('dmesg_')],
                         [n for n in names if n.startswith('dmesg_') and n.endswith('_at_crash.txt')])
        self.assertEqual(len([n for n in names if n.startswith('dmesg_')]), 1, names)
        self.assertFalse([n for n in names if n.startswith('crash_') and n.endswith('.json')], names)
        text = (d / 'pcfuzz.log').read_text(encoding='utf-8')
        self.assertIn('[QTMGR] Tester : RS0000-0', text, 'crash 폴더 로그 사본에 [QTMGR] 가 없다')
        self.assertIn('[QTMGR] Dmesg Path : ', text)
        self.assertIn('_at_crash.txt', text.split('[QTMGR] Dmesg Path : ', 1)[1].splitlines()[0])

    def test_firmware_hang(self):
        f = self.f
        f._nvme_id_dict = lambda cmd: ({}, 'EAGAIN', 1)
        f.config.enable_ufas = True
        f._run_ufas_dump = Mock()
        self.assertTrue(f._capture_firmware_hang_if_stuck('test'))   # assertLogs 는 FileHandler 를 떼어 쓰지 않는다
        self.check(self.crash_dir())

    def test_pm_preflight_failure(self):
        f = self.f
        (f.crashes_dir / 'crash_Read_0x2_abc.json').write_text('{}')     # 예전 경로가 남긴 json
        (f.crashes_dir / 'crash_nvme_pid.txt').write_text('42')         # 다른 루트 파일은 그대로 옮긴다
        self.assertFalse(f._pm_preflight_fail('PM', 'entry', 'PS4', 'no response', []))
        d = self.crash_dir()
        self.check(d)
        self.assertTrue((d / 'crash_nvme_pid.txt').exists())

    def test_save_crash_json_stays_in_crashes_root(self):
        f = self.f
        d = f.crashes_dir / 'crash_x'
        d.mkdir()
        f._seed_meta = Mock(return_value={})
        f._save_crash(b'', v.Seed(data=b'', cmd=v._NAME_TO_CMD['Read']), dest_dir=d)
        self.assertEqual(list(d.iterdir()), [])
        self.assertEqual(len(list(f.crashes_dir.glob('crash_Read_*.json'))), 1)


class DumpOutputsAndSmart(unittest.TestCase):
    def test_dump_wrapper_records_new_files_but_not_tool_log(self):
        f = make()
        f.output_dir = Path(tempfile.mkdtemp())
        self.addCleanup(__import__('shutil').rmtree, f.output_dir)
        dest = f.output_dir / 'crash_1'
        dest.mkdir()
        (dest / 'replay_x.sh').write_text('old')
        f._dump_snapshot = Mock(return_value={})
        f._copy_new_dump_files = Mock(return_value=[])
        f._log_dump_output = Mock()

        def body():
            log_path = Path(dest) / 'UFAS_1.log'
            f._dump_logs.append((log_path, 'UFAS'))
            log_path.write_text('tool output')
            (dest / 'ufas_dump.bin').write_bytes(b'\0')
        f._run_dump_collected('UFAS', dest, body)
        self.assertEqual(f._dump_outputs, [('UFAS', os.path.abspath(dest / 'ufas_dump.bin'))])

    def test_log_smart_keeps_last_temperature(self):
        f = make()
        proc = Mock(returncode=0)
        proc.communicate.return_value = (b'critical_warning : 0\ntemperature : 38 \xc2\xb0C (311 K)\n', b'')
        with patch.object(v.subprocess, 'Popen', return_value=proc), self.assertLogs('pcfuzz', level='INFO'):
            f._log_smart()
        self.assertEqual(f._last_smart_temp, 38)


if __name__ == '__main__':
    unittest.main()
