"""crash 덤프 산출물을 crash_<ts>/ 로 모으는지.

덤프 도구(ufas / unified_pcie_dump_tool / JLink 스크립트 / Debug_Tool)는 산출물을 자기
폴더(dump/)에 쓴다. 예전 수집은 script_dir 최상위의 *.bin/*dump* 만 봐서 하나도 못
찾았고("[ARTIFACT] 수집 폴더" 로그만 남음), 도구 출력 로그는 output_dir(crash 폴더의
두 단계 위)에 떨어졌다. FW 행·v11 경로는 수집 자체를 부르지 않았다.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from test_v10_2_learning import fuzzer   # noqa: F401


class Env:
    """가짜 script_dir: fuzzer.py, dump/ 에 도구 + 기존 파일."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.dump = self.root / 'dump'
        (self.dump / 'SnapShot').mkdir(parents=True)
        (self.dump / 'ufas').write_bytes(b'tool')
        (self.dump / 'old_UFAS_Dump.bin').write_bytes(b'old')
        (self.root / 'out' / 'crashes').mkdir(parents=True)
        self.dest = self.root / 'out' / 'crashes' / 'crash_20260928_120000'
        self.patches = [
            patch.object(sys, 'argv', [str(self.root / 'pc_sampling_fuzzer_v11.py')]),
            patch.object(fuzzer, 'UFAS_BINARY', 'dump/ufas'),
            patch.object(fuzzer, 'JLINK_DUMP_SCRIPT', 'dump/run_smi_mem_dump_JLINK_USB.sh'),
            patch.object(fuzzer, 'DEBUG_TOOL_BINARY', 'Debug_Tool_v1.0.0.2'),
        ]
        for p in self.patches:
            p.start()
        o = fuzzer.NVMeFuzzer.__new__(fuzzer.NVMeFuzzer)
        o.config = Mock(ufas_binary=None)
        o.output_dir = self.root / 'out'
        o.crashes_dir = self.root / 'out' / 'crashes'
        self.obj = o

    def close(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()


class DumpCollection(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.addCleanup(self.env.close)

    def test_new_files_in_tool_dir_are_copied_not_moved(self):
        e = self.env

        def run():
            (e.dump / '20260928_120001_UFAS_Dump.bin').write_bytes(b'x' * 1000)
            (e.dump / 'SnapShot' / 'region.bin').write_bytes(b'y' * 10)
        e.obj._run_dump_collected('UFAS', e.dest, run)
        self.assertEqual((e.dest / '20260928_120001_UFAS_Dump.bin').stat().st_size, 1000)
        self.assertTrue((e.dest / 'SnapShot' / 'region.bin').exists(), '하위 폴더 구조 보존')
        self.assertTrue((e.dump / '20260928_120001_UFAS_Dump.bin').exists(), '원본은 남긴다(복사)')
        self.assertFalse((e.dest / 'old_UFAS_Dump.bin').exists(), '이전 crash 덤프는 안 가져온다')
        self.assertFalse((e.dest / 'ufas').exists(), '도구 자체는 안 가져온다')

    def test_script_root_is_scanned_shallow_only(self):
        e = self.env
        (e.root / 'products').mkdir()

        def run():
            (e.root / 'legacy_dump.bin').write_bytes(b'l')          # 루트 최상위: 수집
            (e.root / 'products' / 'unrelated.bin').write_bytes(b'u')  # 루트 하위: 무관
        e.obj._run_dump_collected('JLINK', e.dest, run)
        self.assertTrue((e.dest / 'legacy_dump.bin').exists())
        self.assertFalse((e.dest / 'unrelated.bin').exists())

    def test_new_folder_in_script_root_is_copied(self):
        # RDDump 는 cwd=script_dir. 도구가 거기에 폴더를 만들어 쓰면 통째로 가져온다.
        e = self.env
        (e.root / 'existing_dir').mkdir()

        def run():
            d = e.root / 'RDDump_20260928' / 'core0'
            d.mkdir(parents=True)
            (d / 'ram.bin').write_bytes(b'r')
            (e.root / 'existing_dir' / 'noise.bin').write_bytes(b'n')   # 기존 폴더 안: 무관
        e.obj._run_dump_collected('RDDUMP', e.dest, run)
        self.assertTrue((e.dest / 'RDDump_20260928' / 'core0' / 'ram.bin').exists())
        self.assertFalse((e.dest / 'existing_dir').exists())

    def test_crash_folder_itself_is_not_recopied(self):
        # 첫 실행에 output/ 가 script_dir 아래 새로 생겨도 crash 폴더를 자기 안으로 복사하지 않는다.
        e = self.env
        import shutil
        shutil.rmtree(e.root / 'out')
        dest = e.root / 'out' / 'crashes' / 'crash_x'
        e.obj._run_dump_collected('UFAS', dest, lambda: (dest / 'UFAS_Dump.bin').write_bytes(b'u'))
        self.assertEqual(sorted(p.name for p in dest.rglob('*')), ['UFAS_Dump.bin'])

    def test_tool_log_goes_into_crash_folder(self):
        e = self.env

        def run():
            e.obj._spawn_dump_logged([sys.executable, '-c', 'print(1)'], 'UFAS').wait(timeout=10)
        e.obj._run_dump_collected('UFAS', e.dest, run)
        self.assertEqual(len(list(e.dest.glob('UFAS_*.log'))), 1)
        self.assertEqual(list((e.root / 'out').glob('UFAS_*.log')), [], 'output_dir 에 남으면 안 된다')
        self.assertIsNone(getattr(e.obj, '_dump_log_dir', None), '다음 덤프로 새지 않게 복원')

    def test_without_dest_keeps_legacy_behavior(self):
        e = self.env

        def run():
            (e.dump / 'x.bin').write_bytes(b'x')
            e.obj._spawn_dump_logged([sys.executable, '-c', 'pass'], 'UFAS').wait(timeout=10)
        e.obj._run_dump_collected('UFAS', None, run)
        self.assertFalse(e.dest.exists())
        self.assertEqual(len(list((e.root / 'out').glob('UFAS_*.log'))), 1)

    def test_partial_output_survives_failure(self):
        e = self.env

        def run():
            (e.dump / 'partial.bin').write_bytes(b'p')
            raise RuntimeError('tool died')
        with self.assertRaises(RuntimeError):
            e.obj._run_dump_collected('UFAS', e.dest, run)
        self.assertTrue((e.dest / 'partial.bin').exists())

    def test_file_already_in_dest_is_not_duplicated_and_collision_renamed(self):
        e = self.env
        e.dest.mkdir(parents=True)
        (e.dest / 'same.bin').write_bytes(b'abc')
        (e.dest / 'clash.bin').write_bytes(b'1')

        def run():
            (e.dump / 'same.bin').write_bytes(b'abc')
            (e.dump / 'clash.bin').write_bytes(b'2222')
        copied = e.obj._copy_new_dump_files(e.obj._dump_snapshot(), e.dest, 'T')
        self.assertEqual(copied, [])
        before = {k: v for k, v in e.obj._dump_snapshot().items()}
        run()
        copied = e.obj._copy_new_dump_files(before, e.dest, 'T')
        self.assertEqual(len(copied), 1)
        self.assertEqual((e.dest / 'clash.bin').read_bytes(), b'1', '기존 파일을 덮지 않는다')
        self.assertTrue(copied[0].name.startswith('clash_'))

    def test_all_dump_entrypoints_collect(self):
        e = self.env
        for name, tag in (('_run_jlink_dump', 'JLINK'), ('_run_ufas_dump', 'UFAS'),
                          ('_run_debug_tool_dump', 'RDDUMP')):
            body = name + '_body'
            with patch.object(fuzzer.NVMeFuzzer, body,
                              lambda self, *a, **k: (e.dump / f'{tag}.bin').write_bytes(b'z')):
                getattr(e.obj, name)(dest_dir=e.dest)
            self.assertTrue((e.dest / f'{tag}.bin').exists(), name)

    def test_crash_handler_passes_crash_dir(self):
        import inspect
        src = inspect.getsource(fuzzer.NVMeFuzzer._handle_timeout_crash)
        for call in ('_run_jlink_dump(dest_dir=_crash_dir)', '_run_ufas_dump(dest_dir=_crash_dir)',
                     '_run_debug_tool_dump(dest_dir=_crash_dir)'):
            self.assertIn(call, src)

    def test_final_collect_catches_outputs_outside_wrappers(self):
        # 미지원 판정 파서 출력처럼 래퍼 밖에서 생긴 파일도 최종 수집이 거둔다.
        e = self.env
        from datetime import datetime
        e.obj._log_file = None
        e.obj._capture_dmesg = lambda lines=200: ''
        e.obj._crash_dump_before = e.obj._dump_snapshot()
        (e.dump / 'g16arEventLog_1.txt').write_text('evt')
        e.obj._collect_crash_artifacts(datetime(2026, 9, 28, 12, 0, 0))
        self.assertTrue((e.dest / 'g16arEventLog_1.txt').exists())

    def test_latest_jlink_dump_is_found_in_tool_dir(self):
        e = self.env
        import time
        t0 = time.time()
        (e.dump / 'smi_mem_dump.bin').write_bytes(b'd')
        got = e.obj._find_latest_jlink_dump(str(e.root), t0)
        self.assertEqual(os.path.basename(got), 'smi_mem_dump.bin')


class DumpOutputInTextLog(unittest.TestCase):
    """da5104b 이후 도구 출력이 텍스트 로그에서 사라졌다 — 스트리밍으로 되살린다."""

    def setUp(self):
        self.env = Env()
        self.addCleanup(self.env.close)

    def spawn(self, code, tag='UFAS', dest=None):
        e = self.env
        with self.assertLogs(fuzzer.log, level='INFO') as cm:
            e.obj._run_dump_collected(tag, dest, lambda: e.obj._spawn_dump_logged(
                [sys.executable, '-c', code], tag).wait(timeout=10))
        return cm.records

    def test_output_lines_go_to_file_log_and_tail_to_terminal(self):
        recs = self.spawn("print('\\n'.join('line%d' % i for i in range(30)))")
        info = [r.getMessage() for r in recs if r.levelname == 'INFO']
        warn = [r.getMessage() for r in recs if r.levelname == 'WARNING']
        self.assertIn('[UFAS] | line0', info)
        self.assertIn('[UFAS] | line29', info)
        self.assertEqual([m for m in warn if m.startswith('[UFAS]   ')],
                         ['[UFAS]   line%d' % i for i in range(20, 30)])

    def test_jlink_prefix_passes_terminal_filter(self):
        recs = self.spawn("print('done')", tag='JLINK_DUMP')
        msgs = [r.getMessage() for r in recs]
        self.assertIn('[JLINK DUMP] | done', msgs)
        flt = fuzzer._FuzzingTerminalFilter()
        term = [r for r in recs if r.levelname == 'WARNING' and r.getMessage().endswith('done')]
        self.assertTrue(term and all(flt.filter(r) for r in term))

    def test_huge_output_is_bounded(self):
        with patch.object(fuzzer.NVMeFuzzer, '_DUMP_LOG_HEAD', 5), \
                patch.object(fuzzer.NVMeFuzzer, '_DUMP_LOG_TAIL', 5):
            recs = self.spawn("print('\\n'.join('L%d' % i for i in range(1000)))")
        body = [r.getMessage() for r in recs if r.getMessage().startswith('[UFAS] |')]
        self.assertEqual(len(body), 11)                       # 앞 5 + 생략 1 + 뒤 5
        self.assertIn('[UFAS] | … 990줄 생략', body[5])
        self.assertEqual(body[-1], '[UFAS] | L999')

    def test_logged_even_without_crash_folder_and_on_failure(self):
        e = self.env

        def run():
            e.obj._spawn_dump_logged([sys.executable, '-c', "print('boom')"], 'UFAS').wait(timeout=10)
            raise RuntimeError('tool failed')
        with self.assertLogs(fuzzer.log, level='INFO') as cm, self.assertRaises(RuntimeError):
            e.obj._run_dump_collected('UFAS', None, run)
        self.assertIn('[UFAS] | boom', [r.getMessage() for r in cm.records])


if __name__ == '__main__':
    unittest.main()
