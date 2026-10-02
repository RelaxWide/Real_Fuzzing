"""Launcher contract tests with a fake analyzeHeadless; no device/Ghidra required."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'tools' / 'ghidra_export_headless.py'


class LauncherTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='export test ')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ghidra = self.root / 'fake ghidra'
        support = self.ghidra / 'support'
        support.mkdir(parents=True)
        head = support / 'analyzeHeadless'
        head.write_text('''#!/usr/bin/env python3
import sys, os, json
from pathlib import Path
a=sys.argv[1:]
payload=Path(a[a.index('-import')+1]).read_bytes().hex()
Path(os.environ['EXPORT_LOG']).write_text(json.dumps({'argv':a,'payload':payload}))
mode=os.environ.get('FAKE_MODE','ok')
if mode=='fail': sys.exit(7)
if mode=='missing': sys.exit(0)
out=Path(a[a.index('-postScript')+3])
(out/'basic_blocks.txt').write_text('0x00000010 0x00000014\\n')
(out/'functions.txt').write_text('0x00000010 4 entry\\n')
''')
        head.chmod(0o755)
        self.fw = self.root / 'test firmware.bin'
        self.fw.write_bytes(b'HEADERpayload')
        self.out = self.root / 'output dir'
        self.log = self.root / 'invocation.json'
        self.env = dict(os.environ, EXPORT_LOG=str(self.log), GHIDRA=str(self.ghidra))
        for key in ('PROC', 'BASE', 'CUT', 'LOADER', 'MATCH_GUI'):
            self.env.pop(key, None)

    def run_cli(self, *extra):
        cmd = [sys.executable, str(SCRIPT), 'analyze']
        return subprocess.run(cmd + [str(self.fw), str(self.out)] + list(extra),
                              env=self.env, capture_output=True, text=True)

    def invocation(self):
        return json.loads(self.log.read_text())

    def test_import_cut_paths_and_output(self):
        result = self.run_cli('--cut', '6', '--base', '0x1000', '--processor', 'ARM:LE:32:v7')
        self.assertEqual(result.returncode, 0, result.stderr)
        call = self.invocation()
        self.assertEqual(call['payload'], b'payload'.hex())
        self.assertEqual(call['argv'][call['argv'].index('-loader-baseAddr')+1], '0x1000')
        self.assertFalse(Path(call['argv'][0]).exists())
        self.assertEqual((self.out / 'functions.txt').read_text(), '0x00000010 4 entry\n')
        self.assertEqual(self.fw.read_bytes(), b'HEADERpayload')

    def test_cut_matches_real_dd_byte_skip_at_block_boundaries(self):
        # Exercise the actual launcher/import path, not a duplicate of its seek code.
        data = bytes(range(256)) * 8192 + b'END-of-firmware!'
        self.fw.write_bytes(data)
        cases = [('0', 0), ('1', 1), ('511', 511), ('0x200', 512),
                 ('1048575', 1048575), ('0x100000', 1048576),
                 (str(len(data) - 1), len(data) - 1)]
        for text, offset in cases:
            with self.subTest(cut=text):
                result = self.run_cli('--cut', text)
                self.assertEqual(result.returncode, 0, result.stderr)
                actual = bytes.fromhex(self.invocation()['payload'])
                expected = subprocess.run(
                    ['dd', 'if=' + str(self.fw), 'bs=1M', 'iflag=skip_bytes',
                     'skip=' + str(offset), 'status=none'], check=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
                self.assertEqual(actual, expected)
                self.assertEqual(len(actual), len(data) - offset)
                self.assertEqual(self.fw.read_bytes(), data)

    def test_hex_environment_cut_and_explicit_zero_override(self):
        self.env['CUT'] = '0x6'
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(bytes.fromhex(self.invocation()['payload']), b'payload')
        result = self.run_cli('--cut', '0')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(bytes.fromhex(self.invocation()['payload']), b'HEADERpayload')

    def test_failure_cleans_project_and_does_not_accept_old_outputs(self):
        self.out.mkdir()
        for name in ('basic_blocks.txt', 'functions.txt'):
            (self.out / name).write_text('old')
        for mode, rc in (('fail', 7), ('missing', 1)):
            with self.subTest(mode=mode):
                self.env['FAKE_MODE'] = mode
                result = self.run_cli()
                self.assertEqual(result.returncode, rc)
                self.assertFalse(Path(self.invocation()['argv'][0]).exists())
                self.assertEqual((self.out / 'basic_blocks.txt').read_text(), 'old')
                self.assertEqual((self.out / 'functions.txt').read_text(), 'old')

    def test_environment_and_flag_precedence(self):
        self.env.update(CUT='6', BASE='0x20', PROC='from-environment')
        result = self.run_cli('--processor', 'from-flag')
        self.assertEqual(result.returncode, 0, result.stderr)
        call = self.invocation()
        self.assertEqual(call['payload'], b'payload'.hex())
        self.assertEqual(call['argv'][call['argv'].index('-processor')+1], 'from-flag')

    def test_invalid_options_do_not_launch(self):
        for flags in (('--cut', '999'), ('--cut', '-1'), ('--analysis-timeout', '0'), ('--match-gui',)):
            with self.subTest(flags=flags):
                self.assertNotEqual(self.run_cli(*flags).returncode, 0)
                self.assertFalse(self.log.exists())

    def test_export_mode_requires_ghidra_and_legacy_args_work(self):
        result = subprocess.run([sys.executable, str(SCRIPT), 'export', str(self.out)],
                                capture_output=True)
        self.assertEqual(result.returncode, 2)
        spec = importlib.util.spec_from_file_location('export_test', SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertEqual(mod.export_args(['export', '/somewhere']), '/somewhere')
        self.assertEqual(mod.export_args(['/somewhere']), '/somewhere')


if __name__ == '__main__':
    unittest.main()
