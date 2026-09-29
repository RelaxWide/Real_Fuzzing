"""Deploy v11 without any older fuzzer scripts; no hardware operations."""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class StandaloneDeployment(unittest.TestCase):
    def test_cli_and_engine_work_without_previous_versions(self):
        with tempfile.TemporaryDirectory() as tmp:
            dst = Path(tmp)
            for src in ROOT.iterdir():
                if src.name in ('exception_control.py', 'exception_probe.py'):
                    continue
                if src.name.startswith('pc_sampling_fuzzer_v') and src.name != 'pc_sampling_fuzzer_v11.py':
                    continue
                if src.is_file() and src.suffix in ('.py', '.json'):
                    shutil.copy2(src, dst / src.name)
                elif src.is_dir() and src.name in ('rag', 'products'):
                    (dst / src.name).symlink_to(src, target_is_directory=True)
            for obsolete in ('pc_sampling_fuzzer_v10.3.py', 'exception_control.py', 'exception_probe.py'):
                self.assertFalse((dst / obsolete).exists())
            env = dict(os.environ, PYTHONPATH=str(dst))
            env.pop('PCFUZZ_FREEZE_TRACE', None)
            result = subprocess.run(
                [sys.executable, 'pc_sampling_fuzzer_v11.py', '--help'],
                cwd=dst, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('--config', result.stdout)
            # Construct the actual exported engine, with device-facing asset loads
            # mocked. Exercise the permanent transport guard before any submission.
            code = '''
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import pc_sampling_fuzzer_v11 as v
from pc_sampling_fuzzer_v11 import ExceptionFuzzerMixin
assert v.FUZZER_VERSION == '11.0.0'
assert v.NVMeFuzzer.__module__ == v.__name__
assert issubclass(v.NVMeFuzzer, ExceptionFuzzerMixin)
assert v._V101Fuzzer.__module__ == v.__name__
with TemporaryDirectory() as out:
    cfg = v.FuzzConfig(no_jlink=True, rag_enabled=False, state_enabled=False, output_dir=out)
    with patch.object(v.NVMeFuzzer, '_load_static_analysis'), patch.object(v.NVMeFuzzer, '_load_riscv_coverage'):
        f = v.NVMeFuzzer(cfg)
    assert f._exception_controller is None
    f._excluded_opcodes = {v._NAME_TO_CMD['Identify'].opcode}
    seed = v.Seed(data=b'', cmd=v._NAME_TO_CMD['Identify'])
    with patch.object(v.subprocess, 'Popen', side_effect=AssertionError('unexpected device command')):
        assert f._send_nvme_command(seed.data, seed) == f.RC_SKIP
    v.NVMeFuzzer.exception_config = dict(v._CFG, exceptions=dict(v._CFG['exceptions'], enabled=True))
    with patch.object(v.NVMeFuzzer, '_load_static_analysis'), patch.object(v.NVMeFuzzer, '_load_riscv_coverage'):
        enabled = v.NVMeFuzzer(cfg)
    assert enabled._exception_controller is not None
print('standalone-v11-ok')
'''
            result = subprocess.run([sys.executable, '-c', code], cwd=dst, env=env,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('standalone-v11-ok', result.stdout)


if __name__ == '__main__':
    unittest.main()
