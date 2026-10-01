"""--exception: config exceptions.enabled(기본 false)를 CLI 로 켠다. 끄는 방향으로는 바꾸지 않는다."""
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fuzzer_target import fuzzer as v                   # noqa: E402
from fuzzer_target import FUZZER_FILE                      # noqa: E402


class ExceptionFlag(unittest.TestCase):
    def test_flag_enables_only(self):
        cfg = {'exceptions': {'enabled': False, 'seed': 0}}
        self.assertFalse(v.apply_exception_flag(cfg, False))
        self.assertFalse(cfg['exceptions']['enabled'])            # 플래그 없으면 config 그대로
        self.assertTrue(v.apply_exception_flag(cfg, True))
        self.assertTrue(cfg['exceptions']['enabled'])
        self.assertEqual(cfg['exceptions']['seed'], 0)            # 다른 설정은 유지
        cfg = {'exceptions': {'enabled': True}}
        v.apply_exception_flag(cfg, False)
        self.assertTrue(cfg['exceptions']['enabled'])             # config 의 true 는 유지

    def test_default_config_is_off(self):
        import json
        cfg = json.loads((ROOT / 'fuzzer_config.json').read_text(encoding='utf-8-sig'))
        self.assertIs(cfg['exceptions']['enabled'], False)

    def test_help_lists_flag(self):
        out = subprocess.run([sys.executable, str(FUZZER_FILE), '--help'],
                             cwd=ROOT, capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr[-500:])
        self.assertIn('--exception', out.stdout)


if __name__ == '__main__':
    unittest.main()
