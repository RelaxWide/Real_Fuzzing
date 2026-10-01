"""제품별 명령 timeout — BM9K1 은 Write 계열 30s, Flush 2s, FormatNVM 180s, 그 외 8s.

timeout 은 명령의 timeout_group 으로 정해진다. Write/WriteUncorrectable/WriteZeroes 는 전용
'write' 그룹을 쓰고, 설정에 그 키가 없는 제품은 예전처럼 'command' 값을 쓴다(하위호환).
"""
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fuzzer_target import fuzzer as v                   # noqa: E402

CFG = json.loads((ROOT / 'fuzzer_config.json').read_text(encoding='utf-8-sig'))


def resolved(product):
    """main() 과 같은 규칙: 전역 NVME_TIMEOUTS 위에 제품 nvme_timeouts 를 덮는다."""
    t = dict(v.NVME_TIMEOUTS)
    t.update(CFG['products'][product].get('nvme_timeouts') or {})
    return t


def timeout_of(product, name):
    t = resolved(product)
    return t.get(v._NAME_TO_CMD[name].timeout_group, t['command'])


class BM9K1Timeouts(unittest.TestCase):
    def test_write_family_uses_write_group(self):
        for name in ('Write', 'WriteUncorrectable', 'WriteZeroes'):
            self.assertEqual(v._NAME_TO_CMD[name].timeout_group, 'write', name)

    def test_requested_values(self):
        expect = {'Write': 30000, 'WriteUncorrectable': 30000, 'WriteZeroes': 30000,
                  'Flush': 2000, 'FormatNVM': 180000}
        for name, ms in expect.items():
            self.assertEqual(timeout_of('BM9K1', name), ms, name)

    def test_every_other_command_is_8s(self):
        special = {'Write', 'WriteUncorrectable', 'WriteZeroes', 'Flush', 'FormatNVM'}
        for cmd in v.NVME_COMMANDS:
            if cmd.name in special:
                continue
            self.assertEqual(timeout_of('BM9K1', cmd.name), 8000, f'{cmd.name}({cmd.timeout_group})')

    def test_other_products_keep_command_timeout_for_writes(self):
        # 'write' 키가 없는 제품은 Write 계열이 예전처럼 command 값을 쓴다.
        for product, prof in CFG['products'].items():
            if 'write' in (prof.get('nvme_timeouts') or {}):
                continue
            self.assertEqual(timeout_of(product, 'Write'), resolved(product)['command'], product)


if __name__ == '__main__':
    unittest.main()
