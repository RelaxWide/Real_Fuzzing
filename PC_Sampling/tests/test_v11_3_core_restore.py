"""v11.3 — 재연결 때 직전 연결에서 빠진 코어가 이번에 pin·정합성을 통과하면 되살린다.

예전엔 후보를 직전 계획(self._weights)에서 골라, 한 번 빠진 코어가 이후 재연결에서 200/200 으로 통과해도
캠페인 끝까지 'cores=[0, 1]' 로 남았다(적응 가중치 set_weights 도 코어 집합이 달라 계속 거부됐다).
"""
import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch

from fuzzer_target import fuzzer as v

PLAN = {'0': 8, '1': 1, '2': 4, '3': 1}


def sampler(primary=None):
    plan = {'weights': PLAN, 'seed': 1}
    if primary is not None:
        plan['primary_core'] = primary
    cfg = v.FuzzConfig(sampler_type='riscv_pcsr', riscv={'sample_plan': plan,
                                                          'cores': [{'id': i} for i in range(4)]})
    s = v.RiscvPcsrSampler(cfg)
    s._init_overlay_probe = lambda: None
    return s


def connect(s, pin_ok, bad=()):
    s.session = NS(pin=lambda cid: cid in pin_ok, auth_count=1, auth_ms=0.0)
    with patch.object(s, '_verify_ranges', return_value=list(bad)), patch.object(s, 'close'):
        return s._connect_verify()


class CoreRestore(unittest.TestCase):
    def test_dropped_core_comes_back(self):
        s = sampler()
        with self.assertLogs(v.log, 'WARNING'):
            self.assertTrue(connect(s, pin_ok={0, 1}))
        self.assertEqual(sorted(s._weights), [0, 1])
        with self.assertLogs(v.log, 'WARNING') as cm:
            self.assertTrue(connect(s, pin_ok={0, 1, 2, 3}))
        self.assertEqual(s._weights, {0: 8, 1: 1, 2: 4, 3: 1})
        out = '\n'.join(cm.output)
        self.assertIn('코어 복귀: [2, 3]', out)
        self.assertIn('cores=[0, 1, 2, 3]', out)

    def test_verify_failure_drop_also_restored(self):
        s = sampler()
        with self.assertLogs(v.log, 'WARNING'):
            connect(s, pin_ok={0, 1, 2, 3}, bad=[3])
        self.assertNotIn(3, s._weights)
        with self.assertLogs(v.log, 'WARNING'):
            connect(s, pin_ok={0, 1, 2, 3})
        self.assertIn(3, s._weights)

    def test_learned_weights_of_kept_cores_survive(self):
        s = sampler()
        with self.assertLogs(v.log, 'WARNING'):
            connect(s, pin_ok={0, 1})
        self.assertTrue(s.set_weights({0: 3, 1: 7}))
        with self.assertLogs(v.log, 'WARNING'):
            connect(s, pin_ok={0, 1, 2, 3})
        self.assertEqual(s._weights, {0: 3, 1: 7, 2: 4, 3: 1})
        self.assertTrue(s.set_weights({0: 1, 1: 1, 2: 1, 3: 1}), '코어 집합이 맞아 적응 가중치가 다시 반영된다')

    def test_primary_returns_to_plan(self):
        s = sampler()
        self.assertEqual(s._primary, 0)
        with self.assertLogs(v.log, 'WARNING'):
            connect(s, pin_ok={1, 2, 3})
        self.assertEqual(s._primary, 2)
        with self.assertLogs(v.log, 'WARNING') as cm:
            connect(s, pin_ok={0, 1, 2, 3})
        self.assertEqual(s._primary, 0)
        self.assertIn('시작 계획의 0 로 되돌림', '\n'.join(cm.output))

    def test_never_adds_cores_outside_plan(self):
        s = sampler()
        s._plan_weights = {0: 1, 1: 1}
        s._weights = {0: 1, 1: 1}
        s._primary = s._plan_primary = 0
        with self.assertLogs(v.log, 'WARNING'):
            connect(s, pin_ok={0, 1, 2, 3})
        self.assertEqual(sorted(s._weights), [0, 1])


if __name__ == '__main__':
    unittest.main()
