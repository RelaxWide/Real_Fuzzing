"""(opcode, CDW 값) 조합 차단 — strategy.blocked_cdw_rules.

PM9M1 에서 vendor 0xC0 + CDW12=0x2 가 디버그 포트를 영구히 닫았다. 전원 사이클로도
복구되지 않아(공장 초기화 필요) 그 샘플로 더는 PC 샘플링을 못 한다 — OpenOCD 포트 4444
대기 타임아웃의 근본 원인.

0xC0 은 이름 붙은 명령이 아니라 opcode 변이(0xC0~0xFF)로만 나오므로 스키마·excluded_opcodes
로는 막을 수 없다. 발송 chokepoint 가 유일한 자리다. 그래서 **실제 _send_nvme_command 를
호출해서** 확인한다.
"""
import json
import unittest
import unittest.mock
from unittest.mock import Mock

from test_v10_2_learning import ROOT, fuzzer      # noqa: F401

RC_SKIP = fuzzer.NVMeFuzzer.RC_SKIP


def _stub():
    obj = fuzzer.NVMeFuzzer.__new__(fuzzer.NVMeFuzzer)
    obj._max_xfer_bytes = lambda: 4096
    obj._excluded_opcodes = frozenset()
    obj._active_nsids = None
    obj.stats = {}
    obj.config = Mock(nvme_lba_size=512, nvme_namespace=1)
    return obj


def send(opcode=None, force_admin=None, base='Identify', **cdws):
    """실제 발송 경로를 태우고 (반환값, stats) 를 준다.

    차단되지 않은 명령은 그 뒤 subprocess 단계에서 어차피 죽는다 — 그래서 반환값이 아니라
    **차단 카운터**로 판정한다. 카운터가 안 올랐으면 가드를 통과한 것이다.
    """
    cmd = next(c for c in fuzzer.NVME_COMMANDS if c.name == base)
    obj = _stub()
    seed = fuzzer.Seed(data=b'', cmd=cmd)
    seed.opcode_override = opcode
    seed.force_admin = force_admin
    for k, v in cdws.items():
        setattr(seed, k, v)
    try:
        rc = fuzzer.NVMeFuzzer._send_nvme_command(obj, b'', seed)
    except Exception as exc:                      # 가드 이후 단계의 실패는 관심 밖
        rc = f'{type(exc).__name__}'
    return rc, obj.stats


def blocked(stats):
    return stats.get('blocked_cdw_rule', 0) > 0


class TheReportedCommandIsBlocked(unittest.TestCase):
    def test_opcode_c0_with_cdw12_2_is_skipped(self):
        rc, stats = send(opcode=0xC0, cdw12=0x2)
        self.assertEqual(rc, RC_SKIP, '전송이 차단되지 않았다')
        self.assertEqual(stats.get('blocked_cdw_rule'), 1)

    def test_other_cdw_values_do_not_matter(self):
        # "다른 cdw 값은 상관없다" — cdw12 만 보면 된다.
        rc, stats = send(opcode=0xC0, cdw12=0x2,
                         cdw10=0xDEADBEEF, cdw11=0xFFFFFFFF, cdw13=0x1234, cdw15=0x99)
        self.assertEqual(rc, RC_SKIP)
        self.assertTrue(blocked(stats))

    def test_same_opcode_other_cdw12_passes(self):
        _, stats = send(opcode=0xC0, cdw12=0x3)
        self.assertFalse(blocked(stats), '0xC0 전체를 막아버렸다 — 규칙은 값까지 봐야 한다')

    def test_other_opcode_same_cdw12_passes(self):
        _, stats = send(opcode=0xC1, cdw12=0x2)
        self.assertFalse(blocked(stats), 'cdw12=2 만 보고 막았다')

    def test_cdw12_zero_passes(self):
        _, stats = send(opcode=0xC0, cdw12=0x0)
        self.assertFalse(blocked(stats))


class RuleSemantics(unittest.TestCase):
    def _with(self, rules):
        p = unittest.mock.patch.object(fuzzer, 'BLOCKED_CDW_RULES', tuple(rules))
        p.start()
        self.addCleanup(p.stop)

    def test_mask_matches_a_bitfield_not_the_whole_word(self):
        self._with([(0xC0, 12, 0x2, 0xF, 'any', 'low nibble')])
        _, s1 = send(opcode=0xC0, cdw12=0xABCD0002)
        self.assertTrue(blocked(s1), 'mask 가 안 먹었다')
        _, s2 = send(opcode=0xC0, cdw12=0xABCD0003)
        self.assertFalse(blocked(s2))

    def test_value_bits_outside_the_mask_are_ignored(self):
        # 파서가 value 를 마스크로 잘라 넣으므로 규칙이 절대 매칭 불가가 되지 않는다.
        rules = fuzzer._parse_blocked_cdw_rules(
            [{'opcode': 0xC0, 'cdw': 12, 'value': 0xFF02, 'mask': 0xF}])
        self.assertEqual(rules[0][2], 0x2)

    def test_scope_admin_does_not_touch_io(self):
        self._with([(0xC0, 12, 0x2, 0xFFFFFFFF, 'admin', '')])
        _, s_io = send(opcode=0xC0, cdw12=0x2, force_admin=False)
        self.assertFalse(blocked(s_io), 'scope=admin 인데 io 를 막았다')
        _, s_ad = send(opcode=0xC0, cdw12=0x2, force_admin=True)
        self.assertTrue(blocked(s_ad))

    def test_scope_io_does_not_touch_admin(self):
        self._with([(0xC0, 12, 0x2, 0xFFFFFFFF, 'io', '')])
        _, s_ad = send(opcode=0xC0, cdw12=0x2, force_admin=True)
        self.assertFalse(blocked(s_ad), 'scope=io 인데 admin 을 막았다')

    def test_default_scope_any_covers_both_queues(self):
        for admin in (True, False):
            _, stats = send(opcode=0xC0, cdw12=0x2, force_admin=admin)
            self.assertTrue(blocked(stats), f'force_admin={admin} 에서 안 막혔다')


class ConfigParsing(unittest.TestCase):
    def test_hex_strings_are_accepted(self):
        rules = fuzzer._parse_blocked_cdw_rules(
            [{'opcode': '0xC0', 'cdw': 12, 'value': '0x2'}])
        self.assertEqual(rules[0][:4], (0xC0, 12, 0x2, 0xFFFFFFFF))

    def test_shipped_config_bans_the_reported_command(self):
        cfg = json.loads((ROOT / 'fuzzer_config.json').read_text(encoding='utf-8'))
        rules = fuzzer._parse_blocked_cdw_rules(cfg['strategy']['blocked_cdw_rules'])
        self.assertIn((0xC0, 12, 0x2, 0xFFFFFFFF),
                      [r[:4] for r in rules], '설정에 0xC0/CDW12=0x2 규칙이 없다')

    def test_live_constant_has_the_rule(self):
        self.assertIn((0xC0, 12, 0x2), [(r[0], r[1], r[2]) for r in fuzzer.BLOCKED_CDW_RULES])

    def test_malformed_rules_fail_loudly(self):
        for bad in ([{'cdw': 12, 'value': 2}],                      # opcode 없음
                    [{'opcode': 0xC0, 'value': 2}],                 # cdw 없음
                    [{'opcode': 0xC0, 'cdw': 12}],                  # value 없음
                    [{'opcode': 0x1FF, 'cdw': 12, 'value': 2}],     # opcode 범위 밖
                    [{'opcode': 0xC0, 'cdw': 9, 'value': 2}],       # 없는 CDW
                    [{'opcode': 0xC0, 'cdw': 12, 'value': 2, 'scope': 'nope'}],
                    [{'opcode': 0xC0, 'cdw': 12, 'value': 'xx'}],
                    ['not-a-dict'], 'not-a-list'):
            with self.assertRaises(SystemExit, msg=f'{bad} 를 통과시켰다'):
                fuzzer._parse_blocked_cdw_rules(bad)

    def test_rules_are_reported_in_the_guard_snapshot(self):
        guards = fuzzer._llm_schema_dict()['guards']
        self.assertIn('blocked_cdw_rules', guards)
        self.assertTrue(any(r['opcode'] == 0xC0 and r['cdw'] == 12 and r['value'] == 0x2
                            for r in guards['blocked_cdw_rules']))


if __name__ == '__main__':
    unittest.main()
