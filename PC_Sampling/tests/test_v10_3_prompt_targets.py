"""프롬프트 후보에서 **영원히 거절되는 명령**을 빼는지.

닫힌 고리가 있었다. 차단은 RC_SKIP 이라 cmd_stats 에 안 남고, 그래서 막힌 명령은
영원히 exercised 가 되지 않는다 → 'Never-sent command groups' 최상단에 고정 →
LLM 이 매 라운드 그것만 다시 제안 → 또 차단. Lockdown(blocked admin opcode 0x24)과
FormatNVM/Sanitize(destructive)가 그 고리에 있었다.

시퀀스는 더 나쁘다 — 멤버 하나가 막히면 체인 전체가 폐기된다(부분 채택 금지).
"""
import sys
import unittest
import unittest.mock

from test_v10_2_learning import ROOT, fuzzer, harness   # noqa: F401

sys.path.insert(0, str(ROOT))
from rag.rag_schema import SchemaBridge                 # noqa: E402


def bridge():
    return SchemaBridge.from_dict(fuzzer._llm_schema_dict())


def obj(excluded=frozenset()):
    o = harness({'enabled': True})
    o._excluded_opcodes = frozenset(excluded)
    o._llm_unreachable_logged = False
    return o


class AlwaysRefusedCommandsAreExcluded(unittest.TestCase):
    def test_the_three_known_offenders(self):
        got = obj()._llm_unreachable_names(bridge())
        self.assertEqual(got, {'FormatNVM', 'Sanitize', 'Lockdown'},
                         f'영구 거절 목록이 달라졌다: {sorted(got)}')

    def test_it_agrees_with_is_dangerous(self):
        # 목록을 손으로 들고 있으면 가드와 어긋난다. 같은 판정을 써야 한다.
        sb = bridge()
        got = obj()._llm_unreachable_names(sb)
        for name in got:
            self.assertTrue(sb.is_dangerous(name)[0],
                            f'{name} 은 is_dangerous 가 막지 않는다')

    def test_excluded_opcodes_are_added(self):
        # Identify(0x06) 를 제외하면 후보에서도 빠져야 한다.
        got = obj(excluded={0x06})._llm_unreachable_names(bridge())
        self.assertIn('Identify', got)

    def test_value_conditional_guards_are_not_excluded(self):
        # SecuritySend 는 SECP 값에 따라 갈린다 — 허용값으로는 실제로 나가므로 후보로 남긴다.
        got = obj()._llm_unreachable_names(bridge())
        for name in ('SecuritySend', 'NamespaceManagement', 'SetFeatures'):
            self.assertNotIn(name, got, f'{name} 이 값 무관 거절로 잘못 분류됐다')

    def test_a_broken_bridge_does_not_shrink_the_candidates(self):
        # 판정이 터져도 프롬프트는 살아야 한다(후보 유지 = 기존 동작).
        sb = bridge()
        sb.is_dangerous = unittest.mock.Mock(side_effect=RuntimeError('boom'))
        self.assertEqual(obj()._llm_unreachable_names(sb), set())


class BuildersUseTheFilter(unittest.TestCase):
    """소스 대조 — 두 빌더 모두 필터를 통과시키는지."""

    @staticmethod
    def _src(task_marker):
        import ast
        from test_v10_2_learning import FUZZER_FILE
        text = FUZZER_FILE.read_text(encoding='utf-8')
        fn = [n for n in ast.walk(ast.parse(text))
              if isinstance(n, ast.FunctionDef) and n.name == '_llm_build_request'][0]
        src = ast.get_source_segment(text, fn)
        start = src.index(task_marker)
        return src[start:start + 1200]

    def test_new_group_seeds_filters_known(self):
        src = self._src("if task == 'new_group_seeds':")
        self.assertIn('_llm_unreachable_names', src)
        self.assertIn('not in _unreach', src)

    def test_sequences_filters_members(self):
        src = self._src("if task == 'sequences':")
        self.assertIn('_llm_unreachable_names', src)
        self.assertIn('not in _unreach', src)


if __name__ == '__main__':
    unittest.main()
