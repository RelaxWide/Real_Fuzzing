"""프롬프트 축소 시험 — 의미를 바꾸지 않으면서 줄었는지.

크기만 보면 안 된다. 스키마 축약은 **같은 이름이 명령마다 다른 비트 위치를 갖는 경우**
(SEL/STC/CA/NUMD 등)를 뭉개면 LLM 이 틀린 CDW 를 만든다. 그래서 '줄었나' 와
'정의가 보존됐나' 를 함께 본다.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

from test_v10_2_learning import ROOT, fuzzer, harness   # noqa: F401

sys.path.insert(0, str(ROOT))
from rag.rag_schema import SchemaBridge                 # noqa: E402


def bridge():
    return SchemaBridge.from_dict(fuzzer._llm_schema_dict())


class SchemaRenderingIsDeduplicated(unittest.TestCase):
    def test_shared_fields_appear_once(self):
        sb = bridge()
        text = sb.schemas_to_prompt(['Read', 'Write', 'Compare'])
        # SLBA_LO 는 세 명령이 공유 → 용어집에 1회, 명령줄엔 이름만
        self.assertEqual(text.count('SLBA_LO = CDW10[31:0]'), 1,
                         '공유 필드 정의가 여러 번 나온다')
        self.assertEqual(text.count('SLBA_LO'), 4, '명령 3개 + 용어집 1회여야 한다')

    def test_it_is_smaller_than_per_command_rendering(self):
        sb = bridge()
        names = sorted(sb.commands)
        old = sum(len(sb.schema_to_prompt(n)) + 2 for n in names)
        new = len(sb.schemas_to_prompt(names))
        self.assertLess(new, old, '줄어들지 않았다')

    def test_ambiguous_field_names_are_inlined_not_merged(self):
        """같은 이름이 명령마다 다른 정의를 갖는 경우 — 뭉개면 틀린 CDW 가 나온다."""
        sb = bridge()
        conflict = None
        for name in sb.schemas:
            for f in sb.schemas[name]:
                sigs = {(g['word'], g['hi'], g['lo'])
                        for other in sb.schemas for g in sb.schemas[other]
                        if g['name'] == f['name']}
                if len(sigs) > 1:
                    conflict = f['name']
                    break
            if conflict:
                break
        self.assertIsNotNone(conflict, '정의가 엇갈리는 필드를 못 찾았다(전제 확인 필요)')
        text = sb.schemas_to_prompt(sorted(sb.commands))
        self.assertNotIn(f'  {conflict} = CDW', text,
                         f'{conflict} 는 정의가 엇갈리므로 용어집에 올리면 안 된다')

    def test_every_command_and_field_still_appears(self):
        sb = bridge()
        names = sorted(sb.commands)
        text = sb.schemas_to_prompt(names)
        for n in names:
            self.assertIn(n, text, f'{n} 가 사라졌다')
            for f in sb.schemas.get(n, []):
                self.assertIn(f['name'], text, f"{n}.{f['name']} 가 사라졌다")

    def test_unknown_names_are_skipped(self):
        self.assertEqual(bridge().schemas_to_prompt(['NoSuchCommand']), '')


class FuzzerActuallyUsesTheDedupedRenderer(unittest.TestCase):
    """렌더러만 고치고 배선을 안 하면 프롬프트는 그대로다."""

    def test_schema_summary_emits_the_glossary_form(self):
        o = harness()
        text = o._llm_schema_summary(['Read', 'Write', 'Compare'])
        self.assertIn('Field definitions', text,
                      '_llm_schema_summary 가 중복 제거 렌더러를 안 쓴다')
        self.assertEqual(text.count('SLBA_LO = CDW10[31:0]'), 1)

    def test_summary_is_smaller_than_the_per_command_form(self):
        o = harness()
        sb = o.llm.schema_bridge
        names = sorted(sb.commands)[:12]
        old = sum(len(sb.schema_to_prompt(n)) + 2 for n in names)
        self.assertLess(len(o._llm_schema_summary(names)), old)


class SchemaCapIsEffective(unittest.TestCase):
    def test_default_cap_is_below_the_command_count(self):
        sb = bridge()
        self.assertLess(fuzzer.RAG_SCHEMA_MAX, len(sb.commands),
                        '캡이 명령 수보다 크면 캡이 없는 것과 같다')

    def test_pick_preserves_caller_priority_order(self):
        o = harness()
        ordered = ['Zzz', 'Aaa', 'Mmm'] * 10
        got = o._llm_schema_pick(ordered)
        self.assertEqual(got[:3], ['Zzz', 'Aaa', 'Mmm'], '호출부 우선순위를 재정렬했다')

    def test_pick_deduplicates_and_caps(self):
        o = harness()
        got = o._llm_schema_pick(['A', 'A', 'B'] * 50)
        self.assertEqual(got, ['A', 'B'])
        self.assertLessEqual(len(o._llm_schema_pick([f'c{i}' for i in range(100)])),
                             fuzzer.RAG_SCHEMA_MAX)

    def test_no_caller_truncates_the_list_itself(self):
        """알파벳 순 목록을 그대로 자르면 A~M 만 남는 임의 절단이 된다.

        상한 적용은 _llm_schema_pick 한 곳에서만 일어나야 한다.
        """
        src = (ROOT / 'pc_sampling_fuzzer_v10.3.py').read_text(encoding='utf-8')
        users = [ln.strip() for ln in src.splitlines() if 'RAG_SCHEMA_MAX' in ln]
        slicing = [ln for ln in users if '[:RAG_SCHEMA_MAX]' in ln]
        self.assertEqual(slicing, [], f'호출부가 직접 자르고 있다: {slicing}')
        self.assertIn('_llm_schema_pick', src)


class FavoredExamplesAreDistinct(unittest.TestCase):
    """예시 6칸이 동일 줄로 채워지면 few-shot 가치가 없다."""

    def seeds(self, triples):
        out = []
        for name, a, b in triples:
            s = Mock(cdw10=a, cdw11=b, is_favored=True, new_pcs=1)
            s.cmd = Mock()
            s.cmd.name = name
            out.append(s)
        return out

    def test_duplicate_command_cdw_pairs_are_collapsed(self):
        import ast
        src = (ROOT / 'pc_sampling_fuzzer_v10.3.py').read_text(encoding='utf-8')
        tree = ast.parse(src)
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == '_llm_grounding_block')
        seg = ast.get_source_segment(src, fn) or ''
        self.assertIn('_seen_ex', seg, 'favored 예시 중복 제거가 없다')
        self.assertNotIn('for s in prod[:6]', seg,
                         'prod[:6] 을 그대로 찍고 있다 — 중복이 6칸을 채운다')

    def test_dedup_key_matches_what_is_printed(self):
        """중복 판정 키는 프롬프트에 실제로 찍히는 값과 같아야 한다."""
        import ast
        src = (ROOT / 'pc_sampling_fuzzer_v10.3.py').read_text(encoding='utf-8')
        tree = ast.parse(src)
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == '_llm_grounding_block')
        seg = ast.get_source_segment(src, fn) or ''
        self.assertIn('(s.cmd.name, s.cdw10, s.cdw11)', seg,
                      '찍는 값과 다른 키로 중복을 판정하면 중복이 남는다')


if __name__ == '__main__':
    unittest.main()
