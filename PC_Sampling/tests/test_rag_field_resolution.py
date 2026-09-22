import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rag import retrieval_policy as p


class ResolutionTests(unittest.TestCase):
    def test_no_abbreviation_aliases_across_commands(self):
        rows = p.extract_definitions('CNS Specific Identifier: text\nUUID Index: text', 'spec', 'a')
        lookup, _ = p.definition_lookup(rows)
        self.assertEqual(p.field_full_name(lookup, 'Identify', 11, 'CNSSI'), 'CNS Specific Identifier')
        for cmd in ('Identify', 'GetFeatures', 'SetFeatures'):
            detail = p.resolve_field(lookup, cmd, 14, 'UIDX')
            self.assertEqual(detail['full_name'], 'UUID Index')
            self.assertTrue(detail['alias_applied'])
        self.assertIsNone(p.field_full_name(lookup, 'Unknown', 14, 'UIDX'))
        detail = p.resolve_field(lookup, 'Lockdown', 10, 'UUID')
        self.assertEqual(detail['reason'], 'schema_location_mismatch')
        self.assertIsNone(detail['full_name'])
        self.assertEqual(detail['expected_dword'], 14)

    def test_shared_split_field_aliases_not_arbitrary_suffixes(self):
        rows = p.extract_definitions('Starting LBA (SLBA): text', 'spec', 'a')
        lookup, _ = p.definition_lookup(rows)
        for cmd in ('Read', 'Write', 'Compare', 'Verify', 'GetLBAStatus', 'WriteZeroes', 'WriteUncorrectable'):
            for word, name in [(10, 'SLBA_LO'), (11, 'SLBA_HI')]:
                self.assertEqual(p.field_full_name(lookup, cmd, word, name), 'Starting LBA')
        self.assertIsNone(p.field_full_name(lookup, 'Other', 10, 'SLBA_LO'))
        self.assertIsNone(p.field_full_name(lookup, 'Read', 12, 'SLBA_LO'))

    def test_reasons_candidates_and_permission(self):
        rows = [dict(command=None, dword=None, abbreviation='CSI', full_name=name,
                     permission_groups=['private'], source_doc_id=str(i))
                for i, name in enumerate(['Command Set Identifier', 'Different Name'])]
        lookup, _ = p.definition_lookup(rows)
        detail = p.resolve_field(lookup, 'Identify', 11, 'CSI')
        self.assertEqual(detail['reason'], 'definition_conflict')
        self.assertEqual(detail['candidate_count'], 2)
        lookup, _ = p.definition_lookup(rows, ['public'])
        detail = p.resolve_field(lookup, 'Identify', 11, 'CSI')
        self.assertEqual(detail['reason'], 'definition_missing')
        self.assertEqual(detail['candidates'], [])

    def test_same_scope_conflict_not_hidden_by_global(self):
        rows = [dict(command='Read', dword=10, abbreviation='X', full_name=name) for name in ['One', 'Two']]
        lookup, _ = p.definition_lookup(rows)
        self.assertEqual(p.resolve_field(lookup, 'Read', 10, 'X')['reason'], 'definition_conflict')

    def test_all_schema_audit_includes_non_requested_commands(self):
        from tools.rag_field_audit import read_schemas
        schemas = read_schemas(Path(__file__).resolve().parents[1] / 'pc_sampling_fuzzer_v10.3.py')
        lookup, _ = p.definition_lookup([])
        report = p.expansion_report(list(schemas), schemas, lookup, True)
        self.assertEqual(report['missing_count'], sum(map(len, schemas.values())))
        self.assertEqual(report['missing_reasons']['schema_location_mismatch'], 1)
        self.assertGreater(len(schemas), 30)

    def test_wrong_dword_is_reported_with_evidence(self):
        rows = [dict(command='GetLogPage', dword=11, abbreviation='NUMDL',
                     full_name='Number of Dwords Lower', source_doc_id='wrong-word')]
        lookup, _ = p.definition_lookup(rows)
        detail = p.resolve_field(lookup, 'GetLogPage', 10, 'NUMDL')
        self.assertEqual(detail['reason'], 'context_mismatch')
        self.assertEqual(detail['candidates'][0]['source_doc_id'], 'wrong-word')
