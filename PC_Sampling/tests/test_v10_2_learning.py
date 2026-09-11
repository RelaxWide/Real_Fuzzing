"""Execution-grounded learning tests; no NVMe/JTAG operations are performed."""
import importlib.util
import json
import logging
from pathlib import Path
import random
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from llm_learning import LearningState, compile_recipe, seed_item
from rag.rag_schema import SchemaBridge
from riscv_cov import CoreMap, CoverageModel, pack

# Import the real entrypoint with CLI argv isolated; __main__ never executes.
spec = importlib.util.spec_from_file_location('fuzzer_v102_test', ROOT / 'pc_sampling_fuzzer_v10.2.py')
fuzzer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = fuzzer
with patch.object(sys, 'argv', [str(ROOT / 'pc_sampling_fuzzer_v10.2.py')]):
    spec.loader.exec_module(fuzzer)


def recipe():
    return {'base': {'command': 'DatasetManagement', 'cdw11': 4},
            'values': [1, 2, 16],
            'record': [{'width': 4, 'value': 0}, {'width': 4, 'value': 1},
                       {'width': 8, 'value': 0}],
            'repeat': {'param': True},
            'bindings': [{'field': 'cdw10', 'lo': 0, 'bits': 8,
                          'value': {'param': True, 'add': -1}}]}


def harness(options=None):
    obj = fuzzer.NVMeFuzzer.__new__(fuzzer.NVMeFuzzer)
    obj.learning = LearningState(options)
    obj._learning_apply_ctx = {}
    obj._learning_sequence = None
    obj._learning_last_send = None
    obj._learning_window_valid = True
    obj._learning_save_warned = False
    obj._learning_save = Mock()
    obj._learning_max_bytes = 4096
    obj._learning_max_seeds = 16
    obj._learning_max_seqs = 4
    obj.executions = 1
    obj.corpus = []
    obj.cov = None
    obj._credit_seed = None
    obj._last_wire = {}
    obj._last_nvme_status = 0
    obj._pending_workload = None
    obj._pending_seq_ctx = None
    obj._pending_seq_seeds = None
    obj._seq_sink = None
    obj._llm_stats = dict(seeds=0, seqs=0, dropped=0, dupes=0, rounds=0)
    obj._llm_seen = set()
    obj._llm_archive = Mock()
    obj._llm_seq_reject = Mock()
    obj._llm_repair_note = Mock()
    obj._proposal_write = Mock()
    obj._seq_at_pattern_cap = Mock(return_value=False)
    obj._run_id_get = Mock(return_value='test')
    ids = iter(range(1, 10000))
    obj._prov_next = lambda: next(ids)
    obj.start_time = None
    obj.stats = {}
    obj._active_nsids = {1}
    obj.llm = NS(enabled=True, schema_bridge=SchemaBridge.from_dict(fuzzer._llm_schema_dict()))
    obj.sampler = NS(_stopped_reason='max_samples')
    obj._mutate = lambda s: fuzzer.Seed(data=b'changed', cmd=s.cmd, cdw10=s.cdw10+1,
                                       cdw12=123, nsid_override=99)
    return obj


def add_target(obj, core='sa', bank=0, entry=100, end=200):
    return obj.learning.target(dict(core=core, bank=bank, entry=entry, end=end,
                                    name='target', frontier_callers=0, size=end-entry))


def result(data, targets=(), **kw):
    return dict(raw=json.dumps(data), task=kw.get('task', 'new_group_seeds'), error=None,
                submitted_at=0, req_id=7, ctx=dict(learning_targets=list(targets),
                                                  learning_setups=kw.get('setups', {})),
                llm_seconds=2.0)


def row(valid=True, status='completion', gain=0, seconds=1):
    return dict(observable=valid, submission=status, device_seconds=seconds, new_coverage=gain)


class RecipeTests(unittest.TestCase):
    def test_descriptor_count_and_wire_count_match(self):
        gid, seeds = compile_recipe(recipe(), 4096)
        self.assertTrue(gid.startswith('g'))
        for seed, count in zip(seeds, [1, 2, 16]):
            data = bytes.fromhex(seed['data_hex'])
            self.assertEqual(len(data), count * 16)
            self.assertEqual(seed['cdw10'] & 255, count - 1)
            self.assertEqual(int.from_bytes(data[4:8], 'little'), 1)

    def test_length_fault_injection_is_retained_in_both_directions(self):
        for delta in [-1, 1, 16]:
            r = recipe()
            r['break_length'] = delta
            _, seeds = compile_recipe(r, 4096)
            for seed in seeds:
                self.assertEqual(seed['data_len'], len(bytes.fromhex(seed['data_hex'])) + delta)

    def test_identity_depends_on_rule_not_target(self):
        r = recipe()
        gid, _ = compile_recipe(r, 4096)
        r['target_id'] = 'different-target'
        self.assertEqual(gid, compile_recipe(r, 4096)[0])
        r['break_length'] = -1
        self.assertNotEqual(gid, compile_recipe(r, 4096)[0])

    def test_rejects_unbounded_and_ambiguous_rules_atomically(self):
        cases = []
        r = recipe(); r['values'] = [1, 2, 2**32]; cases.append(r)
        r = recipe(); r['repeat'] = 10**9; cases.append(r)
        r = recipe(); r['record'][0]['width'] = True; cases.append(r)
        r = recipe(); r['bindings'] *= 2; cases.append(r)
        r = recipe(); r['values'] = [0]; cases.append(r)  # count-1 must not silently wrap
        r = recipe(); r['code'] = 'print(1)'; cases.append(r)
        r = recipe(); r['record'][0]['value'] = {'eval': '1+1'}; cases.append(r)
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                compile_recipe(case, 4096)


class EvidenceAndSchedulerTests(unittest.TestCase):
    def test_offered_selected_accepted_executed_are_separate(self):
        obj = harness()
        t1, t2 = add_target(obj), add_target(obj, entry=200, end=300)
        obj.learning.submitted('new_group_seeds', [t1, t2], 100)
        obj._llm_apply_result(result({'seeds': [{'command': 'Write', 'target_id': t1}]}, [t1, t2]))
        p = obj.corpus[0].prov_id
        self.assertEqual(obj.learning.targets[t1]['selected'], 1)
        self.assertEqual(obj.learning.targets[t2]['selected'], 0)
        self.assertEqual(obj.learning.targets[t1]['executed'], 0)
        obj.learning.observe(p, row(), set(), {100})
        self.assertEqual(obj.learning.targets[t1]['executed'], 1)
        self.assertEqual(obj.learning.targets[t2]['executed'], 0)

    def test_delayed_response_uses_its_own_request_targets(self):
        obj = harness()
        old, new = add_target(obj), add_target(obj, entry=300, end=400)
        # Model guesses a target from a different request: don't attribute it.
        obj._llm_apply_result(result({'seeds': [{'command': 'Write', 'target_id': new}]}, [old]))
        self.assertIsNone(obj.corpus[0].learning_meta['target_id'])
        self.assertEqual(obj.learning.targets[new]['accepted'], 0)

    def test_observation_loss_or_unknown_submission_is_not_zero_reward(self):
        state = LearningState({'evaluation_commands': 2})
        state.register(1, 'sequences', {})
        for _ in range(10):
            state.observe(1, row(valid=False), set(), set())
            state.observe(1, row(status='unknown'), set(), {1})
        self.assertEqual(state.proposals[1]['evaluated'], 0)
        self.assertEqual(state._task('sequences')['rewards'], [])
        state.observe(1, row(gain=4), set(), {1})
        self.assertEqual(state._task('sequences')['rewards'], [])
        state.observe(1, row(), set(), {1})
        self.assertEqual(len(state._task('sequences')['rewards']), 1)
        for _ in range(10):
            state.observe(1, row(gain=999), set(), {1})
        self.assertEqual(len(state._task('sequences')['rewards']), 1)

    def test_exploration_keeps_all_tasks_alive_without_global_rng(self):
        state = LearningState()
        active = ['new_group_seeds', 'sequences', 'io_patterns', 'corpus_eval']
        state._task('sequences')['rewards'] = [1000]
        global_rng = random.getstate()
        choices = []
        for _ in range(64):
            t = state.choose(active, 'new_group_seeds')
            choices.append(t)
            state.submitted(t, [], 10)
        self.assertEqual(set(choices), set(active))
        from itertools import groupby
        self.assertLessEqual(max(len(list(g)) for _, g in groupby(choices)), 3)
        self.assertEqual(random.getstate(), global_rng)
        self.assertEqual(state._task('corpus_eval')['rewards'], [])

    def test_model_cost_is_measured_separately(self):
        obj = harness({'evaluation_commands': 1})
        obj._llm_apply_result(result({'seeds': [{'command': 'Write'}]}))
        pid = obj.corpus[0].prov_id
        obj.learning.observe(pid, row(gain=1), set(), {1})
        task = obj.learning.tasks['new_group_seeds']
        self.assertEqual(task['llm_seconds'], 2)
        self.assertIsNone(task['usage_tokens'])
        self.assertEqual(task['device_seconds'], 1)
        self.assertLess(task['rewards'][0], 0.3)

    def test_bank_identity_and_observed_functions(self):
        obj = harness()
        cm = CoreMap(0, 'F')
        cm.fn_entries, cm.fn_ends, cm.fn_names = [100], [200], ['base']
        cm.bb_starts, cm.bb_ends = [100], [200]
        cm.banks[1] = dict(fn_entries=[100], fn_ends=[200], fn_names=['overlay'],
                           bb_starts=[100], bb_ends=[200])
        obj.cov = NS(loaded=True, cores={0: cm})
        base, overlay = add_target(obj, 0, 0), add_target(obj, 0, 1)
        obj.learning.register(1, 'new_group_seeds', {'target_id': overlay})
        seed = fuzzer.Seed(data=b'', cmd=fuzzer._NAME_TO_CMD['Write'], prov_id=1)
        obj._learning_observe(seed, 0, 0, {pack(0, 0, 100)}, 1, 'c1', False)
        self.assertEqual(obj.learning.targets[overlay]['observed'], 0)
        obj._learning_observe(seed, 0, 0, {pack(0, 1, 100)}, 1, 'c1', False)
        self.assertEqual(obj.learning.targets[overlay]['observed'], 1)
        self.assertNotEqual(base, overlay)

    def test_generator_complement_is_preserved_without_discovery_credit(self):
        state = LearningState()
        for pid, gid, coverage in [(1, 'g1', {1, 2}), (2, 'g2', {2, 3})]:
            state.generators[gid] = dict(coverage=set(), coverage_truncated=False,
                                         executions=0, new_coverage=0)
            state.register(pid, 'new_group_seeds', {'generator_id': gid})
            state.observe(pid, row(gain=0), set(), coverage)
        self.assertEqual(state.generators['g2']['coverage'] - state.generators['g1']['coverage'], {3})


class IntegrationTests(unittest.TestCase):
    def test_generator_response_uses_real_schema_and_existing_guards(self):
        obj = harness()
        r = recipe(); r['break_length'] = -1
        obj._llm_apply_result(result({'generators': [r]}))
        self.assertEqual(len(obj.corpus), 3)
        for seed in obj.corpus:
            self.assertEqual(seed.data_len_override, len(seed.data)-1)
            self.assertTrue(seed.learning_meta['generator_id'])
            self.assertIn(seed.prov_id, obj.learning.proposals)
        obj._llm_apply_result(result({'generators': [{'base': {'command': 'Sanitize'}, 'values': [1]}]}))
        self.assertEqual(len(obj.corpus), 3)

    def test_malformed_response_containers_do_not_crash(self):
        obj = harness()
        obj._llm_apply_result(result({'seeds': 10, 'sequences': 'x', 'generators': {}}))
        self.assertEqual(obj.corpus, [])
        self.assertTrue(obj.learning.errors)

    def test_parser_recognizes_generator_only_reply(self):
        self.assertIsNotNone(fuzzer._llm_extract_json(json.dumps({'generators': [recipe()]})))

    def test_setup_is_exact_trigger_is_mutated_and_shared_lba_is_preserved(self):
        obj = harness({'setup_preserve_ratio': 1})
        setup = fuzzer.Seed(data=b'original', cmd=fuzzer._NAME_TO_CMD['Write'],
                            cdw10=456, cdw12=7, nsid_override=2)
        trigger = fuzzer.Seed(data=b'', cmd=fuzzer._NAME_TO_CMD['Compare'])
        seq = fuzzer.SequenceSeed(commands=[setup, trigger])
        self.assertTrue(obj._learning_seq_start(seq))
        first = obj._learning_seq_member(setup, first=True)
        self.assertIsNot(first, setup)
        self.assertEqual(seed_item(first), seed_item(setup))
        obj._learning_observe(first, 0, 0, {100}, 0, 'c1', True)
        last = obj._learning_seq_member(trigger)
        self.assertEqual(last.cdw10, 456)
        self.assertEqual(last.cdw12 & 0xffff, 7)
        self.assertEqual(last.data, b'original')
        self.assertEqual(last.nsid_override, 2)
        obj._learning_observe(last, 0, 0, {100}, 0, 'c1', True)
        self.assertEqual(seq.learning_meta['successful_setup'], [seed_item(first)])
        self.assertEqual(obj.learning.counts['trigger_after_successful_setup'], 1)

    def test_failed_or_skipped_setup_aborts_pending_trigger(self):
        for status, rc in [(2, 1), (None, 22), (None, fuzzer.NVMeFuzzer.RC_SKIP)]:
            with self.subTest(status=status):
                obj = harness({'setup_preserve_ratio': 1})
                setup = fuzzer.Seed(data=b'', cmd=fuzzer._NAME_TO_CMD['Write'])
                seq = fuzzer.SequenceSeed(commands=[setup, setup])
                obj._learning_seq_start(seq)
                obj._pending_seq_seeds = [setup]
                obj._seq_sink = {'commands': []}
                obj._learning_observe(setup, status, rc, set(), 0, 'c1', True)
                self.assertIsNone(obj._pending_seq_seeds)
                self.assertIsNone(obj._seq_sink)
                self.assertEqual(obj.learning.counts['trigger_attempts'], 0)

    def test_failed_setup_in_exploratory_mode_can_continue_but_is_not_success(self):
        obj = harness({'setup_preserve_ratio': 0})
        setup = fuzzer.Seed(data=b'', cmd=fuzzer._NAME_TO_CMD['Write'])
        seq = fuzzer.SequenceSeed(commands=[setup, setup])
        obj._learning_seq_start(seq)
        obj._pending_seq_seeds = [setup]
        obj._learning_observe(setup, 2, 1, {100}, 0, 'c1', True)
        self.assertIsNotNone(obj._pending_seq_seeds)
        obj._learning_seq_member(setup)
        obj._learning_observe(setup, 0, 0, {100}, 0, 'c1', True)
        self.assertNotIn('setup_successes', seq.learning_meta)
        self.assertEqual(obj.learning.counts['trigger_after_successful_setup'], 0)

    def test_setup_reference_uses_request_snapshot(self):
        obj = harness()
        setup = {'command': 'Write', 'cdw10': 64}
        obj._llm_apply_result(result({'sequences': [{'setup_id': 's1',
                                  'commands': [{'command': 'Read'}]}]},
                                   task='sequences', setups={'s1': [setup]}))
        self.assertEqual(len(obj.corpus), 1)
        seq = obj.corpus[0]
        self.assertEqual(len(seq.commands), 2)
        self.assertEqual(seq.commands[0].cdw10, 64)
        self.assertEqual(obj.learning.proposals[seq.prov_id]['task'], 'sequences')
        obj._llm_apply_result(result({'sequences': [{'setup_id': 'missing',
                                  'commands': [{'command': 'Read'}]}]}, task='sequences'))
        self.assertEqual(len(obj.corpus), 1)

    def test_disabled_mode_has_no_learning_records_or_generator_injection(self):
        obj = harness({'enabled': False})
        obj._llm_apply_result(result({'seeds': [{'command': 'Write'}], 'generators': [recipe()]}))
        self.assertEqual(len(obj.corpus), 1)
        self.assertEqual(obj.learning.proposals, {})
        obj._learning_observe(obj.corpus[0], 0, 0, {100}, 2, 'c1', False)
        self.assertFalse(obj.learning.recent)


    def test_different_host_lengths_are_not_deduplicated(self):
        obj = harness()
        for delta in [-1, 0, 1]:
            r = recipe(); r['values'] = [1]; r['break_length'] = delta
            obj._llm_apply_result(result({'generators': [r]}))
        self.assertEqual([s.data_len_override for s in obj.corpus], [15, 16, 17])

    def test_small_proposal_capacity_does_not_crash_response_registration(self):
        obj = harness({'max_proposals': 1})
        obj._llm_apply_result(result({'generators': [recipe()]}))
        self.assertEqual(len(obj.learning.proposals), 1)
        self.assertEqual(obj.learning.counts['proposals_evicted'], 2)

    def test_sampler_failure_during_stop_is_not_mistaken_for_valid_recovery(self):
        import threading
        obj = harness()
        obj.sampler.openocd_error = threading.Event()
        def stop():
            obj.sampler.openocd_error.set()
            return 1
        obj.sampler.stop_sampling = stop
        obj.sampler._reinit_target = Mock(return_value=True)
        obj._stop_sampling_checked('command:Write')
        self.assertFalse(obj._learning_window_valid)
        self.assertFalse(obj.sampler.openocd_error.is_set())

    def test_missing_target_core_is_unobservable_not_a_failed_target(self):
        obj = harness()
        tid = add_target(obj, core=1)
        obj.learning.register(1, 'new_group_seeds', {'target_id': tid})
        r = dict(row(), sampled_scopes=[[0, 0]])
        obj.learning.observe(1, r, set(), {100})
        self.assertEqual(obj.learning.targets[tid]['observed'], 0)
        self.assertEqual(obj.learning.targets[tid]['unobservable'], 1)

    def test_real_constructor_does_not_access_device(self):
        with tempfile.TemporaryDirectory() as d:
            config = fuzzer.FuzzConfig(no_jlink=True, rag_enabled=False, state_enabled=False, output_dir=d)
            with patch.object(fuzzer.NVMeFuzzer, '_load_static_analysis'), \
                 patch.object(fuzzer.NVMeFuzzer, '_load_riscv_coverage'), \
                 patch('subprocess.run', side_effect=AssertionError('device access')):
                obj = fuzzer.NVMeFuzzer(config)
            self.assertEqual(obj.VERSION, '10.2.0')
            self.assertTrue(obj.learning.enabled)

    def test_inflight_request_does_not_consume_a_scheduler_slot(self):
        obj = harness()
        obj.llm.can_submit = Mock(return_value=False)
        obj._llm_build_request = Mock()
        obj._llm_maybe_submit()
        obj._llm_build_request.assert_not_called()
        self.assertEqual(obj.learning.turn, 0)

    def test_real_accounting_preserves_status_and_proposal_for_descendants(self):
        with tempfile.TemporaryDirectory() as d:
            config = fuzzer.FuzzConfig(no_jlink=True, rag_enabled=False, state_enabled=False,
                                       output_dir=d, vmon_enabled=False)
            with patch.object(fuzzer.NVMeFuzzer, '_load_static_analysis'), \
                 patch.object(fuzzer.NVMeFuzzer, '_load_riscv_coverage'):
                obj = fuzzer.NVMeFuzzer(config)
            obj._learning_window_valid = True
            seed = fuzzer.Seed(data=b'input', cmd=fuzzer._NAME_TO_CMD['Write'],
                               prov_id=42, seed_class='llm_test', learning_meta={'target_id': None})
            obj.learning.register(42, 'new_group_seeds', seed.learning_meta)
            obj._last_nvme_status = 0
            obj._last_wire = {'opcode': 1, 'queue': 'io', 'nsid': 1, 'xfer_len': 5}
            obj._learning_last_send = (seed, 0.5)
            obj._credit_seed = seed
            obj.sampler.current_trace = {100}
            obj.sampler.evaluate_coverage = Mock(return_value=(True, 1))
            obj._ledger_write = Mock()
            obj._account_command(seed, seed.data, 0, 1)
            self.assertIsNone(obj._last_nvme_status)
            self.assertEqual(obj.learning.recent[-1]['status'], 0)
            self.assertEqual(obj.learning.proposals[42]['evaluated'], 1)
            self.assertEqual(obj.corpus[-1].prov_id, 42)
            self.assertEqual(obj._boost_exec.get('llm'), 1)

    def test_calibration_records_each_valid_execution_before_status_is_lost(self):
        with tempfile.TemporaryDirectory() as d:
            config = fuzzer.FuzzConfig(no_jlink=True, rag_enabled=False, state_enabled=False,
                                       output_dir=d, calibration_runs=2)
            with patch.object(fuzzer.NVMeFuzzer, '_load_static_analysis'), \
                 patch.object(fuzzer.NVMeFuzzer, '_load_riscv_coverage'):
                obj = fuzzer.NVMeFuzzer(config)
            seed = fuzzer.Seed(data=b'', cmd=fuzzer._NAME_TO_CMD['Write'], prov_id=42)
            obj.learning.register(42, 'new_group_seeds', {})
            obj._send_nvme_command = Mock(return_value=0)
            obj._last_nvme_status = 0
            obj._last_wire = {'opcode': 1, 'queue': 'io'}
            obj._stop_sampling_checked = Mock(return_value=(1, True))
            obj._learning_window_valid = True
            obj.sampler.current_trace = {100}
            obj._ledger_write = Mock()
            obj._calibrate_seed(seed)
            self.assertEqual(obj.learning.proposals[42]['evaluated'], 2)
            self.assertEqual(obj.learning.proposals[42]['gain'], 1)
            self.assertEqual([r['source'] for r in obj.learning.recent], ['calibration']*2)


    def test_evaluation_waits_for_sequence_trigger_boundary(self):
        state = LearningState({'evaluation_commands': 2})
        state.register(1, 'sequences', {})
        for _ in range(3):
            state.observe(1, dict(row(gain=1), evaluation_boundary=False), set(), {1})
        self.assertFalse(state.proposals[1]['rewarded'])
        state.observe(1, dict(row(), evaluation_boundary=True), set(), {1})
        self.assertTrue(state.proposals[1]['rewarded'])

    def test_device_paths_match_frozen_v102_baseline(self):
        """Frozen at 13204e6; v10.1 hotfixes must not redefine this baseline.

        If a v10.2 device path intentionally changes, review it and update the
        fixture hashes/source_commit explicitly. Never auto-refresh on test failure.
        Empty type_params are ignored for Python 3.8/3.12 AST compatibility.
        """
        import ast
        import hashlib
        def normalize(node):
            if isinstance(node, ast.AST):
                return {'type': type(node).__name__,
                        'fields': {k: normalize(v) for k, v in ast.iter_fields(node)
                                   if not (k == 'type_params' and not v)}}
            if isinstance(node, list):
                return [normalize(x) for x in node]
            if node is Ellipsis:
                return {'literal': 'Ellipsis'}
            if isinstance(node, bytes):
                return {'bytes': node.hex()}
            return node
        frozen = json.loads((ROOT / 'tests/fixtures/v10_2_device_ast.json').read_text())
        tree = ast.parse((ROOT / 'pc_sampling_fuzzer_v10.2.py').read_text())
        classes = {n.name: n for n in tree.body if isinstance(n, ast.ClassDef)}
        for path, expected in frozen['hashes'].items():
            cls, _, method = path.partition('.')
            node = classes[cls]
            if method:
                node = next(n for n in node.body if isinstance(n, ast.FunctionDef) and n.name == method)
            value = json.dumps(normalize(node), sort_keys=True, separators=(',', ':'))
            self.assertEqual(hashlib.sha256(value.encode()).hexdigest(), expected, path)

    def test_comparison_tool_reports_complement_without_claiming_significance(self):
        from importlib.util import spec_from_file_location, module_from_spec
        spec = spec_from_file_location('compare_learning', ROOT / 'tools/compare_llm_learning.py')
        compare = module_from_spec(spec); spec.loader.exec_module(compare)
        obj = harness()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'snapshot.json'
            path.write_text(json.dumps(obj.learning.snapshot()))
            report = compare.summarize(path)
            self.assertIsNone(report['unobservable_ratio'])
            self.assertIsNone(report['corpus_sha256'])
            self.assertIn('not proof', report['interpretation'])

    def test_snapshot_is_valid_json_with_rules_and_coverage(self):
        obj = harness()
        obj._llm_apply_result(result({'generators': [recipe()]}))
        obj._learning_save = fuzzer.NVMeFuzzer._learning_save.__get__(obj)
        with tempfile.TemporaryDirectory() as d:
            obj.output_dir = Path(d)
            obj._learning_save()
            saved = json.loads((Path(d) / 'llm/learning_v10.2.json').read_text())
            self.assertEqual(saved['schema_version'], 1)
            self.assertEqual(len(saved['generators']), 1)
            self.assertFalse((Path(d) / 'llm/learning_v10.2.json.tmp').exists())


if __name__ == '__main__':
    unittest.main()
