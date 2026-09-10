"""v10.2 execution-grounded LLM learning. No device access or generated code execution.

All mutable learning state is owned by the fuzzer's main thread. The bridge carries
immutable request snapshots; the worker never reads or writes this state.
"""
from __future__ import annotations

import bisect
from collections import Counter, OrderedDict, deque
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import logging
import math
from pathlib import Path
import platform
import random
import time

log = logging.getLogger(__name__)
CDWS = tuple(f'cdw{x}' for x in (2, 3, 10, 11, 12, 13, 14, 15))
DEFAULTS = dict(enabled=True, evidence=True, preserve_setup=True, generators=True,
                adaptive_tasks=True, setup_preserve_ratio=0.8, evaluation_commands=8,
                exploration_every=4, max_targets=512, max_proposals=2048,
                max_generators=128, max_generator_keys=4096, recent_commands=256,
                max_variants=16, random_seed=102)


def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False).encode()).hexdigest()


def checked_int(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f'{label}: expected integer in {low}..{high}')
    return value


def seed_item(seed):
    """Exact input representation, including deliberately inconsistent data_len."""
    row = {'command': seed.cmd.name, **{k: getattr(seed, k) for k in CDWS},
           'data_hex': bytes(seed.data).hex()}
    for src, dst in (('nsid_override', 'nsid'), ('data_len_override', 'data_len')):
        if getattr(seed, src, None) is not None:
            row[dst] = getattr(seed, src)
    return row


def compile_recipe(recipe, max_bytes, max_variants=16):
    """Finite JSON DSL: one integer parameter, packed LE records, bitfield bindings.

    Values are integers or {param: true, add: integer}. There is no eval/import,
    random expression, cross product, file access, or implicit length repair.
    """
    if not isinstance(recipe, dict):
        raise ValueError('generator must be an object')
    if set(recipe) - {'base', 'values', 'record', 'repeat', 'bindings', 'break_length', 'target_id'}:
        raise ValueError('unknown generator key')
    base = recipe.get('base')
    if not isinstance(base, dict) or not isinstance(base.get('command'), str):
        raise ValueError('generator.base.command is required')
    if set(base) - set(CDWS) - {'command', 'nsid', 'data_hex'}:
        raise ValueError('unknown generator base field')
    values = recipe.get('values')
    if not isinstance(values, list) or not 1 <= len(values) <= max_variants:
        raise ValueError('values must be a bounded nonempty list')
    for v in values:
        checked_int(v, 0, 0xffffffff, 'parameter')
    record = recipe.get('record', [])
    bindings = recipe.get('bindings', [])
    if not isinstance(record, list) or len(record) > 32:
        raise ValueError('record must contain at most 32 fields')
    if not isinstance(bindings, list) or len(bindings) > 16:
        raise ValueError('bindings must contain at most 16 fields')

    def value(expr, param):
        if type(expr) is int:
            return expr
        if (isinstance(expr, dict) and set(expr) <= {'param', 'add'}
                and expr.get('param') is True):
            return param + checked_int(expr.get('add', 0), -0xffffffff, 0xffffffff, 'add')
        raise ValueError('value must be integer or {param:true,add:integer}')

    identity = {k: v for k, v in recipe.items() if k != 'target_id'}
    gid = 'g' + digest(identity)[:20]
    out = []
    for param in values:
        item = deepcopy(base)
        for k in CDWS:
            if k in item:
                checked_int(item[k], 0, 0xffffffff, k)
        if 'nsid' in item:
            checked_int(item['nsid'], 0, 0xffffffff, 'nsid')
        raw_hex = item.get('data_hex', '')
        if not isinstance(raw_hex, str) or len(raw_hex) > max_bytes * 2:
            raise ValueError('base payload exceeds limit')
        payload = bytes.fromhex(raw_hex)
        if record:
            packed = bytearray()
            for field in record:
                if not isinstance(field, dict) or set(field) != {'width', 'value'}:
                    raise ValueError('record field needs width and value')
                width = field['width']
                if type(width) is not int or width not in (1, 2, 4, 8):
                    raise ValueError('record width must be 1,2,4,8')
                v = checked_int(value(field['value'], param), 0, (1 << (8 * width)) - 1, 'record value')
                packed.extend(v.to_bytes(width, 'little'))
            count = checked_int(value(recipe.get('repeat', 1), param), 0, max_bytes, 'repeat')
            if len(packed) * count > max_bytes:
                raise ValueError('expanded payload exceeds limit')
            payload = bytes(packed) * count
        used = {}
        for b in bindings:
            if not isinstance(b, dict) or set(b) != {'field', 'lo', 'bits', 'value'}:
                raise ValueError('binding needs field,lo,bits,value')
            field = b['field']
            if field not in CDWS:
                raise ValueError('binding field must be a CDW')
            lo = checked_int(b['lo'], 0, 31, 'lo')
            bits = checked_int(b['bits'], 1, 32 - lo, 'bits')
            mask = ((1 << bits) - 1) << lo
            if used.get(field, 0) & mask:
                raise ValueError('overlapping bindings')
            used[field] = used.get(field, 0) | mask
            v = checked_int(value(b['value'], param), 0, (1 << bits) - 1, 'binding value')
            item[field] = (item.get(field, 0) & ~mask) | (v << lo)
        item['data_hex'] = payload.hex()
        if 'break_length' in recipe:
            delta = checked_int(recipe['break_length'], -max_bytes, max_bytes, 'break_length')
            item['data_len'] = checked_int(len(payload) + delta, 0, max_bytes, 'data_len')
        item['_generator_id'] = gid
        item['target_id'] = recipe.get('target_id')
        out.append(item)
    return gid, out


class LearningState:
    def __init__(self, config=None):
        self.options = dict(DEFAULTS)
        supplied = config or {}
        if not isinstance(supplied, dict) or set(supplied) - set(DEFAULTS):
            raise ValueError('rag.learning contains unknown options')
        self.options.update(supplied)
        for k in ('enabled', 'evidence', 'preserve_setup', 'generators', 'adaptive_tasks'):
            if type(self.options[k]) is not bool:
                raise ValueError(f'rag.learning.{k} must be boolean')
        for k in ('evaluation_commands', 'exploration_every', 'max_targets', 'max_proposals',
                  'max_generators', 'max_generator_keys', 'recent_commands', 'max_variants'):
            checked_int(self.options[k], 1, 100000, k)
        if self.options['max_variants'] > 64:
            raise ValueError('max_variants must be <=64')
        ratio = self.options['setup_preserve_ratio']
        if type(ratio) not in (int, float) or not math.isfinite(ratio) or not 0 <= ratio <= 1:
            raise ValueError('setup_preserve_ratio must be 0..1')
        checked_int(self.options['random_seed'], 0, 0xffffffff, 'random_seed')
        self.rng = random.Random(self.options['random_seed'])
        self.targets = OrderedDict()
        self.proposals = OrderedDict()
        self.generators = OrderedDict()
        self.tasks = {}
        self.recent = deque(maxlen=self.options['recent_commands'])
        self.errors = deque(maxlen=32)
        self.counts = Counter()
        self.turn = self.explore_cursor = 0
        self.last_task = None
        self.consecutive = 0
        self.baseline = None
        self.function_commands = OrderedDict()

    @property
    def enabled(self):
        return self.options['enabled']

    def _task(self, name):
        return self.tasks.setdefault(name, dict(requests=0, request_chars=0, response_chars=0,
                                               completed_evaluations=0, rewards=[], usage_tokens=None,
                                               device_seconds=0.0, llm_seconds=0.0))

    def target(self, row):
        tid = 't' + digest([row['core'], row['bank'], row['entry']])[:20]
        if tid not in self.targets:
            if len(self.targets) >= self.options['max_targets']:
                # Never reuse an evicted identity for another target.
                self.targets.popitem(last=False)
                self.counts['targets_evicted'] += 1
            self.targets[tid] = dict(row, target_id=tid, offered=0, selected=0,
                                     accepted=0, executed=0, observed=0, unobservable=0,
                                     recent=[])
        self.targets[tid]['caller_commands'] = row.get('caller_commands', [])
        self.targets[tid]['frontier_callers'] = row.get('frontier_callers', 0)
        self.targets[tid]['previously_observed'] = row.get('observed', False)
        return tid

    def request(self, task, ids, chars):
        t = self._task(task)
        t['requests'] += 1
        t['request_chars'] += chars
        for tid in set(ids):
            if tid in self.targets:
                self.targets[tid]['offered'] += 1
        self.turn += 1
        self.consecutive = self.consecutive + 1 if task == self.last_task else 1
        self.last_task = task

    def choose(self, active, fallback, max_consecutive=3):
        """Minimum exploration plus recent completed evaluation reward; no global RNG."""
        if not self.enabled or not self.options['adaptive_tasks']:
            return fallback
        allowed = [t for t in active if t != self.last_task or self.consecutive < max_consecutive]
        allowed = allowed or active
        if self.turn % self.options['exploration_every'] == 0:
            for offset in range(len(active)):
                candidate = active[(self.explore_cursor + offset) % len(active)]
                if candidate in allowed:
                    return candidate
        ranked = []
        for task in allowed:
            # corpus_eval has indirect effects, so it only gets exploration slots.
            if task == 'corpus_eval':
                continue
            rewards = self._task(task)['rewards']
            if rewards:
                ranked.append((sum(rewards) / len(rewards), task))
        return max(ranked)[1] if ranked else (fallback if fallback in allowed else allowed[0])

    def submitted(self, task, ids, chars):
        if self.turn % self.options['exploration_every'] == 0:
            self.explore_cursor += 1
        self.request(task, ids, chars)

    def register(self, pid, task, meta):
        if pid in self.proposals:
            return
        if len(self.proposals) >= self.options['max_proposals']:
            self.proposals.popitem(last=False)
            self.counts['proposals_evicted'] += 1
        tid = meta.get('target_id')
        if tid in self.targets:
            self.targets[tid]['accepted'] += 1
        self.proposals[pid] = dict(task=task, **meta, attempts=0, evaluated=0,
                                  gain=0, seconds=0.0, rewarded=False, inputs=[], inputs_truncated=False)

    def observe(self, pid, row, observed_targets, coverage_keys):
        self.recent.append(row)
        self.counts['attempts'] += 1
        if not row['observable']:
            self.counts['unobservable'] += 1
        proposal = self.proposals.get(pid)
        if proposal is None:
            return
        proposal['attempts'] += 1
        signature = row.get('input_signature')
        if signature and row['submission'] == 'completion' and signature not in proposal['inputs']:
            if len(proposal['inputs']) < 64:
                proposal['inputs'].append(signature)
            else:
                proposal['inputs_truncated'] = True
        task = self._task(proposal['task'])
        task['device_seconds'] += row['device_seconds']
        tid = proposal.get('target_id')
        target = self.targets.get(tid)
        if target is not None:
            if row['submission'] == 'completion':
                target['executed'] += 1
            target_observable = row['observable'] and row['submission'] == 'completion' and (
                'sampled_scopes' not in row or [target['core'], target['bank']] in row['sampled_scopes'])
            if target_observable:
                target['observed'] += int(tid in observed_targets)
            else:
                target['unobservable'] += 1
            target['recent'] = (target['recent'] + [row])[-8:]
        gid = proposal.get('generator_id')
        if gid in self.generators and row['observable'] and row['submission'] == 'completion':
            g = self.generators[gid]
            g['executions'] += 1
            g['new_coverage'] += row['new_coverage']
            for key in sorted(coverage_keys):
                if len(g['coverage']) < self.options['max_generator_keys']:
                    g['coverage'].add(key)
                elif key not in g['coverage']:
                    g['coverage_truncated'] = True
        # No CQE or no valid sampling window: record evidence, but never learn zero reward.
        if not row['observable'] or row['submission'] != 'completion' or proposal['rewarded']:
            return
        proposal['evaluated'] += 1
        proposal['gain'] += row['new_coverage']
        proposal['seconds'] += row['device_seconds']
        if (proposal['evaluated'] >= self.options['evaluation_commands']
                and row.get('evaluation_boundary', True)):
            proposal['rewarded'] = True
            if proposal['task'] != 'corpus_eval':
                reward = math.log1p(proposal['gain']) / max(
                    proposal['seconds'] + proposal.get('llm_cost_share', 0.0), 0.001)
                task['rewards'] = (task['rewards'] + [reward])[-32:]
                task['completed_evaluations'] += 1

    def snapshot(self):
        generators = {}
        for gid, value in self.generators.items():
            generators[gid] = {**value, 'coverage': sorted(value['coverage'])}
        return dict(schema_version=1, options=self.options, baseline=self.baseline,
                    counts=dict(self.counts), targets=list(self.targets.values()),
                    proposals=self.proposals, generators=generators, tasks=self.tasks,
                    recent=list(self.recent), errors=list(self.errors),
                    function_commands=self.function_commands)


class LearningMixin:
    """Small adapter around v10.1. The NVMe transport and its guards stay upstream."""
    def __init__(self, config):
        super().__init__(config)
        self.learning = LearningState(self._learning_config)
        self._learning_apply_ctx = {}
        self._learning_sequence = None
        self._learning_last_send = None
        self._learning_window_valid = False
        self._learning_save_warned = False

    def _learning_candidates(self, limit=12):
        rows = []
        cov = getattr(self, 'cov', None)
        if cov is not None and getattr(cov, 'loaded', False):
            # function_rows preserves bank identity, unlike legacy frontier tuples.
            rows = [dict(core=r['core_id'], bank=r['bank'], entry=r['entry'],
                         end=r['end'], name=r['name'], observed=r['entered'],
                         frontier_callers=r['frontier_callers'], size=r['size'])
                    for r in cov.function_rows() if not r['name'].startswith(('FUN_', 'sub_'))]
        else:
            entries = getattr(self, '_sa_func_entries', None) or []
            ends = getattr(self, '_sa_func_ends', None) or []
            names = getattr(self, '_sa_func_names', None) or []
            seen = getattr(self, '_sa_entered_funcs', set())
            rows = [dict(core='sa', bank=0, entry=e, end=end, name=name,
                         observed=e in seen, frontier_callers=0, size=end-e)
                    for e, end, name in zip(entries, ends, names)
                    if not name.startswith(('FUN_', 'sub_'))]
        def rank(r):
            tid = 't' + digest([r['core'], r['bank'], r['entry']])[:20]
            old = self.learning.targets.get(tid, {})
            return (r['observed'], old.get('offered', 0), -r['frontier_callers'], -r['size'])
        rows.sort(key=rank)
        # Fair interleaving prevents a large core from filling the whole prompt.
        groups = OrderedDict()
        for r in rows:
            groups.setdefault(r['core'], deque()).append(r)
        selected = []
        while groups and len(selected) < limit:
            for core in list(groups):
                selected.append(groups[core].popleft())
                if not groups[core]:
                    del groups[core]
                if len(selected) == limit:
                    break
        for r in selected:
            r['caller_commands'] = []
            if cov is not None and r['bank'] == 0:
                cm = cov.cores.get(r['core'])
                callers = [caller for caller, callees in cm.callees.items() if r['entry'] in callees]
                commands = set()
                for caller in callers:
                    commands.update(self.learning.function_commands.get(f"{r['core']}:0:{caller}", []))
                r['caller_commands'] = sorted(commands)[:8]
        return [self.learning.target(r) for r in selected]

    def _llm_build_request(self, task):
        built = super()._llm_build_request(task)
        if built is None or not self.learning.enabled:
            return built
        options = self.learning.options
        if not (options['evidence'] or (task == 'sequences' and options['preserve_setup'])
                or (task == 'new_group_seeds' and options['generators'])):
            return built
        ids = self._learning_candidates() if options['evidence'] else []
        ctx = dict(getattr(self, '_llm_pending_ctx', None) or {})
        ctx['learning_targets'] = ids
        ctx['learning_task'] = task
        setups = {}
        if task == 'sequences' and self.learning.options['preserve_setup']:
            for s in self.corpus:
                meta = getattr(s, 'learning_meta', {}) or {}
                if hasattr(s, 'commands') and meta.get('setup_successes', 0) > 0:
                    setup = meta.get('successful_setup', [])
                    if not setup:
                        continue
                    if sum(len(x.get('data_hex', '')) for x in setup) > 8192:
                        continue
                    sid = 's' + digest(setup)[:20]
                    setups[sid] = setup
                    if len(setups) == 3:
                        break
        ctx['learning_setups'] = setups
        self._llm_pending_ctx = ctx
        evidence = []
        for tid in ids:
            target = self.learning.targets[tid]
            recent = [{k: v for k, v in r.items() if k != 'state_context'} for r in target['recent'][-3:]]
            evidence.append(dict(target, recent=recent))
        extra = '\n\nv10.2 execution evidence (PC observation is NOT execution frequency):\n'
        extra += json.dumps(evidence, ensure_ascii=False)
        extra += ('\nYou may attach target_id from this request to each seed, sequence, or generator. '
                  'An unobserved target is not proof that code did not execute. '
                  'Keep hypotheses separate from measured dependencies. Telemetry changes alone '
                  'are not bugs or rewards. Existing transport guards still apply.\n')
        if task == 'sequences':
            extra += ('Successful setup templates: ' + json.dumps(setups) + '\n'
                      'To preserve one, return a sequence with setup_id and commands containing '
                      'ONE new final trigger; the host prepends the exact setup. Otherwise return '
                      'a full setup->trigger sequence. The final command is the trigger. Optional '
                      'preserve_fields:["cdw10","cdw11","data"] locks named fields of the '
                      'trigger to its original values during protected replay; use this for explicit '
                      'dependencies. Supported names are CDW fields, data, nsid_override and '
                      'data_len_override. Dependency declarations are hypotheses until measured.\n')
        if task == 'new_group_seeds' and self.learning.options['generators']:
            feedback = [dict(generator_id=gid, rule=g['rule'], executions=g['executions'],
                             new_coverage=g['new_coverage'], observed_keys=len(g['coverage']),
                             coverage_truncated=g['coverage_truncated'])
                        for gid, g in list(self.learning.generators.items())[-3:]]
            extra += 'Retained generator feedback: ' + json.dumps(feedback) + '\n'
            extra += ('Optional top-level generators array (at most 2). Each rule has '
                      'base:{command,cdw10,...}, values:[integer,...] (at most '
                      f'{self.learning.options["max_variants"]}), '
                      'record:[{width:1|2|4|8,value:integer|{param:true,add:integer}}], '
                      'repeat:integer|{param:true,add:integer}, '
                      'bindings:[{field:"cdw10",lo:0,bits:8,value:{param:true,add:-1}}]. '
                      'Records are little endian. Optional break_length:integer deliberately sets '
                      'host data_len=payload length+delta; this is fault injection, not a safety claim. '
                      'Use bindings to preserve count/CDW relationships; choose one relationship to '
                      'vary. No executable code. Generator variants share the seed budget.\n')
        return built[0] + '\nThe v10.2 JSON extensions in the user prompt are supported.', built[1] + extra

    def _learning_submitted(self, task, system, user, ctx):
        if not self.learning.enabled:
            return
        self.learning.submitted(task, (ctx or {}).get('learning_targets', []), len(system) + len(user))
        if self.learning.baseline is None:
            self._learning_baseline()
        self._learning_save()

    def _learning_baseline(self, phase='first_request'):
        if not self.learning.enabled:
            return
        config = vars(self.config)
        corpus = [([seed_item(x) for x in s.commands] if hasattr(s, 'commands') else seed_item(s))
                  for s in self.corpus]
        self.learning.baseline = dict(version=self.VERSION, phase=phase, kernel=platform.release(),
                                     sampling_config_sha256=digest(json.loads(json.dumps(config, default=str))),
                                     state_snapshot=deepcopy(getattr(self, '_state_snap_prev', {}) or {}),
                                     config=json.loads(json.dumps(config, default=str)),
                                     corpus_sha256=digest(corpus), corpus_size=len(corpus),
                                     device_info=deepcopy(getattr(self, '_llm_device_info', {})),
                                     sampler=type(self.sampler).__name__,
                                     initial_state='not assumed reset; see campaign state telemetry')
        cov = getattr(self, 'cov', None)
        if cov is not None:
            self.learning.baseline['elf_hashes'] = {str(k): v.elf_sha256 for k, v in cov.cores.items()}

    def _learning_meta_for(self, seed):
        meta = getattr(seed, 'learning_meta', {}) or {}
        if not meta:
            meta = getattr(getattr(self, '_credit_seed', None), 'learning_meta', {}) or {}
        return dict(meta)

    def _llm_seed_sig(self, seed):
        signature = super()._llm_seed_sig(seed)
        if not self.learning.enabled:
            return signature
        return signature + (seed.opcode_override, seed.nsid_override,
                            seed.force_admin, seed.data_len_override)

    def _llm_make_seed(self, item, seed_class, why=None):
        seed = super()._llm_make_seed(item, seed_class, why)
        if seed is None or not self.learning.enabled:
            return seed
        tid = item.get('target_id')
        allowed = self._learning_apply_ctx.get('learning_targets', [])
        meta = {'target_id': tid if tid in allowed else None,
                'generator_id': item.get('_generator_id'),
                'request_id': self._learning_apply_ctx.get('request_id'),
                'preserve_fields': item.get('_preserve_fields', [])}
        seed.learning_meta = meta
        if 'data_len' in item:
            try:
                seed.data_len_override = checked_int(item['data_len'], 0, self._learning_max_bytes, 'data_len')
            except ValueError as exc:
                if why is not None:
                    why.append(str(exc))
                return None
        return seed

    def _llm_apply_result(self, res):
        if not self.learning.enabled:
            return super()._llm_apply_result(res)
        task = str(res.get('task', 'unknown'))
        st = self.learning._task(task)
        st['response_chars'] += len(res.get('raw') or '')
        st['llm_seconds'] += max(0.0, float(res.get('llm_seconds', 0)))
        if res.get('error') or self.executions - res.get('submitted_at', 0) > self._learning_stale:
            return super()._llm_apply_result(res)
        data = self._learning_parse(res.get('raw'))
        if not isinstance(data, dict):
            return super()._llm_apply_result(res)
        ctx = dict(res.get('ctx') or {})
        ctx['request_id'] = res.get('req_id')
        self._learning_apply_ctx = ctx
        self._learning_original_response = res
        before = {id(s) for s in self.corpus}
        try:
            # Normalize malformed containers before the legacy apply loop.
            for key in ('seeds', 'sequences', 'evaluations', 'generators'):
                if not isinstance(data.get(key, []), list):
                    self.learning.errors.append(f'{key}: expected array')
                    data[key] = []
            data['seeds'] = data.get('seeds', [])[:self._learning_max_seeds]
            for item in data['seeds']:
                if isinstance(item, dict):
                    item.pop('_generator_id', None)
                    item.pop('_preserve_fields', None)
            for sq in data.get('sequences', [])[:self._learning_max_seqs]:
                if not isinstance(sq, dict):
                    continue
                locks = sq.get('preserve_fields', [])
                if (not isinstance(locks, list) or len(locks) > 12
                        or any(not isinstance(k, str) or k not in (*CDWS, 'data', 'nsid_override',
                                                                   'data_len_override') for k in locks)):
                    sq['commands'] = []
                    self.learning.errors.append('invalid preserve_fields')
                    continue
                if sq.get('setup_id') is not None:
                    setup = (ctx.get('learning_setups', {}).get(sq['setup_id'])
                             if isinstance(sq['setup_id'], str) else None)
                    trigger = sq.get('commands')
                    if setup is None or not isinstance(trigger, list) or len(trigger) != 1:
                        sq['commands'] = []
                        self.learning.errors.append('unknown setup_id or trigger count != 1')
                        continue
                    sq['commands'] = deepcopy(setup) + trigger
                for item in sq.get('commands', []) if isinstance(sq.get('commands'), list) else []:
                    if isinstance(item, dict):
                        item['target_id'] = sq.get('target_id')
                        item['_preserve_fields'] = list(locks)
                        item.pop('_generator_id', None)
            if self.learning.options['generators']:
                for rule in data.get('generators', [])[:2]:
                    try:
                        gid, variants = compile_recipe(rule, self._learning_max_bytes,
                                                       self.learning.options['max_variants'])
                        if gid not in self.learning.generators:
                            if len(self.learning.generators) >= self.learning.options['max_generators']:
                                raise ValueError('generator capacity reached; existing rules retained')
                            self.learning.generators[gid] = dict(rule=deepcopy(rule), executions=0,
                                                                new_coverage=0, coverage=set(),
                                                                coverage_truncated=False)
                        room = self._learning_max_seeds - len(data['seeds'])
                        data['seeds'].extend(variants[:room])
                        self.learning.counts['generator_variants_budgeted_out'] += max(0, len(variants)-room)
                    except (ValueError, TypeError, OverflowError) as exc:
                        self.learning.errors.append(str(exc))
                        self.learning.counts['generator_rejected'] += 1
            for item in data.get('seeds', []) + data.get('sequences', [])[:self._learning_max_seqs]:
                if isinstance(item, dict):
                    tid = item.get('target_id')
                    if isinstance(tid, str) and tid in ctx.get('learning_targets', []) and tid in self.learning.targets:
                        self.learning.targets[tid]['selected'] += 1
            prepared = dict(res, raw=json.dumps(data))
            super()._llm_apply_result(prepared)
            accepted = []
            for seed in self.corpus:
                if id(seed) in before or getattr(seed, 'prov_id', None) is None:
                    continue
                meta = (getattr(seed.commands[-1], 'learning_meta', {}) if hasattr(seed, 'commands')
                        else getattr(seed, 'learning_meta', {})) or {}
                seed.learning_meta = dict(meta)
                self.learning.register(seed.prov_id, task, meta)
                accepted.append(seed.prov_id)
            workload = getattr(self, '_pending_workload', None)
            if workload and workload.get('prov_id') is not None:
                if workload['prov_id'] not in self.learning.proposals:
                    self.learning.register(workload['prov_id'], 'io_patterns', {})
                    accepted.append(workload['prov_id'])
            for pid in accepted:
                if pid not in self.learning.proposals:
                    continue
                self.learning.proposals[pid]['llm_cost_share'] = (
                    max(0.0, float(res.get('llm_seconds', 0))) / max(1, len(accepted)))
        finally:
            self._learning_apply_ctx = {}
            self._learning_original_response = None
            self._learning_save()

    def _llm_archive(self, res, data=None, added_s=None, added_q=None):
        original = getattr(self, '_learning_original_response', None)
        return super()._llm_archive(original or res, data, added_s, added_q)

    def _proposal_write(self, rec):
        if self.learning.enabled:
            rec = dict(rec, request_id=self._learning_apply_ctx.get('request_id'))
        return super()._proposal_write(rec)

    def _send_nvme_command(self, data, seed, *args, **kwargs):
        started = time.monotonic()
        try:
            return super()._send_nvme_command(data, seed, *args, **kwargs)
        finally:
            self._learning_last_send = (seed, time.monotonic() - started)

    def _stop_sampling_checked(self, context='command'):
        err = getattr(self.sampler, 'openocd_error', None)
        had_error = bool(err and err.is_set())
        result = super()._stop_sampling_checked(context)
        reason = getattr(self.sampler, '_stopped_reason', '')
        self._learning_window_valid = bool(result[1] and not had_error
                                           and not getattr(self, '_learning_window_failed', False)
                                           and reason not in ('transport', 'pin_fail', 'openocd_error'))
        if (not result[1] and self._learning_last_send is not None
                and context.startswith(('command:', 'calibration:', 'workload:', 'replay:'))):
            seed, _ = self._learning_last_send
            self._learning_observe(seed, getattr(self, '_last_nvme_status', None),
                                   None, set(), 0, 'sampling_failure', False)
        return result

    def _learning_observe(self, seed, status, rc, keys, new_count, source, seq_member):
        if not self.learning.enabled:
            return
        parent = getattr(self, '_credit_seed', None)
        pid = getattr(seed, 'prov_id', None)
        if pid is None:
            pid = getattr(parent, 'prov_id', None)
        wire = dict(getattr(self, '_last_wire', None) or {})
        seconds = self._learning_last_send[1] if self._learning_last_send else 0.0
        observable = bool(keys) and self._learning_window_valid
        scopes = {('sa', 0)} if keys else set()
        submitted = 'completion' if status is not None else 'unknown'
        if rc == self.RC_SKIP:
            submitted, observable = 'guard_skip', False
        input_signature = digest([seed.cmd.name, [getattr(seed, k) for k in CDWS],
                                  wire, hashlib.sha256(seed.data).hexdigest()])
        state = self._learning_sequence
        boundary = not seq_member or state is None or state['index'] == state['length'] - 1
        row = dict(exec=self.executions, attempt_id=self.learning.counts['attempts'] + 1,
                   input_signature=input_signature, evaluation_boundary=boundary, prov_id=pid, command=seed.cmd.name,
                   cdw={k: getattr(seed, k) for k in CDWS}, wire=wire,
                   status=status, rc=rc, submission=submitted, observable=observable,
                   new_coverage=new_count if observable and status is not None else 0,
                   device_seconds=seconds, source=source,
                   sampler_reason=getattr(self.sampler, '_stopped_reason', None),
                   state_context=dict(getattr(self, '_state_snap_prev', {}) or {}))
        observed = set()
        cov = getattr(self, 'cov', None)
        if cov is not None and getattr(cov, 'loaded', False):
            from riscv_cov import unpack
            functions = set()
            scopes = set()
            for key in keys:
                core, bank, addr = unpack(key)
                scopes.add((core, bank))
                cm = cov.cores.get(core)
                fn = cm.func_of(addr, bank) if cm else None
                if fn is not None:
                    functions.add((core, bank, fn))
            if observable and status is not None:
                for core, bank, fn in functions:
                    k = f'{core}:{bank}:{fn}'
                    known = self.learning.function_commands.setdefault(k, [])
                    label = f"{wire.get('queue')}:{wire.get('opcode')}:{seed.cmd.name}"
                    if label not in known and len(known) < 8:
                        known.append(label)
                    if len(self.learning.function_commands) > 4096:
                        self.learning.function_commands.popitem(last=False)
            for tid, target in self.learning.targets.items():
                if (target['core'], target['bank'], target['entry']) in functions:
                    observed.add(tid)
        else:
            pcs = sorted(keys)
            for tid, target in self.learning.targets.items():
                i = bisect.bisect_left(pcs, target['entry'])
                if i < len(pcs) and pcs[i] < target['end']:
                    observed.add(tid)
        row['sampled_scopes'] = [list(x) for x in sorted(scopes, key=str)]
        self.learning.observe(pid, row, observed, keys)
        state = self._learning_sequence
        if seq_member and state is not None:
            idx = state['index']
            state['executed'].append(seed_item(seed))
            if idx < state['length'] - 1:
                # A CQE success establishes the observable setup contract, not identical FTL state.
                if status != 0 or rc != 0:
                    state['setup_ok'] = False
                    if state['preserve']:
                        self._pending_seq_seeds = None
                        self._pending_seq_ctx = None
                        self._seq_sink = None
                        self.learning.counts['setup_aborted'] += 1
                        self._learning_sequence = None
            else:
                self.learning.counts['trigger_attempts'] += 1
                if state['setup_ok']:
                    self.learning.counts['trigger_after_successful_setup'] += 1
                    if observable and status is not None and state['preserve']:
                        base = state['base']
                        base.learning_meta = dict(getattr(base, 'learning_meta', {}) or {})
                        base.learning_meta['setup_successes'] = base.learning_meta.get('setup_successes', 0) + 1
                        base.learning_meta['successful_setup'] = deepcopy(state['executed'][:-1])
                self._learning_sequence = None

    def _learning_setup_active(self):
        state = self._learning_sequence
        return bool(state and state['preserve'])

    def _learning_seq_start(self, base):
        preserve = (self.learning.enabled and self.learning.options['preserve_setup']
                    and self.learning.rng.random() < self.learning.options['setup_preserve_ratio'])
        if not self.learning.enabled or not self.learning.options['preserve_setup']:
            self._learning_sequence = None
            return False
        self._learning_sequence = dict(base=base, index=0, length=len(base.commands),
                                       preserve=preserve, setup_ok=True, executed=[])
        self.learning.counts['sequence_starts'] += 1
        return preserve

    def _learning_seq_member(self, seed, first=False):
        state = self._learning_sequence
        if state is None:
            return self._mutate(seed)
        if not first:
            state['index'] += 1
        if state['preserve'] and state['index'] < state['length'] - 1:
            return replace(seed)
        result = self._mutate(seed)
        if state['preserve']:
            for key in (getattr(state['base'], 'learning_meta', {}) or {}).get('preserve_fields', []):
                setattr(result, key, deepcopy(getattr(seed, key)))
            # Preserve the established LBA/NLB/data dependency for known two-command chains.
            names = tuple(x.cmd.name for x in state['base'].commands)
            mode = self._CTX_SEQUENCES.get(names)
            if mode:
                setup = state['base'].commands[0]
                result.cdw10, result.cdw11 = setup.cdw10, setup.cdw11
                result.cdw12 = (result.cdw12 & ~0xffff) | (setup.cdw12 & 0xffff)
                result.nsid_override = setup.nsid_override
                if mode == 'full':
                    result.data = setup.data
                    result.data_len_override = setup.data_len_override
        return result

    def _learning_save(self):
        if not self.learning.enabled:
            return
        try:
            directory = Path(self.output_dir) / 'llm'
            directory.mkdir(parents=True, exist_ok=True)
            temporary = directory / 'learning_v10.2.json.tmp'
            temporary.write_text(json.dumps(self.learning.snapshot(), ensure_ascii=False, indent=2),
                                 encoding='utf-8')
            temporary.replace(directory / 'learning_v10.2.json')
        except (OSError, TypeError, ValueError) as exc:
            if not self._learning_save_warned:
                log.warning('[LLM/v10.2] learning snapshot save failed: %s', exc)
                self._learning_save_warned = True

    def run(self):
        try:
            return super().run()
        finally:
            self._learning_save()

    def _collect_stats(self):
        stats = super()._collect_stats()
        if self.learning.enabled:
            stats['llm_learning'] = dict(self.learning.counts)
            self._learning_save()
        return stats
