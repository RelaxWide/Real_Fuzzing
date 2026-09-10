#!/usr/bin/env python3
"""Summarize independent v10.2 learning snapshots without accessing a device.

This reports observations and comparison conditions, not statistical significance.
"""
import argparse
import json
from pathlib import Path


def summarize(path):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    if data.get('schema_version') != 1:
        raise ValueError(f'{path}: unsupported learning schema')
    counts = data.get('counts', {})
    starts = counts.get('sequence_starts', 0)
    attempts = counts.get('attempts', 0)
    generators = data.get('generators', {})
    sets = {k: set(g['coverage']) for k, g in generators.items()}
    complements = {}
    for gid, coverage in sets.items():
        others = set().union(*(s for k, s in sets.items() if k != gid))
        complements[gid] = dict(observed_keys=len(coverage),
                                unique_to_retained_generator=len(coverage - others),
                                coverage_truncated=generators[gid].get('coverage_truncated', False))
    base = data.get('baseline') or {}
    return dict(path=str(path), options=data['options'], kernel=base.get('kernel'),
                config_sha256=base.get('sampling_config_sha256'),
                corpus_sha256=base.get('corpus_sha256'), elf_hashes=base.get('elf_hashes'),
                attempts=attempts, unobservable=counts.get('unobservable', 0),
                unobservable_ratio=counts.get('unobservable', 0)/attempts if attempts else None,
                sequence_starts=starts,
                trigger_after_setup_ratio=(counts.get('trigger_after_successful_setup', 0)/starts
                                           if starts else None),
                setup_aborted=counts.get('setup_aborted', 0),
                tasks=data.get('tasks', {}), generator_complements=complements,
                interpretation='Sampled observations only; absence is not proof of no execution. '
                               'Keep runs independent and compare their distributions. '
                               'Null baseline hashes mean comparison conditions were not captured.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshots', nargs='+', type=Path)
    args = parser.parse_args()
    print(json.dumps([summarize(p) for p in args.snapshots], ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
