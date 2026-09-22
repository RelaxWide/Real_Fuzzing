#!/usr/bin/env python3
"""Audit every fuzzer schema field against the pinned local index. No device/API access."""
import argparse
import ast
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from rag import rag_retrieval, vllm_client
from rag.retrieval_policy import definition_lookup, expansion_report


def read_schemas(path):
    # fuzzer를 import/초기화하지 않고 선언된 _F 필드의 문자/숫자만 읽는다.
    for node in ast.parse(path.read_text(encoding='utf-8')).body:
        if isinstance(node, ast.AnnAssign) and getattr(node.target, 'id', None) == 'CMD_SCHEMAS':
            return {key.value: [dict(zip(('name', 'word', 'hi', 'lo'),
                                        [ast.literal_eval(arg) for arg in field.args[:4]]))
                                for field in val.args[1].elts]
                    for key, val in zip(node.value.keys, node.value.values)}
    raise ValueError('CMD_SCHEMAS declaration not found')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT / 'fuzzer_config.json')
    parser.add_argument('--index-dir', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.output.exists():
            raise ValueError('Output exists; choose a new path')
        cfg = vllm_client._config({'config': json.loads(args.config.read_text(encoding='utf-8-sig'))})
        opts = rag_retrieval._settings(cfg)
        if args.index_dir:
            opts['index_dir'] = str(args.index_dir.resolve())
        manifest, _, _, version = rag_retrieval._load(opts['index_dir'])
        lookup, conflicts = definition_lookup(manifest.get('field_definitions') or [], opts['permission_groups'])
        schemas = read_schemas(ROOT / 'pc_sampling_fuzzer_v10.3.py')
        report = expansion_report(list(schemas), schemas, lookup, 'field_definitions' in manifest)
        report.update(index_version=version.name, command_count=len(schemas), conflicting_keys=conflicts,
                      field_definition_source=manifest.get('_field_definition_source'))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open('x', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(json.dumps({k: report[k] for k in ('command_count','matched_count','missing_count','missing_reasons')}, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
