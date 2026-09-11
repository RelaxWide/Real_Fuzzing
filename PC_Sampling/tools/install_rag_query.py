#!/usr/bin/env python3
"""Patch the existing online guide without replacing its connection settings.
Default: print a reviewable diff. --apply: back up guide and install helper.
"""
import argparse
import ast
import difflib
from datetime import datetime
from pathlib import Path
import shutil


def patch_source(source):
    if 'from rag_query import generate_with_rag, extract_search_context' in source:
        return source
    tree = ast.parse(source)
    functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    def choose(names):
        found = [functions[n] for n in names if n in functions]
        if len(found) != 1:
            raise ValueError('Expected exactly one of: ' + ', '.join(names))
        return found[0]
    retrieve = choose(('retrieve_from_rag', 'retreive_from_rag'))
    generate = choose(('generate_rag_response', 'generate_rag_responses'))
    if 'generate_response' not in functions:
        raise ValueError('Missing generate_response; inspect guide manually')
    if len(generate.args.args) != 1:
        raise ValueError('Expected single-argument RAG guide')
    # Only replace the known terminal response.json()/hits parsing pair.
    body = retrieve.body
    if len(body) < 2 or not isinstance(body[-1], ast.Return) or not isinstance(body[-2], ast.Assign):
        raise ValueError('Unexpected retrieval layout; no changes made')
    assignment, returned = body[-2], body[-1]
    call = assignment.value
    if (not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute)
            or call.func.attr != 'json' or not isinstance(call.func.value, ast.Name)
            or len(assignment.targets) != 1 or not isinstance(assignment.targets[0], ast.Name)):
        raise ValueError('Expected terminal result = response.json(); no changes made')
    result = assignment.targets[0].id
    expected = ast.parse(f"{result}['hits']['hits'][0]['_source']['merge_title_content']", mode='eval').body
    if ast.dump(returned.value) != ast.dump(expected):
        raise ValueError('Unexpected hit selection; inspect guide manually')
    lines = source.splitlines(keepends=True)
    arg = generate.args.args[0].arg
    edits = [
        (assignment.lineno - 1, returned.end_lineno,
         f'    return extract_search_context({call.func.value.id})\n'),
        (generate.body[0].lineno - 1, generate.end_lineno,
         f'    return generate_with_rag({arg}, {retrieve.name}, generate_response)\n'),
    ]
    for start, end, replacement in sorted(edits, reverse=True):
        lines[start:end] = [replacement]
    # Insert after docstring/future imports to preserve Python import rules.
    anchor = 0
    for node in tree.body:
        if (isinstance(node, ast.Expr) and isinstance(node.value, (ast.Str, ast.Constant))
                and isinstance(getattr(node.value, 'value', getattr(node.value, 's', None)), str)):
            anchor = node.end_lineno
        elif isinstance(node, ast.ImportFrom) and node.module == '__future__':
            anchor = node.end_lineno
        else:
            break
    lines.insert(anchor, '\nfrom rag_query import generate_with_rag, extract_search_context\n')
    patched = ''.join(lines)
    compile(patched, '<patched guide>', 'exec')
    return patched


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('guide', type=Path)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    source = args.guide.read_text(encoding='utf-8-sig')
    patched = patch_source(source)
    if not args.apply:
        print(''.join(difflib.unified_diff(source.splitlines(True), patched.splitlines(True),
                                         fromfile=str(args.guide), tofile=str(args.guide) + ' (patched)')))
        return
    helper = Path(__file__).resolve().parents[1] / 'rag' / 'rag_query.py'
    target = args.guide.parent / 'rag_query.py'
    # Validate/read all inputs before modifying the live guide.
    helper_source = helper.read_bytes()
    backup = args.guide.with_name(args.guide.name + datetime.now().strftime('.%Y%m%d_%H%M%S_%f.bak'))
    shutil.copy2(args.guide, backup)
    if target.exists():
        shutil.copy2(target, backup.with_name(backup.name + '.rag_query'))
    temporary = target.with_suffix('.py.tmp')
    temporary.write_bytes(helper_source)
    temporary.replace(target)
    temporary = args.guide.with_suffix('.py.tmp')
    temporary.write_text(patched, encoding='utf-8')
    shutil.copymode(args.guide, temporary)
    temporary.replace(args.guide)
    print(f'Installed. Backup: {backup}. Restart srag_llm_service.py.')


if __name__ == '__main__':
    main()
