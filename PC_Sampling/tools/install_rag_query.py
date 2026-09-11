#!/usr/bin/env python3
"""Patch the existing online guide without replacing its connection settings.
Default: print a reviewable diff. --apply: back up guide and inline search support (no extra runtime file).
"""
import argparse
import ast
import difflib
from datetime import datetime
from pathlib import Path
import shutil


# Self-contained payload: this installer is the only migration file to copy.
INLINE_SOURCE = r'''# BEGIN INLINED RAG QUERY V1
import logging
import os

_rag_query_log = logging.getLogger(__name__)
_RAG_QUERY_START, _RAG_QUERY_END = '[RAG-QUERY]', '[/RAG-QUERY]'
_RAG_QUERY_TOKENIZER = None


class _rag_RagSearchError(RuntimeError):
    """Search failure which must not be represented as an empty successful search."""
    def __init__(self, message, retryable=False):
        super().__init__(message)
        self.retryable = retryable






def _rag_extract_query(prompt):
    if prompt.count(_RAG_QUERY_START) == 1 and prompt.count(_RAG_QUERY_END) == 1:
        start = prompt.index(_RAG_QUERY_START) + len(_RAG_QUERY_START)
        end = prompt.index(_RAG_QUERY_END)
        if end > start and prompt[start:end].strip():
            return prompt[start:end].strip(), 'marker'
    _rag_query_log.warning('[RAG query] missing/invalid marker; using token-bounded legacy query')
    return prompt, 'legacy'


def _rag_get_tokenizer():
    global _RAG_QUERY_TOKENIZER
    if _RAG_QUERY_TOKENIZER is None:
        try:
            from transformers import AutoTokenizer
        except ImportError as exc:
            raise _rag_RagSearchError('Install transformers and sentencepiece on the online LLM PC') from exc
        # Set a local path to avoid downloads on the online rig if desired.
        _RAG_QUERY_TOKENIZER = AutoTokenizer.from_pretrained(
            os.environ.get('RAG_TOKENIZER_PATH', 'BAAI/bge-m3'), trust_remote_code=False)
    return _RAG_QUERY_TOKENIZER


def _rag_prepare_query(prompt, tokenizer=None, budget=None):
    tokenizer = tokenizer if tokenizer is not None else _rag_get_tokenizer()
    budget = int(os.environ.get('RAG_QUERY_TOKEN_BUDGET', '1024')) if budget is None else budget
    if not isinstance(budget, int) or isinstance(budget, bool) or not 16 <= budget <= 8000:
        raise ValueError('RAG_QUERY_TOKEN_BUDGET must be 16..8000 (default 1024)')
    query, mode = _rag_extract_query(prompt)
    def count(text):
        return len(tokenizer.encode(text, add_special_tokens=True))
    before = count(query)
    if before > budget:
        ids = tokenizer.encode(query, add_special_tokens=False)
        take = max(0, budget - tokenizer.num_special_tokens_to_add(pair=False))
        # Decode/re-encode can differ. Verify the actual outgoing string too.
        while take > 0:
            clipped = tokenizer.decode(ids[:take], skip_special_tokens=True)
            if count(clipped) <= budget:
                query = clipped
                break
            take -= max(1, count(clipped) - budget)
        else:
            raise _rag_RagSearchError('RAG query cannot fit tokenizer budget')
    after = count(query)
    if not query.strip():
        raise _rag_RagSearchError('RAG query is empty')
    _rag_query_log.warning('[RAG query] mode=%s tokens=%d->%d budget=%d truncated=%s',
                mode, before, after, budget, before > after)
    return query


def _rag_extract_search_context(response):
    status = response.status_code
    try:
        result = response.json()
    except (ValueError, TypeError) as exc:
        raise _rag_RagSearchError(f'RAG search HTTP {status}: invalid JSON',
                             retryable=status == 429 or status >= 500) from exc
    if not isinstance(result, dict):
        raise _rag_RagSearchError(f'RAG search HTTP {status}: expected JSON object')
    code = result.get('error_code')
    if not 200 <= status < 300 or code or result.get('error'):
        # Preserve the reported cause without dumping document bodies or credentials.
        details = {key: result[key] for key in
                   ('error_code', 'query_tokens', 'max_tokens', 'embedding_model') if key in result}
        if isinstance(result.get('message'), str):
            details['message'] = result['message'][:500]
        raise _rag_RagSearchError(f'RAG search HTTP {status}: {details or "server error"}',
                             retryable=code != 'QUERY_TOKEN_LIMIT_EXCEEDED' and
                             (status == 429 or status >= 500))
    envelope = result.get('hits')
    if not isinstance(envelope, dict) or not isinstance(envelope.get('hits'), list):
        raise _rag_RagSearchError('RAG search malformed response: expected hits.hits array')
    hits = envelope['hits']
    if not hits:
        _rag_query_log.warning('[RAG query] no documents; generating with original prompt only')
        return ''
    first = hits[0]
    source = first.get('_source') if isinstance(first, dict) else None
    text = source.get('merge_title_content') if isinstance(source, dict) else None
    if not isinstance(text, str):
        raise _rag_RagSearchError('RAG search malformed hit: missing merge_title_content string')
    return text


def _rag_generate_with_rag(prompt, retrieve, generate, tokenizer=None):
    query = _rag_prepare_query(prompt, tokenizer=tokenizer)
    context = retrieve(query)
    suffix = '\n[참고 문서]\n' + context if context else '\n[RAG 문서 없음]'
    return generate(prompt + suffix)
# END INLINED RAG QUERY V1
'''

def patch_source(source):
    if '# BEGIN INLINED RAG QUERY V1' in source:
        compile(source, '<guide>', 'exec')
        return source
    legacy_import = 'from rag_query import generate_with_rag, extract_search_context'
    if legacy_import in source:
        # Migrate the previous split-file installation; keep original guide settings.
        import io
        import tokenize
        tokens = []
        for token in tokenize.generate_tokens(io.StringIO(source.replace(legacy_import, '')).readline):
            if token.type == tokenize.NAME and token.string in ('generate_with_rag', 'extract_search_context'):
                token = token._replace(string='_rag_' + token.string)
            tokens.append(token)
        source = tokenize.untokenize(tokens)
        return insert_support(source)

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
         f'    return _rag_extract_search_context({call.func.value.id})\n'),
        (generate.body[0].lineno - 1, generate.end_lineno,
         f'    return _rag_generate_with_rag({arg}, {retrieve.name}, generate_response)\n'),
    ]
    for start, end, replacement in sorted(edits, reverse=True):
        lines[start:end] = [replacement]
    return insert_support(''.join(lines))


def insert_support(source):
    tree = ast.parse(source)
    # Refuse to shadow an existing integration or user-defined helper.
    if any(isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name.startswith('_rag_')
           for n in tree.body):
        raise ValueError('Existing _rag_ helpers found; inspect guide before merging')
    anchor = 0
    for node in tree.body:
        if (isinstance(node, ast.Expr) and isinstance(node.value, (ast.Str, ast.Constant))
                and isinstance(getattr(node.value, 'value', getattr(node.value, 's', None)), str)):
            anchor = node.end_lineno
        elif isinstance(node, ast.ImportFrom) and node.module == '__future__':
            anchor = node.end_lineno
        else:
            break
    lines = source.splitlines(keepends=True)
    lines.insert(anchor, '\n' + INLINE_SOURCE + '\n')
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
    backup = args.guide.with_name(args.guide.name + datetime.now().strftime('.%Y%m%d_%H%M%S_%f.bak'))
    shutil.copy2(args.guide, backup)
    temporary = args.guide.with_suffix('.py.tmp')
    temporary.write_text(patched, encoding='utf-8')
    shutil.copymode(args.guide, temporary)
    temporary.replace(args.guide)
    print(f'Installed. Backup: {backup}. Restart srag_llm_service.py.')


if __name__ == '__main__':
    main()
