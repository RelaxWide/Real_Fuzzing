"""Search-only query contract. No network or tokenizer load at import time."""
import logging
import os

log = logging.getLogger(__name__)
START, END = '[RAG-QUERY]', '[/RAG-QUERY]'
TASKS = {
    'new_group_seeds': 'NVMe command field requirements, boundary conditions and error completion status.',
    'sequences': 'NVMe command prerequisites, setup and trigger sequences, state transitions and completion status.',
    'corpus_eval': 'NVMe command validity, field relationships and completion status interpretation.',
    'io_patterns': 'NVMe I/O workload patterns, write read deallocate interactions and controller state transitions.',
}
_TOKENIZER = None


class RagSearchError(RuntimeError):
    """Search failure which must not be represented as an empty successful search."""
    def __init__(self, message, retryable=False):
        super().__init__(message)
        self.retryable = retryable


def build_query(task, commands=(), targets=()):
    # These are identifiers from structured state, never payloads or raw evidence.
    def names(values):
        out = []
        for value in values:
            value = str(value).replace(START, '').replace(END, '')
            value = ' '.join(value.split())[:96]
            if value and value not in out:
                out.append(value)
            if len(out) == 3:
                break
        return ', '.join(out)
    lines = [TASKS.get(task, 'NVMe command requirements and firmware error handling.')]
    for label, values in [('Commands', commands), ('Target firmware functions', targets)]:
        value = names(values)
        if value:
            lines.append(f'{label}: {value}.')
    return '\n'.join(lines)


def query_block(task, commands=(), targets=()):
    return START + '\n' + build_query(task, commands, targets) + '\n' + END + '\n\n'


def extract_query(prompt):
    if prompt.count(START) == 1 and prompt.count(END) == 1:
        start = prompt.index(START) + len(START)
        end = prompt.index(END)
        if end > start and prompt[start:end].strip():
            return prompt[start:end].strip(), 'marker'
    log.warning('[RAG query] missing/invalid marker; using token-bounded legacy query')
    return prompt, 'legacy'


def get_tokenizer():
    global _TOKENIZER
    if _TOKENIZER is None:
        try:
            from transformers import AutoTokenizer
        except ImportError as exc:
            raise RagSearchError('Install transformers and sentencepiece on the online LLM PC') from exc
        # Set a local path to avoid downloads on the online rig if desired.
        _TOKENIZER = AutoTokenizer.from_pretrained(
            os.environ.get('RAG_TOKENIZER_PATH', 'BAAI/bge-m3'), trust_remote_code=False)
    return _TOKENIZER


def prepare_query(prompt, tokenizer=None, budget=None):
    tokenizer = tokenizer if tokenizer is not None else get_tokenizer()
    budget = int(os.environ.get('RAG_QUERY_TOKEN_BUDGET', '1024')) if budget is None else budget
    if not isinstance(budget, int) or isinstance(budget, bool) or not 16 <= budget <= 8000:
        raise ValueError('RAG_QUERY_TOKEN_BUDGET must be 16..8000 (default 1024)')
    query, mode = extract_query(prompt)
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
            raise RagSearchError('RAG query cannot fit tokenizer budget')
    after = count(query)
    if not query.strip():
        raise RagSearchError('RAG query is empty')
    log.warning('[RAG query] mode=%s tokens=%d->%d budget=%d truncated=%s',
                mode, before, after, budget, before > after)
    return query


def extract_search_context(response):
    status = response.status_code
    try:
        result = response.json()
    except (ValueError, TypeError) as exc:
        raise RagSearchError(f'RAG search HTTP {status}: invalid JSON',
                             retryable=status == 429 or status >= 500) from exc
    if not isinstance(result, dict):
        raise RagSearchError(f'RAG search HTTP {status}: expected JSON object')
    code = result.get('error_code')
    if not 200 <= status < 300 or code or result.get('error'):
        # Preserve the reported cause without dumping document bodies or credentials.
        details = {key: result[key] for key in
                   ('error_code', 'query_tokens', 'max_tokens', 'embedding_model') if key in result}
        if isinstance(result.get('message'), str):
            details['message'] = result['message'][:500]
        raise RagSearchError(f'RAG search HTTP {status}: {details or "server error"}',
                             retryable=code != 'QUERY_TOKEN_LIMIT_EXCEEDED' and
                             (status == 429 or status >= 500))
    envelope = result.get('hits')
    if not isinstance(envelope, dict) or not isinstance(envelope.get('hits'), list):
        raise RagSearchError('RAG search malformed response: expected hits.hits array')
    hits = envelope['hits']
    if not hits:
        log.warning('[RAG query] no documents; generating with original prompt only')
        return ''
    first = hits[0]
    source = first.get('_source') if isinstance(first, dict) else None
    text = source.get('merge_title_content') if isinstance(source, dict) else None
    if not isinstance(text, str):
        raise RagSearchError('RAG search malformed hit: missing merge_title_content string')
    return text


def generate_with_rag(prompt, retrieve, generate, tokenizer=None):
    query = prepare_query(prompt, tokenizer=tokenizer)
    context = retrieve(query)
    suffix = '\n[참고 문서]\n' + context if context else '\n[RAG 문서 없음]'
    return generate(prompt + suffix)
