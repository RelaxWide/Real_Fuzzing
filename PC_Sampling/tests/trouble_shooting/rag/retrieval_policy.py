"""평가 도구와 운영 검색이 공유하는 명령 태그 규칙. 벡터/본문은 변경하지 않는다."""
import re

CAPTION = re.compile(r'Figure\s+\d+\s*:\s*([^:\n]{1,140}?)\s*[-–—]\s*Command\s+Dword', re.I)


def canonical(s):
    return re.sub(r'[^a-z0-9]', '', s.lower())


def tags(content):
    # 평가에 사용한 규칙 그대로. 제목 없는 후속 청크로 추정 전파하지 않는다.
    return sorted(set(m.group(1).strip() for m in CAPTION.finditer(
        re.sub(r'\s+', ' ', content))))

COMMAND_NAMES = {'FWCommit': 'Firmware Commit', 'FWDownload': 'Firmware Image Download',
                 'FirmwareDownload': 'Firmware Image Download',
                 'CreateIOSQ': 'Create I/O Submission Queue', 'CreateIOCQ': 'Create I/O Completion Queue',
                 'DeleteIOSQ': 'Delete I/O Submission Queue', 'DeleteIOCQ': 'Delete I/O Completion Queue',
                 'NamespaceMgmt': 'Namespace Management', 'NamespaceAttach': 'Namespace Attachment',
                 'CapacityMgmt': 'Capacity Management', 'VirtMgmt': 'Virtualization Management'}
QUERY_VERSION = 'command-dword-fields-v2'


def spec_name(name):
    return COMMAND_NAMES.get(name, re.sub(r'(?<=[a-z0-9])(?=[A-Z])', ' ', name))


def enhanced_query(commands, schemas, definitions=None):
    """구조화 스키마에서 검색문을 생성한다. 미등록 필드 전체명은 추측하지 않는다.

    Dword 번호는 현행 스키마에서 읽는다. 선택 사항인 enum 이름은 추가하지
    않는다. 복수 명령은 각 템플릿을 개행으로 결합하며 최대 6개로 제한한다.
    """
    parts = []
    for command in list(dict.fromkeys(commands))[:6]:
        fields = schemas.get(command, [])
        words = sorted({f['word'] for f in fields})
        terms = list(dict.fromkeys(f['name'] for f in fields))
        text = spec_name(command) + ' command'
        if words:
            text += ' Command Dword ' + ' '.join(map(str, words))
        for term in terms:
            text += ' ' + term
            if definitions is None:
                full = None  # 원문 근거 없는 고정 전체명은 사용하지 않는다.
            else:
                candidates = {field_full_name(definitions, command, f['word'], term)
                              for f in fields if f['name'] == term}
                candidates.discard(None)
                full = next(iter(candidates)) if len(candidates) == 1 else None
            if full:
                text += ' ' + full
        parts.append(text + ' field encoding')
    return '\n'.join(parts) or None

EXTRACTION_VERSION = 'figure-field-definitions-v3'
# 필드 표의 줄 시작/비트 범위 다음에 오는 "전체명 (약칭):"만 채택한다.
# 일반 설명의 괄호나 임의 약칭을 전체명으로 추측하지 않는다.
_SECTION = re.compile(r'Figure\s+\d+\s*:\s*([^:\n]{1,140}?)\s*[-–—]\s*Command\s+Dword\s+(\d+)', re.I)
_FIELD = re.compile(r'(?m)^\s*(?:\|\s*)?(?:\d+(?::\d+)?\s*(?:\|\s*)?)?'
                    r'([A-Za-z][A-Za-z0-9 /-]{2,100}(?:\n[ \t]*[A-Za-z][A-Za-z0-9 /-]{0,60}){0,2})\s*\(([A-Z][A-Z0-9_]{1,15})\)\s*(?::|\||$)')


def extract_definitions(content, source_file, source_doc_id, permission_groups=()):
    """분할 전 원문의 명시적 정의를 읽는다. Figure가 없어도 공통 후보로 수집한다."""
    definitions = []
    # Markdown 굵게/코드 표시와 HTML 줄바꿈을 제거하되 표/줄 경계는 유지한다.
    content = re.sub(r'<br\s*/?>', '\n', content, flags=re.I)
    content = content.replace('**', '').replace('`', '')
    # 다른 Figure가 나오면 문맥을 종료하여 다음 표에 잘못 귀속하지 않는다.
    starts = list(re.finditer(r'(?i)Figure\s+\d+\s*:', content))
    for i, start in enumerate(starts):
        end = starts[i + 1].start() if i + 1 < len(starts) else len(content)
        section = content[start.start():end]
        heading = _SECTION.match(section)
        if not heading:
            continue
        for match in _FIELD.finditer(section[heading.end():]):
            name = ' '.join(match.group(1).split())
            definitions.append(dict(command=heading.group(1).strip(), dword=int(heading.group(2)),
                                    abbreviation=match.group(2), full_name=name,
                                    source_file=source_file, source_doc_id=source_doc_id,
                                    permission_groups=list(permission_groups),
                                    evidence=match.group(0).strip()[:240]))
    # 이어지는 원본 청크에는 Figure 제목이 없을 수 있다. 명시적 정의는 전부
    # 수집하되, 제목 없는 정의에 임의 명령/Dword를 붙이지 않는다.
    seen = {(r['abbreviation'], r['full_name']) for r in definitions}
    for match in _GLOBAL_FIELD.finditer(content):
        name = ' '.join(match.group(1).split())
        pair = (match.group(2), name)
        if pair in seen:
            continue
        seen.add(pair)
        definitions.append(dict(command=None, dword=None, abbreviation=pair[0], full_name=name,
                                source_file=source_file, source_doc_id=source_doc_id,
                                permission_groups=list(permission_groups), evidence=match.group(0)[:240]))
    # 스펙에서 괄호 약칭 없이 정의하는 필드도 수집한다. 이름 자체를 키로 사용.
    for name in ('CNS Specific Identifier', 'UUID Index'):
        for match in re.finditer(r'\b' + r'\s+'.join(map(re.escape, name.split())) + r'\s*:', content):
            definitions.append(dict(command=None, dword=None, abbreviation=name, full_name=name,
                                    source_file=source_file, source_doc_id=source_doc_id,
                                    permission_groups=list(permission_groups), evidence=match.group(0)))
    return definitions


# 문장 전체가 아니라 제목식 전체명과 명시적인 '(약칭):' 경계를 읽는다.
_GLOBAL_FIELD = re.compile(r'(?<![A-Za-z])([A-Z][A-Za-z0-9/-]*(?:[ \t\r\n]+(?:[A-Z][A-Za-z0-9/-]*|of|or|and|to|for|in|per)){0,12})'
                           r'[ \t\r\n]*\(([A-Z][A-Z0-9_]{1,15})\)[ \t]*:')


# 검색용 정규화만 수행. 전송 스키마와 bit/valid 값은 변경하지 않는다.
# 근거: NVMe Base 2.0d Identify CDW11/14 및 UUID Index Field.
# https://nvmexpress.org/wp-content/uploads/NVM-Express-Base-Specification-2.0d-2024.01.11-Ratified.pdf
FIELD_ALIASES = {('identify', 11, 'CNSSI'): 'CNS Specific Identifier'}
for _command in ('identify', 'getfeatures', 'setfeatures'):
    FIELD_ALIASES[(_command, 14, 'UIDX')] = 'UUID Index'
# 하나의 64-bit SLBA를 분리한 내부 이름. 임의의 _LO/_HI 필드를 일반화하지 않는다.
for _command in ('getlbastatus', 'read', 'write', 'compare', 'verify', 'writezeroes', 'writeuncorrectable'):
    FIELD_ALIASES[(_command, 10, 'SLBA_LO')] = 'SLBA'
    FIELD_ALIASES[(_command, 11, 'SLBA_HI')] = 'SLBA'


class DefinitionLookup(dict):
    """이름 조회와 진단에 같은 권한 필터/후보를 사용한다."""
    def __init__(self, names, rows):
        super().__init__((k, next(iter(v))) for k, v in names.items() if len(v) == 1)
        self.names = names
        self.rows = rows


def resolve_field(lookup, command, word, abbreviation):
    cmd = canonical(spec_name(command))
    normalized = FIELD_ALIASES.get((cmd, word, abbreviation), abbreviation)
    report = {'normalized_field': normalized, 'alias_applied': normalized != abbreviation}
    if (cmd, word, abbreviation) == ('lockdown', 10, 'UUID'):
        return dict(report, reason='schema_location_mismatch', full_name=None,
                    expected_field='UUID Index', expected_dword=14,
                    expected_bits='6:0', candidates=[], candidate_count=0)
    key = (cmd, word, normalized)
    global_key = (None, None, normalized)
    names = getattr(lookup, 'names', {})
    rows = getattr(lookup, 'rows', {}).get(normalized, [])
    # 정확한 문맥에 충돌이 있으면 전역 정의로 숨기지 않는다.
    if len(names.get(key, ())) > 1:
        reason, full = 'definition_conflict', None
    elif key in lookup:
        reason, full = 'matched_scoped', lookup[key]
    elif normalized == abbreviation and any(canonical(spec_name(r.get('command') or '')) == cmd
                                               and r.get('dword') != word for r in rows):
        reason, full = 'context_mismatch', None
    elif len(names.get(global_key, ())) > 1:
        reason, full = 'definition_conflict', None
    elif global_key in lookup:
        reason, full = 'matched_global', lookup[global_key]
    else:
        reason, full = ('context_mismatch' if rows else 'definition_missing'), None
    candidates = [dict((k, r.get(k)) for k in
                      ('command', 'dword', 'abbreviation', 'full_name', 'source_file', 'source_doc_id', 'evidence'))
                  for r in rows[:8]]
    return dict(report, reason=reason, full_name=full, candidates=candidates,
                candidate_count=len(rows), candidates_truncated=len(rows) > 8)


def field_full_name(lookup, command, word, abbreviation):
    return resolve_field(lookup, command, word, abbreviation)['full_name']


def definition_lookup(definitions, groups=None):
    """충돌 후보도 진단용으로 보존한다. 권한이 허용한 근거만 노출한다."""
    names, rows = {}, {}
    for row in definitions:
        if groups and not set(groups) & set(row.get('permission_groups') or []):
            continue
        key = (canonical(spec_name(row['command'])), row['dword'], row['abbreviation']) if row.get('command') else (None, None, row['abbreviation'])
        names.setdefault(key, set()).add(row['full_name'])
        names.setdefault((None, None, row['abbreviation']), set()).add(row['full_name'])
        group = rows.setdefault(row['abbreviation'], [])
        if row not in group:
            group.append(row)
    return DefinitionLookup(names, rows), sum(len(v) > 1 for v in names.values())


def cache_chunk_tags(chunks):
    """구형 인덱스는 최초 로드 때만 본문에서 추출. _ 키는 메모리 전용."""
    for row in chunks:
        if '_command_keys' not in row:
            covers = row.get('covers_commands')
            if not isinstance(covers, list) or any(not isinstance(c, str) for c in covers):
                covers = tags(row.get('content', ''))
            row['covers_commands'] = covers
            row['_command_keys'] = frozenset(canonical(c) for c in covers)


def expansion_report(commands, schemas, definitions, metadata_present):
    """추출 총수와 실제 요청의 필드 적용률을 구분한다. 0건도 숨기지 않는다."""
    matched, missing = [], []
    for command in commands:
        for field in schemas.get(command, []):
            row = {'command': command, 'dword': field['word'], 'abbreviation': field['name']}
            detail = resolve_field(definitions, command, field['word'], field['name'])
            if detail['full_name']:
                matched.append(dict(row, **detail))
            else:
                missing.append(dict(row, **detail))
    reasons = {}
    for row in missing:
        reasons[row['reason']] = reasons.get(row['reason'], 0) + 1
    return {'metadata_present': metadata_present, 'missing_reasons': reasons, 'matched_fields': matched,
            'missing_fields': missing, 'matched_count': len(matched), 'missing_count': len(missing)}
