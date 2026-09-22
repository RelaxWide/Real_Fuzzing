"""평가 도구와 운영 검색이 공유하는 명령 태그 규칙. 벡터/본문은 변경하지 않는다."""
import re

CAPTION = re.compile(r'Figure\s+\d+\s*:\s*([^:\n]{1,140}?)\s*[-–—]\s*Command\s+Dword', re.I)


def canonical(s):
    return re.sub(r'[^a-z0-9]', '', s.lower())


def tags(content):
    # 평가에 사용한 규칙 그대로. 제목 없는 후속 청크로 추정 전파하지 않는다.
    return sorted(set(m.group(1).strip() for m in CAPTION.finditer(
        re.sub(r'\s+', ' ', content))))

# 전체명은 현재 CDWField에 없다. 아래는 사용자 평가에서 확인한 검색용 용어다.
# 미등록 약칭은 그대로 사용한다. 실행 스키마/valid 값/명령 가드는 변경하지 않는다.
FIELD_NAMES = {'OFI': 'Opcode or Feature Identifier', 'IFC': 'Interface',
               'PRHBT': 'Prohibit', 'SCP': 'Scope', 'SANACT': 'Sanitize Action',
               'FID': 'Feature Identifier', 'SEL': 'Select'}
COMMAND_NAMES = {'FWCommit': 'Firmware Commit', 'FWDownload': 'Firmware Image Download',
                 'FirmwareDownload': 'Firmware Image Download',
                 'CreateIOSQ': 'Create I/O Submission Queue', 'CreateIOCQ': 'Create I/O Completion Queue',
                 'DeleteIOSQ': 'Delete I/O Submission Queue', 'DeleteIOCQ': 'Delete I/O Completion Queue',
                 'NamespaceMgmt': 'Namespace Management', 'NamespaceAttach': 'Namespace Attachment',
                 'CapacityMgmt': 'Capacity Management', 'VirtMgmt': 'Virtualization Management'}
QUERY_VERSION = 'command-dword-fields-v1'


def spec_name(name):
    return COMMAND_NAMES.get(name, re.sub(r'(?<=[a-z0-9])(?=[A-Z])', ' ', name))


def enhanced_query(commands, schemas):
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
            if term in FIELD_NAMES:
                text += ' ' + FIELD_NAMES[term]
        parts.append(text + ' field encoding')
    return '\n'.join(parts) or None
