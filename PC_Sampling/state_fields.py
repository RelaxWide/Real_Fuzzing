"""
NVMe State 관측 필드 정의 — pc_sampling_fuzzer_v7.0.py 전용

이 파일만 편집하면 state monitoring 대상 추가/삭제 가능.
퍼저 본체(pc_sampling_fuzzer_v7.0.py)는 수정하지 않아도 됨.

──────────────────────────────────────────────────────────────────────
필드 확인 방법
──────────────────────────────────────────────────────────────────────
source='smart':
    sudo nvme smart-log /dev/nvme0 --output-format=json | python3 -m json.tool
    → 출력된 JSON 최상위 키 이름을 'key'에 지정

source='vendor':
    sudo nvme get-log /dev/nvme0 --log-id=0xCA --log-len=512 | xxd
    → 관심 값의 바이트 오프셋과 길이를 'offset' / 'length'에 지정

──────────────────────────────────────────────────────────────────────
필드 공통 속성
──────────────────────────────────────────────────────────────────────
name    : 식별자 (stats 로그, coverage map 키로 사용)
source  : 'smart' | 'vendor'
weight  : delta score 가중치 — state corpus energy 계산에 반영
desc    : 설명 (로그 출력용)

source='smart' 추가 속성:
    key     : nvme smart-log JSON 최상위 키 이름

source='vendor' 추가 속성:
    lid     : log page ID (예: 0xCA)
    log_len : 읽을 바이트 수 (예: 512)
    offset  : 관심 값의 시작 바이트 오프셋
    length  : 값의 바이트 크기 (1 / 2 / 4 / 8)
    endian  : 'little' | 'big'
"""

STATE_FIELDS = [
    # ──────────────────────────────────────────────────────────────
    # SMART-log (source='smart')
    # 확인: sudo nvme smart-log /dev/nvme0 --output-format=json | python3 -m json.tool
    # ──────────────────────────────────────────────────────────────
    {
        'name':   'media_errors',
        'source': 'smart',
        'key':    'media_errors',
        'weight': 10.0,
        'desc':   'NAND ECC 에러 누적 — 에러 경로 진입 시 증가',
    },
    {
        'name':   'num_err_log_entries',
        'source': 'smart',
        'key':    'num_err_log_entries',
        'weight': 5.0,
        'desc':   '에러 로그 엔트리 수 — 새 에러 기록 시 증가',
    },
    {
        'name':   'critical_warning',
        'source': 'smart',
        'key':    'critical_warning',
        'weight': 20.0,
        'desc':   '헬스 비트마스크 — 헬스 상태 변화 시 변동',
    },

    # ──────────────────────────────────────────────────────────────
    # Vendor Log (source='vendor')
    # 확인: sudo nvme get-log /dev/nvme0 --log-id=0xCA --log-len=512 | xxd
    # 아래 항목의 주석을 해제하고 실제 offset / length로 수정
    # ──────────────────────────────────────────────────────────────
    # {
    #     'name':    'vendor_counter_0x10',
    #     'source':  'vendor',
    #     'lid':     0xCA,
    #     'log_len': 512,
    #     'offset':  0x10,
    #     'length':  4,
    #     'endian':  'little',
    #     'weight':  3.0,
    #     'desc':    '벤더 내부 카운터 (offset 0x10) — 용도 확인 필요',
    # },
]
