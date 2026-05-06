"""
NVMe State 관측 필드 정의 — pc_sampling_fuzzer_v7.0.py 전용

이 파일만 편집하면 state monitoring 대상 추가/삭제 가능.
퍼저 본체(pc_sampling_fuzzer_v7.0.py)는 수정하지 않아도 됨.

──────────────────────────────────────────────────────────────────────
필드 확인 명령어
──────────────────────────────────────────────────────────────────────
source='smart'  (LID 02h):
    sudo nvme smart-log /dev/nvme0 --output-format=json | python3 -m json.tool
    → 출력된 JSON 최상위 키 이름을 'key'에 지정

source='vendor' (LID 01h / DFh 등):
    sudo nvme get-log /dev/nvme0 --log-id=0x01 --log-len=64 | xxd
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
    lid     : log page ID (예: 0x01)
    log_len : 읽을 바이트 수
    offset  : 관심 값의 시작 바이트 오프셋
    length  : 값의 바이트 크기 (1 / 2 / 4 / 8)
    endian  : 'little' | 'big'
"""

STATE_FIELDS = [

    # ══════════════════════════════════════════════════════════════════
    # LID 02h — SMART / Health Information  (NVM Spec §5.14.1.2)
    # 확인: sudo nvme smart-log /dev/nvme0 --output-format=json | python3 -m json.tool
    # ══════════════════════════════════════════════════════════════════

    # ── 에러 지표 (weight 높음) ────────────────────────────────────────
    {
        'name':   'critical_warning',
        'source': 'smart',
        'key':    'critical_warning',
        'weight': 20.0,
        'desc':   '[02h 00h] 헬스 비트마스크 (spare/temp/reliability/ro/volatile)',
    },
    {
        'name':   'media_errors',
        'source': 'smart',
        'key':    'media_errors',
        'weight': 10.0,
        'desc':   '[02h 92h] NAND ECC 비복구 에러 누적',
    },
    {
        'name':   'num_err_log_entries',
        'source': 'smart',
        'key':    'num_err_log_entries',
        'weight': 5.0,
        'desc':   '[02h 9Ch] 에러 로그 엔트리 수 (단조증가)',
    },
    {
        'name':   'unsafe_shutdowns',
        'source': 'smart',
        'key':    'unsafe_shutdowns',
        'weight': 8.0,
        'desc':   '[02h 72h] 비정상 종료(power-fail) 횟수',
    },

    # ── 수명 지표 ─────────────────────────────────────────────────────
    {
        'name':   'percent_used',
        'source': 'smart',
        'key':    'percent_used',
        'weight': 3.0,
        'desc':   '[02h 05h] 수명 소모율 (%) — 100 초과 가능',
    },
    {
        'name':   'avail_spare',
        'source': 'smart',
        'key':    'avail_spare',
        'weight': 2.0,
        'desc':   '[02h 03h] 여유 스페어 블록 비율 (%) — 감소 방향 주목',
    },

    # ── 온도 지표 ─────────────────────────────────────────────────────
    {
        'name':   'warning_temp_time',
        'source': 'smart',
        'key':    'warning_temp_time',
        'weight': 3.0,
        'desc':   '[02h A0h] Warning Composite Temperature 초과 누적 시간(분)',
    },
    {
        'name':   'critical_comp_time',
        'source': 'smart',
        'key':    'critical_comp_time',
        'weight': 5.0,
        'desc':   '[02h A4h] Critical Composite Temperature 초과 누적 시간(분)',
    },

    # ── I/O 볼륨 (퍼저 I/O 패턴 다양성 반영) ─────────────────────────
    {
        'name':   'data_units_written',
        'source': 'smart',
        'key':    'data_units_written',
        'weight': 1.0,
        'desc':   '[02h 48h] 호스트 기록량 (512B×1000 단위, 128-bit)',
    },
    {
        'name':   'data_units_read',
        'source': 'smart',
        'key':    'data_units_read',
        'weight': 1.0,
        'desc':   '[02h 32h] 호스트 읽기량 (512B×1000 단위, 128-bit)',
    },

    # ══════════════════════════════════════════════════════════════════
    # LID 01h — Error Information  (NVM Spec §5.14.1.1)
    # 확인: sudo nvme get-log /dev/nvme0 --log-id=0x01 --log-len=64 | xxd
    # 엔트리 1개 = 64B. 에러가 없으면 전체 0x00 패딩.
    # 최신 에러(entry[0]) 기준으로 읽음.
    #
    # Offset  Size  Field
    # 0x00     8    Error Count       — num_err_log_entries와 동일 값
    # 0x08     2    Submission Queue ID
    # 0x0A     2    Command ID
    # 0x0C     2    Status Field      ← DNR|More|SCT[2:0]|SC[7:0]
    # 0x0E     2    Parameter Error Location (byte+bit)
    # 0x10     8    LBA
    # 0x18     4    Namespace ID
    # 0x1C     1    Vendor Specific Info Available
    # 0x20     8    Command Specific Info
    # ══════════════════════════════════════════════════════════════════
    {
        'name':    'err_status_field',
        'source':  'vendor',
        'lid':     0x01,
        'log_len': 64,
        'offset':  0x0C,
        'length':  2,
        'endian':  'little',
        'weight':  4.0,
        'desc':    '[01h 0Ch] 최신 에러 Status Field — SCT/SC 변화로 에러 종류 구분',
    },
    {
        'name':    'err_param_location',
        'source':  'vendor',
        'lid':     0x01,
        'log_len': 64,
        'offset':  0x0E,
        'length':  2,
        'endian':  'little',
        'weight':  2.0,
        'desc':    '[01h 0Eh] Parameter Error Location — 에러 발생 CDW 위치',
    },

    # ══════════════════════════════════════════════════════════════════
    # LID DFh — Lenovo Drive Identification Page (512B, NSID 무시)
    # 확인: sudo nvme get-log /dev/nvme0 --log-id=0xDF --log-len=512 | xxd
    # offset 정보 수신 후 아래 주석 해제 및 수정
    # ══════════════════════════════════════════════════════════════════
    # {
    #     'name':    'lenovo_df_0x??',
    #     'source':  'vendor',
    #     'lid':     0xDF,
    #     'log_len': 512,
    #     'offset':  0x??,
    #     'length':  4,
    #     'endian':  'little',
    #     'weight':  3.0,
    #     'desc':    '[DFh 0x??] Lenovo Drive ID — offset 확인 필요',
    # },
]
