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
    #
    # Offset  Size  Field
    # 0x00     3    "LEN" ASCII (고정값, 모니터링 제외)
    # 0x03     1    Spec Version (35h = v1.44+, 고정값, 모니터링 제외)
    # 0x04   220    Reserved
    # 0xE0    16    Main NAND 기록량 (512B×1000 단위, 128-bit LE) → 하위 8B 사용
    # 0xF0     4    LCRC/ECRC 에러 누적 수
    # 0xF4    16    SLC Buffer 기록량 (512B×1000 단위, 128-bit LE) → 하위 8B 사용
    # 0x104    1    SLC Buffer Percentage Used
    # 0x105   10    FRU Number (ASCII, 고정값, 모니터링 제외)
    # 0x10F    8    Patrol Read에 의한 Relocated Block 수
    # 0x117    2    Average PE Cycles
    # 0x119    2    Max PE Cycles
    # 0x11B    2    Grown Bad Block 수
    # 0x11D    2    DRAM Parity 에러 수
    # 0x11F    2    SRAM Parity 에러 수
    # 0x121  223    Reserved
    # ══════════════════════════════════════════════════════════════════

    # ── 에러 지표 ─────────────────────────────────────────────────────
    {
        'name':    'df_dram_parity_errors',
        'source':  'vendor',
        'lid':     0xDF,
        'log_len': 512,
        'offset':  0x11D,
        'length':  2,
        'endian':  'little',
        'weight':  10.0,
        'desc':    '[DFh 0x11D] DRAM Parity 에러 누적 — 메모리 무결성 이상',
    },
    {
        'name':    'df_sram_parity_errors',
        'source':  'vendor',
        'lid':     0xDF,
        'log_len': 512,
        'offset':  0x11F,
        'length':  2,
        'endian':  'little',
        'weight':  10.0,
        'desc':    '[DFh 0x11F] SRAM Parity 에러 누적 — 캐시/버퍼 무결성 이상',
    },
    {
        'name':    'df_crc_errors',
        'source':  'vendor',
        'lid':     0xDF,
        'log_len': 512,
        'offset':  0xF0,
        'length':  4,
        'endian':  'little',
        'weight':  8.0,
        'desc':    '[DFh 0xF0] LCRC/ECRC 에러 누적 — 인터페이스 에러',
    },
    {
        'name':    'df_grown_bad_blocks',
        'source':  'vendor',
        'lid':     0xDF,
        'log_len': 512,
        'offset':  0x11B,
        'length':  2,
        'endian':  'little',
        'weight':  8.0,
        'desc':    '[DFh 0x11B] Grown Bad Block 수 — NAND 열화 지표',
    },

    # ── NAND 마모 지표 ─────────────────────────────────────────────────
    {
        'name':    'df_patrol_relocated',
        'source':  'vendor',
        'lid':     0xDF,
        'log_len': 512,
        'offset':  0x10F,
        'length':  8,
        'endian':  'little',
        'weight':  4.0,
        'desc':    '[DFh 0x10F] Patrol Read Relocated Block 수',
    },
    {
        'name':    'df_max_pe_cycles',
        'source':  'vendor',
        'lid':     0xDF,
        'log_len': 512,
        'offset':  0x119,
        'length':  2,
        'endian':  'little',
        'weight':  3.0,
        'desc':    '[DFh 0x119] Max PE Cycles — 최대 소거 횟수',
    },
    {
        'name':    'df_slc_percent_used',
        'source':  'vendor',
        'lid':     0xDF,
        'log_len': 512,
        'offset':  0x104,
        'length':  1,
        'endian':  'little',
        'weight':  3.0,
        'desc':    '[DFh 0x104] SLC Buffer Percentage Used',
    },
    {
        'name':    'df_avg_pe_cycles',
        'source':  'vendor',
        'lid':     0xDF,
        'log_len': 512,
        'offset':  0x117,
        'length':  2,
        'endian':  'little',
        'weight':  2.0,
        'desc':    '[DFh 0x117] Average PE Cycles — 평균 소거 횟수',
    },

    # ── I/O 볼륨 ──────────────────────────────────────────────────────
    {
        'name':    'df_nand_written',
        'source':  'vendor',
        'lid':     0xDF,
        'log_len': 512,
        'offset':  0xE0,
        'length':  8,
        'endian':  'little',
        'weight':  1.5,
        'desc':    '[DFh 0xE0] Main NAND 기록량 (512B×1000 단위, 하위 64-bit)',
    },
    {
        'name':    'df_slc_written',
        'source':  'vendor',
        'lid':     0xDF,
        'log_len': 512,
        'offset':  0xF4,
        'length':  8,
        'endian':  'little',
        'weight':  1.0,
        'desc':    '[DFh 0xF4] SLC Buffer 기록량 (512B×1000 단위, 하위 64-bit)',
    },
]
