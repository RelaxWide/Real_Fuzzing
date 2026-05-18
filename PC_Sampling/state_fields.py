"""
NVMe State 관측 필드 정의 — pc_sampling_fuzzer_v7.x.py 전용

이 파일만 편집하면 state monitoring 대상 추가/삭제 가능.
퍼저 본체는 수정하지 않아도 됨.

──────────────────────────────────────────────────────────────────────
v7.6 정리 (55 → 25 필드)
──────────────────────────────────────────────────────────────────────
제외 사유:
  · 중복: df_* 가 sec_* 와 동일 지표 측정 (8 필드)
  · 위치/식별자: err_param_location (state 측정 아님)
  · 활동 카운터: nand_written/slc_written/host_*/user_erase/set_feature/
                pel_save (fuzzing 실행으로 인한 증가 → state 발산 신호 아님)
  · 리셋/이벤트 (4b 전체): fuzzer POR / PERST 등으로 직접 트리거
  · PS/Power (4d 전체): --pm 으로 fuzzer 직접 트리거
  · bad_nand_blocks, incomplete_shutdowns: 상대적으로 신호 약함 (제거)
  · sec_thermal_throttle: 제거

가중치 조정 원칙:
  · 메모리 무결성 (DRAM/SRAM parity) → 최강 (10)
  · NAND 마모/수명 (4c) → 최강~상 (10~4) — 가장 중요 카테고리
  · 인터페이스 에러 (CRC) → 중 (4)
  · fuzzing 정상 동작으로 변화 가능한 필드 → 하향 (1~2)

──────────────────────────────────────────────────────────────────────
필드 확인 명령어
──────────────────────────────────────────────────────────────────────
source='smart' (LID 02h):
    sudo nvme smart-log /dev/nvme0 --output-format=json | python3 -m json.tool

source='vendor' (LID 01h / DFh):
    sudo nvme get-log /dev/nvme0 --log-id=0x01 --log-len=64 | xxd

source='security_recv' (SECP=0xFE SPSP=0x3D):
    nvme security-recv /dev/nvme0 -n 1 -p 0xFE -s 0x3D -x 4096 -t 4096 --raw-binary | xxd

──────────────────────────────────────────────────────────────────────
필드 공통 속성
──────────────────────────────────────────────────────────────────────
name    : 식별자 (stats 로그, coverage map 키로 사용)
source  : 'smart' | 'vendor' | 'security_recv'
weight  : delta score 가중치 — state corpus energy 계산에 반영
desc    : 설명 (로그 출력용)
"""

STATE_FIELDS = [

    # ══════════════════════════════════════════════════════════════════
    # LID 02h — SMART / Health Information
    # ══════════════════════════════════════════════════════════════════
    {
        'name':   'critical_warning',
        'source': 'smart',
        'key':    'critical_warning',
        'weight': 2.0,
        'desc':   '[02h 00h] 헬스 비트마스크 (spare/temp/reliability/ro/volatile)',
    },
    {
        'name':   'media_errors',
        'source': 'smart',
        'key':    'media_errors',
        'weight': 2.0,
        'desc':   '[02h 92h] NAND ECC 비복구 에러 — WriteUncorrectable로도 증가 가능',
    },
    {
        'name':   'num_err_log_entries',
        'source': 'smart',
        'key':    'num_err_log_entries',
        'weight': 2.0,
        'desc':   '[02h 9Ch] 에러 로그 엔트리 수 — fuzz 에러마다 단조증가',
    },
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

    # ══════════════════════════════════════════════════════════════════
    # LID 01h — Error Information
    # 엔트리 1개 = 64B.
    # Offset 0x0C  Status Field (SCT/SC)
    # ══════════════════════════════════════════════════════════════════
    {
        'name':    'err_status_field',
        'source':  'vendor',
        'lid':     0x01,
        'log_len': 64,
        'offset':  0x0C,
        'length':  2,
        'endian':  'little',
        'weight':  1.0,
        'desc':    '[01h 0Ch] 최신 에러 SCT/SC — fuzz 에러마다 변화 (noisy)',
    },

    # ══════════════════════════════════════════════════════════════════
    # LID DFh — Lenovo Drive Identification Page (512B)
    # 중복 필드 제외 후 인터페이스/마모 unique 지표만 유지.
    # ══════════════════════════════════════════════════════════════════
    {
        'name':    'df_crc_errors',
        'source':  'vendor',
        'lid':     0xDF,
        'log_len': 512,
        'offset':  0xF0,
        'length':  4,
        'endian':  'little',
        'weight':  4.0,
        'desc':    '[DFh 0xF0] LCRC/ECRC 에러 누적 — 인터페이스 무결성',
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
        'desc':    '[DFh 0x119] Max PE Cycles — 최대 소거 횟수 (느린 변화)',
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

    # ══════════════════════════════════════════════════════════════════
    # Security Receive (SECP=0xFE, SPSP=0x3D, NSID=1, SIZE=4096)
    #
    # source='security_recv' 추가 속성:
    #   secp / spsp / nsid / size / offset / length / endian
    # ══════════════════════════════════════════════════════════════════

    # ── 4a. 메모리 무결성 / 에러 지표 ────────────────────────────────────
    {
        'name':   'sec_dram_parity_errors',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 416, 'length': 2, 'endian': 'little',
        'weight': 10.0,
        'desc':   '[SecRecv 416h] DRAM Parity error — 메모리 corruption',
    },
    {
        'name':   'sec_sram_parity_errors',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 418, 'length': 2, 'endian': 'little',
        'weight': 10.0,
        'desc':   '[SecRecv 418h] SRAM Parity error — 캐시/버퍼 무결성',
    },
    {
        'name':   'sec_uncorr_read_errors',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 400, 'length': 8, 'endian': 'little',
        'weight': 2.0,
        'desc':   '[SecRecv 400h] Uncorrectable read — WriteUncorrectable로도 증가',
    },
    {
        'name':   'sec_e2e_corrections',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 408, 'length': 8, 'endian': 'little',
        'weight': 2.0,
        'desc':   '[SecRecv 408h] End-to-End Correction Counts',
    },
    {
        'name':   'sec_pcie_corr_errors',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 212, 'length': 8, 'endian': 'little',
        'weight': 2.0,
        'desc':   '[SecRecv 212h] PCIe Correctable Error — PM 전환 시 정상 발생',
    },
    {
        'name':   'sec_soft_ecc_errors',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 420, 'length': 8, 'endian': 'little',
        'weight': 2.0,
        'desc':   '[SecRecv 420h] Soft ECC error — read 부하 시 흔함',
    },

    # ── 4c. NAND 마모 / 수명 (가장 중요 카테고리, 가중치 상향) ──────────
    {
        'name':   'sec_patrol_relocated',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 332, 'length': 8, 'endian': 'little',
        'weight': 10.0,
        'desc':   '[SecRecv 332h] Read Patrol relocated block — NAND 열화 직접 지표',
    },
    {
        'name':   'sec_sys_wear_level',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 239, 'length': 1, 'endian': 'little',
        'weight': 7.0,
        'desc':   '[SecRecv 239h] System Area Wear Level',
    },
    {
        'name':   'sec_system_max_ec',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 671, 'length': 4, 'endian': 'little',
        'weight': 7.0,
        'desc':   '[SecRecv 671h] System Max EC — 시스템 영역 최대 소거',
    },
    {
        'name':   'sec_endurance_estimate',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 252, 'length': 8, 'endian': 'little',
        'weight': 6.0,
        'desc':   '[SecRecv 252h] Endurance Estimate (하위 64-bit)',
    },
    {
        'name':   'sec_read_reclaim',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 324, 'length': 8, 'endian': 'little',
        'weight': 6.0,
        'desc':   '[SecRecv 324h] Lifetime Read Reclaim — read 부하 자동',
    },
    {
        'name':   'sec_free_blocks_pct',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 242, 'length': 1, 'endian': 'little',
        'weight': 5.0,
        'desc':   '[SecRecv 242h] % Free Blocks',
    },
    {
        'name':   'sec_wear_level_count',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 234, 'length': 4, 'endian': 'little',
        'weight': 4.0,
        'desc':   '[SecRecv 234h] Wear Level Count — write 부하 자동',
    },
    {
        'name':   'sec_refresh_counts',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 340, 'length': 4, 'endian': 'little',
        'weight': 4.0,
        'desc':   '[SecRecv 340h] Refresh Counts (하위 4 바이트) — 백그라운드 자동',
    },

    # ── 4e. I/O 볼륨 / 활동 (느린 변화 분만 유지) ──────────────────────
    {
        'name':   'sec_slc_pct_used',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 241, 'length': 1, 'endian': 'little',
        'weight': 1.0,
        'desc':   '[SecRecv 241h] Percentage Used in Static SLC',
    },
    {
        'name':   'sec_sys_data_pct_used',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 240, 'length': 1, 'endian': 'little',
        'weight': 1.5,
        'desc':   '[SecRecv 240h] System data % used',
    },
]
