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

    # ══════════════════════════════════════════════════════════════════
    # Security Receive (SECP=0xFE, SPSP=0x3D, NSID=1, SIZE=4096)
    # 확인: nvme security-send /dev/nvme0 -n 1 -p 0xFE -s 0x3D -t 4 -f /tmp/dummy.bin
    #       nvme security-recv /dev/nvme0 -n 1 -p 0xFE -s 0x3D -x 4096 -t 4096 --raw-binary | xxd
    #
    # source='security_recv' 추가 속성:
    #   secp    : Security Protocol (SECP)
    #   spsp    : SP Specific (SPSP)
    #   nsid    : Namespace ID
    #   size    : Allocation/Transfer Length (bytes)
    #   offset  : 관심 값의 시작 바이트 오프셋
    #   length  : 값의 바이트 크기 (1 / 2 / 4 / 8)
    #   endian  : 'little' | 'big'
    # ══════════════════════════════════════════════════════════════════

    # ── 에러 지표 (weight 높음) ────────────────────────────────────────
    {
        'name':   'sec_dram_parity_errors',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 416, 'length': 2, 'endian': 'little',
        'weight': 10.0,
        'desc':   '[SecRecv 416h] Detected DRAM Parity error count',
    },
    {
        'name':   'sec_sram_parity_errors',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 418, 'length': 2, 'endian': 'little',
        'weight': 10.0,
        'desc':   '[SecRecv 418h] Detected SRAM Parity error count',
    },
    {
        'name':   'sec_uncorr_read_errors',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 400, 'length': 8, 'endian': 'little',
        'weight': 10.0,
        'desc':   '[SecRecv 400h] Uncorrectable read error count',
    },
    {
        'name':   'sec_bad_nand_blocks',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 384, 'length': 8, 'endian': 'little',
        'weight': 8.0,
        'desc':   '[SecRecv 384h] Bad User NAND Block count',
    },
    {
        'name':   'sec_e2e_corrections',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 408, 'length': 8, 'endian': 'little',
        'weight': 6.0,
        'desc':   '[SecRecv 408h] End to End Correction Counts',
    },
    {
        'name':   'sec_incomplete_shutdowns',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 192, 'length': 4, 'endian': 'little',
        'weight': 8.0,
        'desc':   '[SecRecv 192h] Incomplete Shutdowns',
    },
    {
        'name':   'sec_pcie_corr_errors',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 212, 'length': 8, 'endian': 'little',
        'weight': 6.0,
        'desc':   '[SecRecv 212h] PCIe Correctable Error Count',
    },
    {
        'name':   'sec_soft_ecc_errors',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 420, 'length': 8, 'endian': 'little',
        'weight': 5.0,
        'desc':   '[SecRecv 420h] Soft ECC error count',
    },

    # ── 리셋/이벤트 카운터 ────────────────────────────────────────────
    {
        'name':   'sec_ctrl_reset_count',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 655, 'length': 4, 'endian': 'little',
        'weight': 5.0,
        'desc':   '[SecRecv 655h] Controller Reset Count',
    },
    {
        'name':   'sec_ftl_spor_count',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 675, 'length': 4, 'endian': 'little',
        'weight': 5.0,
        'desc':   '[SecRecv 675h] FTL Internal SPOR Count',
    },
    {
        'name':   'sec_shn_count',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 635, 'length': 4, 'endian': 'little',
        'weight': 4.0,
        'desc':   '[SecRecv 635h] SHN Count',
    },
    {
        'name':   'sec_perst_count',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 639, 'length': 4, 'endian': 'little',
        'weight': 4.0,
        'desc':   '[SecRecv 639h] PERST Count',
    },
    {
        'name':   'sec_nssr_count',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 647, 'length': 4, 'endian': 'little',
        'weight': 4.0,
        'desc':   '[SecRecv 647h] NSSR Count',
    },
    {
        'name':   'sec_flr_count',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 651, 'length': 4, 'endian': 'little',
        'weight': 4.0,
        'desc':   '[SecRecv 651h] FLR Count',
    },

    # ── 마모 / 수명 지표 ──────────────────────────────────────────────
    {
        'name':   'sec_wear_level_count',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 234, 'length': 4, 'endian': 'little',
        'weight': 4.0,
        'desc':   '[SecRecv 234h] Wear Level Count',
    },
    {
        'name':   'sec_percent_used',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 238, 'length': 1, 'endian': 'little',
        'weight': 3.0,
        'desc':   '[SecRecv 238h] Percentage Used',
    },
    {
        'name':   'sec_free_blocks_pct',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 242, 'length': 1, 'endian': 'little',
        'weight': 3.0,
        'desc':   '[SecRecv 242h] % Free Blocks',
    },
    {
        'name':   'sec_sys_wear_level',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 239, 'length': 1, 'endian': 'little',
        'weight': 3.0,
        'desc':   '[SecRecv 239h] System Area Wear Level',
    },
    {
        'name':   'sec_system_max_ec',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 671, 'length': 4, 'endian': 'little',
        'weight': 3.0,
        'desc':   '[SecRecv 671h] System Max EC',
    },
    {
        'name':   'sec_read_reclaim',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 324, 'length': 8, 'endian': 'little',
        'weight': 4.0,
        'desc':   '[SecRecv 324h] Lifetime Read Reclaim Count',
    },
    {
        'name':   'sec_patrol_relocated',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 332, 'length': 8, 'endian': 'little',
        'weight': 4.0,
        'desc':   '[SecRecv 332h] Read Patrol relocated block counts',
    },
    {
        'name':   'sec_refresh_counts',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 340, 'length': 4, 'endian': 'little',
        'weight': 3.0,
        'desc':   '[SecRecv 340h] Refresh Counts (하위 4바이트)',
    },
    {
        'name':   'sec_endurance_estimate',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 252, 'length': 8, 'endian': 'little',
        'weight': 2.0,
        'desc':   '[SecRecv 252h] Endurance Estimate (하위 64-bit)',
    },

    # ── PS 카운터 ─────────────────────────────────────────────────────
    {
        'name':   'sec_ps3_count',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 202, 'length': 4, 'endian': 'little',
        'weight': 2.0,
        'desc':   '[SecRecv 202h] Accumulated PS3 Counter',
    },
    {
        'name':   'sec_ps4_count',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 206, 'length': 4, 'endian': 'little',
        'weight': 2.0,
        'desc':   '[SecRecv 206h] Accumulated PS4 Counter',
    },
    {
        'name':   'sec_short_power_on',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 210, 'length': 1, 'endian': 'little',
        'weight': 2.0,
        'desc':   '[SecRecv 210h] Counter of short power on',
    },
    {
        'name':   'sec_d3hot_count',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 631, 'length': 4, 'endian': 'little',
        'weight': 2.0,
        'desc':   '[SecRecv 631h] D3Hot count',
    },
    {
        'name':   'sec_pci_hotreset_count',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 643, 'length': 4, 'endian': 'little',
        'weight': 2.0,
        'desc':   '[SecRecv 643h] PCI HotReset count',
    },

    # ── I/O 볼륨 ──────────────────────────────────────────────────────
    {
        'name':   'sec_nand_written',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 128, 'length': 8, 'endian': 'little',
        'weight': 1.0,
        'desc':   '[SecRecv 128h] Total Data Written to NAND (하위 64-bit)',
    },
    {
        'name':   'sec_slc_written',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 144, 'length': 8, 'endian': 'little',
        'weight': 1.0,
        'desc':   '[SecRecv 144h] Total Data Written to SLC NAND (하위 64-bit)',
    },
    {
        'name':   'sec_host_active_idle',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 160, 'length': 4, 'endian': 'little',
        'weight': 1.5,
        'desc':   '[SecRecv 160h] Accumulated Host Active Idle Count',
    },
    {
        'name':   'sec_user_erase_counts',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 244, 'length': 8, 'endian': 'little',
        'weight': 1.5,
        'desc':   '[SecRecv 244h] User data erase counts',
    },
    {
        'name':   'sec_slc_pct_used',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 241, 'length': 1, 'endian': 'little',
        'weight': 1.5,
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
    {
        'name':   'sec_host_flush_cmds',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 659, 'length': 4, 'endian': 'little',
        'weight': 1.0,
        'desc':   '[SecRecv 659h] Host Flush Commands',
    },
    {
        'name':   'sec_set_feature_sv1',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 663, 'length': 4, 'endian': 'little',
        'weight': 1.0,
        'desc':   '[SecRecv 663h] Set Feature Commands (SV=1)',
    },
    {
        'name':   'sec_pel_save_count',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 667, 'length': 4, 'endian': 'little',
        'weight': 1.5,
        'desc':   '[SecRecv 667h] PEL Save Count',
    },
    {
        'name':   'sec_thermal_throttle',
        'source': 'security_recv',
        'secp': 0xFE, 'spsp': 0x3D, 'nsid': 1, 'size': 4096,
        'offset': 588, 'length': 4, 'endian': 'little',
        'weight': 4.0,
        'desc':   '[SecRecv 588h] Thermal throttling status (하위 4바이트)',
    },
]
