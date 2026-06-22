#!/usr/bin/env python3
"""
PC Sampling 기반 SSD 펌웨어 Coverage-Guided Fuzzer v8.4

OpenOCD PCSR 비침습 샘플링 + nvme-cli passthru 기반 Coverage-Guided + State-Aware
Fuzzer. 제품별 target profile(PRODUCT_PROFILES)로 interface/코어/주소/덤프를 데이터 주도 설정.
지원: PM9M1(SWD·R8·3코어) / BM9H1(JTAG·R8·2코어) / P9(SWD·R5, J-Link halt 샘플러).

핵심 구성
- Coverage: OpenOCD telnet → PCSR (CoreBase+0x84). Ghidra BB 정보가 있으면 BB 기준.
- State:    NVMeStateMonitor delta → state corpus. CSFuzz 적응형 p.
- Mutation: Havoc/Splice + Deterministic + MOpt + Schema + Phase 1/2/3.
- Power:    PS0~4 × L0/L1/L1.2 × D0/D3 + S1/S2 perturb (PCIe bit / CLKREQ#).
- POR:      pmu_4_1.py 전원 사이클 → PCIe rescan → OpenOCD 재연결.
- Defect:   timeout 시 stuck PC 분석 → JLink dump → UFAS dump → PC 모니터링.

버전 요약 (자세한 내용은 git log / 각 버전 md 참조)
- v8.4: device-aware IO 워크로드 엔진 추가. fuzz 100 명령 사이에 rc=0 보장 Write/Read 100 명령
        블록을 주입(load-class 6 + structural 8 패턴)하여 SSD 내부 동작(GC/wear leveling/
        read disturb/SLC)을 의도적으로 자극. 워크로드를 정상 회계(source='workload')로 흘려
        every-100 state 캡처가 결과 state 변화를 state_corpus(C2)에 수확·replay. rc=0 경계는
        Identify(nsze/mdts/lba) 런타임 자동. config io_workload 섹션 + --no-io-workload.
- v8.3: 모든 사용자 설정값·경로를 fuzzer_config.json 으로 외부화. 모듈 로드 시 JSON 을 읽어
        같은 이름의 전역(FW_ADDR_*/PRODUCT_PROFILES/NVME_TIMEOUTS/mutation·power·paths 등)에
        주입 → FuzzConfig 기본값/argparse default 가 자동으로 JSON 값을 따름. 버전 비종속 공유
        파일이라 .py 복사해도 설정 재사용. --config PATH 로 교체. 동작은 v8.2 와 byte-동등(검증).
- v8.2: P9 profile 정리 — J-Link halt 에서 안 쓰는 OpenOCD/PCSR/UFAS 키
        (openocd_config/tcl_prefix/pcsr_addrs/power_addr/power_mask/ufas_ini) 제거.
        main() profile 읽기를 .get(기본값) 으로 관용화 → 제품이 N/A 키 생략 가능.
        PM9M1/BM9H1 동작 불변.
- v8.1: P9 전용 J-Link(pylink) halt 샘플러(JLinkHaltSampler) 추가. OpenOCD telnet halt 의
        소켓 desync(빈 reg pc → resume 누락 → R5 컨트롤러 wedge) 문제를 in-process pylink
        halt/register_read/JLINKARM_Go 로 대체. P9 sampler_type='jlink_halt'. PM9M1/BM9H1
        (PCSR) 경로는 무변경. pylink 미설치 호스트는 import 가드로 무영향(P9 선택 시에만 필요).
- v8.0: 제품 추가 P9(Cortex-R5·SWD). 모든 target-specific 값을 PRODUCT_PROFILES 한 곳으로
        일반화(interface/cfg/jlink_device/tcl_prefix/pcsr_addrs/power/DPIDR/addr_range/
        UFAS·JLink dump on-off). 신규 제품은 데이터만 추가. P9 는 UFAS·J-Link 덤프 불가 →
        둘 다 비활성, bring-up 값은 placeholder(P9_BRINGUP.md 참조).
- v7.8: `--unsupported-skip` (EngineErrInt 자동 감지 → power cycle 후 메인 루프 계속),
        `--no-jlink` (J-Link 없이 NVMe-only fuzz).
- v7.7: S1 PCIe config bit perturb + S2 CLKREQ# timing perturb (PM rotation 통합).
- v7.6: 시각화 (coverage_growth velocity, firmware_map gradient, csfuzz_dynamics).
- v7.5: SequenceSeed corpus + 2-pass favored cull + ctx 모드.
- v7.4: Phase 1/2/3 (NLB/MDTS, 64-bit LBA, builtin sequence).
- v7.3: _account_command 헬퍼, m2 정규화.
- v7.0: State-Aware (NVMeStateMonitor / dual interesting).
- v6.x: OpenOCD PCSR, JTAG 지원, Schema Mutation, PS3/PS4 idle slot.
"""

from __future__ import annotations

import socket
import struct
import time
import threading
import subprocess
import os
import sys
import shutil
import json
import hashlib
import random
import logging
import math
import re
from collections import defaultdict, deque
from typing import Set, List, Optional, Tuple, Dict, Union
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
# v8.3: state 관측 필드는 fuzzer_config.json 의 state_fields 섹션에서 제품별로 로드
# (STATE_FIELD_SETS, 아래 _CFG 로드 후 정의). state_fields.py 는 더 이상 import 하지 않음.
from enum import Enum, IntEnum
import contextlib
import bisect

# 시드 파일 import (같은 디렉토리의 nvme_seeds.py)
sys.path.insert(0, str(Path(__file__).parent))
from nvme_seeds import SEED_TEMPLATES as _DEFAULT_SEED_TEMPLATES

# pylink (J-Link Python SDK) — P9 의 JLinkHaltSampler 에서만 사용.
# 미설치 호스트(PM9M1/BM9H1 만 돌리는 경우)에서도 import 실패로 죽지 않도록 가드.
# 실제 사용 시점(JLinkHaltSampler.connect)에 None 체크로 안내 메시지 출력.
try:
    import pylink as _pylink
except Exception:
    _pylink = None

# 버전
FUZZER_VERSION = "8.5.0"

# ─────────────────────────────────────────────────────────────────────────
# USER CONFIGURATION  — 값은 모두 fuzzer_config.json 에서 로드한다 (v8.3).
#   이 .py 를 버전업으로 복사해도 fuzzer_config.json 은 그대로 재사용된다.
#   값을 바꾸려면 fuzzer_config.json 을 편집(코드 수정 불필요). --config PATH 로 교체 가능.
#   16진수는 "0x.." 문자열로 둬도 로더가 int 로 변환한다.
# ─────────────────────────────────────────────────────────────────────────

def _cfg_hexnorm(o):
    """JSON 값 재귀 정규화: '0x..' 문자열 → int. 그 외는 그대로."""
    if isinstance(o, str):
        s = o.strip()
        if s[:2].lower() == '0x':
            try:
                return int(s, 16)
            except ValueError:
                return o
        return o
    if isinstance(o, list):
        return [_cfg_hexnorm(x) for x in o]
    if isinstance(o, dict):
        return {k: _cfg_hexnorm(v) for k, v in o.items()}
    return o


def _early_config_path():
    """import 시점에 sys.argv 에서 --config 값을 미리 추출(argparse 보다 먼저 필요)."""
    a = sys.argv
    for i, tok in enumerate(a):
        if tok == '--config' and i + 1 < len(a):
            return a[i + 1]
        if tok.startswith('--config='):
            return tok.split('=', 1)[1]
    return None


def load_user_config(path=None):
    """fuzzer_config.json 로드 + hex 정규화. 없으면 명확한 fatal 종료."""
    _dir = Path(__file__).resolve().parent
    p = Path(path) if path else _dir / 'fuzzer_config.json'
    if not p.is_file():
        sys.exit(f"[FATAL] 설정 파일이 없습니다: {p}\n"
                 f"        fuzzer_config.json 을 fuzzer 와 같은 디렉토리에 두거나 "
                 f"--config PATH 로 지정하세요.")
    try:
        with open(p, encoding='utf-8') as _f:
            _raw = json.load(_f)
    except Exception as e:
        sys.exit(f"[FATAL] 설정 파일 파싱 실패({p}): {e}")
    return _cfg_hexnorm(_raw)


_CFG = load_user_config(_early_config_path())
_SCRIPT_DIR = str(Path(__file__).resolve().parent)


def _sect(name):
    try:
        return _CFG[name]
    except KeyError:
        sys.exit(f"[FATAL] fuzzer_config.json 에 '{name}' 섹션이 없습니다.")


_G  = _sect('globals')
_P  = _sect('paths')
_T  = _sect('timeouts')
_SA = _sect('sampling')
_DI = _sect('diagnose_idle_calibration')
_FZ = _sect('fuzzing')
_MU = _sect('mutation')
_PW = _sect('power')
_VI = _sect('visualization')
_RT = _sect('runtime_hw')
_ST = _sect('strategy')
# 제품별 state 관측 필드 세트 {"r8":[...], "p9":[...]}. 제품의 'state_fields' 키가 세트명을 가리킴.
STATE_FIELD_SETS = _sect('state_fields')
_DEFAULT_STATE_FIELDS = STATE_FIELD_SETS.get('r8', [])

# v8.4: IO 워크로드 엔진 설정 (io_workload 섹션). 섹션이 없어도 fatal 아님 — 기본값으로 비활성/동작.
#   fuzz 100 명령 사이에 rc=0 보장 Write/Read 100 명령 블록을 주입하여 SSD 내부 동작 자극.
_IW = _CFG.get('io_workload', {})
IO_WL_ENABLED        = bool(_IW.get('enabled', True))
IO_WL_BLOCK_SIZE     = int(_IW.get('block_size', 100))
IO_WL_FUZZ_GAP       = int(_IW.get('fuzz_gap', 100))
IO_WL_SELECTION      = str(_IW.get('selection', 'round_robin'))
IO_WL_MDTS_FALLBACK  = int(_IW.get('mdts_fallback_bytes', 262144))   # mdts=0(무제한) 시 전송 상한
IO_WL_WORKING_FRAC   = float(_IW.get('working_set_frac', 0.02))      # churn/rand 영역 = nsze 비율
IO_WL_HOT_WINDOW_B   = int(_IW.get('hot_window_bytes', 8 * 1024 * 1024))
IO_WL_GC_UNIT_B      = int(_IW.get('gc_unit_bytes', 1024 * 1024))
IO_WL_STRIDE_LBAS    = int(_IW.get('strided_period_lbas', 32))
IO_WL_RAND_BUF_MB    = int(_IW.get('rand_buf_mb', 8))                # 사전생성 랜덤 write 버퍼 크기
# 패턴 목록 (없으면 전체 기본). 순서 = round_robin 회전 순서.
_IW_DEFAULT_PATTERNS = [
    'seq_write', 'rand_write', 'overwrite_churn', 'hot_cold', 'read_disturb', 'mixed_rw',
    'pingpong_write', 'pingpong_read', 'subpage_rmw', 'single_lba_hammer',
    'strided_write', 'reverse_seq', 'boundary', 'bursty_mixed_size',
]
IO_WL_PATTERNS = list(_IW.get('patterns', _IW_DEFAULT_PATTERNS))

# 펌웨어 코드(.text) 영역 주소
FW_ADDR_START = _G['fw_addr_start']
FW_ADDR_END   = _G['fw_addr_end']

# OpenOCD / J-Link
JLINK_BINARY            = _G['jlink_binary']
JLINK_DEVICE            = _G['jlink_device']
OPENOCD_BINARY          = _G['openocd_binary']
OPENOCD_CONFIG          = _G['openocd_config']
OPENOCD_CONFIG_JTAG     = _G['openocd_config_jtag']
OPENOCD_TELNET_HOST     = _G['openocd_telnet_host']
OPENOCD_TELNET_PORT     = _G['openocd_telnet_port']
OPENOCD_STARTUP_TIMEOUT = _G['openocd_startup_timeout']

# PCSR 주소 (CoreBase + 0x084, APB-AP ap-num 0)
PCSR_CORE0      = _G['pcsr_core0']
PCSR_CORE1      = _G['pcsr_core1']
PCSR_CORE2      = _G['pcsr_core2']
PCSR_POWER_ADDR = _G['pcsr_power_addr']
PCSR_POWER_MASK = _G['pcsr_power_mask']
PCSR_ADDRS_SWD  = list(_G['pcsr_addrs_swd'])
PCSR_ADDRS_JTAG = list(_G['pcsr_addrs_jtag'])

# R8 SWD/JTAG DPIDR — PCSR 샘플 필터에서 "디버그 프로토콜 ID(=실코드 아님)" 제거용
R8_DPIDR_VALS = tuple(_G['r8_dpidr_vals'])

# ─────────────────────────────────────────────────────────────────────────
# 제품별 Target Profile (--product 옵션)  [v8.0]
#
# 모든 target-specific 값을 제품별 레코드 한 곳에 모은다. 새 제품 추가는
# 이 dict 에 레코드 하나만 추가하면 된다(코드 수정 불필요).
#
# 필드:
#   interface         : 'swd' | 'jtag'
#   openocd_config    : OpenOCD cfg 파일명 (스크립트 디렉토리 기준)
#   jlink_device      : JLinkExe -device 문자열
#   tcl_prefix        : OpenOCD cfg 가 만든 target object 접두사 (cfg 의 'r8'/'r5')
#   pcsr_addrs        : per-core DBGPCSR(샘플 PC) 주소 리스트 (코어 수 = len)
#   power_addr        : per-core debug power-up 레지스터 주소 (AXI-AP write). None=단계 생략
#   power_mask        : 위 레지스터의 코어별 enable 비트 마스크
#   invalid_pc_vals   : PCSR 필터에서 제외할 DPIDR/IDCODE 값들 (tuple)
#   fw_addr_start/end : 펌웨어 .text(coverage 필터) 주소 범위
#   enable_ufas       : crash 시 UFAS 펌웨어 덤프 수행 여부
#   ufas_ini          : UFAS --ini 파일명 (enable_ufas=True 일 때)
#   enable_jlink_dump : crash 시 J-Link 메모리 덤프 수행 여부
#
# placeholder(None)인 필드는 해당 제품 bring-up 시 실제 HW 값으로 채워야 한다.
# P9 처럼 None 이 남아 있으면 --product 선택 시 명확한 에러로 중단된다.
# ─────────────────────────────────────────────────────────────────────────
# v8.3: 제품 레코드는 fuzzer_config.json 의 "products" 에서 로드(hex 정규화 완료).
#   PM9M1/BM9H1=PCSR, P9=jlink_halt. 새 제품은 JSON 에 레코드 추가(코드 수정 불필요).
PRODUCT_PROFILES = _sect('products')

# 하위호환: 기존 코드/문서가 참조하던 이름 유지 (interface/cfg 2-필드 뷰)
# v8.2: openocd_config 는 OpenOCD 미사용 제품(J-Link halt, P9)에선 생략될 수 있어 .get 으로 관용.
PRODUCT_CONFIGS = {
    _name: {'interface': _p['interface'],
            'openocd_config': _p.get('openocd_config', OPENOCD_CONFIG)}
    for _name, _p in PRODUCT_PROFILES.items()
}

# NVMe 장치 설정
NVME_DEVICE    = _G['nvme_device']
NVME_NAMESPACE = _G['nvme_namespace']

# nvme_device 경로가 이미 namespace 형태(/dev/nvme0n1)인지 판단.
# WSL2 등 일부 환경에선 controller char device(/dev/nvme0)가 없고
# namespace block device 만 노출됨 → fallback 처리에 사용.
_NVME_NS_SUFFIX_RE = re.compile(r'n\d+$')

# NVMe 명령어 그룹별 타임아웃 (ms)
# 그룹에 속하지 않는 명령어는 모두 'command'에 해당
NVME_TIMEOUTS = dict(_T['nvme_timeouts'])   # command/format/flush/selftest_*/verify (ms)

# PC 샘플링 설정
SAMPLE_INTERVAL_US      = _SA['sample_interval_us']
MAX_SAMPLES_PER_RUN     = _SA['max_samples_per_run']
SATURATION_LIMIT        = _SA['saturation_limit']
GLOBAL_SATURATION_LIMIT = _SA['global_saturation_limit']
POST_CMD_DELAY_MS       = _SA['post_cmd_delay_ms']

# crash 후 커널이 controller reset 하지 않도록 큰 값. 정상 실행에는 영향 없음.
NVME_PASSTHRU_TIMEOUT_MS = _T['nvme_passthru_timeout_ms']   # 기본 30일
NVME_KERNEL_TIMEOUT_SEC  = _T['nvme_kernel_timeout_sec']    # 기본 30일

# 퍼징 설정
MAX_INPUT_LEN     = _FZ['max_input_len']
TOTAL_RUNTIME_SEC = _FZ['total_runtime_sec']
OUTPUT_DIR        = f'./output/pc_sampling_v{FUZZER_VERSION}/'   # 버전 종속 → 코드 유지
SEED_DIR          = _G['seed_dir']
RESUME_COVERAGE   = _G['resume_coverage']

# .py 파일과 같은 디렉토리에 있는 파일명만 입력하세요.
# 예: FW_BIN_FILENAME = 'FW.bin'
# None 또는 파일이 없으면 더미 1KB zeros 시드로 대체됩니다.
FW_BIN_FILENAME   = _P['fw_bin']
_FW_BIN_PATH = (
    str(Path(__file__).parent / FW_BIN_FILENAME)
    if FW_BIN_FILENAME else None
)

# Power Schedule 설정 (v4 추가)
MAX_ENERGY        = _FZ['max_energy']

RANDOM_GEN_RATIO  = _FZ['random_gen_ratio']
DET_BUDGET        = _FZ['det_budget']

EXCLUDED_OPCODES: List[int] = list(_FZ['excluded_opcodes'])

# admin-passthru 로 보내면 firmware 결함이 아니라 *호스트(kernel 소유) 전송로/프로토콜*만
# 깨져 self-inflicted timeout(가성 불량)을 만드는 admin opcode 집합.
#   0x00 Delete I/O SQ / 0x01 Create I/O SQ / 0x04 Delete I/O CQ / 0x05 Create I/O CQ
#        → kernel 이 소유한 I/O 큐를 삭제/오염 → 이후 io-passthru 무응답 timeout
#   0x0C Async Event Request → 이벤트 생길 때까지 무한 block → timeout
#   0x7C Doorbell Buffer Config → shadow doorbell 재설정으로 kernel I/O doorbell 깨짐 → hang
# admin-passthru 일 때만 차단. 같은 번호의 IO 명령(Flush 0x00/Write 0x01/WriteUncorrectable
# 0x04/Compare 0x05/Verify 0x0C)은 정상이므로 영향 없음.
BLOCKED_ADMIN_OPCODES = frozenset(_ST['blocked_admin_opcodes'])

# SecuritySend(0x81) 로 보내면 device 가 영구적으로 잠기거나 브릭되는 Security Protocol(SECP) 집합.
#   0x01~0x06 TCG (Opal/Pyrite/Enterprise/Ruby): Locking SP Activate, C_PIN(SID/Admin/User)
#        credential 설정, Read/WriteLockEnabled → 잠금(PSID revert 외 복구 불가).
#   0xEC ATA Device Server Password / 0xEF ATA Security: SET PASSWORD/LOCK/ERASE/FREEZE →
#        password 설정 시 host I/O 잠김(잠긴 채 굳어 가성 불량 + 후속 명령 전부 실패).
# SECP 단위 차단이 가장 안전(특정 SPSP 만 막아도 다른 잠금성 op 가 남음).
# SECP = CDW10[31:24]. SecuritySend 일 때만 차단(SecurityReceive 0x82 는 read-only 라 안전).
# 벤더(0xF0~0xFF)는 잠금 위험 있으나 fuzz 가치 높아 기본 미차단 — 필요 시 config 에 추가.
_SECURITY_SEND_OPCODE = 0x81
BLOCKED_SECURITY_SEND_SECP = frozenset(
    _ST.get('blocked_security_send_secp',
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xEC, 0xEF])
)

# Namespace Management/Attachment (admin). SEL = CDW10[3:0].
#   NamespaceManagement(0x0D): SEL 0=Create, 1=Delete. Delete 는 namespace 를 영구 파괴
#       → /dev/nvmeXnY 소멸 + 데이터 소멸 + 재생성 시 NSID 변경 위험 → 기본 차단(복구 어려움).
#   NamespaceAttachment(0x15): SEL 0=Attach, 1=Detach. Detach 는 namespace 보존(컨트롤러에서만
#       분리) → 실행 허용 후 즉시 재부착(auto re-attach)으로 fuzzing 대상 device 복구.
# admin 일 때만 적용(IO 0x0D=ReservationRegister/0x15=ReservationRelease 는 정상 — 번호만 겹침).
_NS_MGMT_OPCODE   = 0x0D
_NS_ATTACH_OPCODE = 0x15
BLOCK_NS_DELETE   = bool(_ST.get('block_ns_delete', True))
AUTO_REATTACH_NS  = bool(_ST.get('auto_reattach_ns', True))

OPCODE_MUT_PROB        = _MU['opcode']
NSID_MUT_PROB          = _MU['nsid']
ADMIN_SWAP_PROB        = _MU['admin_swap']
DATALEN_MUT_PROB       = _MU['datalen']
SCHEMA_MUT_PROB        = _MU['schema']
_PAGE_SIZE             = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096
LBA_PAIR_MUT_PROB      = _MU['lba_pair']
STRUCT_PAYLOAD_MUT_PROB= _MU['struct_payload']
SEQ_PROB               = _MU['seq_prob']
SEQ_MAX_PER_100        = _MU['seq_max_per_100']
MAX_SEQUENCE_CORPUS    = _FZ['max_sequence_corpus']
IO_ADMIN_RATIO         = _FZ['io_admin_ratio']
CORPUS_EPOCH_SIZE      = _FZ['corpus_epoch_size']

# Phase 3: builtin sequence 패턴 (명령 이름 리스트)
# 비활성 명령이 포함된 시퀀스는 _valid_seqs 필터로 자동 제외됨
# FWDownload→FWCommit: --all-commands 없이는 실행되지 않음
# v7.5+: 기본 모드(NVME_COMMANDS_DEFAULT) 활성 시퀀스 추가 — 기본 명령어만으로 시퀀스 작동.
BUILTIN_SEQUENCES: List[List[str]] = [list(s) for s in _ST['builtin_sequences']]

PM_ROTATE_INTERVAL = _PW['pm_rotate_interval']   # 이 횟수마다 PS 상태 전환

# 시각화 주기 갱신 간격 (executions 단위). 종료 시에도 항상 전체 그래프 생성됨.
GRAPH_REFRESH_INTERVAL = _VI['graph_refresh_interval']
# PS entry/exit latency 마진 — entry+exit 합산을 모든 timeout 에 가산
PS_ENTRY_EXIT_MARGIN_MS = _PW['ps_entry_exit_margin_ms']

# v7.7 PM perturbation 분기 (--pm 시 자동):
#   0.00~0.60 POWER_COMBO 30종 / 0.60~0.70 forced_idle PS3/PS4
#   0.70~0.90 S1 PCIe config bit perturb (변경 유지) / 0.90~1.00 S2 CLKREQ# timing

# S1 대상: (cap_name, offset_in_cap, bit_lo, bit_width, name, constraint)
#   cap_name: 'exp' | 'pm' | 'l1ss'
#   constraint: None / {'min','max'} / 'forced_one_shot' (D1/D2 → 50ms → D0)
# S1 대상 (cap_name, offset, bit_lo, bit_width, name, constraint) — fuzzer_config.json strategy 에서 로드.
PCIE_PM_FUZZ_TARGETS = [tuple(t) for t in _ST['pcie_pm_fuzz_targets']]

# CLKREQ# timing perturbation modes (S2) — strategy.clkreq_fuzz_modes 에서 로드. [(name, params_dict), ...]
CLKREQ_FUZZ_MODES = [(m[0], m[1]) for m in _ST['clkreq_fuzz_modes']]

class PCIeLState(IntEnum):
    L0   = 0   # ASPM 비활성 (항상 L0 active)
    L1   = 1   # ASPM L1 활성
    L1_2 = 2   # ASPM L1 + L1.2 활성

class PCIeDState(IntEnum):
    D0 = 0   # D0 (fully active)
    D3 = 3   # D3hot (절전)

@dataclass(frozen=True)
class PowerCombo:
    """NVMe PS + PCIe L-state + PCIe D-state 조합."""
    nvme_ps: int
    pcie_l:  PCIeLState
    pcie_d:  PCIeDState

    @property
    def label(self) -> str:
        ln = {0: 'L0', 1: 'L1', 2: 'L1.2'}[int(self.pcie_l)]
        dn = 'D0' if self.pcie_d == PCIeDState.D0 else 'D3'
        return f"PS{self.nvme_ps}+{ln}+{dn}"

# 전체 30개 조합 (PS0~4 × L0/L1/L1.2 × D0/D3)
POWER_COMBOS: list = [
    PowerCombo(ps, PCIeLState(l), PCIeDState(d))
    for ps in range(5)
    for l  in (0, 1, 2)
    for d  in (0, 3)
]


# PCIe L1 / L1.2 진입 settle 시간 기본값 (FuzzConfig.l1_settle_s / l1_2_settle_s)
# --l1-settle / --l1-2-settle CLI로 런타임 조정 가능.
L1_SETTLE     = _PW['l1_settle']      # L1 진입 settle (초)
L1_2_SETTLE   = _PW['l1_2_settle']    # L1.2 추가 settle (초)

# preflight + 메인 퍼징 공통 settle 상수
RESTORE_SETTLE_S      = _PW['restore_settle_s']
D3_RESTORE_SETTLE_S   = _PW['d3_restore_settle_s']
D3_EXTRA_S            = _PW['d3_extra_s']

# v5.2+: PS별 preflight settle 시간은 런타임에 nvme id-ctrl로 동적 계산 (_init_ps_settle).
# formula: (enlat_us + exlat_us) × 2 / 1e6 + 0.05s
# 파싱 실패 시 아래 fallback 값(초) 사용.
_PS_SETTLE_FALLBACK: dict[int, float] = {int(k): v for k, v in _PW['ps_settle_fallback'].items()}


def _hex_or_na(v: 'int | None', width: int = 6) -> str:
    """int를 #0Nx 형식으로, None이면 'N/A' 반환. f-string 내 조건 format spec 오류 방지."""
    return 'N/A' if v is None else f'{v:#0{width}x}'

# PMU 스크립트 절대경로 — subprocess CWD와 무관하게 항상 올바른 파일 사용 (파일명은 paths.pmu_script)
_PMU_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), _P['pmu_script'])

# POR (Power-On Reset) 설정
ENABLE_POR        = _PW['enable_por']
POR_POWEROFF_WAIT = _PW['por_poweroff_wait']
POR_BOOT_WAIT     = _PW['por_boot_wait']

# SWD에서 WFI wake로 주기적 인터럽트 핸들러까지 idle_pcs에 포함되도록
# 새 PC가 N회 연속 나오지 않을 때까지 충분히 샘플링한다.
DIAGNOSE_STABILITY  = _DI['diagnose_stability']
DIAGNOSE_MAX        = _DI['diagnose_max']
DIAGNOSE_SAMPLE_MS  = _DI['diagnose_sample_ms']

IDLE_WINDOW_SIZE  = _DI['idle_window_size']
IDLE_RATIO_THRESH = _DI['idle_ratio_thresh']

CALIBRATION_RUNS  = _DI['calibration_runs']

DETERMINISTIC_ENABLED = _MU['deterministic_enabled']
DETERMINISTIC_ARITH_MAX = _MU['deterministic_arith_max']

MOPT_ENABLED      = _MU['mopt_enabled']
MOPT_PILOT_PERIOD = _MU['mopt_pilot_period']
MOPT_CORE_PERIOD  = _MU['mopt_core_period']

# v4.5+: Corpus 하드 상한 (안전망)
# 0 = 무제한. 양수로 설정하면 culling 후에도 상한을 초과할 경우
# exec_count가 높은(많이 실행된) 비선호 seed부터 강제 제거한다.
MAX_CORPUS_HARD_LIMIT = _FZ['max_corpus_hard_limit']

# v8.3: 외부 파일 경로/파일명 (paths 섹션) — 메서드 본문에서 참조 (script_dir 기준).
UFAS_BINARY        = _P['ufas_binary']            # crash UFAS 덤프 실행 파일
JLINK_DUMP_SCRIPT  = _P['jlink_dump_script']      # crash J-Link 메모리 덤프 셸 스크립트
DEBUG_PACKAGE_DIR  = _P['debug_package_dir']      # vendor 파서 위치 (script_dir 기준 상대)
PARSER_SCRIPT_SH   = _P['parser_script_sh']       # customer parsing tool (.sh 우선)
PARSER_SCRIPT_PY   = _P['parser_script_py']       # customer parsing tool (.py 폴백)
ENGINE_ERRINT_LOGS = list(_P['engine_errint_logs'])  # EngineErrInt 검출용 event log 파일명

# v8.3: runtime/hardware 기본값 (runtime_hw 섹션) — FuzzConfig 기본값/argparse default 가 참조.
CLKREQ_ASSERT_PIN   = _RT['clkreq_assert_pin']
CLKREQ_DEASSERT_PIN = _RT['clkreq_deassert_pin']
CLKREQ_VOLTAGE_MV   = _RT['clkreq_voltage_mv']
FW_XFER_SIZE        = _RT['fw_xfer_size']
FW_SLOT             = _RT['fw_slot']
PREFILL_BS          = _RT['prefill_bs']
BOOT_SWEEP_S        = _RT['boot_sweep_s']
SETTLE_SWEEP        = _RT['settle_sweep']
SETTLE_SWEEP_REPS   = _RT['settle_sweep_reps']
SETTLE_SWEEP_VALUES = list(_RT['settle_sweep_values'])
NVME_LBA_SIZE       = _RT['nvme_lba_size']
PM_TEST_CYCLES      = _RT['pm_test_cycles']

class NVMeCommandType(Enum):
    ADMIN = "admin"
    IO = "io"

@dataclass
class NVMeCommand:
    name: str
    opcode: int
    cmd_type: NVMeCommandType
    needs_namespace: bool = True
    needs_data: bool = True
    timeout_group: str = "command"   # NVME_TIMEOUTS 키 참조
    description: str = ""
    weight: int = 1                  # 명령어 선택 가중치 (높을수록 자주 선택)

# ─────────────────────────────────────────────────────────────────
# Rule-based Schema Mutation (v6.2)
# ─────────────────────────────────────────────────────────────────

class FieldType(Enum):
    ENUM       = "enum"
    LBA        = "lba"
    LBA_CNT    = "lba_cnt"
    FLAGS      = "flags"
    SIZE_DW    = "size_dw"
    OFFSET_DW  = "offset_dw"
    SLOT       = "slot"
    OPAQUE     = "opaque"

@dataclass
class CDWField:
    name: str
    word: int        # 10-15
    hi: int          # inclusive high bit
    lo: int          # inclusive low bit
    ftype: FieldType
    valid: list = field(default_factory=list)
    reserved: tuple = ()   # (min, max) inclusive range for reserved values
    vendor: tuple = ()     # (min, max) inclusive range for vendor-specific
    max_val: int = 0       # for SLOT type

@dataclass
class CmdSchema:
    cmd_name: str
    fields: list  # List[CDWField]

def _F(name, word, hi, lo, ftype, valid=None, reserved=(), vendor=(), max_val=0):
    """CDWField 생성 단축함수."""
    return CDWField(name, word, hi, lo, ftype,
                    valid=valid or [], reserved=reserved, vendor=vendor, max_val=max_val)

_E = FieldType.ENUM
_L = FieldType.LBA
_LC = FieldType.LBA_CNT
_FL = FieldType.FLAGS
_S = FieldType.SIZE_DW
_O = FieldType.OFFSET_DW
_SL = FieldType.SLOT
_OP = FieldType.OPAQUE

CMD_SCHEMAS: dict = {

    # ── Admin Commands ──────────────────────────────────────────────

    "Identify": CmdSchema("Identify", [
        _F("CNS",   10,  7,  0, _E,
           valid=[0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,
                  0x10,0x11,0x12,0x13,0x14,0x1A,0x1C,0x1D,0x1E],
           reserved=(0x1F, 0x6F), vendor=(0x70, 0xFF)),
        _F("CNTID", 10, 31, 16, _SL, max_val=0xFFFF),
        _F("CNSSI", 11, 15,  0, _OP),
        _F("CSI",   11, 31, 24, _E,  valid=[0x00, 0x02]),
        _F("UIDX",  14,  6,  0, _SL, max_val=0x7F),
    ]),

    "GetLogPage": CmdSchema("GetLogPage", [
        _F("LID",   10,  7,  0, _E,
           valid=list(range(0x01, 0x0C)) + [0x0D,0x0E,0x0F,0x10,0x11,0x12,0x13,
                                             0x14,0x15,0x19,0x1A,0x1B,
                                             0x20,0x21,0x22,0x23,
                                             0x70,0x71,0x72,0x73,0x80,0x81],
           vendor=(0xC0, 0xFF)),
        _F("LSP",   10, 14,  8, _OP),
        _F("RAE",   10, 15, 15, _FL, valid=[0, 1]),
        _F("NUMDL", 10, 31, 16, _S),
        _F("NUMDU", 11, 15,  0, _S),
        _F("LSI",   11, 31, 16, _OP),
        _F("LPOL",  12, 31,  0, _O),
        _F("LPOU",  13, 31,  0, _O),
    ]),

    "GetFeatures": CmdSchema("GetFeatures", [
        _F("FID", 10,  7,  0, _E,
           valid=list(range(0x01, 0x16)) + [0x19, 0x1A, 0x1B, 0x1C, 0x1D,
                                             0x7E, 0x7F,
                                             0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D],
           reserved=(0x16, 0x77), vendor=(0x80, 0xFF)),
        _F("SEL", 10, 10,  8, _E, valid=[0, 1, 2, 3]),
        _F("UIDX", 14,  6,  0, _SL, max_val=0x7F),
    ]),

    "SetFeatures": CmdSchema("SetFeatures", [
        _F("FID", 10,  7,  0, _E,
           valid=list(range(0x01, 0x16)) + [0x19, 0x1A, 0x1B, 0x1C, 0x1D,
                                             0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F],
           reserved=(0x16, 0x77), vendor=(0x80, 0xFF)),
        _F("SV",  10, 31, 31, _FL, valid=[0, 1]),
        _F("CDW11", 11, 31, 0, _OP),
        _F("UIDX", 14,  6,  0, _SL, max_val=0x7F),
    ]),

    "DeviceSelfTest": CmdSchema("DeviceSelfTest", [
        _F("STC", 10, 3, 0, _E,
           valid=[0x1, 0x2, 0x3, 0xE, 0xF],
           reserved=(0x4, 0xD)),
    ]),

    "FWCommit": CmdSchema("FWCommit", [
        _F("FS",   10,  2,  0, _SL, max_val=7),
        _F("CA",   10,  5,  3, _E,  valid=[0, 1, 2, 3, 4, 5]),
        _F("BPID", 10, 31, 31, _FL, valid=[0, 1]),
    ]),

    "FWDownload": CmdSchema("FWDownload", [
        _F("NUMD", 10, 31,  0, _S),
        _F("OFST", 11, 31,  0, _O),
    ]),

    "FormatNVM": CmdSchema("FormatNVM", [
        _F("LBAFL", 10,  3,  0, _SL, max_val=0xF),
        _F("MSET",  10,  4,  4, _FL, valid=[0, 1]),
        _F("PI",    10,  7,  5, _E,  valid=[0, 1, 2, 3, 4]),
        _F("PIL",   10,  8,  8, _FL, valid=[0, 1]),
        # SES bits [11:9] intentionally omitted (erase = destructive)
        _F("LBAFU", 10, 13, 12, _SL, max_val=3),
    ]),

    "Sanitize": CmdSchema("Sanitize", [
        # Only safe SANACT values: 001=Exit Failure, 101=Exit Media Verification
        _F("SANACT", 10, 2, 0, _E, valid=[0x1, 0x5]),
    ]),

    "SecuritySend": CmdSchema("SecuritySend", [
        _F("NSSF",  10,  7,  0, _OP),
        _F("SPSP0", 10, 15,  8, _OP),
        _F("SPSP1", 10, 23, 16, _OP),
        # TCG(0x01~0x06)/ATA(0xEC/0xEF) 은 valid 에서 제외 — device 잠금/브릭.
        # send-time GUARD(BLOCKED_SECURITY_SEND_SECP)가 랜덤/opcode 변이 경로도 net 으로 차단.
        _F("SECP",  10, 31, 24, _E,
           valid=[0x00, 0xEA],
           vendor=(0xF0, 0xFF)),
        _F("TL",    11, 31,  0, _S),
    ]),

    "SecurityReceive": CmdSchema("SecurityReceive", [
        _F("NSSF",  10,  7,  0, _OP),
        _F("SPSP0", 10, 15,  8, _OP),
        _F("SPSP1", 10, 23, 16, _OP),
        _F("SECP",  10, 31, 24, _E,
           valid=[0x00, 0x01, 0x02, 0xEA, 0xEF],
           vendor=(0xF0, 0xFF)),
        _F("AL",    11, 31,  0, _S),
    ]),

    "GetLBAStatus": CmdSchema("GetLBAStatus", [
        _F("SLBA_LO", 10, 31,  0, _L),
        _F("SLBA_HI", 11, 31,  0, _L),
        _F("MNDW",    12, 31,  0, _S),
        _F("RL",      13, 15,  0, _SL, max_val=0xFFFF),
        _F("ATYPE",   13, 31, 16, _E, valid=[0, 1, 2]),
    ]),

    "NamespaceManagement": CmdSchema("NamespaceManagement", [
        # SEL=0 only (Create). Delete=1 is excluded.
        _F("SEL", 10,  3,  0, _E, valid=[0x0]),
        _F("CSI", 11, 31, 24, _E, valid=[0x00, 0x02]),
    ]),

    "TelemetryHostInitiated": CmdSchema("TelemetryHostInitiated", [
        _F("CTHID", 10,  8,  8, _FL, valid=[0, 1]),
        _F("RAE",   10, 15, 15, _FL, valid=[0, 1]),
        _F("NUMDL", 10, 31, 16, _S),
    ]),

    "Abort": CmdSchema("Abort", [
        _F("SQID", 10, 15,  0, _SL, max_val=0xFFFF),
        _F("CID",  10, 31, 16, _SL, max_val=0xFFFF),
    ]),

    "NamespaceAttachment": CmdSchema("NamespaceAttachment", [
        # SEL=0 only (Attach). Detach=1 is excluded.
        _F("SEL", 10, 3, 0, _E, valid=[0x0]),
    ]),

    "KeepAlive": CmdSchema("KeepAlive", []),  # No CDW parameters

    "DirectiveSend": CmdSchema("DirectiveSend", [
        _F("NUMD",  10, 31,  0, _S),
        _F("DOPER", 11,  7,  0, _E, valid=[0x00, 0x01, 0x02]),
        _F("DTYPE", 11, 15,  8, _E, valid=[0x00, 0x01]),
        _F("DSPEC", 11, 31, 16, _OP),
    ]),

    "DirectiveReceive": CmdSchema("DirectiveReceive", [
        _F("NUMD",  10, 31,  0, _S),
        _F("DOPER", 11,  7,  0, _E, valid=[0x00, 0x01]),
        _F("DTYPE", 11, 15,  8, _E, valid=[0x00, 0x01]),
        _F("DSPEC", 11, 31, 16, _OP),
    ]),

    "VirtMgmt": CmdSchema("VirtMgmt", [
        _F("ACT",  10,  3,  0, _E, valid=[0x1, 0x7, 0x8, 0x9]),
        _F("RT",   10,  6,  5, _E, valid=[0x0, 0x1]),
        _F("CNTLID", 10, 31, 16, _SL, max_val=0xFFFF),
        _F("NR",   11, 15,  0, _SL, max_val=0xFFFF),
    ]),

    "CapacityMgmt": CmdSchema("CapacityMgmt", [
        _F("OP",   10,  7,  0, _E, valid=[0x0, 0x1]),
        _F("EGID", 10, 31, 16, _SL, max_val=0xFFFF),
        _F("EGCAP_LO", 11, 31,  0, _S),
        _F("EGCAP_HI", 12, 31,  0, _S),
    ]),

    "Lockdown": CmdSchema("Lockdown", [
        # PRHBT=0 only (no prohibition / unlock). PRHBT=1 could permanently disable commands.
        _F("OFI",   10,  7,  0, _E, valid=[0x0, 0x1, 0x2, 0x3]),
        _F("UUID",  10, 14,  9, _SL, max_val=0x3F),
        _F("PRHBT", 10, 15, 15, _E, valid=[0x0]),  # 0 only
        _F("SCP",   10, 19, 16, _E, valid=[0x0, 0x1, 0x2, 0x3, 0x4]),
        _F("IFC",   10, 25, 24, _E, valid=[0x0, 0x1, 0x2]),
    ]),

    "MigrationSend": CmdSchema("MigrationSend", [
        _F("NUMD",   10, 31,  0, _S),
        _F("SEQIND", 11,  1,  0, _E, valid=[0x0, 0x1, 0x2, 0x3]),
        _F("CSVI",   11, 15,  8, _SL, max_val=0xFF),
    ]),

    "MigrationReceive": CmdSchema("MigrationReceive", [
        _F("NUMD",   10, 31,  0, _S),
        _F("CSVI",   11, 15,  8, _SL, max_val=0xFF),
    ]),

    "ControllerDataQueue": CmdSchema("ControllerDataQueue", [
        _F("OP",   10,  3,  0, _E, valid=[0x0, 0x1]),
        _F("CNTLID", 10, 31, 16, _SL, max_val=0xFFFF),
        _F("NUMD",  11, 31,  0, _S),
    ]),

    # ── I/O Commands ────────────────────────────────────────────────

    "Read": CmdSchema("Read", [
        _F("SLBA_LO", 10, 31,  0, _L),
        _F("SLBA_HI", 11, 31,  0, _L),
        _F("NLB",     12, 15,  0, _LC),
        _F("STCR",    12, 25, 25, _FL, valid=[0, 1]),
        _F("PRINFO",  12, 29, 26, _FL, valid=[0,1,2,4,8,0xF]),
        _F("LR",      12, 30, 30, _FL, valid=[0, 1]),
        _F("FUA",     12, 31, 31, _FL, valid=[0, 1]),
        _F("DSM",     13,  3,  0, _OP),
        _F("ILBRT",   14, 31,  0, _OP),
        _F("ELBAT",   15, 15,  0, _OP),
        _F("ELBATM",  15, 31, 16, _OP),
    ]),

    "Write": CmdSchema("Write", [
        _F("SLBA_LO", 10, 31,  0, _L),
        _F("SLBA_HI", 11, 31,  0, _L),
        _F("NLB",     12, 15,  0, _LC),
        _F("STCW",    12, 25, 25, _FL, valid=[0, 1]),
        _F("CETYPE",  12, 19, 16, _E,  valid=[0, 1]),
        _F("DTYPE",   12, 23, 20, _E,  valid=[0, 1]),
        _F("PRINFO",  12, 29, 26, _FL, valid=[0,1,2,4,8,0xF]),
        _F("LR",      12, 30, 30, _FL, valid=[0, 1]),
        _F("FUA",     12, 31, 31, _FL, valid=[0, 1]),
        _F("DSPEC",   13, 31, 16, _OP),
        _F("DSM",     13,  3,  0, _OP),
        _F("ILBRT",   14, 31,  0, _OP),
        _F("LBAT",    15, 15,  0, _OP),
        _F("LBATM",   15, 31, 16, _OP),
    ]),

    "WriteUncorrectable": CmdSchema("WriteUncorrectable", [
        _F("SLBA_LO", 10, 31,  0, _L),
        _F("SLBA_HI", 11, 31,  0, _L),
        _F("NLB",     12, 15,  0, _LC),
    ]),

    "Compare": CmdSchema("Compare", [
        _F("SLBA_LO", 10, 31,  0, _L),
        _F("SLBA_HI", 11, 31,  0, _L),
        _F("NLB",     12, 15,  0, _LC),
        _F("STCR",    12, 25, 25, _FL, valid=[0, 1]),
        _F("PRINFO",  12, 29, 26, _FL, valid=[0,1,2,4,8,0xF]),
        _F("LR",      12, 30, 30, _FL, valid=[0, 1]),
        _F("FUA",     12, 31, 31, _FL, valid=[0, 1]),
        _F("ELBRT",   14, 31,  0, _OP),
        _F("ELBAT",   15, 15,  0, _OP),
        _F("ELBATM",  15, 31, 16, _OP),
    ]),

    "WriteZeroes": CmdSchema("WriteZeroes", [
        _F("SLBA_LO", 10, 31,  0, _L),
        _F("SLBA_HI", 11, 31,  0, _L),
        _F("NLB",     12, 15,  0, _LC),
        _F("DEAC",    12, 25, 25, _FL, valid=[0, 1]),
        _F("PRINFO",  12, 29, 26, _FL, valid=[0,1,2,4,8,0xF]),
        _F("LR",      12, 30, 30, _FL, valid=[0, 1]),
        _F("FUA",     12, 31, 31, _FL, valid=[0, 1]),
    ]),

    "Verify": CmdSchema("Verify", [
        _F("SLBA_LO", 10, 31,  0, _L),
        _F("SLBA_HI", 11, 31,  0, _L),
        _F("NLB",     12, 15,  0, _LC),
        _F("STC",     12, 25, 25, _FL, valid=[0, 1]),
        _F("PRINFO",  12, 29, 26, _FL, valid=[0,1,2,4,8,0xF]),
        _F("LR",      12, 30, 30, _FL, valid=[0, 1]),
    ]),

    "Flush": CmdSchema("Flush", []),  # No CDW parameters

    "DatasetManagement": CmdSchema("DatasetManagement", [
        _F("NR",  10,  7,  0, _LC),
        _F("IDR", 11,  0,  0, _FL, valid=[0, 1]),
        _F("IDW", 11,  1,  1, _FL, valid=[0, 1]),
        _F("AD",  11,  2,  2, _FL, valid=[0, 1]),
    ]),

    "Copy": CmdSchema("Copy", [
        _F("SDLBA_LO", 10, 31,  0, _L),
        _F("SDLBA_HI", 11, 31,  0, _L),
        _F("DF",       12,  7,  4, _E,  valid=[0, 1, 2, 3]),
        _F("NR",       12, 11,  8, _SL, max_val=0xFF),
        _F("PRINFOR",  12, 15, 12, _FL),
        _F("STCW",     12, 24, 24, _FL, valid=[0, 1]),
        _F("STCR",     12, 25, 25, _FL, valid=[0, 1]),
        _F("PRINFOW",  12, 29, 26, _FL),
        _F("FUA",      12, 30, 30, _FL, valid=[0, 1]),
        _F("LR",       12, 31, 31, _FL, valid=[0, 1]),
    ]),

    "ReservationRegister": CmdSchema("ReservationRegister", [
        _F("RREGA",   10,  2,  0, _E, valid=[0, 1, 2]),
        _F("IEKEY",   10,  3,  3, _FL, valid=[0, 1]),
        _F("DISNSRS", 10,  4,  4, _FL, valid=[0, 1]),
        _F("CPTPL",   10, 31, 30, _E, valid=[0, 2, 3]),
    ]),

    "ReservationReport": CmdSchema("ReservationReport", [
        _F("NUMD", 10, 31,  0, _S),
        _F("EDS",  11,  0,  0, _FL, valid=[0, 1]),
    ]),

    "ReservationAcquire": CmdSchema("ReservationAcquire", [
        _F("RACQA",   10,  2,  0, _E, valid=[0, 1, 2]),
        _F("IEKEY",   10,  3,  3, _FL, valid=[0, 1]),
        _F("DISNSRS", 10,  4,  4, _FL, valid=[0, 1]),
        _F("RTYPE",   10, 15,  8, _E, valid=list(range(0, 7))),
    ]),

    "ReservationRelease": CmdSchema("ReservationRelease", [
        _F("RRELA",   10,  2,  0, _E, valid=[0, 1]),
        _F("IEKEY",   10,  3,  3, _FL, valid=[0, 1]),
        _F("RTYPE",   10, 15,  8, _E, valid=list(range(0, 7))),
    ]),

    "Cancel": CmdSchema("Cancel", [
        _F("SQID", 10, 15,  0, _SL, max_val=0xFFFF),
        _F("CID",  10, 31, 16, _SL, max_val=0xFFFF),
        _F("CA",   11,  3,  0, _E,  valid=[0, 1, 2]),
    ]),

    "IOMgmtReceive": CmdSchema("IOMgmtReceive", [
        _F("NUMD",  10, 31,  0, _S),
        _F("MO",    11,  7,  0, _E, valid=[0x0, 0x1]),
        _F("MOSPC", 11, 31, 16, _SL, max_val=0xFFFF),
    ]),

    "IOMgmtSend": CmdSchema("IOMgmtSend", [
        _F("NUMD",  10, 31,  0, _S),
        _F("MO",    11,  7,  0, _E, valid=[0x1, 0x2]),
        _F("MOSPC", 11, 31, 16, _SL, max_val=0xFFFF),
    ]),
}

# 기본 활성화 (비파괴, 빠른 응답) — --commands 없이 실행 시 이것만 사용
# weight 합계: Admin=4(1+1+1+1), IO=4(2+2) → Admin 50% / IO 50%
NVME_COMMANDS_DEFAULT = [
    NVMeCommand("Identify",    0x06, NVMeCommandType.ADMIN, needs_data=False),
    NVMeCommand("GetLogPage",  0x02, NVMeCommandType.ADMIN, needs_data=False),
    NVMeCommand("GetFeatures", 0x0A, NVMeCommandType.ADMIN, needs_data=False),
    NVMeCommand("SetFeatures", 0x09, NVMeCommandType.ADMIN),
    NVMeCommand("Read",        0x02, NVMeCommandType.IO,    needs_data=False, weight=2),
    NVMeCommand("Write",       0x01, NVMeCommandType.IO,    weight=2),
]

# 전체 명령어 (위험/파괴적 포함) — --commands 또는 --all-commands로 활성화
NVME_COMMANDS_EXTENDED = [
    NVMeCommand("FWDownload",            0x11, NVMeCommandType.ADMIN, needs_namespace=False),
    NVMeCommand("FWCommit",              0x10, NVMeCommandType.ADMIN, needs_namespace=False, timeout_group="fw_commit"),
    NVMeCommand("FormatNVM",             0x80, NVMeCommandType.ADMIN, timeout_group="format"),
    NVMeCommand("Sanitize",              0x84, NVMeCommandType.ADMIN, needs_namespace=False, timeout_group="sanitize"),
    NVMeCommand("TelemetryHostInitiated",0x02, NVMeCommandType.ADMIN, needs_data=False, timeout_group="telemetry"),
    NVMeCommand("Flush",                 0x00, NVMeCommandType.IO,    needs_data=False, timeout_group="flush"),
    NVMeCommand("DatasetManagement",     0x09, NVMeCommandType.IO,    timeout_group="dsm"),
    NVMeCommand("WriteZeroes",           0x08, NVMeCommandType.IO,    needs_data=False),
    NVMeCommand("Compare",               0x05, NVMeCommandType.IO),
    NVMeCommand("WriteUncorrectable",    0x04, NVMeCommandType.IO,    needs_data=False),
    NVMeCommand("Verify",                0x0C, NVMeCommandType.IO,    needs_data=False, timeout_group="verify"),
    NVMeCommand("DeviceSelfTest",        0x14, NVMeCommandType.ADMIN, needs_data=False, needs_namespace=False, timeout_group="selftest_short"),
    NVMeCommand("SecuritySend",          0x81, NVMeCommandType.ADMIN, needs_namespace=False, timeout_group="security"),
    NVMeCommand("SecurityReceive",       0x82, NVMeCommandType.ADMIN, needs_data=False, needs_namespace=False, timeout_group="security"),
    NVMeCommand("GetLBAStatus",          0x86, NVMeCommandType.ADMIN, needs_data=False),
    # New commands (rejection path fuzzing + new functionality)
    NVMeCommand("NamespaceManagement",   0x0D, NVMeCommandType.ADMIN, needs_namespace=False),
    NVMeCommand("NamespaceAttachment",   0x15, NVMeCommandType.ADMIN, needs_data=False, needs_namespace=False),
    NVMeCommand("KeepAlive",             0x18, NVMeCommandType.ADMIN, needs_data=False, needs_namespace=False),
    NVMeCommand("DirectiveSend",         0x19, NVMeCommandType.ADMIN, needs_namespace=False),
    NVMeCommand("DirectiveReceive",      0x1A, NVMeCommandType.ADMIN, needs_data=False, needs_namespace=False),
    NVMeCommand("VirtMgmt",              0x1C, NVMeCommandType.ADMIN, needs_data=False, needs_namespace=False),
    NVMeCommand("CapacityMgmt",          0x20, NVMeCommandType.ADMIN, needs_data=False, needs_namespace=False),
    NVMeCommand("Lockdown",              0x24, NVMeCommandType.ADMIN, needs_data=False, needs_namespace=False),
    NVMeCommand("MigrationSend",         0x41, NVMeCommandType.ADMIN, needs_namespace=False),
    NVMeCommand("MigrationReceive",      0x42, NVMeCommandType.ADMIN, needs_data=False, needs_namespace=False),
    NVMeCommand("ControllerDataQueue",   0x45, NVMeCommandType.ADMIN, needs_data=False, needs_namespace=False),
    NVMeCommand("Abort",                 0x08, NVMeCommandType.ADMIN, needs_data=False, needs_namespace=False),
    # AER(0x0C) 제외: 컨트롤러가 Thermal/SMART 등 이벤트 발생 시 자동 완료하는 명령.
    # 퍼저가 직접 보내면 이벤트 없이 indefinite block → timeout만 발생.
    NVMeCommand("Copy",                  0x19, NVMeCommandType.IO),
    NVMeCommand("ReservationRegister",   0x0D, NVMeCommandType.IO),
    NVMeCommand("ReservationReport",     0x0E, NVMeCommandType.IO,    needs_data=False),
    NVMeCommand("ReservationAcquire",    0x11, NVMeCommandType.IO),
    NVMeCommand("ReservationRelease",    0x15, NVMeCommandType.IO),
    NVMeCommand("Cancel",                0x18, NVMeCommandType.IO,    needs_data=False),
    NVMeCommand("IOMgmtReceive",         0x12, NVMeCommandType.IO,    needs_data=False),
    NVMeCommand("IOMgmtSend",            0x1D, NVMeCommandType.IO),
]

# 전체 명령어 (이름으로 조회용)
NVME_COMMANDS = NVME_COMMANDS_DEFAULT + NVME_COMMANDS_EXTENDED

# (opcode, cmd_type) → name. 동일 opcode라도 Admin/IO 구분.
_OPCODE_TO_NAME: dict[tuple[int, str], str] = {}
# (opcode, cmd_type) → NVMeCommand. mutation(opcode_override/force_admin)으로 실제 전송
# opcode/타입이 바뀌면 원본 cmd 의 timeout_group 이 무효 → 실제 opcode 의 cmd 로 timeout 재해석.
_OPCODE_TO_CMD: dict[tuple[int, str], 'NVMeCommand'] = {}
for _c in NVME_COMMANDS:
    _key = (_c.opcode, _c.cmd_type.value)
    if _key not in _OPCODE_TO_NAME:
        _OPCODE_TO_NAME[_key] = _c.name
    if _key not in _OPCODE_TO_CMD:
        _OPCODE_TO_CMD[_key] = _c

@dataclass
class Seed:
    """v4: 시드 데이터 구조 (Power Schedule용)"""
    data: bytes
    cmd: NVMeCommand
    # NVMe CDW (Command Dword) 필드 — 각 Opcode별 정상 파라미터 포함
    cdw2: int = 0
    cdw3: int = 0
    cdw10: int = 0
    cdw11: int = 0
    cdw12: int = 0
    cdw13: int = 0
    cdw14: int = 0
    cdw15: int = 0
    # 확장 mutation 필드 (None = 명령어 기본값 사용)
    opcode_override: Optional[int] = None       # opcode mutation (vendor-specific 등)
    nsid_override: Optional[int] = None         # namespace ID mutation
    force_admin: Optional[bool] = None          # True=admin ioctl, False=IO ioctl, None=정상
    data_len_override: Optional[int] = None     # data_len↔CDW 의도적 불일치
    exec_count: int = 0          # 이 시드가 선택된 횟수
    found_at: int = 0            # 발견된 시점 (execution number)
    new_pcs: int = 0             # 발견한 새 unique PC 수 (primary coverage signal)
    energy: float = 1.0          # 계산된 에너지
    covered_pcs: Optional[set] = None   # 이 시드 실행 시 방문된 PC 주소 집합 (culling용)
    is_favored: bool = False     # v4.3: corpus culling에서 선정된 favored seed
    is_calibrated: bool = False  # calibration 완료 여부
    stability: float = 1.0      # 0.0~1.0, PC 안정성 비율
    stable_pcs: Optional[set] = None    # calibration에서 과반수 실행에 등장한 PC 주소
    det_done: bool = False       # deterministic stage 완료 여부

@dataclass
class SequenceSeed:
    """v7.5: N개 명령어 시퀀스를 단일 corpus 단위로 저장.
    energy = base_energy / len(commands) 패널티로 단일 Seed와 per-exec 공정 경쟁."""
    commands: List['Seed']           # 시퀀스 내 명령어 목록 (실행 순서)
    new_pcs: int = 0                 # 시퀀스 전체에서 발견한 새 PC 수
    energy: float = 1.0              # _calculate_energy() 갱신 시 base / len(commands)
    found_at: int = 0
    exec_count: int = 0
    is_favored: bool = False
    covered_pcs: Optional[set] = None

@dataclass
class FuzzConfig:
    # OpenOCD 설정
    openocd_binary:  str   = OPENOCD_BINARY
    openocd_config:  str   = OPENOCD_CONFIG
    openocd_host:    str   = OPENOCD_TELNET_HOST
    openocd_port:    int   = OPENOCD_TELNET_PORT
    openocd_timeout: float = OPENOCD_STARTUP_TIMEOUT
    interface:       str   = 'swd'   # 'swd' | 'jtag'
    jlink_device:    str   = JLINK_DEVICE
    # v8.0: product profile 에서 채워지는 target-specific 값들
    tcl_prefix:      str   = 'r8'                 # OpenOCD cfg target object 접두사
    pcsr_addrs:      Optional[List[int]] = None   # per-core DBGPCSR 주소 (None=interface 기본)
    power_addr:      Optional[int] = PCSR_POWER_ADDR
    power_mask:      Optional[int] = PCSR_POWER_MASK
    invalid_pc_vals: tuple = R8_DPIDR_VALS        # PCSR 필터 제외 DPIDR 값
    sampler_type:    str   = 'pcsr'               # 'pcsr' | 'halt' | 'jlink_halt' | 'null'
    go_settle_ms:    int   = 0                    # halt 후 resume→다음 halt 최소 실행시간(ms). PCSR=0
    # v8.1: JLinkHaltSampler(P9) 전용 — pylink 직접 제어 파라미터
    jlink_speed:     int   = 4000                 # J-Link SWD/JTAG 속도 (kHz)
    jlink_ap_index:  int   = 0                    # CoreSight APB-AP 인덱스 (P9: AP[0])
    pc_reg_index:    Optional[int] = None         # PC(R15) 레지스터 인덱스. None=connect 시 자동 탐지
    ufas_ini:        Optional[str] = 'PM9M1_A815.ini'  # UFAS --ini (enable_ufas 는 아래 정의)
    allow_no_openocd: bool = False    # OpenOCD 실패 시 --pm 전용 테스트 경로 허용
    no_jlink:         bool = False    # J-Link 자체 없이 NVMe fuzz 만 수행 (coverage 0)
    unsupported_skip: bool = False    # v7.8: J-Link dump 의 EngineErrInt 검출 시 자동 skip + power cycle
    repro_opcodes: tuple = ()  # 재현 모드: 이 opcode(들) timeout 만 크래시 캡처, 나머지는 POR 복구 후 계속
    ignore_opcodes: tuple = ()  # denylist: 이 opcode(들) timeout 은 크래시로 안 치고 POR 복구 후 계속
    pm_test_cycles:   int  = PM_TEST_CYCLES   # OpenOCD 없이 preflight 후 추가 랜덤 PM cycle 수

    nvme_device: str = NVME_DEVICE
    nvme_namespace: int = NVME_NAMESPACE
    nvme_lba_size: int = NVME_LBA_SIZE  # 0 = 시작 시 자동 감지 (blockdev --getss)
    nvme_timeouts: dict = field(default_factory=lambda: NVME_TIMEOUTS.copy())

    enabled_commands: List[str] = field(default_factory=list)
    all_commands: bool = False   # True면 위험(파괴적) 명령어 포함 전체 활성화

    # 샘플링 설정
    sample_interval_us: int = SAMPLE_INTERVAL_US
    max_samples_per_run: int = MAX_SAMPLES_PER_RUN

    # NVMe 커맨드 완료 후 추가 샘플링 시간 (ms)
    post_cmd_delay_ms: int = POST_CMD_DELAY_MS

    nvme_passthru_timeout_ms: int = NVME_PASSTHRU_TIMEOUT_MS
    # crash 상태 보존을 위한 nvme_core 모듈 타임아웃 (초)
    # 퍼저 시작 시 /sys/module/nvme_core/parameters/{admin,io}_timeout 에 설정
    nvme_kernel_timeout_sec: int = NVME_KERNEL_TIMEOUT_SEC

    # 퍼징 설정
    max_input_len: int = MAX_INPUT_LEN
    total_runtime_sec: int = TOTAL_RUNTIME_SEC
    seed_dir: Optional[str] = SEED_DIR
    output_dir: str = OUTPUT_DIR

    # 주소 필터 (펌웨어 .text 섹션 범위)
    addr_range_start: Optional[int] = FW_ADDR_START
    addr_range_end: Optional[int] = FW_ADDR_END
    # Ghidra 정적분석 파일명 (제품별) — script_dir 기준. 없으면 정적 커버리지 통계 생략.
    bb_file:   str = 'basic_blocks.txt'
    func_file: str = 'functions.txt'

    # 이전 세션 커버리지 파일 (resume용)
    resume_coverage: Optional[str] = RESUME_COVERAGE

    random_gen_ratio: float = RANDOM_GEN_RATIO

    excluded_opcodes: List[int] = field(default_factory=lambda: EXCLUDED_OPCODES.copy())

    admin_swap_prob: float = ADMIN_SWAP_PROB

    diagnose_stability: int = DIAGNOSE_STABILITY  # 새 idle PC 없이 연속 N회면 수렴
    diagnose_max: int = DIAGNOSE_MAX              # 수렴 전 최대 샘플 수
    # diagnose() 샘플 간격 (ms)
    diagnose_sample_ms: int = DIAGNOSE_SAMPLE_MS

    calibration_runs: int = CALIBRATION_RUNS

    # POR
    enable_por:        bool  = ENABLE_POR
    por_poweroff_wait: float = POR_POWEROFF_WAIT
    por_boot_wait:     float = POR_BOOT_WAIT   # PCIe rescan 후 NVMe 응답 최대 대기 (초)
    boot_sweep_s:      float = BOOT_SWEEP_S    # connect() 직후 boot-phase PC 수집 창 (초, 0=비활성화)
                                               # POR 시 이 시간 내에서 connect() 재시도도 수행

    # v4.5+: Corpus 하드 상한 (0 = 무제한)
    max_corpus_hard_limit: int = MAX_CORPUS_HARD_LIMIT

    fw_bin: Optional[str] = None        # 펌웨어 바이너리 경로 (없으면 더미 시드)
    fw_xfer_size: int = FW_XFER_SIZE    # FWDownload 청크 크기(바이트), nvme fw-download -x 와 동일
    fw_slot: int = FW_SLOT              # FWCommit 슬롯 번호

    enable_ufas: bool = True            # crash 시 UFAS 펌웨어 덤프 실행 여부 (--no-ufas로 비활성화)
    enable_jlink_dump: bool = True      # crash 시 JLink 메모리 덤프 실행 여부 (--no-jlink-dump로 비활성화)

    prefill: bool = False               # POR 전 드라이브 전체 쓰기 (GC/WL 트리거용, --prefill)
    prefill_bs: int = PREFILL_BS       # prefill dd 블록 크기 (기본 4MB)

    pm_inject_prob: float = 0.0

    pmu_script:          str   = _PMU_SCRIPT
    clkreq_assert_pin:   int   = CLKREQ_ASSERT_PIN     # CLKREQ# assert GPIO pin
    clkreq_deassert_pin: int   = CLKREQ_DEASSERT_PIN   # CLKREQ# deassert GPIO pin
    clkreq_voltage_mv:   int   = CLKREQ_VOLTAGE_MV     # CLKREQ# 전압 (mV)
    l1_settle_s:         float = L1_SETTLE    # L1 진입 idle window settle (초)
    l1_2_settle_s:       float = L1_2_SETTLE  # L1.2 추가 settle (초)

    settle_sweep:        bool  = SETTLE_SWEEP       # --settle-sweep 모드
    settle_sweep_reps:   int   = SETTLE_SWEEP_REPS  # 각 settle 값당 반복 횟수 (Phase1)
    settle_sweep_values: list  = field(default_factory=lambda: list(SETTLE_SWEEP_VALUES))

    # v7.0: State monitoring
    state_enabled: bool = True             # --no-state 시 False
    # v8.3: 제품별 state 관측 필드 (fuzzer_config.json state_fields 세트). 기본=r8 세트.
    state_fields: list = field(default_factory=lambda: list(_DEFAULT_STATE_FIELDS))

    # v8.4: IO 워크로드 엔진 on/off (config io_workload.enabled 기본, --no-io-workload 로 off).
    io_workload_enabled: bool = IO_WL_ENABLED

class _MsFormatter(logging.Formatter):
    """ms 단위 타임스탬프 포매터 (datefmt는 초까지만 지원하므로 formatTime 오버라이드)."""
    def formatTime(self, record: logging.LogRecord, datefmt=None) -> str:
        ct = self.converter(record.created)
        if datefmt:
            s = time.strftime(datefmt, ct)
        else:
            s = time.strftime('%Y-%m-%d %H:%M:%S', ct)
        return f"{s}.{int(record.msecs):03d}"


class _ColorFormatter(_MsFormatter):
    """터미널 출력용 ANSI 컬러 포매터. 파일 핸들러에는 사용하지 않음."""

    import re as _re

    _RESET = "\033[0m"
    _RULES = [
        (_re.compile(r'CRASH'),                              "\033[1;31m"),  # 굵은 빨강
        (_re.compile(r'FAIL CMD'),                           "\033[31m"),    # 빨강
        (_re.compile(r'\[TIMEOUT\]'),                        "\033[31m"),    # 빨강
        (_re.compile(r'\[\+\]'),                             "\033[32m"),    # 초록
        (_re.compile(r'\[PM\]'),                             "\033[33m"),    # 노랑
        (_re.compile(r'\[Stats\]|\[StatCov\]'),              "\033[36m"),    # 시안
        (_re.compile(r'\[UFAS\]|\[REPLAY\]'),                "\033[35m"),    # 마젠타
        (_re.compile(r'={5,}'),                              "\033[34m"),    # 파랑
    ]
    _LEVEL_COLORS = {
        logging.ERROR:    "\033[1;31m",   # 굵은 빨강
        logging.CRITICAL: "\033[1;35m",   # 굵은 마젠타
    }

    def format(self, record: logging.LogRecord) -> str:
        text = super().format(record)
        color = self._LEVEL_COLORS.get(record.levelno)
        if color is None:
            msg = record.getMessage()
            for pat, col in self._RULES:
                if pat.search(msg):
                    color = col
                    break
        if color:
            return color + text + self._RESET
        return text

class _FuzzingTerminalFilter(logging.Filter):
    """메인 퍼징 루프 중 터미널 출력을 필요한 정보로만 제한.

    허용 항목:
      [Stats] / [StatCov]  — 주기 통계 (exec, corpus, coverage, ...)
      [PM]                 — PM combo 전환 / NonOp restore
      [+]                  — 신규 커버리지 발견
      CRASH / FAIL CMD     — 크래시·커맨드 실패
      =====                — 섹션 구분선
      [NVMe TIMEOUT]       — nvme-cli 타임아웃 감지 (_send_nvme_command)
      [TIMEOUT]            — timeout 후속 처리 (_handle_timeout_crash)
      [REPLAY]             — replay .sh 생성 완료
      [UFAS]               — UFAS 펌웨어 덤프 진행/완료
      [JLINK] / [JLINK DUMP] — OpenOCD shutdown / JLink 메모리 덤프 진행·완료
      [MONITOR]            — timeout crash 후 JLink PC 모니터링 출력
      ERROR / CRITICAL     — 예외 없이 항상 출력

    나머지는 파일 로그에만 기록됨.
    """
    import re as _re
    _ALLOW = _re.compile(
        r'\[Stats\]|\[StatCov\]|\[PM\]|\[\+\]|CRASH|FAIL CMD|={5,}'
        r'|\[NVMe TIMEOUT\]|\[TIMEOUT\]|\[REPLAY\]|\[UFAS\]|\[State-Replay\]'
        r'|\[JLINK\]|\[JLINK DUMP\]|\[MONITOR\]|\[UnsupChk\]|\[POR\]|\[Probe-'
        r'|\[State-Snap\]|\[SMART\]'   # v8.3: 주기적 SMART/전체 state field 출력 터미널 노출
        r'|\[IO-WL\]'                   # v8.4: IO 워크로드 블록/검증 로그
        r'|\[DevInfo\]'                 # Device Information(주기 출력) 터미널 노출
    )

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno >= logging.ERROR:
            return True
        return bool(self._ALLOW.search(record.getMessage()))

def _setup_matplotlib_chart_env():
    """차트 생성용 matplotlib 환경 — ASCII 폰트 고정 + glyph missing 경고 억제.

    한글 폰트가 시스템에 없거나 matplotlib 기본 폰트(DejaVu Sans)에 없을 때 발생하는
    'Glyph N missing from current font' UserWarning과 깨진 글자 출력을 방지한다.

    rcParams는 process-global이라 호출 1회만으로 충분하지만, 차트 함수가 각자 lazy
    import 패턴이라 모든 사이트에서 호출하여 idempotent 안전성 확보.
    """
    import matplotlib
    matplotlib.use('Agg')
    matplotlib.rcParams['font.family']        = 'DejaVu Sans'
    matplotlib.rcParams['font.sans-serif']    = ['DejaVu Sans']
    matplotlib.rcParams['axes.unicode_minus'] = False
    import warnings
    warnings.filterwarnings(
        'ignore', message=r'.*missing from (current )?font.*')


def setup_logging(output_dir: str) -> Tuple[logging.Logger, str]:
    """파일 + 콘솔 동시 로깅 설정 (실행마다 날짜시간 로그 파일 생성)"""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(output_dir, f'fuzzer_{timestamp}.log')

    logger = logging.getLogger('pcfuzz')
    logger.setLevel(logging.DEBUG)

    # 이전 핸들러 제거 (중복 방지)
    logger.handlers.clear()

    fmt = _MsFormatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # 파일: 매 실행마다 새 파일 생성 (INFO 이상 전체 기록)
    # encoding='utf-8' 명시 — sudo / C locale 환경에서 μ/✓/→/한글 깨짐 방지.
    # 주의: errors='replace' 는 Python 3.9+ 만 지원 → 호환성 위해 사용 안 함.
    # UTF-8 은 모든 Unicode 표현 가능하므로 encode 실패 가능성 없음.
    fh = logging.FileHandler(log_file, encoding='utf-8')
    fh.setLevel(logging.INFO)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    # 콘솔: 초기화 단계에서는 WARNING 이상 전부 출력
    # 메인 퍼징 루프 진입 시 _FuzzingTerminalFilter 추가로 제한됨
    # stderr 도 UTF-8 로 reconfigure (Python 3.7+) — TTY 인코딩이 C/POSIX 일 때 보호.
    try:
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass
    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING)
    # TTY이면 컬러 포매터, 파이프/리다이렉트이면 일반 포매터
    is_tty = hasattr(sys.stderr, 'isatty') and sys.stderr.isatty()
    ch.setFormatter(_ColorFormatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ) if is_tty else fmt)
    logger.addHandler(ch)

    return logger, log_file


def _logname(p) -> str:
    """로그 표시용 경로 — 버전이 박힌 output 폴더 prefix 를 떼고 파일/폴더 이름만 남긴다.
    로그에 버전(vX.Y.Z)이 노출되지 않게 함. 실제 위치는 OUTPUT_DIR 로 알 수 있음."""
    s = str(p).rstrip('/')
    return os.path.basename(s) or s

# 모듈 레벨 로거 (setup_logging 호출 전까지 콘솔만 사용)
log = logging.getLogger('pcfuzz')


# ──────────────────────────────────────────────────────────────────────
# v7.0: State (Telemetry)-Aware 관련 데이터 구조 및 모니터 클래스
# ──────────────────────────────────────────────────────────────────────

@dataclass
class NVMeStateDelta:
    """100회 명령 window 전후의 state 필드 차분."""
    changes:     Dict[str, int]   # field_name → after - before (0이면 변화 없음)
    weights:     Dict[str, float] # field_name → STATE_FIELDS weight
    buckets:     List[str]        # CSFuzz §III-B 적응형 버킷 (pre-computed)
    init_deltas: Dict[str, int]   # field_name → current - init_value

    @property
    def is_interesting(self) -> bool:
        return any(v != 0 for v in self.changes.values())

    @property
    def score(self) -> float:
        # CSFuzz §III-B 정신: raw delta 대신 log2(1 + |init_delta|) × weight
        # → I/O 볼륨 같은 대량 누적 필드가 score 독식하는 현상 방지
        return sum(
            math.log2(1 + abs(self.init_deltas.get(k, 0))) * self.weights.get(k, 1.0)
            for k in self.changes
        )

    def state_buckets(self) -> List[str]:
        """CSFuzz §III-B 적응형 버킷 목록 반환 (pre-computed)."""
        return self.buckets


@dataclass
class StateCorpusEntry:
    """state 변화를 일으킨 최근 100개 명령 시퀀스."""
    sequence:   List[dict]      # list(self._cmd_history) 스냅샷
    delta:      NVMeStateDelta
    score:      float
    causes:     List[str]       # state_buckets() 결과
    found_at:   int             # 발견 시 exec 번호
    exec_count: int   = 0
    energy:     float = 16.0   # AFLfast 초기 에너지


# state 관측(smart-log/get-log/security)용 nvme 호출 — 최대 STATE_MONITOR_SEC 초 대기, 못 끝내면
# 프로세스를 버리고(D-state 는 SIGKILL 도 무시 → communicate 재호출 시 영구 블록 → 회피) 실패 반환.
# crash 보존이 필요 없는 관측 명령이라 길게 기다릴 이유가 없다 → device 무응답 시 fuzzer 멈춤 방지.
STATE_MONITOR_SEC = int(_T.get('state_monitor_sec', 60))


class _StateProc:
    """_run_nvme_state_cmd 반환 — subprocess.run 결과처럼 .returncode/.stdout/.stderr 제공."""
    __slots__ = ('returncode', 'stdout', 'stderr')

    def __init__(self, returncode, stdout, stderr):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _run_nvme_state_cmd(cmd, timeout_sec=STATE_MONITOR_SEC, merge_stderr=False):
    """관측용 nvme 명령 실행. 타임아웃(기본 60s) 시 프로세스를 버리고 returncode=-1 반환(블록 회피)."""
    try:
        _p = subprocess.Popen(
            cmd, stdout=subprocess.PIPE,
            stderr=(subprocess.STDOUT if merge_stderr else subprocess.PIPE),
            start_new_session=True)
    except Exception as _e:
        return _StateProc(-1, b'', str(_e).encode())
    try:
        _out, _err = _p.communicate(timeout=timeout_sec)
        return _StateProc(_p.returncode, _out or b'', _err if _err is not None else b'')
    except subprocess.TimeoutExpired:
        # D-state 면 SIGKILL 무시 → communicate 재호출 금지. kill 시도 후 파이프만 닫고 버린다.
        try:
            _p.kill()
        except Exception:
            pass
        for _pipe in (_p.stdout, _p.stderr):
            if _pipe:
                try:
                    _pipe.close()
                except Exception:
                    pass
        _p.poll()
        return _StateProc(-1, b'', b'timeout')


class NVMeStateMonitor:
    """100회마다 nvme smart-log / nvme get-log를 실행해 state를 관측."""

    def __init__(self, nvme_device: str, fields: List[dict]) -> None:
        self._device  = nvme_device
        self._fields  = fields
        self._smart_needed = any(f['source'] == 'smart' for f in fields)
        # (lid, log_len) 쌍 집합 — LID별 1회만 get-log 실행
        self._vendor_lids: set = {
            (f['lid'], f['log_len'])
            for f in fields if f['source'] == 'vendor'
        }
        # 정적 weight (state_fields.py 정의값 — 초기 힌트)
        self._weights: Dict[str, float] = {f['name']: f.get('weight', 1.0)
                                            for f in fields}
        # 동적 weight 보정: 변화 횟수 누적 → 자주 바뀌는 필드일수록 weight 감소
        self._change_counts: Dict[str, int] = {f['name']: 0 for f in fields}
        # security_recv: (secp, spsp, nsid) → max_size
        self._sec_groups: Dict[tuple, int] = {}
        for f in fields:
            if f['source'] == 'security_recv':
                key = (f['secp'], f['spsp'], f.get('nsid', 0))
                self._sec_groups[key] = max(
                    self._sec_groups.get(key, 0), f['size'])
        # CSFuzz §III-B: 최초 관측값 (adaptive partitioning 기준점)
        self._init_values: Dict[str, int] = {}

    def capture(self) -> Optional[Dict[str, int]]:
        """활성 필드 기준으로 필요한 nvme 명령만 실행.
        반환: {field_name: int_value} 또는 실패 시 None."""
        result: Dict[str, int] = {}

        # ── SMART-log ──────────────────────────────────────────────
        # JSON 옵션 없는 구버전 nvme-cli 대응: 텍스트 출력 파싱
        # state_fields.py의 'key'는 JSON 키 기준 — 텍스트 키와 다른 경우 아래 매핑 사용
        _SMART_TEXT_KEY_MAP = {
            'percent_used':       'percentage_used',
            'avail_spare':        'available_spare',
            'spare_thresh':       'available_spare_threshold',
            'warning_temp_time':  'warning_temperature_time',
            'critical_comp_time': 'critical_composite_temperature_time',
        }
        if self._smart_needed:
            try:
                proc = _run_nvme_state_cmd(['nvme', 'smart-log', self._device])
                if proc.returncode != 0:
                    log.warning(f"[State] smart-log 실패 "
                                f"(rc={proc.returncode}): "
                                f"{proc.stderr.decode(errors='replace').strip()}")
                    return None
                # 텍스트 파싱: "key_name   : value" 형식
                # 키 정규화: 소문자 + 공백→밑줄, 값: 첫 토큰에서 % / 쉼표 제거
                # 구버전 nvme-cli는 stdout 대신 stderr로 출력하는 경우가 있음
                _raw_out = proc.stdout or proc.stderr
                log.info(f"[State] smart-log stdout={len(proc.stdout)}B "
                         f"stderr={len(proc.stderr)}B")
                _raw_text = _raw_out.decode(errors='replace')
                # 진단: 첫 호출 또는 critical_warning != 0 시 raw 출력 전체 file log 에 dump.
                # 사용자가 nvme-cli 직접 실행 결과와 비교 가능하게.
                _dump_raw = not hasattr(self, '_smart_raw_logged')
                smart_text: Dict[str, int] = {}
                _raw_lines_for_key: Dict[str, str] = {}   # diag: 어떤 raw 라인이 어느 key 로 매핑됐는지
                for line in _raw_text.splitlines():
                    if ':' not in line:
                        continue
                    k, _, v = line.partition(':')
                    k_norm = k.strip().lower().replace(' ', '_')
                    v_clean = v.strip().split()[0].rstrip('%').replace(',', '') if v.strip() else ''
                    try:
                        smart_text[k_norm] = int(v_clean, 0)  # base=0: 0x.. hex / 0o.. octal / decimal 자동 판별
                        _raw_lines_for_key[k_norm] = line.rstrip()
                    except ValueError:
                        pass
                # 진단: critical_warning 처음 비0 검출 시 raw 라인 + raw 출력 전체 dump
                _cw = smart_text.get('critical_warning')
                _need_diag = _dump_raw or (_cw is not None and _cw != 0
                                           and not hasattr(self, '_smart_cw_diag_logged'))
                if _need_diag:
                    log.info(f"[State][DIAG] smart-log raw output ({len(_raw_text)}B):\n"
                             f"--- BEGIN ---\n{_raw_text}\n--- END ---")
                    log.info(f"[State][DIAG] critical_warning 매칭 line: "
                             f"{_raw_lines_for_key.get('critical_warning', '(없음)')}")
                    log.info(f"[State][DIAG] parsed smart_text "
                             f"keys={sorted(smart_text.keys())}")
                    self._smart_raw_logged = True
                    if _cw is not None and _cw != 0:
                        self._smart_cw_diag_logged = True
                hit = 0
                for f in self._fields:
                    if f['source'] != 'smart':
                        continue
                    text_key = _SMART_TEXT_KEY_MAP.get(f['key'], f['key'])
                    if text_key in smart_text:
                        result[f['name']] = smart_text[text_key]
                        hit += 1
                    else:
                        log.warning(f"[State] smart-log 키 없음: "
                                    f"field={f['name']} text_key={text_key}")
                log.info(f"[State] smart-log OK: {hit}개 필드 수집, "
                         f"critical_warning={smart_text.get('critical_warning', 'N/A')}")
            except Exception as e:
                log.warning(f"[State] smart-log 예외: {e}")
                return None

        # ── Vendor log (LID별 1회) ─────────────────────────────────
        # LID 실패 시 해당 LID 필드만 skip — 다른 LID/SMART 결과는 유지
        for (lid, log_len) in self._vendor_lids:
            try:
                proc = _run_nvme_state_cmd(
                    ['nvme', 'get-log', self._device,
                     f'--log-id={lid:#x}',
                     f'--log-len={log_len}',
                     '--raw-binary'])
                if proc.returncode != 0:
                    log.warning(f"[State] get-log LID={lid:#x} 실패 "
                                f"(rc={proc.returncode}): "
                                f"{proc.stderr.decode(errors='replace').strip()}")
                    continue
                raw = proc.stdout
                ok_fields = 0
                for f in self._fields:
                    if f['source'] == 'vendor' and f.get('lid') == lid:
                        start = f['offset']
                        end   = start + f['length']
                        if end > len(raw):
                            log.warning(f"[State] LID={lid:#x} 응답 짧음: "
                                        f"got={len(raw)}B need={end}B "
                                        f"field={f['name']}")
                            continue
                        val = int.from_bytes(raw[start:end],
                                             f.get('endian', 'little'))
                        result[f['name']] = val
                        ok_fields += 1
                log.info(f"[State] get-log LID={lid:#x} OK: {ok_fields}개 필드")
            except Exception as e:
                log.warning(f"[State] get-log LID={lid:#x} 예외: {e}")
                continue

        # ── Security Send → Receive (secp/spsp 그룹별 1회) ───────────
        _DUMMY_PATH = '/tmp/nvme_sec_dummy.bin'
        if self._sec_groups and not os.path.exists(_DUMMY_PATH):
            try:
                with open(_DUMMY_PATH, 'wb') as _df:
                    _df.write(b'\x00' * 4)
            except Exception as e:
                log.warning(f"[State] dummy 파일 생성 실패: {e}")

        for (secp, spsp, nsid), size in self._sec_groups.items():
            try:
                # Security Send (query submission)
                send_cmd = [
                    'nvme', 'security-send', self._device,
                    f'-p', f'{secp:#x}',
                    f'-s', f'{spsp:#x}',
                    f'-t', '4',
                    f'-f', _DUMMY_PATH,
                ]
                if nsid:
                    send_cmd += ['-n', str(nsid)]
                proc_s = _run_nvme_state_cmd(send_cmd)
                if proc_s.returncode not in (0, 1):
                    log.debug(f"[State] security-send secp={secp:#x} spsp={spsp:#x} "
                              f"rc={proc_s.returncode}: "
                              f"{proc_s.stderr.decode(errors='replace').strip()}")
                    continue
                # Security Receive (텍스트 출력 파싱 — --raw-binary 미사용)
                recv_cmd = [
                    'nvme', 'security-recv', self._device,
                    f'-p', f'{secp:#x}',
                    f'-s', f'{spsp:#x}',
                    f'-x', str(size),
                    f'-t', str(size),
                ]
                if nsid:
                    recv_cmd += ['-n', str(nsid)]
                proc_r = _run_nvme_state_cmd(recv_cmd, merge_stderr=True)
                if proc_r.returncode != 0:
                    log.debug(f"[State] security-recv secp={secp:#x} spsp={spsp:#x} "
                              f"rc={proc_r.returncode}: "
                              f"{proc_r.stdout.decode(errors='replace').strip()}")
                    continue
                # 텍스트 hex dump → bytes 변환
                raw = self._parse_sec_hex(proc_r.stdout.decode(errors='replace'))
                if not raw:
                    log.debug(f"[State] sec-recv hex 파싱 실패: "
                              f"{proc_r.stdout.decode(errors='replace')[:80]}")
                    continue
                # magic byte 검증 (raw[0] == SPSP)
                if raw[0] != (spsp & 0xFF):
                    log.warning(f"[State] sec-recv magic 불일치: "
                                f"raw[0]={raw[0]:#04x} expected={spsp & 0xFF:#04x}")
                    continue
                ok_fields = 0
                for f in self._fields:
                    if (f['source'] != 'security_recv'
                            or f['secp'] != secp
                            or f['spsp'] != spsp
                            or f.get('nsid', 0) != nsid):
                        continue
                    start = f['offset']
                    end   = start + f['length']
                    if end > len(raw):
                        log.debug(f"[State] sec-recv short: "
                                  f"got={len(raw)}B need={end}B field={f['name']}")
                        continue
                    result[f['name']] = int.from_bytes(
                        raw[start:end], f.get('endian', 'little'))
                    ok_fields += 1
                log.info(f"[State] security-recv secp={secp:#x} spsp={spsp:#x} "
                         f"OK: {ok_fields}개 필드")
            except Exception as e:
                log.warning(f"[State] security-recv secp={secp:#x} spsp={spsp:#x} 예외: {e}")
                continue

        # CSFuzz §III-B: 최초 관측 시 init_value 등록
        for name, val in result.items():
            if name not in self._init_values:
                self._init_values[name] = val
                log.info(f"[State] init_value 등록: {name}={val:,}")
        log.info(f"[State] capture 완료: 총 {len(result)}개 필드 수집")
        return result

    @staticmethod
    def _parse_sec_hex(text: str) -> Optional[bytes]:
        """nvme security-recv 텍스트 출력에서 hex 바이트 시퀀스를 추출해 bytes로 반환."""
        buf = bytearray()
        for token in text.split():
            if len(token) == 2:
                try:
                    buf.append(int(token, 16))
                except ValueError:
                    pass
        return bytes(buf) if buf else None

    @staticmethod
    def _adaptive_bucket(field: str, init: int, current: int) -> str:
        """CSFuzz §III-B Fig.3(b): 초기값 기준 power-of-2 구간 버킷.
        d=0 → '=init', d=1 → '+2^0', d=2..3 → '+2^1', d=4..7 → '+2^2', ..."""
        d = current - init
        if d == 0:
            return f'{field}:=init'
        sign = '+' if d > 0 else '-'
        n = (abs(d)).bit_length() - 1   # floor(log2(|d|))
        return f'{field}:{sign}2^{n}'

    def delta(self,
              before: Dict[str, int],
              after:  Dict[str, int]) -> NVMeStateDelta:
        changes = {
            name: after.get(name, 0) - before.get(name, 0)
            for name in self._weights
        }
        # 변화 횟수 누적 (delta 호출마다 — before/after 비교 시점)
        for name, diff in changes.items():
            if diff != 0:
                self._change_counts[name] = self._change_counts.get(name, 0) + 1

        # 동적 effective weight: static_weight / log2(2 + change_count)
        # 자주 바뀌는 필드일수록 weight 자동 감소
        effective_weights = {
            name: self._weights[name] / math.log2(2 + self._change_counts.get(name, 0))
            for name in self._weights
        }

        # CSFuzz §III-B: 각 필드를 초기값 기준 power-of-2 구간으로 버킷화
        buckets: List[str] = []
        init_deltas: Dict[str, int] = {}
        for name in self._weights:
            if name not in self._init_values:
                continue
            current = after.get(name, 0)
            init    = self._init_values[name]
            d = current - init
            init_deltas[name] = d
            buckets.append(self._adaptive_bucket(name, init, current))
        return NVMeStateDelta(
            changes=changes,
            weights=effective_weights,
            buckets=buckets,
            init_deltas=init_deltas,
        )

    def update_cov_map(self,
                       delta: NVMeStateDelta,
                       cov_map: Dict[str, int]) -> bool:
        """새 (field, bucket) 조합이면 cov_map 갱신 후 True 반환.
        '=init' 버킷은 기준점이므로 새 state로 취급하지 않음."""
        is_new = False
        for bucket in delta.state_buckets():
            if bucket.endswith(':=init'):
                continue
            if bucket not in cov_map:
                cov_map[bucket] = 0
                is_new = True
            cov_map[bucket] += 1
        return is_new


class NullSampler:
    """J-Link 없이 NVMe fuzz 만 수행할 때 쓰는 no-op sampler.

    `--no-jlink` 활성 시 `OpenOCDPCSampler` 대신 사용. 모든 PC 수집/커버리지
    관련 메서드는 안전한 빈 값/True 를 반환하여 main loop 가 그대로 동작.
    NVMe 명령 전송, state telemetry, PM rotation, crash detection (timeout
    기준) 은 모두 그대로 작동 — coverage 측면만 0 으로 표시.
    """

    def __init__(self, config: 'FuzzConfig') -> None:
        self.config = config
        # 빈 coverage 자료구조 — fuzzer 곳곳에서 참조하므로 None 대신 빈 컨테이너
        self.global_coverage: Set[int] = set()
        self.current_trace:   Set[int] = set()
        self.idle_pcs:        Set[int] = set()
        self.idle_pc:         Optional[int] = None
        self._last_raw_pcs:   List[int] = []
        self._last_new_pcs:   Set[int]  = set()
        self._last_new_at:    int = 0
        self._unique_at_intervals: dict = {}
        self._out_of_range_count: int = 0
        self._stopped_reason: str = ''
        self.total_samples: int = 0
        self.interesting_inputs: int = 0
        # main loop 가 참조할 수 있는 threading 객체 — set 되지 않은 상태로 유지
        self.stop_event    = threading.Event()
        self.openocd_error = threading.Event()
        self.sample_thread = None

    # ── 라이프사이클 / 인프라 (모두 성공으로 가장) ─────────────────
    def connect(self) -> bool:
        log.warning("[NullSampler] J-Link 비활성 모드 — coverage 수집 안 함")
        return True
    def _terminate_proc(self) -> None: pass
    def _close_telnet(self) -> None: pass
    def close(self) -> None: pass
    def _openocd_alive(self) -> bool: return False
    def _reinit_target(self) -> bool: return False
    def _reconnect(self) -> bool: return True

    # ── PC 읽기 (항상 빈 결과) ─────────────────────────────────
    def _read_all_pcs(self) -> Optional[Tuple[int, ...]]:
        return None
    def _in_range(self, pc: int) -> bool:
        return False
    def diagnose(self, count: int = 20) -> bool:
        log.warning("[NullSampler] diagnose 건너뜀 (idle_pcs 비어 있음)")
        return True
    def read_stuck_pcs(self, count: int = 10) -> List[Tuple[int, ...]]:
        return []

    # ── 샘플링 / 커버리지 (no-op) ─────────────────────────────
    def start_sampling(self) -> None:
        self.current_trace = set()
        self._last_raw_pcs = []
    def stop_sampling(self) -> int:
        return 0
    def _stop_worker(self) -> None:
        pass
    def evaluate_coverage(self) -> Tuple[bool, int]:
        # 항상 (interesting=False, new_pcs=0). coverage 신호 없이 fuzz 진행.
        self._last_new_pcs = set()
        return False, 0

    # ── 영속성 (no-op) ─────────────────────────────────────
    def load_coverage(self, filepath: str) -> int:
        log.info(f"[NullSampler] load_coverage 건너뜀: {filepath}")
        return 0
    def save_coverage(self, output_dir: str) -> None:
        # 빈 coverage.txt 라도 작성하여 후처리 스크립트 호환
        pc_path = os.path.join(output_dir, 'coverage.txt')
        try:
            with open(pc_path, 'w') as f:
                pass
            log.info(f"[NullSampler] empty coverage.txt 작성 → {_logname(pc_path)}")
        except OSError:
            pass


class OpenOCDPCSampler:
    """OpenOCD PCSR 비침습 PC 수집기 (3코어 동시, halt 없음)

    r8_pcsr.cfg 설정 파일로 OpenOCD를 서브프로세스로 실행하고,
    telnet 포트(4444)를 통해 Tcl 명령으로 PCSR을 읽는다.
    PCSR = CoreBase+0x084 (APB-AP, ap-num 0): halt 없이 현재 PC를 반환.
    """

    _INTERVAL_CHECKPOINTS = frozenset({10, 25, 50, 100, 200, 500})
    _SOCK_TIMEOUT    = 2.0    # 소켓 recv 타임아웃 (초)
    _RECV_BUF        = 4096
    _CONSECUTIVE_FAIL_LIMIT = 10  # 연속 read 실패 시 stop_event 세팅
    _always_on  = False           # PCSR 비침습: 상시 워커 + per-command 윈도우 (기본 off)
    _win_active = False           # always-on: 현재 명령 윈도우 활성 여부

    def __init__(self, config: FuzzConfig):
        self.config = config
        self._proc: Optional[subprocess.Popen] = None
        self._sock: Optional[socket.socket]    = None

        # Primary coverage signal
        self.global_coverage: Set[int] = set()
        self.current_trace:   Set[int] = set()

        self.stop_event    = threading.Event()
        self.openocd_error = threading.Event()  # 연속 실패로 샘플링 불가 → 메인 루프에 통보
        self.sample_thread: Optional[threading.Thread] = None
        self.total_samples    = 0
        self.interesting_inputs = 0
        self._last_raw_pcs: List[int] = []
        self._out_of_range_count = 0
        self._last_new_pcs: set = set()
        self._last_new_at:  int = 0
        self._unique_at_intervals: dict = {}
        self._stopped_reason: str = ""

        # always-on(PCSR 비침습): 상시 워커 1개로 total coverage(백그라운드/명령 사이 포함)를
        # 잡고, per-command 신규 판정은 윈도우(_win_active) 구간으로 한정. 워커는 global_coverage
        # 를 직접 건드리지 않는다(락 회피) — 명령 사이 샘플은 _bg_pcs(워커 전용)에 모았다가
        # 메인 스레드가 _fold_bg() 로 안전하게 global_coverage 에 합친다.
        self._always_on  = (config.sampler_type == 'pcsr')
        self._win_active = False
        self._bg_pcs: Set[int] = set()

        self.idle_pc:  Optional[int] = None
        self.idle_pcs: Set[int]      = set()
        self._sock_buf: bytes        = b''   # 소켓 읽기 잔여 버퍼

        # v8.0: product profile 의 PCSR 주소 사용 (product 주도).
        #   profile 미지정(구식 --interface 경로)이면 interface 기본값으로 폴백.
        if config.pcsr_addrs:
            self._pcsr_addrs: List[int] = list(config.pcsr_addrs)
        else:
            self._pcsr_addrs = (
                PCSR_ADDRS_JTAG if config.interface == 'jtag' else PCSR_ADDRS_SWD
            )
        # OpenOCD cfg 가 만든 target object 접두사 (r8.* / r5.*)
        self._tcl_prefix: str = config.tcl_prefix
        # PCSR 주소 자체가 에러 메시지에 노출될 경우 무효 PC로 필터링
        _addr_mask: Set[int] = set()
        for _a in self._pcsr_addrs:
            _addr_mask.add(_a); _addr_mask.add(_a & ~1)
        self._invalid_pc_mask: frozenset = frozenset(
            set(config.invalid_pc_vals) | _addr_mask
        )

    # ------------------------------------------------------------------
    # Module 1: 서브프로세스 라이프사이클
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """OpenOCD 실행, telnet 연결, 전원 활성화 + proc 정의, PCSR 검증."""
        try:
            self._kill_stale_openocd()
            if not self._launch_openocd():
                return False
            self._open_telnet()
            self._send_startup_tcl()
            ok = self._verify_pcsr()
            if ok:
                log.warning(f"[OpenOCD] 연결 성공: PCSR read 검증 완료 ({len(self._pcsr_addrs)}코어).")
            else:
                log.error(f"[OpenOCD] PCSR 검증 실패 — {self.config.openocd_config} 및 대상 전원 확인.")
                self._close_telnet()
                self._terminate_proc()
            return ok
        except Exception as e:
            log.error(f"[OpenOCD] connect() 오류: {e}")
            self._close_telnet()
            self._terminate_proc()
            return False

    def _terminate_proc(self):
        """OpenOCD 서브프로세스 강제 종료."""
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None

    def _kill_stale_openocd(self):
        """포트 충돌 방지: 기존 OpenOCD 프로세스 종료 (포트+이름 양쪽)."""
        try:
            subprocess.run(['fuser', '-k', f'{self.config.openocd_port}/tcp'],
                           capture_output=True, timeout=3.0)
        except Exception:
            pass
        try:
            subprocess.run(['pkill', '-x', 'openocd'],
                           capture_output=True, timeout=3.0)
        except Exception:
            pass
        time.sleep(1.0)   # USB 장치 해제 대기

    def _launch_openocd(self) -> bool:
        """OpenOCD 서브프로세스 시작 후 포트 대기."""
        cfg_path = self.config.openocd_config
        if not os.path.isabs(cfg_path):
            cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), cfg_path)
        if not os.path.exists(cfg_path):
            log.error(f"[OpenOCD] 설정 파일 없음: {cfg_path}")
            return False
        cmd = [self.config.openocd_binary, '-f', cfg_path]
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except FileNotFoundError:
            log.error(f"[OpenOCD] 바이너리를 찾을 수 없음: {self.config.openocd_binary}")
            return False
        if not self._wait_for_port():
            log.error(f"[OpenOCD] 포트 {self.config.openocd_port} 대기 타임아웃 "
                      f"({self.config.openocd_timeout}s). OpenOCD 시작 실패.")
            self._proc.terminate()
            try:
                _, stderr_data = self._proc.communicate(timeout=2.0)
                if stderr_data:
                    for line in stderr_data.decode(errors='replace').splitlines():
                        log.error(f"[OpenOCD stderr] {line}")
            except Exception:
                pass
            return False
        return True

    def _wait_for_port(self) -> bool:
        deadline = time.time() + self.config.openocd_timeout
        while time.time() < deadline:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.2)
                s.connect((self.config.openocd_host, self.config.openocd_port))
                s.close()
                return True
            except Exception:
                time.sleep(0.2)
        return False

    def _openocd_alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def _reinit_target(self) -> bool:
        """OpenOCD 프로세스 유지 + 타겟 디버그 전원 재활성화 + proc 재정의.

        SSD 펌웨어 reset 등으로 APB-AP 접근이 끊어졌을 때 사용.
        OpenOCD를 재시작하지 않으므로 빠름 (~1초).
        소켓만 죽은 경우(half-open)도 여기서 복구: telnet 재연결 후 startup TCL 전송.
        실패 시 False 반환 → 호출자가 _reconnect()로 escalate.
        """
        self._stop_worker()   # always-on: 소켓 만지기 전 워커 정지(경합 방지)
        if not self._openocd_alive():
            return False
        try:
            log.warning("[OpenOCD] 타겟 재초기화 시도 (전원 재활성화 + proc 재정의)...")
            # 소켓이 닫혀있으면 먼저 재연결 (stop_sampling()의 강제 close 이후 케이스)
            if self._sock is None:
                log.warning("[OpenOCD] 소켓 없음 — telnet 재연결 시도...")
                self._open_telnet()
            self._send_startup_tcl()
            result = self._read_all_pcs()
            if result is not None:
                _cs = ' '.join(f'Core{i}={hex(pc)}' for i, pc in enumerate(result))
                log.warning(f"[OpenOCD] 타겟 재초기화 성공: {_cs}")
                return True
            log.warning("[OpenOCD] 타겟 재초기화 후 PCSR 읽기 실패 — OpenOCD 재시작으로 전환")
            return False
        except Exception as e:
            log.warning(f"[OpenOCD] 타겟 재초기화 예외: {e}")
            return False

    def _reconnect(self) -> bool:
        log.warning("[OpenOCD] 재시작 시도...")
        self._stop_worker()   # always-on: 소켓/프로세스 만지기 전 워커 정지(경합 방지)
        self._close_telnet()
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None
        return self._launch_openocd() and self._reopen_telnet()

    def _reopen_telnet(self) -> bool:
        try:
            self._open_telnet()
            self._send_startup_tcl()
            return True
        except Exception as e:
            log.error(f"[OpenOCD] telnet 재연결 실패: {e}")
            return False

    # ------------------------------------------------------------------
    # Module 2: Telnet 통신 (raw socket)
    # ------------------------------------------------------------------

    def _open_telnet(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self._SOCK_TIMEOUT)
        s.connect((self.config.openocd_host, self.config.openocd_port))
        self._sock = s
        self._sock_buf = b''
        # 초기 배너 전체 drain: OpenOCD가 > 를 여러 번 보낼 수 있음.
        # 0.5초 대기 후 수신 가능한 데이터를 모두 버려 clean slate 확보.
        time.sleep(0.5)
        self._sock.settimeout(0.2)
        try:
            while True:
                chunk = self._sock.recv(self._RECV_BUF)
                if not chunk:
                    break
        except socket.timeout:
            pass
        finally:
            self._sock.settimeout(self._SOCK_TIMEOUT)
        self._sock_buf = b''   # 버퍼 완전 초기화

    def _close_telnet(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        self._sock_buf = b''

    def _sock_read_until(self, marker: str) -> str:
        """marker가 나올 때까지 읽기. 잔여 데이터는 _sock_buf에 보존."""
        marker_b = marker.encode()
        while True:
            # 이미 버퍼에 marker가 있으면 바로 반환
            idx = self._sock_buf.find(marker_b)
            if idx != -1:
                result = self._sock_buf[:idx]
                # marker 이후 남은 데이터 보존 (다음 호출에 사용)
                self._sock_buf = self._sock_buf[idx + len(marker_b):]
                return result.decode(errors='replace').strip()
            # 더 읽기
            try:
                chunk = self._sock.recv(self._RECV_BUF)
            except socket.timeout:
                result = self._sock_buf
                self._sock_buf = b''
                return result.decode(errors='replace').strip()
            if not chunk:
                result = self._sock_buf
                self._sock_buf = b''
                return result.decode(errors='replace').strip()
            self._sock_buf += chunk

    def _telnet_cmd(self, cmd: str) -> str:
        self._sock.sendall((cmd + '\n').encode())
        return self._sock_read_until('> ')

    def _send_startup_tcl(self):
        """전원 활성화 + read_all_pcs proc 정의 (connect/reconnect 공통)."""
        log.info(f"[Startup] interface={self.config.interface!r}, "
                 f"cores={[hex(a) for a in self._pcsr_addrs]}")

        _px = self._tcl_prefix   # OpenOCD target object 접두사 (r8 / r5)

        # DP CTRL/STAT power-up (CDBGPWRUPREQ | CSYSPWRUPREQ)
        self._telnet_cmd(f'{_px}.dap dpreg 4 0x50000000')
        time.sleep(0.05)

        # sticky error 클리어
        self._telnet_cmd(f'{_px}.dap dpreg 0 0x1e')

        # 칩 고유 per-core debug power enable (AXI AP 경유)
        # AXI write 후 sticky error가 생길 수 있으므로 즉시 클리어
        # v8.0: power_addr 가 None 인 제품(예: P9 bring-up 전)은 이 단계 생략.
        _pwr_addr = self.config.power_addr
        _pwr_mask = self.config.power_mask
        if _pwr_addr is not None and _pwr_mask is not None:
            self._telnet_cmd(
                f'catch {{set _pwr [lindex [{_px}.axi read_memory {hex(_pwr_addr)} 32 1] 0]}}'
            )
            self._telnet_cmd(
                f'catch {{{_px}.axi write_memory {hex(_pwr_addr)} 32 '
                f'[expr {{$_pwr | {hex(_pwr_mask)}}}]}}'
            )
            self._telnet_cmd(f'{_px}.dap dpreg 0 0x1e')

        # read_all_pcs proc 정의 — self._pcsr_addrs 기반으로 코어 수 유연하게 구성
        # JTAG: proc 내 dpreg 제거 (JTAG 상태머신 간섭 방지)
        # SWD: dpreg 0 0x1e로 sticky error 사전 클리어 유지
        _read_stmts = ''.join(
            f'  set pc{i} [lindex [{_px}.abp read_memory {hex(addr)} 32 1] 0];'
            for i, addr in enumerate(self._pcsr_addrs)
        )
        _ret_vars = ' '.join(f'$pc{i}' for i in range(len(self._pcsr_addrs)))
        if self.config.interface == 'jtag':
            proc_body = (
                'proc read_all_pcs {} {'
                ' if {[catch {'
                + _read_stmts +
                ' } _err]} { return "ERR:$_err" };'
                f' return "{_ret_vars}"'
                ' }'
            )
        else:
            proc_body = (
                'proc read_all_pcs {} {'
                f' catch {{{_px}.dap dpreg 0 0x1e}};'
                ' if {[catch {'
                + _read_stmts +
                ' } _err]} { return "ERR:$_err" };'
                f' return "{_ret_vars}"'
                ' }'
            )
        self._telnet_cmd(proc_body)
        log.info("[Startup] read_all_pcs proc 정의 완료")

    def _verify_pcsr(self) -> bool:
        result = self._read_all_pcs()
        if result is not None:
            cores_str = ' '.join(f'Core{i}={hex(pc)}' for i, pc in enumerate(result))
            log.info(f"[OpenOCD] PCSR 검증 OK: {cores_str}")
        return result is not None

    # ------------------------------------------------------------------
    # Module 3: 3코어 PC 읽기
    # ------------------------------------------------------------------

    def _read_all_pcs(self) -> Optional[Tuple[int, ...]]:
        """PCSR 배치 읽기: 1 RTT = N코어 PC 튜플. Thumb bit 마스킹 포함."""
        n = len(self._pcsr_addrs)
        try:
            resp = self._telnet_cmd('read_all_pcs')
            _resp_lower = resp.lower()
            if resp.startswith('ERR:') or 'error' in _resp_lower or 'failed' in _resp_lower:
                log.warning(f"[OpenOCD] 에러 응답 감지: {repr(resp)}")
                return None
            parts = re.findall(r'0x[0-9a-fA-F]+', resp)
            if len(parts) != n:
                log.warning(f"[OpenOCD] 파싱 실패 (토큰 {len(parts)}개, 기대 {n}개): {repr(resp)}")
                return None
            pcs = tuple(int(p, 16) & ~1 for p in parts[:n])
            # 무효 PC 필터 1: sentinel(0xFFFFFFFE) 또는 0 — 모두 해당할 때만
            _sentinel = {0, 0xFFFFFFFE}
            if all(pc in _sentinel for pc in pcs):
                log.warning(f"[OpenOCD] 무효 PC 튜플 (sentinel): "
                            f"{' '.join(f'Core{i}={hex(pc)}' for i, pc in enumerate(pcs))}")
                return None
            # 무효 PC 필터 2: DPIDR / PCSR 주소 자체 — 에러 메시지 오염 잔류 방어
            if any(pc in self._invalid_pc_mask for pc in pcs):
                log.warning(f"[OpenOCD] 무효 PC 튜플 (비-PC 값 포함): "
                            f"{' '.join(f'Core{i}={hex(pc)}' for i, pc in enumerate(pcs))}")
                return None
            log.debug(f"[PCSR] {' '.join(f'Core{i}={hex(pc)}' for i, pc in enumerate(pcs))}")
            return pcs
        except Exception as e:
            log.warning(f"[OpenOCD] _read_all_pcs 예외: {e}")
            return None

    # ------------------------------------------------------------------
    # Module 4: diagnose() — idle 유니버스 수집 (PCSR 적응 버전)
    # ------------------------------------------------------------------

    def diagnose(self, count: int = 20) -> bool:
        """PCSR 기반 idle 유니버스 수집.

        halt 없이 PCSR을 반복 읽어 idle 상태의 PC 집합을 수집한다.
        새 PC가 DIAGNOSE_STABILITY회 연속 나타나지 않으면 수렴으로 판정.
        3코어 튜플을 한 번에 읽으므로 샘플당 최대 3개의 새 PC를 발견할 수 있다.
        """
        stability   = self.config.diagnose_stability
        max_samples = self.config.diagnose_max
        _diag_sleep_ms = self.config.diagnose_sample_ms
        _diag_sleep = max(_diag_sleep_ms, 0) / 1000.0

        log.warning(f"[Diagnose] idle 유니버스 수집 시작 "
                    f"(수렴: {stability}회 연속, max={max_samples}회, "
                    f"간격={_diag_sleep_ms}ms, "
                    f"예상최악={max_samples * _diag_sleep_ms / 1000:.0f}s)...")

        # 1단계: 초기 min(count,20)회 — 동작 검증 + 로그 출력
        initial = min(count, 20)
        pcs_initial: List[int] = []
        failures = 0
        for i in range(initial):
            result = self._read_all_pcs()
            if result is not None:
                for pc in result:
                    pcs_initial.append(pc)
                in_str = ', '.join(hex(p) for p in result)
                log.warning(f"  [{i+1:2d}] PCs = ({in_str})")
            else:
                failures += 1
                log.warning(f"  [{i+1:2d}] PCSR read FAILED")
            if _diag_sleep > 0:
                time.sleep(_diag_sleep)

        if not pcs_initial:
            log.error("[Diagnose] PC를 한 번도 읽지 못했습니다. OpenOCD 연결 및 r8_pcsr.cfg를 확인하세요.")
            return False

        # 2단계: 수렴 기반 adaptive 샘플링
        # 수렴 조건: stability회 연속 새 PC 없음 AND 최소 min_samples 이상 수집
        # min_samples 보장 이유: 주기적 IRQ 핸들러가 stability 간격보다 긴 주기로 뜨면
        # 조기 수렴으로 해당 PC가 idle_pcs에서 누락됨
        min_samples = max(stability * 3, 500)  # 최소 보장 샘플 수
        idle_universe: Set[int] = set(pcs_initial)
        consecutive_no_new = 0
        total = initial
        consecutive_failures = 0
        total_failures = 0

        log.warning(f"[Diagnose] 초기 {initial}회 완료, unique PCs={len(idle_universe)}. "
                    f"idle 유니버스 수렴 샘플링 시작 (최소 {min_samples}회 보장)...")

        while total < max_samples:
            result = self._read_all_pcs()
            total += 1
            if result is not None:
                consecutive_failures = 0
                new_found = [pc for pc in result if pc not in idle_universe]
                if new_found:
                    for pc in new_found:
                        idle_universe.add(pc)
                    consecutive_no_new = 0
                    log.warning(f"  [+{total:4d}] 새 idle PC: "
                                f"{[hex(p) for p in new_found]} "
                                f"(누적 {len(idle_universe)}개)")
                else:
                    consecutive_no_new += 1
            else:
                consecutive_failures += 1
                total_failures += 1
                consecutive_no_new += 1
            if _diag_sleep > 0:
                time.sleep(_diag_sleep)
            # 수렴: stability 연속 AND 최소 샘플 수 충족
            if consecutive_no_new >= stability and total >= min_samples:
                break

        if consecutive_no_new >= stability:
            log.warning(f"[Diagnose] idle 유니버스 수렴 완료: "
                        f"{len(idle_universe)}개 PC, {total}회 샘플 "
                        f"(새 PC 없이 {consecutive_no_new}회 연속)")
        else:
            log.warning(f"[Diagnose] 최대 샘플({max_samples}회) 도달. "
                        f"idle 유니버스 {len(idle_universe)}개 (수렴 미완료, 이대로 사용)")

        self.idle_pcs = set(idle_universe)

        from collections import Counter
        pc_counts = Counter(pcs_initial)
        self.idle_pc = pc_counts.most_common(1)[0][0]

        fail_rate = total_failures / total * 100 if total > 0 else 0
        fail_msg = (f", DAP 실패율={fail_rate:.1f}% ({total_failures}/{total}회)"
                    if total_failures > 0 else "")
        if fail_rate > 10:
            log.warning(f"[Diagnose] 완료: idle_pcs={len(self.idle_pcs)}개, "
                        f"대표 PC={hex(self.idle_pc)}{fail_msg} ← 불안정 주의")
        else:
            log.warning(f"[Diagnose] 완료: idle_pcs={len(self.idle_pcs)}개, "
                        f"대표 PC={hex(self.idle_pc)}{fail_msg}")
        return True

    # ------------------------------------------------------------------
    # Module 5: read_stuck_pcs
    # ------------------------------------------------------------------

    def read_stuck_pcs(self, count: int = 10) -> List[Tuple[int, int, int]]:
        """crash/timeout 후 SSD 펌웨어 위치를 반복 샘플링.
        PCSR 방식: halt 없이 읽으므로 펌웨어 동작에 무관.
        반환값: [(core0_pc, core1_pc, core2_pc), ...] — 코어 구분 보존."""
        if not self._openocd_alive():
            log.warning("[OpenOCD] 프로세스 없음 — stuck PC 읽기 스킵")
            return []
        samples = []
        for _ in range(count):
            result = self._read_all_pcs()
            if result:
                samples.append(result)
            time.sleep(0.05)
        return samples

    def _in_range(self, pc: int) -> bool:
        """PC가 펌웨어 주소 범위 내인지 확인"""
        if self.config.addr_range_start is None or self.config.addr_range_end is None:
            return True
        return self.config.addr_range_start <= pc <= self.config.addr_range_end

    # ------------------------------------------------------------------
    # Module 6: 샘플링 스레드 (3코어 튜플 처리)
    # ------------------------------------------------------------------

    def _sampling_worker(self):
        """PC 주소 기반 글로벌 포화 체크 (3코어 PCSR 튜플 단위).

        global_coverage_ref(unique PC set) 기반 포화 판단:
        튜플 내 어느 한 코어라도 새 PC → global 카운터 리셋.
        idle 판정: 튜플 내 in-range PC가 모두 idle_pcs에 속할 때만 idle 카운트.
        이유: Core 1/2가 idle이어도 Core 0이 NVMe 처리 중이면 조기 종료 안 함.
        """
        self.current_trace = set()
        self._last_raw_pcs = []
        self._out_of_range_count = 0
        self._last_new_at = 0
        self._unique_at_intervals = {}
        self._stopped_reason = ""

        sample_count = 0
        since_last_global_new = 0
        consecutive_idle = 0
        _consecutive_fail  = 0
        from collections import deque as _deque
        _recent_pcs = _deque(maxlen=IDLE_WINDOW_SIZE)
        _recent_idle_count = 0
        _idle_win_thresh = int(IDLE_WINDOW_SIZE * IDLE_RATIO_THRESH)

        _addr_start = self.config.addr_range_start
        _addr_end   = self.config.addr_range_end
        _has_range  = _addr_start is not None and _addr_end is not None

        interval = self.config.sample_interval_us / 1_000_000
        # GO_SETTLE: halt 샘플러에서 resume 후 다음 halt 까지 코어 최소 실행시간 보장
        # (NVMe 명령 굶김/timeout 방지). PCSR 은 go_settle_ms=0 이라 max(interval,0)=interval 무영향.
        effective_interval = max(interval, self.config.go_settle_ms / 1_000.0)
        sat_limit        = SATURATION_LIMIT
        global_sat_limit = GLOBAL_SATURATION_LIMIT
        idle_pcs         = self.idle_pcs
        global_coverage_ref = self.global_coverage

        while not self.stop_event.is_set() and sample_count < self.config.max_samples_per_run:
            pcs_tuple = self._read_all_pcs()

            if pcs_tuple is None:
                _consecutive_fail += 1
                if _consecutive_fail >= self._CONSECUTIVE_FAIL_LIMIT:
                    log.error(f"[OpenOCD] PCSR read 연속 {_consecutive_fail}회 실패 — 샘플링 중단")
                    self.stop_event.set()
                    self.openocd_error.set()
                    break
                if effective_interval > 0:
                    time.sleep(effective_interval)
                continue
            _consecutive_fail = 0

            # 범위 분류
            in_range_pcs = [
                pc for pc in pcs_tuple
                if not _has_range or (_addr_start <= pc <= _addr_end)
            ]
            out_range_count = len(pcs_tuple) - len(in_range_pcs)
            self._out_of_range_count += out_range_count

            # raw log (3코어 모두)
            self._last_raw_pcs.extend(pcs_tuple)

            # in-range PC → current_trace 추가
            for pc in in_range_pcs:
                self.current_trace.add(pc)

            # 글로벌 포화 판정 (튜플 단위: 어느 코어든 새 PC이면 리셋)
            if in_range_pcs:
                has_new_global = any(pc not in global_coverage_ref for pc in in_range_pcs)
                if has_new_global:
                    self._last_new_at = sample_count
                    since_last_global_new = 0
                else:
                    since_last_global_new += 1

            # idle 판정 (튜플 단위: in-range PC가 모두 idle_pcs에 속해야 idle)
            if in_range_pcs and idle_pcs:
                _tuple_all_idle = all(pc in idle_pcs for pc in in_range_pcs)
            else:
                _tuple_all_idle = False

            if _tuple_all_idle:
                consecutive_idle += 1
            else:
                consecutive_idle = 0

            _evicted = _recent_pcs[0] if len(_recent_pcs) == IDLE_WINDOW_SIZE else False
            _recent_pcs.append(_tuple_all_idle)
            _recent_idle_count += int(_tuple_all_idle) - int(_evicted)

            sample_count += 1
            self.total_samples += 1

            if sample_count in self._INTERVAL_CHECKPOINTS:
                self._unique_at_intervals[sample_count] = len(self.current_trace)

            # 조기 종료 조건 (OR)
            if sat_limit > 0:
                if global_sat_limit > 0 and since_last_global_new >= global_sat_limit:
                    self._stopped_reason = (
                        f"global_saturated (no new PC for "
                        f"{since_last_global_new} consecutive samples, "
                        f"limit={global_sat_limit})"
                    )
                    break
                if idle_pcs and consecutive_idle >= sat_limit:
                    self._stopped_reason = (
                        f"idle_saturated (idle universe hit "
                        f"{consecutive_idle} consecutive, "
                        f"universe_size={len(idle_pcs)})"
                    )
                    break
                if (idle_pcs
                        and len(_recent_pcs) == IDLE_WINDOW_SIZE
                        and _recent_idle_count >= _idle_win_thresh):
                    _ratio = _recent_idle_count / IDLE_WINDOW_SIZE
                    self._stopped_reason = (
                        f"idle_saturated (window_ratio "
                        f"{_ratio:.0%} >= {IDLE_RATIO_THRESH:.0%}, "
                        f"window={IDLE_WINDOW_SIZE})"
                    )
                    break

            if effective_interval > 0:
                time.sleep(effective_interval)

        if not self._stopped_reason:
            if self.stop_event.is_set():
                self._stopped_reason = "stop_event"
            else:
                self._stopped_reason = f"max_samples ({self.config.max_samples_per_run})"

    def _sampling_worker_always_on(self):
        """always-on(PCSR) 워커 — 세션 내내 1개만 가동.

        - 윈도우 활성(_win_active) 중 in-range PC → current_trace (per-command attribution).
          global_coverage 는 건드리지 않음(윈도우 종료 후 evaluate_coverage 가 갱신).
        - 윈도우 비활성(명령 사이/백그라운드) 중 신규 PC → _bg_pcs(워커 전용 set)에 누적.
          메인 스레드가 _fold_bg() 로 global_coverage 에 합친다 → 락 없이 경합 회피
          (워커는 global_coverage 를 mutate 하지 않고 멤버십 read 만 함).
        조기 포화 종료 없음 — 윈도우 길이는 명령 지속시간으로 자연 결정.
        """
        interval = self.config.sample_interval_us / 1_000_000
        effective_interval = max(interval, self.config.go_settle_ms / 1_000.0)
        _addr_start = self.config.addr_range_start
        _addr_end   = self.config.addr_range_end
        _has_range  = _addr_start is not None and _addr_end is not None
        _consecutive_fail = 0
        sample_count = 0
        while not self.stop_event.is_set():
            pcs_tuple = self._read_all_pcs()
            if pcs_tuple is None:
                _consecutive_fail += 1
                if _consecutive_fail >= self._CONSECUTIVE_FAIL_LIMIT:
                    log.error(f"[OpenOCD] PCSR read 연속 {_consecutive_fail}회 실패 "
                              f"— always-on 샘플링 중단 (다음 명령에서 재가동)")
                    self.openocd_error.set()
                    break
                if effective_interval > 0:
                    time.sleep(effective_interval)
                continue
            _consecutive_fail = 0
            in_range_pcs = [pc for pc in pcs_tuple
                            if not _has_range or (_addr_start <= pc <= _addr_end)]
            sample_count += 1
            self.total_samples += 1
            if self._win_active:
                self._out_of_range_count += len(pcs_tuple) - len(in_range_pcs)
                self._last_raw_pcs.extend(pcs_tuple)
                for pc in in_range_pcs:
                    self.current_trace.add(pc)
                    if pc not in self.global_coverage:
                        self._last_new_at = sample_count   # plateau 신호(글로벌 갱신은 evaluate)
            else:
                for pc in in_range_pcs:
                    if pc not in self.global_coverage:
                        if pc not in self._bg_pcs:
                            self._last_new_at = sample_count
                        self._bg_pcs.add(pc)
            if effective_interval > 0:
                time.sleep(effective_interval)

    def _fold_bg(self):
        """워커가 명령 사이에 모은 _bg_pcs 를 global_coverage 로 합침(메인 스레드 전용).
        참조 재할당으로 워커와의 경합 없이 스냅샷 → union."""
        if self._bg_pcs:
            bg = self._bg_pcs
            self._bg_pcs = set()
            self.global_coverage.update(bg)

    def _stop_worker(self):
        """샘플링 워커 정지 — POR/reconnect 전 소켓 경합 방지. 다음 start_sampling 이 재가동.
        always-on/windowed 공용(둘 다 sample_thread 사용)."""
        self._win_active = False
        if self.sample_thread and self.sample_thread.is_alive():
            self.stop_event.set()
            self.sample_thread.join(timeout=2.0)
            if self.sample_thread.is_alive():
                self._close_telnet()
                self.sample_thread.join(timeout=1.0)
        self.sample_thread = None

    def start_sampling(self):
        if self._always_on:
            # 상시 워커 lazy-start (POR/연속실패로 죽었으면 재가동)
            if not (self.sample_thread and self.sample_thread.is_alive()):
                if not self._openocd_alive():
                    log.warning("[OpenOCD] 프로세스가 종료됨 — always-on 재시작 시도...")
                    if not self._reconnect():
                        log.error("[OpenOCD] 재시작 실패 — 이번 실행 샘플링 스킵")
                        return
                self.stop_event.clear()
                self.sample_thread = threading.Thread(
                    target=self._sampling_worker_always_on, daemon=True)
                self.sample_thread.start()
            # 이미 윈도우 활성이면(FWDownload 다중 청크 등) 리셋 없이 누적 유지
            if self._win_active:
                return
            # 명령 사이에 쌓인 백그라운드 PC 를 먼저 global_coverage 로 흡수 → 이번 명령의
            # 신규 판정이 백그라운드 발견분을 새것으로 오인하지 않게 함.
            self._fold_bg()
            # 새 per-command 윈도우 시작 (윈도우 상태만 리셋, global_coverage 보존)
            self.current_trace = set()
            self._last_raw_pcs = []
            self._out_of_range_count = 0
            self._unique_at_intervals = {}
            self._stopped_reason = "always_on"
            self._win_active = True
            return
        # 이미 샘플링 중이면 스킵 (PM 구간에서 먼저 시작한 경우 중복 방지)
        if self.sample_thread and self.sample_thread.is_alive():
            return
        # OpenOCD 생존 확인 → 크래시 시 자동 재시작
        if not self._openocd_alive():
            log.warning("[OpenOCD] 프로세스가 종료됨 — 재시작 시도...")
            if not self._reconnect():
                log.error("[OpenOCD] 재시작 실패 — 이번 실행 샘플링 스킵")
                return
        self.stop_event.clear()
        self.sample_thread = threading.Thread(target=self._sampling_worker, daemon=True)
        self.sample_thread.start()

    def stop_sampling(self) -> int:
        """샘플링 종료 후 이번 실행에서 관측된 unique PC 수를 반환 (primary signal).

        current_trace: unique PC 주소 set — 결정론적, primary coverage signal.
        last_run 로그값이 PC 수를 나타내므로 global_pcs와 직접 비교 가능.
        """
        if self._always_on:
            # 윈도우만 종료 — 워커는 계속(명령 사이 백그라운드 누적). evaluate_coverage 가
            # current_trace - global_coverage 로 이번 명령 신규분을 산출(워커가 윈도우 중엔
            # global_coverage 를 안 건드렸으므로 diff 가 정확).
            self._win_active = False
            return len(self.current_trace)
        if self.sample_thread:
            self.stop_event.set()
            self.sample_thread.join(timeout=2.0)
            if self.sample_thread.is_alive():
                # 소켓 half-open 상태: recv()가 _SOCK_TIMEOUT(2.0s)씩 블로킹하며
                # _consecutive_fail이 쌓이기 전에 join이 반복 timeout되는 구조.
                # 소켓을 강제 종료하면 recv()가 즉시 예외를 던져 스레드가 빠져나온다.
                log.warning("[Sampler] stop_sampling() 2.0s join timeout — "
                            "소켓 강제 종료로 샘플링 스레드 해제 시도")
                self._close_telnet()
                self.openocd_error.set()   # 메인 루프에 복구 신호
                self.sample_thread.join(timeout=1.0)
                if self.sample_thread.is_alive():
                    log.warning("[Sampler] 소켓 종료 후에도 스레드 미종료 — daemon이므로 계속 진행")
        return len(self.current_trace)

    def evaluate_coverage(self) -> Tuple[bool, int]:
        """PC 주소 기반 커버리지 평가 (primary signal).

        개별 PC 주소(unique visited addresses)를 primary signal로 사용한다:
        - PC 주소는 결정론적: 코드가 실행되면 반드시 해당 주소가 생성됨
        - corpus 크기가 펌웨어 실제 코드 크기에 자연스럽게 수렴
        - confirmation 없이도 신뢰 가능
        """
        new_pc_set = self.current_trace - self.global_coverage
        self._last_new_pcs = new_pc_set
        self.global_coverage.update(self.current_trace)
        new_pcs = len(new_pc_set)

        is_interesting = new_pcs > 0
        return is_interesting, new_pcs

    def load_coverage(self, filepath: str) -> int:
        """이전 세션의 커버리지 파일을 로드하여 global_coverage에 합산"""
        loaded_pcs = 0
        if not os.path.exists(filepath):
            log.warning(f"[Coverage] File not found: {filepath}")
            return 0
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    self.global_coverage.add(int(line, 16))
                    loaded_pcs += 1
                except ValueError:
                    pass

        log.info(f"[Coverage] Loaded {loaded_pcs} PCs from {filepath} "
                 f"(global: {len(self.global_coverage)} PCs)")
        return loaded_pcs

    def save_coverage(self, output_dir: str):
        """현재 global_coverage를 파일로 저장"""
        self._fold_bg()   # always-on: 아직 안 합쳐진 백그라운드 PC 포함
        pc_path = os.path.join(output_dir, 'coverage.txt')
        with open(pc_path, 'w') as f:
            for pc in sorted(self.global_coverage):
                f.write(f"{hex(pc)}\n")

        log.info(f"[Coverage] Saved {len(self.global_coverage)} PCs → {_logname(pc_path)}")

    def close(self):
        self.stop_event.set()
        if self.sample_thread:
            self.sample_thread.join(timeout=2.0)
        # OpenOCD shutdown 명령으로 USB 정상 해제 (kill보다 먼저)
        # 'shutdown' 없이 kill하면 libjaylink가 USB를 잠근 채 종료 → J-Link 재연결 필요
        if self._sock and self._openocd_alive():
            try:
                self._sock.sendall(b'shutdown\n')
                time.sleep(0.5)   # OpenOCD가 USB 해제하고 종료할 시간
            except Exception:
                pass
        self._close_telnet()
        self._terminate_proc()


class OpenOCDHaltSampler(OpenOCDPCSampler):
    """halt 기반 PC 샘플러 — DBGPCSR(비침습 PC 샘플) 미구현 타깃용 (예: P9/Cortex-R5).

    OpenOCDPCSampler 의 연결/복구/diagnose/worker/회계/저장 인프라를 그대로 상속하고,
    per-sample PC 읽기만 `targets <prefix>; halt; reg pc; resume` 로 교체한다(침습적).
    halt 가 NVMe 명령을 굶겨 timeout 내지 않도록, resume 후 다음 halt 까지 최소 실행시간을
    config.go_settle_ms 로 보장한다(상속 worker 의 effective_interval 에서 적용). 단일코어 → 1-tuple.
    """

    # OpenOCD `reg pc` 출력에서 PC 값 추출. 예: "pc (/32): 0x00012345"
    _REG_PC_RE = re.compile(r'pc\b[^\n]*?(0x[0-9a-fA-F]+)', re.IGNORECASE)

    def __init__(self, config: 'FuzzConfig'):
        super().__init__(config)
        # halt 모드는 reg pc 로 단일 코어 PC 를 읽음(PCSR 주소 미사용) → 1코어로 표기.
        self._pcsr_addrs = [0x80030000]

    def _send_startup_tcl(self):
        """halt 모드 startup: DP power-up + sticky clear + cortex_r 타깃 선택.
        (PCSR read_all_pcs proc 정의는 불필요해서 생략.)"""
        px = self._tcl_prefix
        log.info(f"[Startup] halt-sampler interface={self.config.interface!r}, target={px!r}")
        self._telnet_cmd(f'{px}.dap dpreg 4 0x50000000')   # CDBGPWRUPREQ|CSYSPWRUPREQ
        time.sleep(0.05)
        self._telnet_cmd(f'{px}.dap dpreg 0 0x1e')          # sticky error clear
        self._telnet_cmd(f'targets {px}')                   # 이후 halt/reg/resume 대상
        log.info("[Startup] halt-sampler 준비 완료")

    def _read_all_pcs(self) -> Optional[Tuple[int, ...]]:
        """halt → reg pc → resume 로 단일코어 PC 1개 샘플. 실패 시 None."""
        try:
            self._telnet_cmd('halt')
            resp = self._telnet_cmd('reg pc')
            self._telnet_cmd('resume')
            m = self._REG_PC_RE.search(resp or '')
            if not m:
                log.warning(f"[Halt] reg pc 파싱 실패: {repr(resp)}")
                return None
            pc = int(m.group(1), 16) & ~1
            if pc in (0, 0xFFFFFFFE) or pc in self._invalid_pc_mask:
                return None
            return (pc,)
        except Exception as e:
            log.warning(f"[Halt] _read_all_pcs 예외: {e}")
            try:
                self._telnet_cmd('resume')   # 코어가 halt 로 남지 않게
            except Exception:
                pass
            return None


class JLinkHaltSampler(OpenOCDPCSampler):
    """J-Link(pylink) 기반 halt PC 샘플러 — P9(Cortex-R5, DBGPCSR 미구현)용. [v8.1]

    OpenOCDHaltSampler 의 OpenOCD telnet halt 는 소켓 read 타임아웃(2s) < OpenOCD halt-ack
    지연 시 프롬프트 desync → resume 누락 → 단일 R5 컨트롤러 코어가 halt 로 굳어 NVMe 가 무한
    hang 하는 문제가 있었다. 이 샘플러는 pylink 로 J-Link 를 in-process 단독 점유하고
    halt → register_read(PC) → JLINKARM_Go() 를 블로킹 API 로 직접 호출해 desync 를 없앤다.

    OpenOCDPCSampler 의 샘플링 worker/diagnose/회계/저장 인프라는 그대로 상속하고, 연결 계층
    (connect/close/_reconnect/_openocd_alive/_reinit_target)과 per-sample PC 읽기(_read_all_pcs)
    만 pylink 로 교체한다. OpenOCD 서브프로세스/telnet 메서드는 no-op 로 무력화(미사용).
    pylink 핸들은 단일 세션이라 worker/메인 스레드 동시 접근 방지용 _jlink_lock 으로 직렬화.
    """

    _PC_NAME_EXACT = ('PC', 'EPC', 'MEPC', 'SEPC')   # register_name 정확 일치 PC 후보

    def __init__(self, config: 'FuzzConfig'):
        super().__init__(config)
        self.jlink = None
        self._jlink_lock = threading.Lock()
        self._pc_reg_index: Optional[int] = config.pc_reg_index
        self._halt_func = None
        self._read_reg_func = None
        self._go_func = None
        # 단일코어 표기(halt 는 PC 1개) + invalid mask 를 P9 DPIDR 기준으로 정리
        self._pcsr_addrs = [0x80030000]
        self._invalid_pc_mask = frozenset(set(config.invalid_pc_vals) | {0x80030000})

    # ── 연결 계층 (pylink) ──────────────────────────────────────────
    def connect(self) -> bool:
        if _pylink is None:
            log.error("[J-Link] pylink 미설치 — `pip3 install pylink-square` 후 재시도하세요.")
            return False
        try:
            if self.jlink is not None:
                try:
                    if self.jlink.opened():
                        self.jlink.close()
                except Exception:
                    pass
            jl = _pylink.JLink()
            jl.open()
            tif = (_pylink.enums.JLinkInterfaces.JTAG if self.config.interface == 'jtag'
                   else _pylink.enums.JLinkInterfaces.SWD)
            jl.set_tif(tif)
            # 멀티-AP 시스템: 사용할 APB-AP 인덱스 선택 (P9: AP[0])
            try:
                jl.exec_command(f"CORESIGHT_SetIndexAPBAPToUse = {self.config.jlink_ap_index}")
            except Exception as e:
                log.warning(f"[J-Link] CORESIGHT_SetIndexAPBAPToUse 설정 경고: {e}")
            jl.connect(self.config.jlink_device, speed=self.config.jlink_speed)
            self.jlink = jl
            # PC 레지스터 인덱스: CLI/profile 지정값 우선, 없으면 자동 탐지
            if self._pc_reg_index is None:
                self._pc_reg_index = self._detect_pc_reg_index()
            try:
                _pcname = jl.register_name(self._pc_reg_index)
            except Exception:
                _pcname = '?'
            # DLL 함수 캐싱 (wrapper 오버헤드 회피 — tight halt 루프 가속)
            self._halt_func = jl._dll.JLINKARM_Halt
            self._read_reg_func = jl._dll.JLINKARM_ReadReg
            self._go_func = jl._dll.JLINKARM_Go
            log.warning(f"[J-Link] 연결 성공: {self.config.jlink_device} @ "
                        f"{self.config.jlink_speed}kHz ({self.config.interface.upper()}), "
                        f"PC reg index={self._pc_reg_index} (name={_pcname})")
            # 동작 검증: halt→read→resume 1회
            if self._read_all_pcs() is None:
                log.warning("[J-Link] 초기 PC 읽기 검증 실패 — 연결은 됐으나 "
                            "halt/PC 인덱스 확인 필요(--pc-reg-index, jlink_reg_diag.py)")
            return True
        except Exception as e:
            log.error(f"[J-Link] 연결 실패: {e}")
            self.jlink = None
            return False

    def _detect_pc_reg_index(self) -> int:
        """register_list 에서 R15/PC 인덱스 자동 탐지. 실패 시 15 폴백."""
        try:
            for idx in self.jlink.register_list():
                nm = (self.jlink.register_name(idx) or '').upper()
                if 'R15' in nm or nm in self._PC_NAME_EXACT:
                    return idx
        except Exception as e:
            log.warning(f"[J-Link] PC 레지스터 자동 탐지 실패: {e}")
        log.warning("[J-Link] PC 레지스터 미탐지 — 인덱스 15 폴백 "
                    "(틀리면 --pc-reg-index 로 지정)")
        return 15

    def _read_all_pcs(self) -> Optional[Tuple[int, ...]]:
        """halt → register_read(PC) → JLINKARM_Go() 로 단일코어 PC 1개. 실패 시 None.

        모든 pylink 호출은 _jlink_lock 으로 직렬화. resume 은 항상 JLINKARM_Go()
        (CPU 리셋 없음). go 실패해도 restart() 로 폴백하지 않음(살아있는 SSD 리셋 방지).
        halted() 폴링은 ~50ms 상한 → 못 멈추면 go 후 None(연속 실패는 base 가 복구 신호로).
        """
        if self.jlink is None:
            return None
        with self._jlink_lock:
            pc = None
            try:
                self._halt_func()
                halted = False
                for _ in range(50):   # 최대 ~50ms 대기
                    try:
                        if self.jlink.halted():
                            halted = True
                            break
                    except Exception:
                        break
                    time.sleep(0.001)
                if halted:
                    pc = self._read_reg_func(self._pc_reg_index)
                self._go_func()       # 항상 resume (halt 로 남기지 않음)
            except Exception as e:
                log.warning(f"[J-Link] _read_all_pcs 예외: {e}")
                try:
                    self._go_func()
                except Exception:
                    pass
                return None
        if pc is None:
            return None
        pc &= ~1
        if pc in (0, 0xFFFFFFFE) or pc in self._invalid_pc_mask:
            return None
        return (pc,)

    def _openocd_alive(self) -> bool:
        """(이름은 OpenOCD 잔재) J-Link 연결 생존 여부."""
        try:
            return self.jlink is not None and self.jlink.opened()
        except Exception:
            return False

    def _reconnect(self) -> bool:
        log.warning("[J-Link] 재연결 시도...")
        with self._jlink_lock:
            try:
                if self.jlink is not None:
                    try:
                        if self._go_func:
                            self._go_func()
                    except Exception:
                        pass
                    self.jlink.close()
            except Exception:
                pass
            self.jlink = None
        return self.connect()

    def _reinit_target(self) -> bool:
        """크래시 후 디버그 인프라 접근 가능 여부 (stuck PC 읽기 전제)."""
        if not self._openocd_alive():
            return self._reconnect()
        return True

    def close(self):
        self.stop_event.set()
        if self.sample_thread:
            self.sample_thread.join(timeout=2.0)
        with self._jlink_lock:
            if self.jlink is not None:
                try:
                    if self._go_func:   # 코어를 resume 상태로 두고 닫기
                        self._go_func()
                except Exception:
                    pass
                try:
                    self.jlink.close()
                except Exception:
                    pass
                self.jlink = None

    # ── OpenOCD 전용 메서드 무력화 (이 백엔드는 사용 안 함) ──────────
    def _send_startup_tcl(self):           # 모든 설정은 connect 에서 수행
        pass

    def _close_telnet(self):               # 소켓 없음 (stop_sampling 가 호출)
        pass

    def _open_telnet(self):
        pass

    def _telnet_cmd(self, cmd: str) -> str:
        return ""

    def _terminate_proc(self):
        pass

    def _launch_openocd(self) -> bool:
        return True


class NVMeFuzzer:
    """다중 Opcode 지원 NVMe 퍼저 (v4.3: subprocess nvme-cli + 글로벌 포화 설정 분리)"""

    VERSION = FUZZER_VERSION

    def __init__(self, config: FuzzConfig):
        self.config = config
        # --no-jlink 활성 시 NullSampler 사용 — coverage 수집 없이 NVMe fuzz 만.
        # J-Link/OpenOCD 가 없어도 fuzz / state telemetry / PM rotation / crash
        # detection (timeout 기준) 은 모두 동작.
        # sampler 선택: --no-jlink 또는 sampler_type='null' → NullSampler,
        # 'jlink_halt' → JLinkHaltSampler(P9, pylink 직접 halt), 'halt' → OpenOCDHaltSampler,
        # 그 외 → OpenOCDPCSampler(PCSR 비침습).
        if config.no_jlink or config.sampler_type == 'null':
            self.sampler = NullSampler(config)
        elif config.sampler_type == 'jlink_halt':
            self.sampler = JLinkHaltSampler(config)
        elif config.sampler_type == 'halt':
            self.sampler = OpenOCDHaltSampler(config)
        else:
            self.sampler = OpenOCDPCSampler(config)

        if config.enabled_commands:
            # --commands 지정 시: NVME_COMMANDS 전체에서 이름 매칭
            base = [c for c in NVME_COMMANDS if c.name in config.enabled_commands]
        elif config.all_commands:
            # --all-commands: 위험 명령어 포함 전체
            base = NVME_COMMANDS.copy()
        else:
            # 기본: 안전(비파괴) 명령어만
            base = NVME_COMMANDS_DEFAULT.copy()

        # weight에 따라 리스트 확장 — random.choice()가 가중치 선택을 자동 처리
        # IO_ADMIN_RATIO: I/O 커맨드를 Admin 대비 추가 weight 부여 (75%:25% 비율)
        self.commands = []
        for c in base:
            extra = IO_ADMIN_RATIO if c.cmd_type == NVMeCommandType.IO else 1
            self.commands.extend([c] * (c.weight * extra))

        log.info(f"[Fuzzer] Enabled commands: {[c.name for c in self.commands]}")

        # v4: Seed 리스트로 변경
        self.corpus: List[Seed] = []
        self.crash_inputs: List[Tuple[bytes, NVMeCommand]] = []
        # v7.8: 종료 시 집계 출력용 카운터 dict
        self.stats: dict = {}
        # v7.8: EngineErrInt 누적 baseline — firmware event log 가 persistent (NAND)
        # 이라 동일 entry 가 다음 dump 에도 남음. 마지막 본 count 와 delta 만 평가.
        self._engineerrint_baseline: int = 0
        # FWDownload: 청크 시드 목록 (corpus에는 1개만, 실제 전송 시 여기서 순서대로 전송)
        self._fw_chunks: List[Seed] = []

        self.output_dir = Path(config.output_dir)
        self.crashes_dir = self.output_dir / 'crashes'

        self.executions = 0
        self.start_time: Optional[datetime] = None
        self._current_ps: int = 0                              # 현재 PS 상태
        self._prev_op_ps: int = 0                             # 마지막 operational PS (0~2) — PS3/4 timeout 기준
        self.ps_exec_counts: dict[int, int] = {i: 0 for i in range(5)}  # PS별 실행 횟수
        self.ps_enter_counts: dict[int, int] = {i: 0 for i in range(5)} # PS별 진입 횟수

        self._pcie_bdf: Optional[str]              = None
        self._pcie_cap_offset: Optional[int]       = None  # PCIe Express cap (LNKCTL, DEVCTL2)
        self._pcie_pm_cap_offset: Optional[int]    = None  # PCI PM cap (PMCSR)
        self._pcie_l1ss_offset: Optional[int]      = None  # L1 Sub-States cap (L1.2)
        self._pcie_lnkcap: Optional[int]           = None  # LNKCAP 캐시 (ASPMS bit[11:10], CPM bit18)
        self._pcie_l1ss_cap: Optional[int]         = None  # L1SSCAP 캐시 (지원 substate 비트)
        self._pcie_root_bdf: Optional[str]         = None  # 루트 포트 BDF
        self._pcie_root_cap_offset: Optional[int]  = None  # 루트 포트 PCIe Express cap
        self._pcie_root_l1ss_offset: Optional[int] = None  # 루트 포트 L1SS cap
        self._pcie_root_l1ss_cap: Optional[int]    = None  # RP L1SSCAP 캐시 (지원 substate 비트)
        self._orig_aspm_policy: str                = 'default'  # 원본 ASPM 정책 복원용
        self._orig_apst_cdw11: Optional[int]       = None       # 원본 APST CDW11 (복원용)
        self._orig_keepalive_val: int              = 0          # 원본 Keep-Alive Timer (복원용)

        self._current_combo: PowerCombo  = POWER_COMBOS[0]   # PS0+L0+D0
        self._prev_op_combo: PowerCombo  = POWER_COMBOS[0]   # 마지막 non-PS3/4 combo
        self.combo_exec_counts: dict     = defaultdict(int)
        self.combo_enter_counts: dict    = defaultdict(int)

        # v5.2+: PS별 preflight settle 시간 — _init_ps_settle() 호출 후 채워짐
        self._ps_settle: dict[int, float] = dict(_PS_SETTLE_FALLBACK)

        self._sa_loaded: bool = False
        self._sa_bb_starts: Optional[list] = None  # sorted BB start addrs (bisect용)
        self._sa_bb_ends: Optional[list] = None    # parallel BB end addrs (exclusive)
        self._sa_total_bbs: int = 0
        self._sa_covered_bbs: set = set()          # 커버된 BB start addr 집합
        self._sa_func_entries: Optional[list] = None  # sorted by entry, bisect용
        self._sa_func_ends: Optional[list] = None
        self._sa_func_names: Optional[list] = None
        self._sa_total_funcs: int = 0
        self._sa_entered_funcs: set = set()   # 진입한 함수 entry point 집합
        self._sa_thumb_mask: bool = False     # True면 PC & ~1 로 비교 (Thumb bit 자동 보정)
        self._sa_diag_done: bool = False      # 첫 update 진단 출력 완료 여부
        # 성장 곡선 이력: [(executions, elapsed_s, bb_pct, funcs_pct), ...]
        self._sa_cov_history: list = []
        self._load_static_analysis()

        self.cmd_stats: dict[str, dict] = defaultdict(lambda: {"exec": 0, "interesting": 0})
        for c in self.commands:
            self.cmd_stats[c.name] = {"exec": 0, "interesting": 0}
        self.rc_stats: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))

        self.mutation_stats = {
            "opcode_override": 0,     # opcode가 변형된 횟수
            "nsid_override": 0,       # nsid가 변형된 횟수
            "force_admin_swap": 0,    # Admin↔IO 교차 전송 횟수
            "data_len_override": 0,   # data_len 불일치 횟수
            "datalen_nlb": 0,         # NLB-relative data_len 경계값 사용 횟수
            "datalen_mdts": 0,        # MDTS boundary data_len 사용 횟수
            "lba_pair_64bit": 0,      # 64-bit LBA pair 쌍 변이 횟수
            "dsm_structured": 0,      # DSM structured payload 재구성 횟수
            "copy_structured": 0,     # Copy structured payload 재구성 횟수
            "seq_builtin": 0,         # builtin sequence에서 발행된 명령 횟수
            "schema_field": 0,        # 스키마 기반 CDW 필드 변형 횟수
            "random_gen": 0,          # 완전 랜덤 생성 횟수
            "corpus_mutated": 0,      # corpus 기반 mutation 횟수
        }
        self._nsze_cache: Optional[int] = None
        self._nsze_cache_at: int = 0
        self._mdts_cache: Optional[int] = None
        self._mdts_cache_at: int = 0
        self._cntlid_cache: Optional[int] = None       # NS re-attach 용 컨트롤러 ID (시작 시 스냅샷)
        self._ns_mgmt_supported: Optional[bool] = None  # OACS bit3 (Namespace Management 지원)
        # Phase 3: sequence 상태
        self._pending_sequence: Optional[List[str]] = None
        self._pending_seq_ctx: Optional[dict] = None   # 공유 SLBA/NLB/data (Write→Compare 등)
        self._pending_seq_seeds: Optional[List['Seed']] = None  # corpus SequenceSeed replay용
        self._seq_cmds_in_window: int = 0
        # sequence 실행 중 개별 저장 대신 누적 — 완료 시 SequenceSeed로 저장
        self._seq_sink: Optional[dict] = None  # {'commands', 'new_pcs', 'covered_pcs', 'interesting'}
        # 실제 전송된 opcode 분포 (원본과 다른 경우만)
        self.actual_opcode_dist: dict[int, int] = defaultdict(int)
        # 실제 전송된 passthru 타입 분포
        self.passthru_stats = {"admin-passthru": 0, "io-passthru": 0}

        self._timeout_crash = False
        # calibration 구간 stderr 억제(fd 2 → /dev/null) 중 저장된 원본 fd.
        # _handle_timeout_crash()에서 log.error() 전에 복원하기 위해 사용.
        self._cal_saved_stderr_fd: Optional[int] = None
        self._crash_nvme_pid: Optional[int] = None
        self._log_file: Optional[str] = None   # run()에서 설정, artifact 복사에 사용
        # nvme_core 모듈 파라미터 원래 값 (종료 시 복원용)
        self._nvme_timeout_originals: dict = {}

        self.NUM_MUTATION_OPS = 16
        self.mopt_finds: List[int] = [0] * self.NUM_MUTATION_OPS   # operator별 새 coverage 발견 횟수
        self.mopt_uses: List[int] = [0] * self.NUM_MUTATION_OPS    # operator별 사용 횟수
        self._current_mutations: List[int] = []                     # 현재 실행에서 사용된 operator 목록
        self.mopt_mode: str = 'pilot'  # 'pilot' 또는 'core'
        self.mopt_weights: List[float] = [1.0 / self.NUM_MUTATION_OPS] * self.NUM_MUTATION_OPS
        self.mopt_pilot_rounds: int = 0

        self._det_queue: deque = deque()  # (seed, generator) pairs

        # 명령어별 PC/trace 추적 (그래프 시각화용)
        self.cmd_pcs: dict[str, Set[int]] = defaultdict(set)
        self.cmd_traces: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        # 기본 명령어 키 초기화
        for c in self.commands:
            self.cmd_pcs[c.name] = set()
            self.cmd_traces[c.name] = deque(maxlen=200)

        self._nvme_input_path: Optional[str] = None

        self._cmd_history: deque = deque(maxlen=100)

        # v7.0: State monitoring
        self.state_monitor    = NVMeStateMonitor(config.nvme_device, config.state_fields)
        self.state_corpus:    List[StateCorpusEntry] = []
        self.state_cov_map:   Dict[str, int] = {}
        self._state_snap_prev: Optional[Dict[str, int]] = None
        self.state_corpus_dir: Path = self.output_dir / 'state_corpus'
        self.seq_corpus_dir:   Path = self.output_dir / 'seq_corpus'

        # CSFuzz §III-C/D: dynamic corpus selection
        self._csfuzz_p: float = 0.5            # P(C1 선택), [0.1, 0.9]
        self._csfuzz_a: float = 1.0            # reward 파라미터
        self._csfuzz_b: float = 1.0
        self._csfuzz_c1_rewards: List[int] = [] # C1 선택 후 C1 growth 기록
        self._csfuzz_c2_rewards: List[int] = [] # C2 선택 후 C2 growth 기록
        self._csfuzz_last_from: str = 'c1'     # 마지막 선택 corpus
        self._csfuzz_pre_c1_size: int = 0
        self._csfuzz_pre_c2_size: int = 0
        # §III-D: bucket별 fuzz count
        self._state_bucket_fuzz_count: Dict[str, int] = {}
        # v7.6: 시각화용 히스토리 — _update_csfuzz_p 호출마다 누적
        #   (exec, p, m1, m2_norm, c1_size, c2_size)
        self._csfuzz_history: List[Tuple[int, float, float, float, int, int]] = []

        # v8.4: IO 워크로드 엔진 상태
        self._fuzz_since_workload: int = 0            # fuzz iteration 카운터 (워크로드 cmd 제외)
        self._wl_pattern_idx: int = 0                 # round_robin 패턴 회전 인덱스
        self._wl_base: int = 0                         # seq/strided 회전 base LBA
        self._wl_active_pattern: Optional[str] = None  # 현재 블록 패턴명 (state 캡처 귀속 태깅용)
        self._wl_read_target_written: bool = False     # read_disturb/pingpong_read 타겟 pre-write 여부
        self._wl_limits: Optional[dict] = None         # device 유도 bound 캐시 (_io_workload_limits)
        self._wl_blocks_done: int = 0                  # 실행한 워크로드 블록 수 (통계)
        # 사전생성 랜덤 write 버퍼 (per-cmd os.urandom 회피). 워크로드 활성 시에만 할당.
        self._wl_rand_buf: bytes = (
            os.urandom(max(1, IO_WL_RAND_BUF_MB) * 1024 * 1024)
            if config.io_workload_enabled else b''
        )
        # Write/Read NVMeCommand 객체 (워크로드 전용 — self.commands 와 무관하게 항상 사용 가능)
        self._wl_write_cmd = next((c for c in NVME_COMMANDS if c.name == 'Write'), None)
        self._wl_read_cmd  = next((c for c in NVME_COMMANDS if c.name == 'Read'), None)

    @staticmethod
    def _tracking_label(cmd: 'NVMeCommand', seed: 'Seed') -> str:
        """v4.4: 실제 실행 내용 기준 추적 키 생성.
        opcode_override가 있으면:
          - NVMe 스펙에 일치하는 명령어가 있으면 해당 이름 사용
          - 없으면 unknown_{admin|io}_op0x{XX} 형태 (v7.6: passthru 타입 임베드 —
            command_comparison 차트에서 admin/io 두 버킷으로 합치기 위함)
        """
        if seed.opcode_override is not None:
            # 실제 전송되는 passthru 타입 결정
            if seed.force_admin is not None:
                actual_type = "admin" if seed.force_admin else "io"
            else:
                actual_type = cmd.cmd_type.value
            spec_name = _OPCODE_TO_NAME.get((seed.opcode_override, actual_type))
            if spec_name is not None:
                return spec_name
            return f"unknown_{actual_type}_op0x{seed.opcode_override:02X}"
        return cmd.name

    def _clone_seed(self, seed: Seed) -> Seed:
        """시드의 mutation 대상 필드를 복사한 새 Seed 반환 (실행 통계 제외)"""
        return Seed(
            data=seed.data, cmd=seed.cmd,
            cdw2=seed.cdw2, cdw3=seed.cdw3,
            cdw10=seed.cdw10, cdw11=seed.cdw11,
            cdw12=seed.cdw12, cdw13=seed.cdw13,
            cdw14=seed.cdw14, cdw15=seed.cdw15,
            opcode_override=seed.opcode_override,
            nsid_override=seed.nsid_override,
            force_admin=seed.force_admin,
            data_len_override=seed.data_len_override,
        )

    def _calibrate_seed(self, seed: Seed) -> Seed:
        """시드를 N번 실행하여 PC 주소 안정성 측정 (PC 기반).

        각 실행에서 방문된 PC 주소를 추적하고 과반수 실행에서 등장한 PC를
        stable_pcs로 분류한다. global_coverage에는 관측된 전체 PC 합집합을 반영한다.
        """
        total_runs = self.config.calibration_runs
        if total_runs <= 0:
            seed.is_calibrated = True
            return seed

        pc_appearances: Dict[int, int] = {}          # PC → 등장 횟수
        actual_runs = 0
        self._cal_last_rc = 0  # 호출자에게 마지막 rc 전달용

        for run_i in range(total_runs):
            # _send_nvme_command() 내부에서 start_sampling()을 호출하므로
            # 여기서 별도로 start_sampling()을 호출하면 두 개의 sampling thread가
            # 동시에 실행되어 zombie thread가 누적된다.
            rc = self._send_nvme_command(seed.data, seed)
            self.sampler.stop_sampling()
            self.executions += 1
            actual_runs += 1
            self._cal_last_rc = rc

            for pc in self.sampler.current_trace:
                pc_appearances[pc] = pc_appearances.get(pc, 0) + 1

            if rc == self.RC_TIMEOUT:
                log.error(f"[Calibration] {seed.cmd.name} timeout at run {run_i+1} — treating as crash")
                self._handle_timeout_crash(seed, seed.data)
                # v7.8: unsupported_skip 으로 복구된 경우 calibration 자체는 중단하되
                # _timeout_crash 안 set 이라 메인 루프는 이후 진행 가능.
                break
            elif rc == self.RC_ERROR:
                log.warning(f"[Calibration] {seed.cmd.name} rc={rc} at run {run_i+1} — stopping early")
                break

        # PC 안정성 계산 (과반수 기준)
        all_seen_pcs = set(pc_appearances.keys())
        stable_threshold = actual_runs / 2.0
        stable_pcs = {pc for pc, cnt in pc_appearances.items() if cnt > stable_threshold}
        stability = len(stable_pcs) / max(len(all_seen_pcs), 1)

        seed.is_calibrated = True
        seed.stability = stability
        seed.stable_pcs = stable_pcs
        seed.covered_pcs = all_seen_pcs

        # global_coverage에 관측된 전체 PC 합집합을 반영
        self.sampler.global_coverage.update(all_seen_pcs)
        # calibration PC를 BB/func 커버리지 통계에도 반영
        self._update_static_coverage(all_seen_pcs)

        return seed

    def _deterministic_stage(self, seed: Seed):
        """CDW 필드에 대한 체계적 경계값 탐색 (제너레이터).
        대상: cdw10~cdw15 중 값이 0이 아닌 필드."""
        cdw_fields = ['cdw10', 'cdw11', 'cdw12', 'cdw13', 'cdw14', 'cdw15']
        arith_max = DETERMINISTIC_ARITH_MAX

        for field_name in cdw_fields:
            original = getattr(seed, field_name)
            # cdw10(LBA low)/cdw11(LBA high)/cdw12(NLB+flags)는 0이어도 핵심 필드 — 건너뛰지 않음.
            # cdw13~cdw15는 대부분의 명령에서 미사용(reserved=0) → 0이면 skip하여 노이즈 방지.
            if original == 0 and field_name in ('cdw13', 'cdw14', 'cdw15'):
                continue

            # Phase 1: Walking bitflip (32개)
            for bit in range(32):
                new_seed = self._clone_seed(seed)
                setattr(new_seed, field_name, original ^ (1 << bit))
                yield new_seed

            # Phase 2: Arithmetic +/- 1~arith_max
            for delta in range(1, arith_max + 1):
                new_seed = self._clone_seed(seed)
                setattr(new_seed, field_name, (original + delta) & 0xFFFFFFFF)
                yield new_seed

                new_seed = self._clone_seed(seed)
                setattr(new_seed, field_name, (original - delta) & 0xFFFFFFFF)
                yield new_seed

            # Phase 3: Interesting 32-bit values
            for val in self.INTERESTING_32:
                new_seed = self._clone_seed(seed)
                setattr(new_seed, field_name, val & 0xFFFFFFFF)
                yield new_seed

        # Phase 4: 각 CDW의 바이트 위치에 interesting 8-bit 값 대입
        for field_name in cdw_fields:
            original = getattr(seed, field_name)
            for shift in (0, 8, 16, 24):
                for val in self.INTERESTING_8:
                    mask = 0xFF << shift
                    new_val = (original & ~mask) | ((val & 0xFF) << shift)
                    if new_val != original:  # 동일 값이면 건너뛰기
                        new_seed = self._clone_seed(seed)
                        setattr(new_seed, field_name, new_val & 0xFFFFFFFF)
                        yield new_seed

    def _mopt_select_operator(self) -> int:
        """MOpt: 현재 모드에 따른 mutation operator 선택."""
        if self.mopt_mode == 'pilot':
            # Pilot: 균등 분포
            return random.randint(0, self.NUM_MUTATION_OPS - 1)
        else:
            # Core: 가중치 기반 선택
            r = random.random()
            cumulative = 0.0
            for i, w in enumerate(self.mopt_weights):
                cumulative += w
                if r <= cumulative:
                    return i
            return self.NUM_MUTATION_OPS - 1

    def _mopt_update_phase(self):
        """MOpt: pilot/core 모드 전환 및 가중치 갱신."""
        self.mopt_pilot_rounds += 1

        if self.mopt_mode == 'pilot':
            if self.mopt_pilot_rounds >= MOPT_PILOT_PERIOD:
                # Pilot → Core: 성공률 기반 가중치 계산
                weights = []
                for i in range(self.NUM_MUTATION_OPS):
                    if self.mopt_uses[i] > 0:
                        rate = self.mopt_finds[i] / self.mopt_uses[i]
                    else:
                        rate = 1.0 / self.NUM_MUTATION_OPS
                    weights.append(rate)

                total = sum(weights)
                if total > 0:
                    self.mopt_weights = [w / total for w in weights]
                else:
                    self.mopt_weights = [1.0 / self.NUM_MUTATION_OPS] * self.NUM_MUTATION_OPS

                # 최소 확률 보장 (완전히 0이 되지 않도록)
                min_w = 0.01 / self.NUM_MUTATION_OPS
                for i in range(self.NUM_MUTATION_OPS):
                    self.mopt_weights[i] = max(self.mopt_weights[i], min_w)
                total = sum(self.mopt_weights)
                self.mopt_weights = [w / total for w in self.mopt_weights]

                self.mopt_mode = 'core'
                self.mopt_pilot_rounds = 0

                op_names = ['bitflip1', 'int8', 'int16', 'int32',
                            'arith8', 'arith16', 'arith32', 'randbyte',
                            'byteswap', 'delete', 'insert', 'overwrite',
                            'splice', 'shuffle', 'blockfill', 'asciiint']
                weight_str = ', '.join(f'{op_names[i]}={self.mopt_weights[i]:.3f}'
                                       for i in range(self.NUM_MUTATION_OPS))
                log.info(f"[MOpt] Pilot→Core: {weight_str}")

        elif self.mopt_mode == 'core':
            if self.mopt_pilot_rounds >= MOPT_CORE_PERIOD:
                # Core → Pilot: 통계 리셋
                self.mopt_finds = [0] * self.NUM_MUTATION_OPS
                self.mopt_uses = [0] * self.NUM_MUTATION_OPS
                self.mopt_mode = 'pilot'
                self.mopt_pilot_rounds = 0
                log.info("[MOpt] Core→Pilot (reset)")

    def _preload_fw_slots(self) -> None:
        """calibration: config fw_bin 을 (read-only 제외) 모든 firmware slot 에 미리 기록(CA=0, 비활성).
        이후 어떤 FWCommit(기존 슬롯 활성 CA=2/3 포함)이 와도 모든 슬롯=config fw_bin → '다른 FW
        활성화' 차단. boot partition(BPID/CA4·5)은 대상 아님(특정 시퀀스 필요한 드문 케이스라 제외)."""
        if not self._fw_chunks:
            log.warning("[FW-Preload] config fw_bin 청크 없음 — 슬롯 프리로드 skip")
            return
        ctrl, _, _ = self._nvme_id_dict(['nvme', 'id-ctrl', self.config.nvme_device])
        _frmw = ctrl.get('frmw', 0)
        try:
            frmw = int(_frmw, 0) if isinstance(_frmw, str) else int(_frmw or 0)
        except (ValueError, TypeError):
            frmw = 0
        nslots = ((frmw >> 1) & 0x7) or 1
        slot1_ro = bool(frmw & 0x1)
        fwc = next((c for c in NVME_COMMANDS if c.name == 'FWCommit'), None)
        if fwc is None:
            return
        log.warning(f"[FW-Preload] FRMW=0x{frmw:02x} slots={nslots} slot1_ro={slot1_ro} "
                    f"→ config fw_bin 슬롯 프리로드(CA=0, 비활성)")
        for slot in range(1, nslots + 1):
            if slot == 1 and slot1_ro:
                log.warning("[FW-Preload] 슬롯1 read-only — skip")
                continue
            _ok = True
            for _chunk in self._fw_chunks:        # FWDownload 전체 청크 → 컨트롤러 버퍼
                if self._send_nvme_command(_chunk.data, _chunk, record_history=False) != 0:
                    _ok = False
                    break
            if _ok:
                _seed = Seed(data=b'', cmd=fwc,
                             cdw10=(0x00 << 3) | (slot & 0x7),  # CA=0(슬롯 기록·비활성), FS=slot
                             found_at=0)
                _rc = self._send_nvme_command(b'', _seed, record_history=False)
                log.warning(f"[FW-Preload] 슬롯{slot} 기록 완료 (FWCommit CA=0 rc={_rc})")
            else:
                log.warning(f"[FW-Preload] 슬롯{slot} FWDownload 실패 — skip")
            self.sampler.stop_sampling()

    def _log_smart(self):
        """v4.3: NVMe SMART / Health 로그를 읽어 INFO 레벨로 기록.

        subprocess.run(timeout=) 은 timeout 후 kill() 뒤에 communicate()를 한 번 더
        호출하는데, NVMe 장치가 D-state인 경우 파이프가 절대 닫히지 않아 영구 블로킹된다.
        Popen을 직접 써서 timeout 시 파이프만 닫고 대기 없이 반환한다.
        """
        try:
            proc = subprocess.Popen(
                ['nvme', 'smart-log', self.config.nvme_device],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except FileNotFoundError:
            log.warning("[SMART] nvme-cli가 설치되지 않았습니다")
            return
        except Exception as e:
            log.warning(f"[SMART] smart-log 실행 오류: {e}")
            return

        try:
            stdout_data, stderr_data = proc.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            # D-state 프로세스는 SIGKILL도 무시 → communicate() 재호출 금지.
            # 파이프를 닫고 non-blocking poll만 해서 계속 진행한다.
            # (좀비 프로세스는 인터프리터 종료 시 OS가 정리)
            try:
                proc.kill()
            except Exception:
                pass
            for pipe in (proc.stdout, proc.stderr):
                if pipe:
                    try:
                        pipe.close()
                    except Exception:
                        pass
            proc.poll()
            log.warning("[SMART] smart-log 타임아웃 (60s) — NVMe 장치 무응답")
            return

        if proc.returncode == 0 and stdout_data.strip():
            log.info("[SMART] === NVMe SMART / Health Log ===")
            for line in stdout_data.decode(errors='replace').strip().splitlines():
                log.info(f"[SMART] {line}")
        else:
            log.warning(f"[SMART] smart-log 실패 (rc={proc.returncode}): "
                        f"{stderr_data.decode(errors='replace').strip()}")

    def _log_state_snapshot(self):
        """state_fields.py에 정의된 모든 필드를 읽어 human-readable 형태로 로그에 기록.
        퍼징 시작 시 1회 + 이후 10000회마다 호출."""
        log.warning("[State-Snap] ══════════════ State Fields Snapshot ══════════════")
        log.warning(f"[State-Snap] exec={self.executions:,}  "
                    f"state-cov={len(self.state_cov_map)}  "
                    f"state-corpus={len(self.state_corpus)}")

        # ── SMART (LID 02h) ───────────────────────────────────────────
        smart_fields = [f for f in self.config.state_fields if f['source'] == 'smart']
        if smart_fields:
            try:
                proc = _run_nvme_state_cmd(
                    ['nvme', 'smart-log', self.config.nvme_device])
                raw_out = proc.stdout or proc.stderr
                smart_text: Dict[str, int] = {}
                for line in raw_out.decode(errors='replace').splitlines():
                    if ':' not in line:
                        continue
                    k, _, v = line.partition(':')
                    k = k.strip().lower().replace(' ', '_')
                    v = v.strip().split()[0].rstrip('%').replace(',', '') if v.strip() else ''
                    try:
                        smart_text[k] = int(v, 0)
                    except ValueError:
                        pass
                _SMART_TEXT_KEY_MAP = {
                    'percent_used': 'percentage_used',
                    'avail_spare': 'available_spare',
                    'spare_thresh': 'available_spare_threshold',
                    'warning_temp_time': 'warning_temperature_time',
                    'critical_comp_time': 'critical_composite_temperature_time',
                }
                log.warning("[State-Snap] ── LID 02h SMART / Health ──────────────────")
                for f in smart_fields:
                    text_key = _SMART_TEXT_KEY_MAP.get(f['key'], f['key'])
                    val = smart_text.get(text_key)
                    if val is not None:
                        log.warning(f"[State-Snap]   {f['name']:<30s} = {val:>12,}   ({f['desc']})")
                    else:
                        log.warning(f"[State-Snap]   {f['name']:<30s} = {'N/A':>12}   ({f['desc']})")
            except Exception as e:
                log.warning(f"[State-Snap] SMART 읽기 실패: {e}")

        # ── Vendor log (LID별 1회) ────────────────────────────────────
        vendor_lids: Dict[int, int] = {}
        for f in self.config.state_fields:
            if f['source'] == 'vendor':
                vendor_lids[f['lid']] = f['log_len']

        for lid, log_len in sorted(vendor_lids.items()):
            try:
                proc = _run_nvme_state_cmd(
                    ['nvme', 'get-log', self.config.nvme_device,
                     f'--log-id={lid:#x}', f'--log-len={log_len}', '--raw-binary'])
                if proc.returncode != 0:
                    log.warning(f"[State-Snap] LID={lid:#x} 실패: "
                                f"{proc.stderr.decode(errors='replace').strip()}")
                    continue
                raw = proc.stdout
                log.warning(f"[State-Snap] ── LID {lid:#04x} ({log_len}B) ──────────────────")
                for f in self.config.state_fields:
                    if f['source'] != 'vendor' or f.get('lid') != lid:
                        continue
                    start, end = f['offset'], f['offset'] + f['length']
                    if end > len(raw):
                        log.warning(f"[State-Snap]   {f['name']:<30s} = {'SHORT':>12}   ({f['desc']})")
                        continue
                    val = int.from_bytes(raw[start:end], f.get('endian', 'little'))
                    log.warning(f"[State-Snap]   {f['name']:<30s} = {val:>12,}   ({f['desc']})")
            except Exception as e:
                log.warning(f"[State-Snap] LID={lid:#x} 읽기 실패: {e}")

        # ── Security Receive (secp/spsp 그룹별 Send→Recv) ────────────────
        sec_groups: Dict[tuple, int] = {}
        for f in self.config.state_fields:
            if f['source'] == 'security_recv':
                key = (f['secp'], f['spsp'], f.get('nsid', 0))
                sec_groups[key] = max(sec_groups.get(key, 0), f['size'])

        _DUMMY_PATH = '/tmp/nvme_sec_dummy.bin'
        if sec_groups and not os.path.exists(_DUMMY_PATH):
            try:
                with open(_DUMMY_PATH, 'wb') as _df:
                    _df.write(b'\x00' * 4)
            except Exception as e:
                log.warning(f"[State-Snap] dummy 파일 생성 실패: {e}")

        for (secp, spsp, nsid), size in sorted(sec_groups.items()):
            try:
                send_cmd = [
                    'nvme', 'security-send', self.config.nvme_device,
                    '-p', f'{secp:#x}', '-s', f'{spsp:#x}', '-t', '4',
                    '-f', _DUMMY_PATH,
                ]
                if nsid:
                    send_cmd += ['-n', str(nsid)]
                proc_s = _run_nvme_state_cmd(send_cmd)
                if proc_s.returncode not in (0, 1):
                    log.warning(f"[State-Snap] security-send secp={secp:#x} spsp={spsp:#x} "
                                f"실패 rc={proc_s.returncode}: "
                                f"{proc_s.stderr.decode(errors='replace').strip()}")
                    continue

                recv_cmd = [
                    'nvme', 'security-recv', self.config.nvme_device,
                    '-p', f'{secp:#x}', '-s', f'{spsp:#x}',
                    '-x', str(size), '-t', str(size),
                ]
                if nsid:
                    recv_cmd += ['-n', str(nsid)]
                proc_r = _run_nvme_state_cmd(recv_cmd, merge_stderr=True)
                if proc_r.returncode != 0:
                    log.warning(f"[State-Snap] security-recv secp={secp:#x} spsp={spsp:#x} "
                                f"실패 rc={proc_r.returncode}: "
                                f"{proc_r.stdout.decode(errors='replace').strip()}")
                    continue

                raw = NVMeStateMonitor._parse_sec_hex(
                    proc_r.stdout.decode(errors='replace'))
                if not raw:
                    log.warning(f"[State-Snap] sec-recv hex 파싱 실패")
                    continue
                if raw[0] != (spsp & 0xFF):
                    log.warning(f"[State-Snap] sec-recv magic 불일치: "
                                f"raw[0]={raw[0]:#04x} expected={spsp & 0xFF:#04x}")
                    continue
                log.warning(f"[State-Snap] ── Security Recv secp={secp:#x} spsp={spsp:#x} "
                            f"({size}B) ──────────")
                for f in self.config.state_fields:
                    if (f['source'] != 'security_recv'
                            or f['secp'] != secp
                            or f['spsp'] != spsp
                            or f.get('nsid', 0) != nsid):
                        continue
                    start, end = f['offset'], f['offset'] + f['length']
                    if end > len(raw):
                        log.warning(f"[State-Snap]   {f['name']:<30s} = {'SHORT':>12}   ({f['desc']})")
                        continue
                    val = int.from_bytes(raw[start:end], f.get('endian', 'little'))
                    log.warning(f"[State-Snap]   {f['name']:<30s} = {val:>12,}   ({f['desc']})")
            except Exception as e:
                log.warning(f"[State-Snap] security-recv secp={secp:#x} spsp={spsp:#x} "
                            f"예외: {e}")

        log.warning("[State-Snap] ════════════════════════════════════════════════════")

    def _prefill_drive(self) -> bool:
        """POR 전 드라이브 전체 영역에 랜덤 데이터 쓰기 (GC/Wear Leveling 트리거용).

        목적: FTL GC·Wear Leveling 코드 경로(0x20000+ 영역)를 활성화하여
              퍼징 중 해당 PC 샘플링 확률을 높임.
        수단: dd if=/dev/urandom of=<ns_dev> bs=<prefill_bs> oflag=direct — page cache 우회로
              실제 device 에 기록(버퍼링된 가짜 성공 방지). 블록 디바이스 전체 덮어쓰기.
        주의: 드라이브 용량에 따라 수 분~수십 분 소요. 완료 후 POR로 FTL 상태 리셋됨.
        """
        ns_dev = self._io_device()
        bs = self.config.prefill_bs

        if not os.path.exists(ns_dev):
            log.error(f"[Prefill] 블록 디바이스 없음: {ns_dev} — prefill 건너뜀")
            return False

        # 드라이브 크기 조회 (blockdev --getsize64)
        try:
            r = subprocess.run(['blockdev', '--getsize64', ns_dev],
                               capture_output=True, text=True, timeout=5)
            drive_bytes = int(r.stdout.strip()) if r.returncode == 0 else 0
        except Exception:
            drive_bytes = 0

        size_str = (f"{drive_bytes / (1024**3):.1f} GB"
                    if drive_bytes > 0 else "크기 미확인")
        log.warning(f"[Prefill] 전체 쓰기 시작: {ns_dev} ({size_str}), bs={bs//1024//1024}MB")
        log.warning("[Prefill] GC/Wear Leveling 트리거 목적 — 완료 후 POR로 FTL 상태 리셋됩니다")

        # oflag=direct: page cache 우회 → 실제 device 에 즉시 내려감(버퍼링된 가짜 성공 방지).
        #   device 가 write 못 받으면 EIO 로 즉시 실패가 드러난다. iflag=fullblock: urandom
        #   short-read 시에도 bs 정렬 유지(O_DIRECT EINVAL 방지). conv=fsync: 끝에 device 캐시 flush.
        cmd = ['dd', 'if=/dev/urandom', f'of={ns_dev}',
               f'bs={bs}', 'status=progress',
               'iflag=fullblock', 'oflag=direct', 'conv=fsync']
        log.warning(f"[Prefill] CMD: {' '.join(cmd)}")

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,   # dd는 progress를 stderr에 출력
                start_new_session=True,
            )
        except Exception as e:
            log.error(f"[Prefill] dd 실행 실패: {e}")
            return False

        # dd status=progress 출력을 실시간 파싱해 진행률(%) 표시.
        # dd 는 진행을 "<N> bytes (...) copied, ... , <rate>" 로 \r 갱신, 끝에 \n+요약.
        # drive_bytes 를 알면 N/drive_bytes 로 % 계산.
        POLL_INTERVAL = 30      # 진행 로그 간격(초)
        import threading
        _st: dict = {'bytes': 0, 'line': '', 'buf': '', 'tail': [],
                     'rc': None, 'done': False}

        def _reader():
            try:
                while True:
                    chunk = proc.stdout.read(128)
                    if not chunk:
                        break
                    _st['buf'] += chunk.decode(errors='replace')
                    segs = re.split(r'[\r\n]', _st['buf'])
                    _st['buf'] = segs.pop()          # 미완성 조각은 버퍼에 보존
                    for seg in segs:
                        seg = seg.strip()
                        if not seg:
                            continue
                        m = re.match(r'(\d+)\s+bytes', seg)
                        if m:
                            _st['bytes'] = int(m.group(1))
                            _st['line'] = seg          # 최신 진행 줄(전송량/속도 포함)
                        else:
                            _st['tail'].append(seg)    # records/요약/에러 줄
            except Exception as e:
                _st['tail'].append(f'(reader err: {e})')
            finally:
                try:
                    _st['rc'] = proc.wait()
                except Exception:
                    _st['rc'] = proc.returncode
                _st['done'] = True

        t = threading.Thread(target=_reader, daemon=True)
        t.start()

        # 비침습(PCSR) 샘플러일 때만 prefill 중 동시 PC 샘플링 — write/GC/WL 경로 가시화.
        # PCSR 은 코어 halt 없이 읽으므로 dd 스루풋에 영향 없음. halt/jlink_halt/null 은
        # 제외(코어 halt → write 경로 교란 + prefill 지연). 수집 PC 는 static BB/func
        # 커버리지에만 반영하고 guidance global_coverage 에는 넣지 않는다 — fuzzing 이 GC
        # 경로 재도달 시 new-PC 크레딧을 받도록(idle_pcs 와 동일 정책).
        _pf_sample = (self.config.sampler_type == 'pcsr')
        _pf_pcs: set = set()
        _pf_cnt = {'samples': 0, 'failures': 0}

        def _pf_sampler():
            while not _st['done']:
                res = self.sampler._read_all_pcs()
                _pf_cnt['samples'] += 1
                if res is not None:
                    _pf_pcs.update(res)
                else:
                    _pf_cnt['failures'] += 1

        _pf_thread = None
        if _pf_sample:
            log.warning("[Prefill] PCSR 비침습 동시 샘플링 시작 (write/GC PC 수집)")
            _pf_thread = threading.Thread(target=_pf_sampler, daemon=True)
            _pf_thread.start()

        _last = time.monotonic()
        while not _st['done']:
            time.sleep(1)
            if time.monotonic() - _last >= POLL_INTERVAL:
                _last = time.monotonic()
                b = _st['bytes']
                _detail = f"  [{_st['line']}]" if _st['line'] else ""
                if drive_bytes > 0 and b > 0:
                    pct = min(100.0, b / drive_bytes * 100)
                    log.warning(f"[Prefill] 진행 {pct:5.1f}% "
                                f"({b/(1024**3):.1f}/{drive_bytes/(1024**3):.1f} GB){_detail}")
                elif b > 0:
                    log.warning(f"[Prefill] 진행 {b/(1024**3):.1f} GB 기록{_detail}")
                else:
                    log.warning("[Prefill] 진행 중... (dd 진행정보 대기)")
        t.join(timeout=5)

        if _pf_thread is not None:
            _pf_thread.join(timeout=5)
            if _pf_pcs:
                _pf_new = sum(1 for p in _pf_pcs if p not in self.sampler.global_coverage)
                self._update_static_coverage(_pf_pcs)
                log.warning(
                    f"[Prefill] PCSR 샘플 {_pf_cnt['samples']}회 (실패={_pf_cnt['failures']}) — "
                    f"수집 PC {len(_pf_pcs)}개 (global 대비 신규 {_pf_new}개) → static BB/func 반영")
            else:
                log.warning(
                    f"[Prefill] PCSR 샘플 {_pf_cnt['samples']}회 — 수집 PC 없음 "
                    f"(실패={_pf_cnt['failures']})")

        rc = _st['rc'] if _st['rc'] is not None else -1
        # 완료 요약(전송량/속도) 한 줄
        if _st['line']:
            log.warning(f"[Prefill] dd 완료: {_st['line']}")
        elif _st['tail']:
            log.warning(f"[Prefill] dd 출력: {_st['tail'][-1]}")

        # rc 판정: 정상 완료는 (a) rc=0, 또는 (b) 디바이스 끝 ENOSPC(rc=1, "No space left").
        # O_DIRECT 라 device 가 write 를 거부하면 EIO(역시 rc=1)로 드러난다 — ENOSPC(끝 도달)와
        # EIO(실패)는 둘 다 rc=1 이므로 stderr 문구/기록량으로 구분해야 가짜 성공을 막는다.
        _tail_txt  = ' '.join(_st['tail'][-6:]).lower()
        _enospc    = ('no space left' in _tail_txt) or ('enospc' in _tail_txt)
        _wrote     = _st['bytes']
        _near_full = drive_bytes > 0 and _wrote >= int(drive_bytes * 0.99)
        _wrote_gb  = _wrote / (1024**3)
        if rc == 0:
            log.warning(f"[Prefill] 전체 쓰기 완료 (rc=0, {_wrote_gb:.1f} GB) — POR로 FTL 리셋 진행")
            return True
        if rc == 1 and (_enospc or _near_full):
            log.warning(f"[Prefill] 디바이스 끝 도달 (ENOSPC, {_wrote_gb:.1f} GB) — 정상 완료, POR 진행")
            return True
        # 그 외 — 실제 write 실패. O_DIRECT 라 device 가 write 를 못 받으면 여기서 노출됨.
        log.error(f"[Prefill] dd 실패 (rc={rc}) — device write 거부/오류 의심. "
                  f"기록 {_wrote_gb:.1f} GB"
                  + (f"/{drive_bytes/(1024**3):.1f} GB" if drive_bytes > 0 else "")
                  + f". dd 출력: {_st['tail'][-1] if _st['tail'] else 'N/A'}")
        return False

    def _power_cycle_ssd(self) -> bool:
        """PMU 보드를 이용한 SSD POR Phase 1: 전원 사이클 + SWD 준비 대기.

        순서: PCIe 제거 → 전원 OFF → 방전 대기 → 전원 ON
        PCIe rescan / NVMe 확인은 boot sweep 이후 _por_pcie_rescan()에서 수행.
        J-Link SWD는 USB 연결로 PCIe와 독립적 — 전원 ON 직후 접근 가능.
        """
        if not os.path.isfile(self.config.pmu_script):
            log.error(f"[POR] PMU 스크립트 없음: {self.config.pmu_script} — POR 스킵")
            return False

        log.warning("[POR] SSD 전원 사이클 시작...")
        self.sampler._stop_worker()   # always-on 워커 정지(POR 중 소켓 경합 방지; 재가동은 다음 명령)

        # 1. PCIe 장치 제거. nvme_kernel_timeout_sec 가 크게 설정된 상태에서 device 가
        # 응답 안 하면 sysfs write 영구 block 가능 → subprocess timeout 10초 강제 진행.
        if self._pcie_bdf:
            remove_path = f"/sys/bus/pci/devices/{self._pcie_bdf}/remove"
            try:
                _r = subprocess.run(
                    ['bash', '-c', f'echo 1 > {remove_path}'],
                    timeout=10, capture_output=True)
                if _r.returncode == 0:
                    log.warning(f"[POR] PCIe 장치 제거: {self._pcie_bdf}")
                else:
                    log.warning(f"[POR] PCIe 장치 제거 rc={_r.returncode}: "
                                f"{_r.stderr.decode(errors='replace').strip()} — 무시")
            except subprocess.TimeoutExpired:
                log.warning(f"[POR] PCIe 장치 제거 10초 timeout — 강제 진행 "
                            "(전원 사이클이 device 강제 reset)")
            except Exception as e:
                log.warning(f"[POR] PCIe 장치 제거 예외: {e} — 무시")

        # 2. 전원 OFF
        _off_cmd = ['python3', self.config.pmu_script, '7', '1']
        log.warning(f"[POR] CMD: {' '.join(_off_cmd)}")
        r = subprocess.run(_off_cmd, capture_output=True, timeout=5)
        log.warning(f"[POR] PowerOffAll rc={r.returncode} "
                    f"stdout={r.stdout.decode(errors='replace').strip()!r} "
                    f"stderr={r.stderr.decode(errors='replace').strip()!r}")
        log.warning(f"[POR] 전원 OFF — {self.config.por_poweroff_wait:.1f}초 방전 대기...")
        time.sleep(self.config.por_poweroff_wait)

        # 3. 전원 ON + SWD 준비 대기 (PCIe 부팅 대기는 boot sweep 이후로 분리)
        _on_cmd = ['python3', self.config.pmu_script, '4', '1',
                   str(self.config.clkreq_voltage_mv), '0', '12000', '0', '0']
        log.warning(f"[POR] CMD: {' '.join(_on_cmd)}")
        r = subprocess.run(_on_cmd, capture_output=True, timeout=10)
        log.warning(f"[POR] PowerOnAll rc={r.returncode} "
                    f"stdout={r.stdout.decode(errors='replace').strip()!r} "
                    f"stderr={r.stderr.decode(errors='replace').strip()!r}")
        log.warning("[POR] 전원 ON — OpenOCD 즉시 연결 시도 (boot_sweep_s 내 재시도)")
        return True

    def _por_pcie_rescan(self) -> bool:
        """POR Phase 2: PCIe rescan + NVMe 장치 응답 확인.

        v7.7 의 단순 hammer 방식 유지 — sysfs path 검사 같은 gate 없이 매 iteration
        id-ctrl 무조건 시도. v7.8 에서 추가했던 strict ctrl_ready 검사는 user 환경
        에서 false positive (controller char 잠시 missing 시 무한 wait) 가 있어 제거.

        v7.7 대비 유일한 차이: rescan 도 retry loop 으로 반복 (device 가 늦게 올라
        오는 경우 다중 rescan 으로 다시 잡힘). 단일 rescan 만 했을 때 놓치는 케이스
        를 보완.
        """
        deadline = time.monotonic() + self.config.por_boot_wait
        attempt = 0
        _first_rescan = True
        while time.monotonic() < deadline:
            attempt += 1
            # 1) rescan trigger (매 iteration — device 가 늦게 올라와도 잡힘)
            try:
                with open('/sys/bus/pci/rescan', 'w') as f:
                    f.write('1')
                if _first_rescan:
                    log.warning("[POR] PCIe rescan 완료 (첫 시도)")
                    _first_rescan = False
            except Exception as e:
                log.warning(f"[POR] PCIe rescan 실패 (시도 {attempt}): {e}")

            # 2) id-ctrl 무조건 시도 — kernel 측 path 가 일시적으로 안 보여도
            # 다음 iteration 에서 다시 시도. v7.7 의 단순 hammer 방식.
            r = subprocess.run(
                ['nvme', 'id-ctrl', self.config.nvme_device],
                capture_output=True, timeout=10)
            if r.returncode == 0:
                log.warning(f"[POR] NVMe 장치 응답 확인: {self.config.nvme_device} "
                            f"✓ (시도 {attempt}회)")
                return True
            _err = r.stderr.decode(errors='replace').strip()[:100]
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                log.warning(f"[POR] NVMe 미응답 — 시도 {attempt}회 모두 실패. 마지막 err: {_err}")
                break
            wait = min(1.0, remaining)
            log.warning(f"[POR] NVMe 미응답 (시도 {attempt}회) — {wait:.1f}초 후 재시도 "
                        f"(남은 {remaining:.1f}초) err={_err}")
            time.sleep(wait)

        log.error(f"[POR] NVMe 장치 미응답 — boot sweep + por_boot_wait({self.config.por_boot_wait:.0f}s) "
                  f"내 응답 없음. --por-boot-wait 또는 --boot-sweep-s 값을 늘려보세요.")
        return False

    def _collect_boot_coverage(self, duration_s: float) -> int:
        """connect() 직후 부팅 중 PC를 연속 수집하여 global_coverage에 추가.

        POR 후 firmware 초기화 경로(FTL 테이블 로드, 캐시 워밍 등)의 PC를 조기 확보.
        duration_s 초 동안 PCSR을 as-fast-as-possible로 폴링.
        수집된 PC는 global_coverage 및 static coverage(BB/func)에 반영한다.
        """
        if duration_s <= 0:
            log.info("[BootSweep] 비활성화됨 (--boot-sweep-s 0)")
            return 0

        t_end = time.monotonic() + duration_s
        new_pcs: set = set()
        samples = 0
        failures = 0

        log.warning(f"[BootSweep] POR 직후 boot-phase PC 수집 시작 ({duration_s:.0f}초)...")
        while time.monotonic() < t_end:
            result = self.sampler._read_all_pcs()
            samples += 1
            if result is not None:
                for pc in result:
                    if pc not in self.sampler.global_coverage:
                        new_pcs.add(pc)
                        self.sampler.global_coverage.add(pc)
            else:
                failures += 1

        if new_pcs:
            self._update_static_coverage(new_pcs)
        log.warning(
            f"[BootSweep] 완료: {samples}회 샘플, 신규 PC {len(new_pcs)}개, "
            f"실패={failures}회 → global_coverage={len(self.sampler.global_coverage)}개"
        )
        return len(new_pcs)

    def _setup_directories(self):
        self.crashes_dir.mkdir(parents=True, exist_ok=True)
        self.state_corpus_dir.mkdir(parents=True, exist_ok=True)
        self.seq_corpus_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _normalize_nvme_path(path: str) -> str:
        """터미널의 중복된 nN 접미사 정리. /dev/nvme0n1n1 → /dev/nvme0n1.
        과거 버전에서 nvme_device=/dev/nvme0n1 인 상태로 f"{dev}n{ns}" 가
        실행되어 corpus / cmd_history 에 잘못 들어간 device path 가 있을 수
        있으므로 replay 직전 정규화."""
        # 끝의 연속된 nN+ 패턴을 찾아 첫 번째 nN 만 남김
        m = re.search(r'(n\d+){2,}$', path)
        if m:
            first = re.match(r'n\d+', m.group()).group()
            return path[:m.start()] + first
        return path

    def _io_device(self) -> str:
        """io-passthru / 블록 디바이스 작업용 namespace 경로 반환.
        nvme_device 가 이미 namespace 경로(/dev/nvme0n1)면 그대로,
        controller 경로(/dev/nvme0)면 n{namespace} 를 붙임.
        WSL2 등 controller char device 가 없는 환경 호환을 위한 헬퍼.
        """
        dev = self._normalize_nvme_path(self.config.nvme_device)
        if _NVME_NS_SUFFIX_RE.search(dev):
            return dev
        return f"{dev}n{self.config.nvme_namespace or 1}"

    def _ctrl_device(self) -> str:
        """컨트롤러 레벨 admin feature(APST FID 0x0C / KeepAlive 0x0F 등) 대상 디바이스.

        이 feature 들은 namespace 가 아니라 컨트롤러 스코프다. namespace 블록 디바이스
        (/dev/nvme0n1)로 set-feature 를 보내면 nvme-cli 가 NSID(=namespace)를 실어 보내는데,
        일부 펌웨어(예: P9)는 컨트롤러 feature 에 NSID≠0 이면 거부(Invalid Field)하여 실패한다.
        → 컨트롤러 char device(/dev/nvme0)로 보내 NSID 의존성을 제거한다.
        /dev/nvme0n1 → /dev/nvme0, /dev/nvme1n2 → /dev/nvme1, /dev/nvme0 → /dev/nvme0.
        컨트롤러 char device 가 없으면(WSL2 등) nvme_device 경로 그대로 폴백.
        """
        dev = self._normalize_nvme_path(self.config.nvme_device)
        m = re.match(r'(/dev/nvme\d+)', dev)
        ctrl = m.group(1) if m else dev
        if ctrl != dev and not os.path.exists(ctrl):
            return dev   # 컨트롤러 char device 없음 → namespace 경로 폴백
        return ctrl

    def _detect_lba_size(self) -> int:
        """blockdev --getss로 LBA 크기 자동 감지. 실패 시 512 반환."""
        ns_dev = self._io_device()
        r = self._run_cmd(['blockdev', '--getss', ns_dev])
        if r:
            try:
                size = int(r.stdout.strip())
                if size > 0:
                    return size
            except ValueError:
                pass
        return 512

    def _generate_default_seeds(self) -> List[Seed]:
        """각 Opcode별 NVMe 스펙 기반 정상 명령어를 초기 시드로 생성 (nvme_seeds.py 참조)"""
        seeds: List[Seed] = []
        SEED_TEMPLATES = _DEFAULT_SEED_TEMPLATES

        fw_bin  = self.config.fw_bin
        fw_xfer = self.config.fw_xfer_size
        fw_slot = self.config.fw_slot
        use_real_fw = bool(fw_bin and os.path.isfile(fw_bin))
        if use_real_fw:
            log.info(f"[Seed] fw_bin={fw_bin} (xfer={fw_xfer}B slot={fw_slot}) → 실제 FWDownload 시드 생성")
        else:
            log.info("[Seed] fw_bin 미지정 또는 파일 없음 → FWDownload 더미 시드 사용")

        # FormatNVM / Sanitize는 파괴적 동작이므로 시드에서 제외
        _DESTRUCTIVE = {"FormatNVM", "Sanitize"}

        excluded = set(self.config.excluded_opcodes)
        for cmd in self.commands:
            if cmd.opcode in excluded:
                log.info(f"[Seed] {cmd.name} (0x{cmd.opcode:02x}) — excluded_opcodes 제외")
                continue
            if cmd.name in _DESTRUCTIVE:
                log.info(f"[Seed] {cmd.name} (0x{cmd.opcode:02x}) — 파괴적 명령어 제외")
                continue

            if cmd.name == "FWDownload":
                if use_real_fw:
                    with open(fw_bin, "rb") as f:
                        fw_data = f.read()
                    offset = 0
                    chunk_idx = 0
                    self._fw_chunks.clear()
                    while offset < len(fw_data):
                        chunk = fw_data[offset:offset + fw_xfer]
                        if len(chunk) % 4 != 0:
                            chunk = chunk + b'\x00' * (4 - len(chunk) % 4)
                        numd = (len(chunk) // 4) - 1  # CDW10: NUMD (0-based)
                        ofst = offset // 4             # CDW11: OFST (dword offset)
                        chunk_seed = Seed(data=chunk, cmd=cmd,
                                         cdw10=numd, cdw11=ofst, found_at=0)
                        self._fw_chunks.append(chunk_seed)
                        log.info(f"[Seed] FWDownload chunk {chunk_idx} "
                                 f"offset={offset} ({len(chunk)}B) NUMD=0x{numd:x}")
                        offset += fw_xfer
                        chunk_idx += 1
                    # corpus에는 대표 시드 1개만 — 메인 루프에서 _fw_chunks 전체 전송
                    seeds.append(self._fw_chunks[0])
                    log.info(f"[Seed] FWDownload {chunk_idx}개 청크 → corpus 1개(대표 시드), "
                             f"실행 시 전체 청크 순서대로 전송")
                else:
                    # 더미: 1KB zeros (변이 시작점용)
                    seed = Seed(data=b'\x00' * 32768, cmd=cmd,
                                cdw10=0x1FFF, cdw11=0, found_at=0)
                    seeds.append(seed)
                    log.info("[Seed] FWDownload dummy 32KB (fw_bin 없음)")
                continue

            if cmd.name == "FWCommit":
                if use_real_fw:
                    cdw10_commit = (0x01 << 3) | (fw_slot & 0x7)  # CA=001(슬롯 기록+리셋 활성), FS=fw_slot (이전: FS/CA 뒤바뀜 버그)
                    seed = Seed(data=b'', cmd=cmd, cdw10=cdw10_commit, found_at=0)
                    seeds.append(seed)
                    log.info(f"[Seed] FWCommit slot={fw_slot} action=1 "
                             f"CDW10=0x{cdw10_commit:08x}")
                else:
                    for tmpl in SEED_TEMPLATES["FWCommit"]:
                        seed = Seed(data=b'', cmd=cmd,
                                    cdw10=tmpl.get('cdw10', 0), found_at=0)
                        seeds.append(seed)
                        log.info(f"[Seed] FWCommit CDW10=0x{seed.cdw10:08x} "
                                 f"({tmpl.get('description','')})")
                continue

            templates = SEED_TEMPLATES.get(cmd.name, [])
            if templates:
                for tmpl in templates:
                    data = tmpl.get('data', b'')
                    desc = tmpl.get('description', '')
                    seed = Seed(
                        data=data,
                        cmd=cmd,
                        cdw2=tmpl.get('cdw2', 0),
                        cdw3=tmpl.get('cdw3', 0),
                        cdw10=tmpl.get('cdw10', 0),
                        cdw11=tmpl.get('cdw11', 0),
                        cdw12=tmpl.get('cdw12', 0),
                        cdw13=tmpl.get('cdw13', 0),
                        cdw14=tmpl.get('cdw14', 0),
                        cdw15=tmpl.get('cdw15', 0),
                        nsid_override=tmpl.get('nsid_override', None),
                        found_at=0,
                    )
                    seeds.append(seed)
                    log.info(f"[Seed] {cmd.name} (0x{cmd.opcode:02x}): {desc} "
                             f"CDW10=0x{seed.cdw10:08x}")
            else:
                # 알 수 없는 명령어는 기본 시드
                seeds.append(Seed(data=b'\x00' * 64, cmd=cmd, found_at=0))

        # Write → Read 순서로 corpus 앞에 배치 — I/O 위주 커버리지 우선 수집
        _IO_ORDER = ["Write", "Read"]
        write_seeds = [s for s in seeds if s.cmd.name == "Write"]
        read_seeds  = [s for s in seeds if s.cmd.name == "Read"]
        other_seeds = [s for s in seeds if s.cmd.name not in {"Write", "Read"}]
        io_seeds = write_seeds + read_seeds
        seeds = io_seeds + other_seeds
        if io_seeds:
            log.info(f"[Seed] I/O 우선 정렬: Write {len(write_seeds)}개 → Read {len(read_seeds)}개 → "
                     f"나머지 {len(other_seeds)}개 (총 {len(seeds)}개)")

        return seeds

    def _load_seeds(self):
        # 사용자 시드 디렉토리에서 로드
        if self.config.seed_dir and os.path.isdir(self.config.seed_dir):
            for seed_file in Path(self.config.seed_dir).iterdir():
                if seed_file.is_file() and not seed_file.name.endswith('.json'):
                    with open(seed_file, 'rb') as f:
                        data = f.read()
                    # 메타데이터 JSON이 있으면 CDW 값도 로드
                    meta_file = Path(str(seed_file) + '.json')
                    meta = {}
                    if meta_file.exists():
                        with open(meta_file, 'r') as f:
                            meta = json.load(f)
                    _excluded = set(self.config.excluded_opcodes)
                    for cmd in self.commands:
                        if cmd.opcode in _excluded:
                            continue
                        if meta.get('command') and meta['command'] != cmd.name:
                            continue
                        seed = Seed(
                            data=data, cmd=cmd, found_at=0,
                            cdw2=meta.get('cdw2', 0), cdw3=meta.get('cdw3', 0),
                            cdw10=meta.get('cdw10', 0), cdw11=meta.get('cdw11', 0),
                            cdw12=meta.get('cdw12', 0), cdw13=meta.get('cdw13', 0),
                            cdw14=meta.get('cdw14', 0), cdw15=meta.get('cdw15', 0),
                        )
                        self.corpus.append(seed)
            log.info(f"[Fuzzer] Loaded {len(self.corpus)} seeds from {self.config.seed_dir}")

        # 항상 NVMe 스펙 기반 기본 정상 시드를 추가
        default_seeds = self._generate_default_seeds()
        self.corpus.extend(default_seeds)
        log.info(f"[Fuzzer] Added {len(default_seeds)} default NVMe spec seeds"
                 f" (total corpus: {len(self.corpus)})")

    def _calculate_energy(self, seed: 'Union[Seed, SequenceSeed]') -> float:
        """v4: AFLfast 'explore' 스케줄 - 적게 실행된 시드에 높은 에너지.
        v7.5: SequenceSeed는 base / len(commands) 패널티 적용."""
        n = len(seed.commands) if isinstance(seed, SequenceSeed) else 1

        if seed.exec_count == 0:
            return MAX_ENERGY / n

        ratio = self.executions / seed.exec_count
        if ratio <= 1:
            return 1.0 / n

        try:
            power = int(math.log2(ratio))
            factor = min(MAX_ENERGY, 2 ** power)
        except (ValueError, OverflowError):
            factor = 1.0

        return factor / n

    def _select_seed(self) -> 'Optional[Union[Seed, SequenceSeed]]':
        """v4: 에너지 기반 가중치 랜덤 선택.
        v7.5+: corpus에 Seed와 SequenceSeed가 혼재하므로 두 타입 모두 반환 가능."""
        if not self.corpus:
            return None

        # 에너지 계산
        for seed in self.corpus:
            seed.energy = self._calculate_energy(seed)

        # 가중치 랜덤 선택
        total_energy = sum(s.energy for s in self.corpus)
        if total_energy <= 0:
            seed = random.choice(self.corpus)
            seed.exec_count += 1
            return seed

        r = random.uniform(0, total_energy)
        cumulative = 0
        for seed in self.corpus:
            cumulative += seed.energy
            if r <= cumulative:
                seed.exec_count += 1
                return seed

        # fallback
        self.corpus[-1].exec_count += 1
        return self.corpus[-1]

    def _epoch_reset_corpus(self):
        """v6.1: Epoch 경계에서 corpus를 favored+초기 시드만 유지하고 energy 감쇠.

        CORPUS_EPOCH_SIZE > 0 일 때 매 epoch마다 호출됨.
        목적: 오래된 중복 시드가 selection 확률을 희석하는 현상 방지.
              에너지를 1/4로 감쇠시켜 완전 초기화 없이 fresh 스케줄링 유도.
        v7.5+: SequenceSeed도 동일 규칙 적용 — favored가 아니면 epoch에서 제거.
        """
        if CORPUS_EPOCH_SIZE <= 0:
            return
        before = len(self.corpus)
        # 제거 대상 추적 — SequenceSeed면 replay .sh 청소 필요
        _removed_seqs = [s for s in self.corpus
                         if isinstance(s, SequenceSeed)
                         and not (s.is_favored or s.found_at == 0)]
        self.corpus = [s for s in self.corpus
                       if s.is_favored or s.found_at == 0]
        for s in self.corpus:
            s.exec_count = max(1, s.exec_count // 4)
            s.energy = 1.0
        after = len(self.corpus)
        log.info(f"[Epoch] corpus reset: {before} → {after} "
                 f"(favored+initial 유지, energy 리셋, epoch={self.executions:,})")
        for s in _removed_seqs:
            self._remove_seq_replay_artifacts(s)

    def _cull_state_corpus(self):
        """state corpus 관리: 크기 제한 + 동일 bucket 중복 제거."""
        MAX_STATE_CORPUS = 50

        # 1) 동일 causes(bucket) → score 높은 것만 유지
        seen: dict[str, StateCorpusEntry] = {}
        for entry in self.state_corpus:
            key = '|'.join(sorted(entry.causes))
            if key not in seen or entry.score > seen[key].score:
                seen[key] = entry
        deduped = list(seen.values())

        # 2) 크기 초과 시 score 낮은 것 제거
        if len(deduped) > MAX_STATE_CORPUS:
            deduped.sort(key=lambda e: e.score, reverse=True)
            deduped = deduped[:MAX_STATE_CORPUS]

        before = len(self.state_corpus)
        self.state_corpus = deduped
        after = len(self.state_corpus)
        if before != after:
            log.debug(f"[State-Cull] {before} → {after} entries")

    # ------------------------------------------------------------------ #
    # CSFuzz §III-C/D: corpus selection + seed prioritization             #
    # ------------------------------------------------------------------ #

    def _select_state_entry_csfuzz(self) -> 'Optional[StateCorpusEntry]':
        """CSFuzz §III-D 수식 (6): state corpus에서 entry를 확률적으로 선택."""
        if not self.state_corpus:
            return None
        _a = 0.5
        t_sum = sum(e.found_at for e in self.state_corpus)
        weights = []
        for entry in self.state_corpus:
            causes = entry.causes
            if not causes:
                weights.append(1.0)
                continue
            fuzz_cnts = [self._state_bucket_fuzz_count.get(b, 0) for b in causes]
            min_fuzz  = min(fuzz_cnts)
            sum_inv_n = sum(1.0 / max(n, 1) for n in fuzz_cnts)
            # term1: min_fuzz=0이면 never selected → max priority
            if min_fuzz == 0:
                term1 = 1.0 - _a
            else:
                denom = min_fuzz * sum_inv_n
                term1 = (1 - _a) / max(denom, 1e-9)
            # term2: recently added → prefer large found_at
            term2 = _a * entry.found_at / max(t_sum, 1)
            weights.append(term1 + term2)
        total = sum(weights)
        if total <= 0:
            return random.choice(self.state_corpus)
        r = random.uniform(0, total)
        cumul = 0.0
        for entry, w in zip(self.state_corpus, weights):
            cumul += w
            if r <= cumul:
                return entry
        return self.state_corpus[-1]

    def _replay_state_sequence(self, entry: 'StateCorpusEntry') -> bool:
        """StateCorpusEntry의 명령 시퀀스를 SSD에 재실행해 상태 재현.
        replay 명령도 실제 SSD에서 실행되므로 _cmd_history에 기록한다
        (record_history=True) → crash replay.sh가 replay 시퀀스까지 그대로 재현.
        단, replay 중에는 state corpus 신규 캡처를 하지 않는다(_account_command의
        source='c2' 가드) — 재현 중 새 엔트리 캡처 시 자기복제/중복 방지.
        타임아웃 발생 시 False를 반환."""
        log.warning(f"[State-Replay] found_at={entry.found_at:,}  "
                    f"seq={len(entry.sequence)}  score={entry.score:.1f}")
        # bucket fuzz count 갱신
        for b in entry.causes:
            self._state_bucket_fuzz_count[b] = \
                self._state_bucket_fuzz_count.get(b, 0) + 1
        entry.exec_count += 1

        # P2: replay 전 state 스냅샷 (EMA score 갱신용)
        _pre_snap = self.state_monitor.capture() if self.config.state_enabled else None
        _replay_new_pcs = 0  # P3: replay 중 edge coverage 누적 (EMA score에 반영)

        for hist_item in entry.sequence:
            if hist_item.get('kind') != 'nvme':
                # kind='pm'/'pcie_state' 항목은 replay에서 의도적으로 제외.
                # PM context 재현은 복잡도 대비 이득이 불명확하며, replay 재현성보다
                # 순수 NVMe 시퀀스 효과를 평가하는 것이 C2 score의 목적에 맞음.
                continue
            _data  = hist_item.get('data') or b'\x00' * 4
            # label → (opcode+cmd_type) → fallback 순으로 cmd 복원
            _label  = hist_item.get('label', '')
            _ptype  = hist_item.get('passthru_type', '')
            _is_adm = 'admin' in _ptype.lower()
            _cmd = (
                next((c for c in self.commands if c.name == _label), None)
                or next((c for c in self.commands
                         if c.opcode == hist_item.get('opcode', 0)
                         and (c.cmd_type == NVMeCommandType.ADMIN) == _is_adm), None)
                or self.commands[0]
            )
            # admin↔IO 강제 스왑 복원
            _force_admin = (
                True  if _is_adm and _cmd.cmd_type != NVMeCommandType.ADMIN else
                False if not _is_adm and _cmd.cmd_type == NVMeCommandType.ADMIN else
                None
            )
            # opcode_override 복원: vendor opcode 등 실제 전송 opcode가 다를 경우
            _hist_opcode = hist_item.get('opcode', _cmd.opcode)
            _opcode_override = _hist_opcode if _hist_opcode != _cmd.opcode else None
            # nsid: 0도 유효한 값이므로 key 존재 여부로 판별
            _nsid = hist_item['nsid'] if 'nsid' in hist_item else None
            _seed = Seed(
                data=_data, cmd=_cmd,
                cdw2=hist_item.get('cdw2', 0),   cdw3=hist_item.get('cdw3', 0),
                cdw10=hist_item.get('cdw10', 0),  cdw11=hist_item.get('cdw11', 0),
                cdw12=hist_item.get('cdw12', 0),  cdw13=hist_item.get('cdw13', 0),
                cdw14=hist_item.get('cdw14', 0),  cdw15=hist_item.get('cdw15', 0),
                nsid_override=_nsid,
                opcode_override=_opcode_override,
                force_admin=_force_admin,
                data_len_override=hist_item.get('data_len'),  # zero-length 포함 정확히 복원
            )
            # record_history=True: replay 명령도 실제 실행되므로 crash replay.sh가
            # 그대로 재현하도록 _cmd_history에 기록 (last-100 window 안에서 완전).
            rc = self._send_nvme_command(_data, _seed, record_history=True)
            last_samples = self.sampler.stop_sampling()
            # PM rotation은 replay 정확도를 위해 의도적으로 제외 (main loop 전용)
            _interesting, _new_pcs, _action = self._account_command(
                _seed, _data, rc, last_samples, source='c2')
            _replay_new_pcs += _new_pcs if isinstance(_new_pcs, int) else 0
            if _action == 'break':
                return False

        # replay 후 state 비교 → EMA score + C2 reward 기록 (per-replay)
        _nvme_count = sum(1 for h in entry.sequence if h.get('kind') == 'nvme')
        _seq_len = max(_nvme_count, 1)  # PM 항목 제외한 실제 replay 명령 수 기준
        _state_reproduced = False
        if self.config.state_enabled and _pre_snap is not None:
            _post_snap = self.state_monitor.capture()
            if _post_snap is not None:
                _rdelta = self.state_monitor.delta(_pre_snap, _post_snap)
                if _rdelta is not None:
                    _state_score  = _rdelta.score / _seq_len
                    _edge_score   = _replay_new_pcs / _seq_len
                    _replay_score = _state_score + _edge_score
                    entry.score = 0.8 * entry.score + 0.2 * _replay_score
                    # entry.causes 버킷 중 하나라도 재현됐으면 성공
                    _state_reproduced = bool(set(_rdelta.state_buckets()) & set(entry.causes))
                    log.info(f"[State-Replay] EMA score={entry.score:.2f} "
                             f"(replay={_replay_score:.2f}  "
                             f"state={_state_score:.2f}  edge={_edge_score:.2f}  "
                             f"seq={_seq_len}  state_ok={_state_reproduced})")
        # C2 reward: state 변화 재현 성공이면 1, 실패/불명이면 0 (per-replay 단위)
        self._csfuzz_c2_rewards.append(1 if _state_reproduced else 0)
        return True

    def _update_csfuzz_p(self):
        """CSFuzz §III-C 수식 (4)/(5): 10000회 interval마다 corpus selection 확률 p 갱신.

        m1: per-command edge 성공률 (C1 reward, 0/1 per command)
        m2: per-replay state 재현 성공률 (C2 reward, 0/1 per replay)
        단위를 맞추기 위해 m2를 avg_seq로 나눠 per-command 스케일로 변환 후 비교.
        """
        NC1 = max(len(self.corpus), 1)
        NC2 = max(len(self.state_corpus), 1)
        avg_seq = (sum(len(e.sequence) for e in self.state_corpus)
                   / len(self.state_corpus)) if self.state_corpus else 1.0
        m1 = (sum(self._csfuzz_c1_rewards) / len(self._csfuzz_c1_rewards)
              if self._csfuzz_c1_rewards else 0.0)
        m2_raw = (sum(self._csfuzz_c2_rewards) / len(self._csfuzz_c2_rewards)
                  if self._csfuzz_c2_rewards else 0.0)
        m2 = m2_raw / max(avg_seq, 1.0)   # per-replay → per-command 단위 변환
        delta = (self._csfuzz_a * m1 / NC1
                 - self._csfuzz_b * m2 / NC2) * (NC1 + NC2)
        self._csfuzz_p = max(0.1, min(0.9, self._csfuzz_p + delta))
        log.info(f"[CSFuzz-p] p={self._csfuzz_p:.3f} δ={delta:.4f} "
                 f"m1={m1:.4f} m2_raw={m2_raw:.4f} m2_norm={m2:.6f} "
                 f"avg_seq={avg_seq:.1f} NC1={NC1} NC2={NC2}")
        # v7.6: 시각화용 히스토리 누적 (clear() 전에 기록)
        self._csfuzz_history.append(
            (self.executions, self._csfuzz_p, m1, m2, NC1, NC2)
        )
        self._csfuzz_c1_rewards.clear()
        self._csfuzz_c2_rewards.clear()

    # ------------------------------------------------------------------
    # v7.3: per-command 회계 helper
    # _send_nvme_command() + stop_sampling() 이후 호출.
    # 반환: (is_interesting, new_pcs, action)
    #   action = 'ok' | 'break' | 'continue'
    # ------------------------------------------------------------------
    def _account_command(self,
                         seed: 'Seed',
                         fuzz_data: bytes,
                         rc: int,
                         last_samples: int,
                         source: str = 'c1',
                         is_det_stage: bool = False,
                         seq_member: bool = False) -> tuple:
        """NVMe 명령 1회 실행 후 모든 회계 처리.

        executions 증가, coverage 평가, corpus 추가, 주기적 Stats/state/cull/graph.
        RC_TIMEOUT → _handle_timeout_crash 호출 후 ('break') 반환.
        RC_ERROR   → ('continue') 반환.
        RC_SKIP    → 가드가 전송 차단 (전송·샘플링 없었음) → 회계 없이 ('continue').
        """
        # 가드 차단 명령: 실제 전송/샘플링이 없었으므로 executions/coverage/crash 에 반영하지 않음.
        if rc == self.RC_SKIP:
            return False, 0, 'continue'

        cmd = seed.cmd
        track_key = self._tracking_label(cmd, seed)
        self.cmd_stats[track_key]["exec"] += 1

        self.executions += 1

        # P3: passthru_stats (replay 포함 모든 경로 추적)
        if seed.force_admin is True:
            _pt = 'admin-passthru'
        elif seed.force_admin is False:
            _pt = 'io-passthru'
        else:
            _pt = 'admin-passthru' if cmd.cmd_type == NVMeCommandType.ADMIN else 'io-passthru'
        self.passthru_stats[_pt] += 1

        if rc not in (self.RC_TIMEOUT, self.RC_ERROR):
            self.rc_stats[track_key][rc] += 1

        # coverage 평가
        is_interesting, new_pcs = self.sampler.evaluate_coverage()

        if self._sa_loaded and self._sa_bb_starts:
            _mask = self._sa_thumb_mask
            _cur_bbs: set = set()
            for _pc in self.sampler.current_trace:
                _pk = (_pc & ~1) if _mask else _pc
                _idx = bisect.bisect_right(self._sa_bb_starts, _pk) - 1
                if _idx >= 0 and _pk < self._sa_bb_ends[_idx]:
                    _cur_bbs.add(self._sa_bb_starts[_idx])
            _new_bbs = _cur_bbs - self._sa_covered_bbs
            is_interesting = len(_new_bbs) > 0
            new_pcs = len(_new_bbs)
            _seed_covered = _cur_bbs
            if self.sampler._last_new_pcs:
                self._update_static_coverage(self.sampler._last_new_pcs)
        else:
            _seed_covered = set(self.sampler.current_trace)
            if self._sa_loaded and self.sampler._last_new_pcs:
                self._update_static_coverage(self.sampler._last_new_pcs)

        self.cmd_pcs[track_key].update(self.sampler.current_trace)
        if self.sampler._last_raw_pcs:
            raw_in_range = [pc for pc in self.sampler._last_raw_pcs
                            if self.sampler._in_range(pc)]
            if raw_in_range:
                self.cmd_traces[track_key].append(raw_in_range)

        # 로그
        raw_count = len(self.sampler._last_raw_pcs)
        oor_count = self.sampler._out_of_range_count
        det_tag  = " [Det]" if is_det_stage else ""
        src_tag  = f" [{source}]" if source != 'c1' else ""
        mopt_tag = f" mopt={self.mopt_mode}"
        log.info(f"exec={self.executions}{det_tag}{src_tag} cmd={cmd.name} "
                 f"raw_samples={raw_count} pcs_this_run={len(self.sampler.current_trace)} "
                 f"out_of_range={oor_count} new_pcs={new_pcs} "
                 f"global_pcs={len(self.sampler.global_coverage)} "
                 f"last_new_at={self.sampler._last_new_at}{mopt_tag} "
                 f"stop={self.sampler._stopped_reason}")

        if self.sampler._unique_at_intervals:
            log.debug(f"  saturation: {self.sampler._unique_at_intervals}")
        if self.sampler._last_raw_pcs:
            log.debug(f"  ALL raw PCs: {[hex(pc) for pc in self.sampler._last_raw_pcs]}")

        # timeout / error
        if rc == self.RC_TIMEOUT:
            self._handle_timeout_crash(seed, fuzz_data)
            # v7.8: unsupported_skip 분기에서 _timeout_crash 가 set 되지 않은 경우
            # 다음 mutation 으로 진행 (skip + power cycle 완료된 상태).
            if self._timeout_crash:
                return False, 0, 'break'
            return False, 0, 'continue'
        if rc == self.RC_ERROR:
            # 시퀀스 모드: 실패 명령도 sink에 기록 — replay 시 동일 상태 재현에 필요
            if self._seq_sink is not None and seq_member:
                _err_seed = Seed(
                    data=fuzz_data, cmd=cmd,
                    cdw2=seed.cdw2,   cdw3=seed.cdw3,
                    cdw10=seed.cdw10, cdw11=seed.cdw11,
                    cdw12=seed.cdw12, cdw13=seed.cdw13,
                    cdw14=seed.cdw14, cdw15=seed.cdw15,
                    opcode_override=seed.opcode_override,
                    nsid_override=seed.nsid_override,
                    force_admin=seed.force_admin,
                    data_len_override=seed.data_len_override,
                    found_at=self.executions, new_pcs=new_pcs, covered_pcs=_seed_covered,
                )
                self._seq_sink['commands'].append(_err_seed)
                # RC_ERROR라도 새 PC가 발견되면 sequence interesting으로 표시
                if new_pcs > 0:
                    self.sampler.interesting_inputs += 1
                    self.cmd_stats[track_key]["interesting"] += 1
                    self._seq_sink['interesting'] = True
                    self._seq_sink['new_pcs'] += new_pcs
                    self._seq_sink['covered_pcs'].update(_seed_covered)
                    log.info(f"[+][Seq-Acc/Err] cmd={cmd.name} +{new_pcs} PCs "
                             f"(seq_acc={self._seq_sink['new_pcs']})")
            log.error(f"[ERROR] {cmd.name} subprocess internal error — skipping")
            return False, 0, 'continue'

        # corpus 추가
        if self._seq_sink is not None and seq_member:
            # 시퀀스 모드: interesting 여부에 관계없이 모든 명령 기록
            # (setup 명령이 비interesting이어도 replay에 필요하므로 항상 포함)
            _cmd_seed = Seed(
                data=fuzz_data,
                cmd=cmd,
                cdw2=seed.cdw2,   cdw3=seed.cdw3,
                cdw10=seed.cdw10, cdw11=seed.cdw11,
                cdw12=seed.cdw12, cdw13=seed.cdw13,
                cdw14=seed.cdw14, cdw15=seed.cdw15,
                opcode_override=seed.opcode_override,
                nsid_override=seed.nsid_override,
                force_admin=seed.force_admin,
                data_len_override=seed.data_len_override,
                found_at=self.executions,
                new_pcs=new_pcs,
                covered_pcs=_seed_covered,
            )
            self._seq_sink['commands'].append(_cmd_seed)
            if is_interesting:
                self.sampler.interesting_inputs += 1
                self.cmd_stats[track_key]["interesting"] += 1
                self._seq_sink['interesting'] = True
                self._seq_sink['new_pcs'] += new_pcs
                self._seq_sink['covered_pcs'].update(_seed_covered)
                if self.config.state_enabled and source == 'c1':
                    self._csfuzz_c1_rewards.append(1)
                log.info(f"[+][Seq-Acc] cmd={cmd.name} +{new_pcs} PCs "
                         f"(seq_acc={self._seq_sink['new_pcs']})")
            else:
                if self.config.state_enabled and source == 'c1':
                    self._csfuzz_c1_rewards.append(0)
        elif is_interesting:
            self.sampler.interesting_inputs += 1
            self.cmd_stats[track_key]["interesting"] += 1

            new_seed = Seed(
                data=fuzz_data,
                cmd=cmd,
                cdw2=seed.cdw2,   cdw3=seed.cdw3,
                cdw10=seed.cdw10, cdw11=seed.cdw11,
                cdw12=seed.cdw12, cdw13=seed.cdw13,
                cdw14=seed.cdw14, cdw15=seed.cdw15,
                opcode_override=seed.opcode_override,
                nsid_override=seed.nsid_override,
                force_admin=seed.force_admin,
                data_len_override=seed.data_len_override,
                found_at=self.executions,
                new_pcs=new_pcs,
                covered_pcs=_seed_covered,
            )

            # 단일 명령 모드: 기존 경로
            self.corpus.append(new_seed)
            _cov_label = "BB" if (self._sa_loaded and self._sa_bb_starts) else "PC"
            log.warning(
                f"[+][Edge-Cov] cmd={cmd.name}  "
                f"new_{_cov_label}={new_pcs}  "
                f"total_{_cov_label}={len(self._sa_covered_bbs) if (self._sa_loaded and self._sa_bb_starts) else len(self.sampler.global_coverage)}  "
                f"corpus={len(self.corpus)}  exec={self.executions:,}")
            if self.config.state_enabled and source == 'c1':
                self._csfuzz_c1_rewards.append(1)

            input_hash = hashlib.md5(fuzz_data).hexdigest()[:12]
            corpus_file = self.output_dir / 'corpus' / f"input_{cmd.name}_{hex(cmd.opcode)}_{input_hash}"
            corpus_file.parent.mkdir(parents=True, exist_ok=True)
            with open(corpus_file, 'wb') as f:
                f.write(fuzz_data)
            with open(str(corpus_file) + '.json', 'w') as f:
                json.dump(self._seed_meta(new_seed), f)

            log.info(f"[+] New coverage! cmd={cmd.name} "
                     f"CDW10=0x{seed.cdw10:08x} "
                     f"+{new_pcs} PCs (total: {len(self.sampler.global_coverage)} pcs)")

            if not new_seed.det_done:
                gen = self._deterministic_stage(new_seed)
                self._det_queue.append((new_seed, gen))
                log.info(f"[Det] Queued {new_seed.cmd.name} "
                         f"(queue size: {len(self._det_queue)})")
        else:
            # C1: non-interesting도 0으로 기록 (분모 정확성)
            if self.config.state_enabled and source == 'c1':
                self._csfuzz_c1_rewards.append(0)
            # C2 reward는 replay 단위로만 기록 (여기서는 추가하지 않음)

        # MOpt
        if self._current_mutations:
            if is_interesting:
                for op in self._current_mutations:
                    self.mopt_finds[op] += 1
            for op in self._current_mutations:
                self.mopt_uses[op] += 1

        # 100회 주기
        if self.executions % 100 == 0:
            self._seq_cmds_in_window = 0   # Phase 3: sequence 명령 window 초기화
            _now = datetime.now()
            _wdt = (_now - self._window_t0).total_seconds()
            _wexec = self.executions - self._window_exec0
            _window_eps = _wexec / _wdt if _wdt > 0 else 0
            self._window_t0 = datetime.now()
            self._window_exec0 = self.executions

            if self._sa_loaded:
                _elapsed_snap = (datetime.now() - self.start_time).total_seconds() \
                                if self.start_time else 0
                _bbpct = (100.0 * len(self._sa_covered_bbs) / self._sa_total_bbs
                          if self._sa_total_bbs > 0 else 0.0)
                _fpct  = (100.0 * len(self._sa_entered_funcs) / self._sa_total_funcs
                          if self._sa_total_funcs > 0 else 0.0)
                self._sa_cov_history.append(
                    (self.executions, _elapsed_snap, _bbpct, _fpct))

            stats = self._collect_stats()
            self._print_status(stats, last_samples, window_eps=_window_eps)
            for h in log.handlers:
                h.flush()
                if isinstance(h, logging.FileHandler) and h.stream:
                    os.fsync(h.stream.fileno())

        if self.executions % 10000 == 0 and self.executions > 0:
            self._log_device_info()   # 주기적 Device Information(id-ctrl/id-ns) 재출력
            self._log_smart()
            if self.config.state_enabled:
                self._log_state_snapshot()

        # state monitoring
        if (self.config.state_enabled
                and self.executions % 100 == 0
                and self.executions > 0
                and source != 'c2'):   # replay 중에는 신규 캡처 금지 (자기복제 방지)
            _snap = self.state_monitor.capture()
            if _snap is not None:
                if self._state_snap_prev is not None:
                    _delta = self.state_monitor.delta(self._state_snap_prev, _snap)
                    if (_delta.is_interesting
                            and self.state_monitor.update_cov_map(_delta, self.state_cov_map)
                            and self._cmd_history):
                        _entry = StateCorpusEntry(
                            sequence = list(self._cmd_history),
                            delta    = _delta,
                            score    = _delta.score,
                            causes   = [b for b in _delta.state_buckets()
                                        if not b.endswith(':=init')],
                            found_at = self.executions,
                        )
                        self.state_corpus.append(_entry)
                        # C2 reward는 _replay_state_sequence()에서 replay 후 state 재현 여부로 기록.
                        # periodic state-cov 발견은 새 state_corpus 추가만 담당하고 reward는 추가하지 않음.
                        self._generate_state_replay_sh(_entry)
                        # v8.4: 워크로드 블록 중 캡처면 패턴명 태깅 (귀속 — 어느 IO 패턴이 state 를 움직였나)
                        _wl_tag = (f" [IO-WL:{self._wl_active_pattern}]"
                                   if self._wl_active_pattern else "")
                        log.warning(
                            f"[+][State-Cov]{_wl_tag} {_entry.causes}  "
                            f"score={_entry.score:.1f}  "
                            f"seq={len(_entry.sequence)}  "
                            f"state-corpus={len(self.state_corpus)}")
                        for _fname, _fdelta in _delta.changes.items():
                            if _fdelta != 0:
                                _before = self._state_snap_prev.get(_fname, 0)
                                _after  = _snap.get(_fname, 0)
                                log.warning(
                                    f"[+][State-Cov]   {_fname}: "
                                    f"{_before:,} → {_after:,} (Δ{_fdelta:+,})")
                self._state_snap_prev = _snap

        # 1000회 주기
        if self.executions % 1000 == 0 and self.executions > 0:
            self._cull_corpus()
            if self.config.state_enabled:
                self._cull_state_corpus()
            self._mopt_update_phase()

        # 10000회 주기
        if self.executions % 10000 == 0 and self.executions > 0:
            if self.config.state_enabled and self.state_corpus:
                self._update_csfuzz_p()

        if (CORPUS_EPOCH_SIZE > 0
                and self.executions % CORPUS_EPOCH_SIZE == 0
                and self.executions > 0):
            self._epoch_reset_corpus()
            if not self.config.no_jlink and not self.sampler._openocd_alive():
                log.error("[OpenOCD] heartbeat 실패 — OpenOCD 프로세스가 종료됐습니다.")
                if not self.sampler._reconnect():
                    log.error("  재시작 실패. USB 케이블/J-Link 상태를 확인하세요.")
                    return False, 0, 'break'

        if (self.executions % GRAPH_REFRESH_INTERVAL == 0
                and self.executions > 0):
            try:
                _gdir = self.output_dir / 'graphs'
                _gdir.mkdir(parents=True, exist_ok=True)
                self._generate_comparison_chart(_gdir)
                self._generate_static_coverage_graphs()
                self._generate_heatmaps()
                self._generate_mutation_chart()
                self._generate_csfuzz_dynamics()
                log.info(f"[Graph] 주기 갱신 완료 (exec={self.executions:,})")
            except Exception as _ge:
                log.warning(f"[Graph] 주기 갱신 실패 (무시): {_ge}")

        return is_interesting, new_pcs, 'ok'

    def _cull_corpus(self):
        """v4.3: AFL++ 방식 corpus culling (v4.5+: PC 주소 기반).
        각 PC에 대해 가장 작은 seed를 favored로 마킹하고,
        favored가 아닌 seed 중 기여도 없는 것을 제거한다.
        v7.5+: 2-pass favored 마킹.
          Pass 1 — 단일 Seed만으로 PC → best(data 크기 기준) 매핑.
          Pass 2 — 단일 Seed가 커버하지 못한 PC에 한해 SequenceSeed가 채움.
        단일 Seed와 SequenceSeed가 동일 PC를 커버하면 항상 단일 Seed가 우선."""
        if len(self.corpus) <= 10:
            return

        # Pass 1: 단일 Seed만으로 PC → best 매핑 (data 크기 기준)
        pc_best: dict[int, object] = {}
        for seed in self.corpus:
            if not isinstance(seed, Seed) or not seed.covered_pcs:
                continue
            for pc in seed.covered_pcs:
                cur = pc_best.get(pc)
                if cur is None or len(seed.data) < len(cur.data):
                    pc_best[pc] = seed

        # Pass 2: 단일 Seed가 없는 PC만 SequenceSeed가 채움
        for seed in self.corpus:
            if not isinstance(seed, SequenceSeed) or not seed.covered_pcs:
                continue
            for pc in seed.covered_pcs:
                if pc not in pc_best:
                    pc_best[pc] = seed

        # favored 마킹
        favored_seeds = {id(s) for s in pc_best.values()}
        for seed in self.corpus:
            seed.is_favored = id(seed) in favored_seeds

        # 제거 대상: favored 아님 + exec_count >= 2 + 기본 시드 아님 (found_at > 0)
        # SequenceSeed도 단일 Seed와 동일한 선택 압력 적용.
        before = len(self.corpus)
        _to_remove = [s for s in self.corpus
                      if not (s.is_favored or s.exec_count < 2 or s.found_at == 0)]
        _removed_seq_set = {id(s) for s in _to_remove if isinstance(s, SequenceSeed)}
        self.corpus = [s for s in self.corpus
                       if s.is_favored or s.exec_count < 2 or s.found_at == 0]
        removed = before - len(self.corpus)
        if removed > 0:
            log.info(f"[Cull] corpus {before} → {len(self.corpus)} "
                     f"(-{removed}, favored={sum(1 for s in self.corpus if s.is_favored)})")
        for s in _to_remove:
            if isinstance(s, SequenceSeed):
                self._remove_seq_replay_artifacts(s)

        # 4) 하드 상한: 상한 초과 시 exec_count가 높은 비선호 seed부터 강제 제거
        # SequenceSeed도 일반 cull과 동일 규칙(favored/found_at) 보호.
        # 그 외 SeqSeed는 단일 Seed와 동일하게 exec_count 내림차순으로 evict.
        hard_limit = self.config.max_corpus_hard_limit
        if hard_limit > 0 and len(self.corpus) > hard_limit:
            before_hard = len(self.corpus)
            protected = [s for s in self.corpus if s.found_at == 0 or s.is_favored]
            evictable = sorted(
                [s for s in self.corpus if s.found_at > 0 and not s.is_favored],
                key=lambda s: s.exec_count, reverse=True
            )
            keep = max(0, hard_limit - len(protected))
            kept_ids = {id(s) for s in protected + evictable[:keep]}
            _evicted = [s for s in self.corpus if id(s) not in kept_ids]
            self.corpus = protected + evictable[:keep]
            log.info(f"[Cull] Hard limit {hard_limit}: corpus {before_hard} → {len(self.corpus)}")
            for s in _evicted:
                if isinstance(s, SequenceSeed):
                    self._remove_seq_replay_artifacts(s)

        # 5) SequenceSeed 별도 상한: (favored, new_pcs) 내림차순으로 상위 N개 보존
        # favored인 SeqSeed는 단일 Seed가 도달 못한 PC를 가진 것 — 우선 보존.
        # 동일 favored 등급 내에서는 new_pcs가 큰 것 우선.
        _seq_seeds = [s for s in self.corpus if isinstance(s, SequenceSeed)]
        if len(_seq_seeds) > MAX_SEQUENCE_CORPUS:
            _keep_list = sorted(
                _seq_seeds,
                key=lambda s: (s.is_favored, s.new_pcs),
                reverse=True
            )[:MAX_SEQUENCE_CORPUS]
            _keep_ids = {id(s) for s in _keep_list}
            _seq_evicted = [s for s in _seq_seeds if id(s) not in _keep_ids]
            before_seq = len(self.corpus)
            self.corpus = [s for s in self.corpus
                           if not isinstance(s, SequenceSeed) or id(s) in _keep_ids]
            log.info(f"[Cull] SeqSeed cap {MAX_SEQUENCE_CORPUS}: "
                     f"corpus {before_seq} → {len(self.corpus)} "
                     f"(favored 우선)")
            for s in _seq_evicted:
                self._remove_seq_replay_artifacts(s)

    # AFL++ Mutation Engine

    # AFL++ interesting values (afl-fuzz/include/config.h)
    INTERESTING_8  = [-128, -1, 0, 1, 16, 32, 64, 100, 127]
    INTERESTING_16 = [-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767]
    INTERESTING_32 = [-2147483648, -100663046, -32769, 32768, 65535, 65536,
                      100663045, 2147483647]

    ARITH_MAX = 35  # AFL++ default

    def _mutate_bytes(self, data: bytes) -> bytes:
        """AFL++ havoc 스타일 바이트 변형 — 1~가변 스택 적용"""
        if not data:
            return data

        buf = bytearray(data)
        # AFL++ havoc: 2^(1~7) 스택 횟수
        stack_power = random.randint(1, 7)
        num_mutations = 1 << stack_power

        for _ in range(num_mutations):
            if not buf:
                buf = bytearray(b'\x00')
            mut = self._mopt_select_operator()
            self._current_mutations.append(mut)

            if mut == 0:
                # --- bitflip 1/1 ---
                pos = random.randint(0, len(buf) - 1)
                buf[pos] ^= (1 << random.randint(0, 7))

            elif mut == 1:
                # --- interesting 8-bit ---
                pos = random.randint(0, len(buf) - 1)
                buf[pos] = random.choice(self.INTERESTING_8) & 0xFF

            elif mut == 2 and len(buf) >= 2:
                # --- interesting 16-bit (LE) ---
                pos = random.randint(0, len(buf) - 2)
                val = random.choice(self.INTERESTING_8 + self.INTERESTING_16) & 0xFFFF
                if random.random() < 0.5:
                    # little-endian
                    struct.pack_into('<H', buf, pos, val)
                else:
                    # big-endian
                    struct.pack_into('>H', buf, pos, val)

            elif mut == 3 and len(buf) >= 4:
                # --- interesting 32-bit (LE/BE) ---
                pos = random.randint(0, len(buf) - 4)
                val = random.choice(
                    self.INTERESTING_8 + self.INTERESTING_16 + self.INTERESTING_32
                ) & 0xFFFFFFFF
                if random.random() < 0.5:
                    struct.pack_into('<I', buf, pos, val)
                else:
                    struct.pack_into('>I', buf, pos, val)

            elif mut == 4:
                # --- arith 8-bit (add/sub) ---
                pos = random.randint(0, len(buf) - 1)
                delta = random.randint(1, self.ARITH_MAX)
                if random.random() < 0.5:
                    buf[pos] = (buf[pos] + delta) & 0xFF
                else:
                    buf[pos] = (buf[pos] - delta) & 0xFF

            elif mut == 5 and len(buf) >= 2:
                # --- arith 16-bit (add/sub, LE/BE) ---
                pos = random.randint(0, len(buf) - 2)
                delta = random.randint(1, self.ARITH_MAX)
                if random.random() < 0.5:
                    val = struct.unpack_from('<H', buf, pos)[0]
                    val = (val + random.choice([-delta, delta])) & 0xFFFF
                    struct.pack_into('<H', buf, pos, val)
                else:
                    val = struct.unpack_from('>H', buf, pos)[0]
                    val = (val + random.choice([-delta, delta])) & 0xFFFF
                    struct.pack_into('>H', buf, pos, val)

            elif mut == 6 and len(buf) >= 4:
                # --- arith 32-bit (add/sub, LE/BE) ---
                pos = random.randint(0, len(buf) - 4)
                delta = random.randint(1, self.ARITH_MAX)
                if random.random() < 0.5:
                    val = struct.unpack_from('<I', buf, pos)[0]
                    val = (val + random.choice([-delta, delta])) & 0xFFFFFFFF
                    struct.pack_into('<I', buf, pos, val)
                else:
                    val = struct.unpack_from('>I', buf, pos)[0]
                    val = (val + random.choice([-delta, delta])) & 0xFFFFFFFF
                    struct.pack_into('>I', buf, pos, val)

            elif mut == 7:
                # --- random byte set ---
                pos = random.randint(0, len(buf) - 1)
                buf[pos] = random.randint(0, 255)

            elif mut == 8 and len(buf) >= 2:
                # --- byte swap (2 bytes) ---
                pos1 = random.randint(0, len(buf) - 1)
                pos2 = random.randint(0, len(buf) - 1)
                buf[pos1], buf[pos2] = buf[pos2], buf[pos1]

            elif mut == 9:
                # --- delete bytes (1~len/4) ---
                if len(buf) > 1:
                    del_len = random.randint(1, max(1, len(buf) // 4))
                    del_pos = random.randint(0, len(buf) - del_len)
                    del buf[del_pos:del_pos + del_len]

            elif mut == 10:
                # --- insert bytes (clone or random) ---
                ins_len = random.randint(1, min(128, max(1, len(buf) // 4)))
                ins_pos = random.randint(0, len(buf))
                if random.random() < 0.5 and len(buf) >= ins_len:
                    # clone existing chunk
                    src = random.randint(0, len(buf) - ins_len)
                    chunk = bytes(buf[src:src + ins_len])
                else:
                    # random bytes
                    chunk = bytes(random.randint(0, 255) for _ in range(ins_len))
                buf[ins_pos:ins_pos] = chunk

            elif mut == 11 and len(buf) >= 2:
                # --- overwrite bytes (clone or random) ---
                ow_len = random.randint(1, min(128, max(1, len(buf) // 4)))
                ow_pos = random.randint(0, max(0, len(buf) - ow_len))
                if random.random() < 0.5 and len(buf) >= ow_len:
                    src = random.randint(0, len(buf) - ow_len)
                    buf[ow_pos:ow_pos + ow_len] = buf[src:src + ow_len]
                else:
                    for i in range(min(ow_len, len(buf) - ow_pos)):
                        buf[ow_pos + i] = random.randint(0, 255)

            elif mut == 12 and len(buf) >= 4:
                # --- crossover / splice (with another corpus entry) ---
                _seed_pool = [s for s in self.corpus if isinstance(s, Seed)]
                if len(_seed_pool) > 1:
                    other = random.choice(_seed_pool)
                    if other.data and len(other.data) > 0:
                        other_buf = bytearray(other.data)
                        # 두 버퍼에서 랜덤 구간을 교차
                        src_pos = random.randint(0, max(0, len(other_buf) - 1))
                        copy_len = random.randint(1, min(len(other_buf) - src_pos, len(buf)))
                        dst_pos = random.randint(0, max(0, len(buf) - copy_len))
                        buf[dst_pos:dst_pos + copy_len] = other_buf[src_pos:src_pos + copy_len]

            elif mut == 13 and len(buf) >= 2:
                # --- shuffle bytes in a random range ---
                chunk_len = random.randint(2, min(16, len(buf)))
                start = random.randint(0, len(buf) - chunk_len)
                chunk = buf[start:start + chunk_len]
                random.shuffle(chunk)
                buf[start:start + chunk_len] = chunk

            elif mut == 14:
                # --- set block to fixed value ---
                block_len = random.randint(1, min(32, len(buf)))
                start = random.randint(0, len(buf) - block_len)
                val = random.choice([0x00, 0xFF, 0x41, 0x20, random.randint(0, 255)])
                buf[start:start + block_len] = bytes([val]) * block_len

            elif mut == 15 and len(buf) >= 8:
                # --- ASCII integer insertion (AFL++ MOpt) ---
                pos = random.randint(0, max(0, len(buf) - 8))
                num = random.choice([
                    0, 1, -1, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF, 0x10000,
                    0x7FFFFFFF, 0xFFFFFFFF, random.randint(-1000000, 1000000)
                ])
                num_str = str(num).encode('ascii')
                end = min(pos + len(num_str), len(buf))
                buf[pos:end] = num_str[:end - pos]

            # 무한 반복 방지: 너무 커지면 잘라냄
            if len(buf) > self.config.max_input_len * 2:
                buf = buf[:self.config.max_input_len]

        return bytes(buf[:self.config.max_input_len])

    # ── NSZE cache ───────────────────────────────────────────────────
    NSZE_CACHE_TTL = 5000

    def _get_nsze(self) -> int:
        """Namespace Size (NSZE) 조회 및 캐싱 (5000 exec 마다 갱신).
        구버전 nvme-cli 호환 — JSON 미지원 시 text 출력 파싱 fallback."""
        if (self._nsze_cache is None or
                self.executions - self._nsze_cache_at > self.NSZE_CACHE_TTL):
            _ns = self.config.nvme_namespace or 1
            ns_info, _, _ = self._nvme_id_dict(
                ['nvme', 'id-ns', self.config.nvme_device, '-n', str(_ns)])
            try:
                self._nsze_cache = int(ns_info.get("nsze", 0x100000))
            except (ValueError, TypeError):
                self._nsze_cache = 0x100000   # 1M blocks fallback
            self._nsze_cache_at = self.executions
        return self._nsze_cache

    def _snapshot_ctrl_info(self) -> None:
        """시작 시 1회: Identify Controller 에서 CNTLID(재부착용) + OACS bit3(NS Management
        지원 여부)를 스냅샷·로깅. NS Delete/Detach 가드가 이 제품에서 의미 있는지 즉시 가시화."""
        info, _, _ = self._nvme_id_dict(['nvme', 'id-ctrl', self._ctrl_device()])
        try:
            self._cntlid_cache = int(info.get('cntlid'))
        except (ValueError, TypeError, AttributeError):
            self._cntlid_cache = None
        try:
            oacs = int(info.get('oacs', 0))
            self._ns_mgmt_supported = bool(oacs & (1 << 3))   # OACS[3] = NS Mgmt Supported
        except (ValueError, TypeError):
            self._ns_mgmt_supported = None
        log.warning(f"[Pre-flight] CNTLID={self._cntlid_cache} "
                    f"NS-Mgmt(OACS[3])={'지원' if self._ns_mgmt_supported else '미지원/미상'} "
                    f"— Delete 차단={'on' if BLOCK_NS_DELETE else 'off'}, "
                    f"Detach auto-attach={'on' if AUTO_REATTACH_NS else 'off'}")

    def _get_cntlid(self) -> Optional[int]:
        """재부착에 쓸 컨트롤러 ID(CNTLID). 스냅샷 안 됐으면 즉시 조회."""
        if self._cntlid_cache is None:
            info, _, _ = self._nvme_id_dict(['nvme', 'id-ctrl', self._ctrl_device()])
            try:
                self._cntlid_cache = int(info.get('cntlid'))
            except (ValueError, TypeError, AttributeError):
                self._cntlid_cache = None
        return self._cntlid_cache

    def _reattach_namespace(self, nsid: int) -> None:
        """Detach(SEL=1) 성공 후 namespace 를 컨트롤러에 재부착 — fuzzing 대상 device 복구.
        nvme attach-ns(-c CNTLID) + ns-rescan. NS 보존 명령이라 inverse 로 되돌릴 수 있다."""
        cntlid = self._get_cntlid()
        ctrl = self._ctrl_device()
        if cntlid is None:
            log.error(f"[NS-Reattach] CNTLID 미상 — nsid={nsid} 재부착 불가(수동 복구 필요: "
                      f"nvme attach-ns {ctrl} -n {nsid} -c <cntlid>; nvme ns-rescan {ctrl})")
            return
        try:
            r = subprocess.run(['nvme', 'attach-ns', ctrl,
                                '-n', str(nsid), '-c', str(cntlid)],
                               capture_output=True, timeout=10)
            subprocess.run(['nvme', 'ns-rescan', ctrl], capture_output=True, timeout=10)
            if r.returncode == 0:
                log.warning(f"[NS-Reattach] nsid={nsid} → cntlid={cntlid} 재부착 성공 (Detach 복구)")
                self.stats['ns_reattach_ok'] = self.stats.get('ns_reattach_ok', 0) + 1
            else:
                log.error(f"[NS-Reattach] nsid={nsid} 재부착 실패 rc={r.returncode}: "
                          f"{r.stderr.decode(errors='replace')[:200]}")
                self.stats['ns_reattach_fail'] = self.stats.get('ns_reattach_fail', 0) + 1
        except Exception as e:
            log.error(f"[NS-Reattach] nsid={nsid} 재부착 예외: {e}")
            self.stats['ns_reattach_fail'] = self.stats.get('ns_reattach_fail', 0) + 1

    @staticmethod
    def _parse_nvme_text(text: str) -> dict:
        """nvme id-ctrl / id-ns 의 text 출력 파싱 → dict.
        JSON 미지원 구버전 nvme-cli fallback. 가능한 한 JSON 출력 스키마와
        호환되는 키 이름 / 타입을 사용 (vid/ssvid/mn/sn/fr/ver/mdts/nn,
        nsze/ncap/nuse/flbas/lbafs).
        """
        result: dict = {}
        lbafs: list = []
        for line in text.splitlines():
            # 'lbaf  0 : ms:0   lbads:9  rp:0x2 (in use)' 같은 LBA format 라인
            m = re.match(r'\s*lbaf\s+(\d+)\s*:\s*ms:(\d+)\s+lbads:(\d+)', line)
            if m:
                lbafs.append({
                    'ms': int(m.group(2)),
                    'ds': int(m.group(3)),
                    'in_use': '(in use)' in line,
                })
                continue
            # 'key : value' 일반 라인
            m = re.match(r'\s*([A-Za-z_][\w\-]*)\s*:\s*(.+?)\s*$', line)
            if not m:
                continue
            key, val = m.group(1), m.group(2).strip()
            # 텍스트 포맷은 필드마다 표기 다름:
            #   - '0x...' prefix      → hex int (vid/ssvid 등)
            #   - 일반 십진수 (1자리 또는 leading 0 없음)  → dec int (mdts/nn 등)
            #   - leading-zero 또는 hex digit 포함  → 문자열 유지 (ieee/eui64/nguid 등)
            #     JSON 출력 schema 와 정확히 일치하진 않지만 표시 / 키 lookup 에는 충분.
            try:
                if val.startswith('0x') or val.startswith('0X'):
                    result[key] = int(val, 16)
                elif val.isdigit() and (len(val) == 1 or val[0] != '0'):
                    result[key] = int(val)
                else:
                    result[key] = val
            except ValueError:
                result[key] = val
        if lbafs:
            result['lbafs'] = lbafs
        return result

    def _nvme_id_dict(self, cmd_args: list) -> Tuple[dict, str, int]:
        """nvme id-* 호출 → dict 반환. JSON 우선, 실패 시 text 파싱 fallback.
        반환: (parsed_dict, stderr_str, returncode).
        성공 시 parsed_dict 채워짐, 실패 시 빈 dict 와 진단 정보.
        """
        # 1) JSON 시도
        _json_cmd = cmd_args + ['--output-format=json']
        try:
            _r = subprocess.run(_json_cmd, timeout=5,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if _r.returncode == 0:
                try:
                    return json.loads(_r.stdout), '', 0
                except json.JSONDecodeError:
                    pass   # text fallback 으로
            # 옵션 인식 실패 / JSON 미지원 → text fallback
        except Exception:
            pass
        # 2) text fallback (JSON 옵션 빼고)
        try:
            _r = subprocess.run(cmd_args, timeout=5,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            _err = _r.stderr.decode(errors='replace').strip()
            if _r.returncode != 0:
                return {}, _err, _r.returncode
            _text = _r.stdout.decode(errors='replace')
            return self._parse_nvme_text(_text), _err, 0
        except Exception as e:
            return {}, str(e), -1

    def _log_device_info(self) -> None:
        """nvme id-ctrl / id-ns + PCIe 정보를 한 번에 출력 (시작 시 + 주기적).
        모든 줄을 [DevInfo] 태그로 출력 → 터미널 필터 통과(=== 만 보이고 내용이 사라지던 문제 해결).
        실패해도 fuzz 진행에 영향 없음 (best-effort).
        """
        def _w(s):
            log.warning(f"[DevInfo] {s}")

        _w("=" * 56)
        _w("Device Information")

        # id-ctrl — JSON 우선, 실패 시 text 파싱 fallback (_nvme_id_dict)
        _cmd = ['nvme', 'id-ctrl', self.config.nvme_device]
        ctrl, _err, _rc = self._nvme_id_dict(_cmd)
        if not ctrl:
            _w(f"  id-ctrl rc={_rc}")
            _w(f"    cmd    : {' '.join(_cmd)}")
            if _err:
                _w(f"    stderr : {_err}")

        if ctrl:
            _model  = str(ctrl.get('mn', '')).strip()
            _serial = str(ctrl.get('sn', '')).strip()
            _fw     = str(ctrl.get('fr', '')).strip()
            _vid    = ctrl.get('vid', 0)
            _ssvid  = ctrl.get('ssvid', 0)
            # ieee 는 JSON 에선 int, text 파싱에선 leading-zero 문자열 → 양쪽 통일.
            _ieee_raw = ctrl.get('ieee', 'N/A')
            if isinstance(_ieee_raw, int):
                _ieee = f"{_ieee_raw:06x}"
            else:
                _ieee = str(_ieee_raw)
            _ver    = ctrl.get('ver', 0)
            _nn     = ctrl.get('nn', '?')
            _mdts   = ctrl.get('mdts', 0)
            _subnqn = str(ctrl.get('subnqn', '')).strip()
            _major  = (_ver >> 16) & 0xFFFF
            _minor  = (_ver >> 8) & 0xFF
            _tert   = _ver & 0xFF
            _w(f"  Model       : {_model}")
            _w(f"  Serial      : {_serial}")
            _w(f"  Firmware    : {_fw}")
            _w(f"  Vendor ID   : 0x{_vid:04x}  /  Subsys 0x{_ssvid:04x}")
            _w(f"  IEEE OUI    : {_ieee}")
            _w(f"  NVMe spec   : {_major}.{_minor}.{_tert}  (raw 0x{_ver:08x})")
            _w(f"  Namespaces  : {_nn}")
            _w(f"  MDTS        : {_mdts}  (0 = unlimited)")
            if _subnqn:
                _w(f"  SubNQN      : {_subnqn}")

        # id-ns — JSON 우선, 실패 시 text 파싱 fallback
        _ns = self.config.nvme_namespace or 1
        _ns_cmd = ['nvme', 'id-ns', self.config.nvme_device, '-n', str(_ns)]
        ns_info, _err, _rc = self._nvme_id_dict(_ns_cmd)
        if not ns_info:
            _w(f"  id-ns rc={_rc}")
            _w(f"    cmd    : {' '.join(_ns_cmd)}")
            if _err:
                _w(f"    stderr : {_err}")
            _w("=" * 56)
            return
        try:
            nsze = ns_info.get('nsze', 0)
            ncap = ns_info.get('ncap', 0)
            nuse = ns_info.get('nuse', 0)
            # 현재 활성 LBA format 의 data size
            lbafs    = ns_info.get('lbafs', [])
            flbas    = ns_info.get('flbas', 0)
            cur_idx  = flbas & 0xF
            lba_size = 512
            if 0 <= cur_idx < len(lbafs):
                _ds = lbafs[cur_idx].get('ds', 9)   # log2(LBA size)
                lba_size = 1 << _ds
            _size_gb = nsze * lba_size / 1e9
            _use_pct = (100 * nuse / ncap) if ncap else 0.0
            _w(f"  Namespace {_ns}")
            _w(f"    LBA size  : {lba_size} B  (lbaf={cur_idx})")
            _w(f"    NSZE      : {nsze:,} LBAs  ({_size_gb:,.2f} GB)")
            _w(f"    NCAP      : {ncap:,} LBAs")
            _w(f"    NUSE      : {nuse:,} LBAs  ({_use_pct:.1f}% used)")
        except Exception as e:
            _w(f"  id-ns 조회 실패: {e}")

        # PCIe 정보 (이미 _detect_pcie_info 가 호출되었으면 출력)
        if self._pcie_bdf:
            _w(f"  PCIe BDF    : {self._pcie_bdf}")
            if self._pcie_root_bdf:
                _w(f"  Root Port   : {self._pcie_root_bdf}")
            if self._pcie_lnkcap is not None:
                _aspms = (self._pcie_lnkcap >> 10) & 0x3
                _cpm   = (self._pcie_lnkcap >> 18) & 0x1
                _aspm_str = {0:'none',1:'L0s',2:'L1',3:'L0s+L1'}.get(_aspms, f'?{_aspms}')
                _w(f"  ASPM cap    : {_aspm_str}  /  ClockPM={_cpm}")

        _w("=" * 56)

    MDTS_CACHE_TTL = 5000

    def _get_mdts(self) -> int:
        """MDTS (Maximum Data Transfer Size) 조회 및 캐싱 (5000 exec마다 갱신).
        반환값: MDTS 값 (0 = no limit). nvme id-ctrl의 mdts 필드.
        구버전 nvme-cli 호환 — JSON 미지원 시 text 출력 파싱 fallback."""
        if (self._mdts_cache is None or
                self.executions - self._mdts_cache_at > self.MDTS_CACHE_TTL):
            ctrl_info, _, _ = self._nvme_id_dict(
                ['nvme', 'id-ctrl', self.config.nvme_device])
            try:
                self._mdts_cache = int(ctrl_info.get("mdts", 0))
            except (ValueError, TypeError):
                self._mdts_cache = 0
            self._mdts_cache_at = self.executions
        return self._mdts_cache

    # 공유 컨텍스트가 필요한 시퀀스 — 첫 명령 mutation 결과의 SLBA/NLB/[data]를 후속 명령에 적용.
    # 모드:
    #   'full'    — SLBA + NLB + data 공유. Compare/Read가 Write의 정확한 결과를 따라감.
    #   'lba_nlb' — SLBA + NLB만 공유, data는 각 명령이 독립 mutation.
    #               (Write→Write: 같은 LBA 범위에 다른 데이터로 overwrite 경로 탐색)
    _CTX_SEQUENCES: dict = {
        ("Write", "Compare"): 'full',
        ("Write", "Read"):    'full',
        ("Write", "Write"):   'lba_nlb',
    }

    def _pick_seq_seed(self, cmd_name: str,
                       ctx: Optional[dict] = None) -> 'Seed':
        """builtin sequence용 seed 선택: corpus에서 cmd_name 일치 seed 반환, 없으면 기본 생성.
        ctx가 주어지면 SLBA/NLB/data를 고정."""
        candidates = [s for s in self.corpus if isinstance(s, Seed) and s.cmd.name == cmd_name]
        if candidates:
            seed = self._mutate(random.choice(candidates))
        else:
            cmd_obj = next((c for c in self.commands if c.name == cmd_name), None)
            if cmd_obj is None:
                raise RuntimeError(
                    f"_pick_seq_seed: {cmd_name!r} not in enabled commands — "
                    "sequence prefilter should have prevented this"
                )
            seed = Seed(data=b'\x00' * 512, cmd=cmd_obj)
        if ctx:
            seed = self._apply_seq_ctx(seed, ctx)
        return seed

    def _apply_seq_ctx(self, seed: 'Seed', ctx: dict) -> 'Seed':
        """시퀀스 공유 컨텍스트를 seed에 적용.

        ctx['data']가 있으면 data와 data_len_override까지 덮어씀 (full 모드).
        없으면 SLBA/NLB만 공유하고 seed의 mutation 결과 data는 보존 (lba_nlb 모드).
        """
        slba = ctx['slba']
        nlb  = ctx['nlb']
        seed.cdw10 = slba & 0xFFFFFFFF
        seed.cdw11 = (slba >> 32) & 0xFFFFFFFF
        seed.cdw12 = (seed.cdw12 & ~0xFFFF) | (nlb & 0xFFFF)
        if ctx.get('data') is not None:
            seed.data = ctx['data']
            seed.data_len_override = len(ctx['data'])
        # lba_nlb 모드: seed.data / seed.data_len_override 는 mutation 결과 유지
        # 시퀀스 명령은 정상 opcode/queue/nsid로 실행 — 변이 필드 초기화
        seed.opcode_override = None
        seed.force_admin     = None
        seed.nsid_override   = None
        return seed

    def _make_dsm_payload(self, entry_count: int, nsze: int) -> bytes:
        """DSM range payload 생성. 각 entry = 16B (Context Attrs 4B + LBA Count 4B + SLBA 8B)."""
        payload = b''
        for _ in range(entry_count):
            ctx = random.randint(0, 0xFFFFFFFF)
            lba_count = random.choice([0, 1, max(0, nsze - 1), nsze, 0xFFFFFFFF,
                                       random.randint(0, max(1, nsze))])
            slba = random.choice([0, 1, max(0, nsze - 2), max(0, nsze - 1),
                                  nsze, nsze + 1, 0xFFFFFFFF, 0x100000000,
                                  random.randint(0, max(1, nsze))])
            payload += struct.pack('<IIQ', ctx, lba_count & 0xFFFFFFFF,
                                   slba & 0xFFFFFFFFFFFFFFFF)
        return payload

    def _make_copy_payload(self, entry_count: int, nsze: int) -> bytes:
        """Copy source range payload 생성. Format 0h: 32B per entry."""
        payload = b''
        for _ in range(entry_count):
            slba = random.choice([0, 1, max(0, nsze - 2), max(0, nsze - 1),
                                  nsze, nsze + 1, 0xFFFFFFFF, 0x100000000,
                                  random.randint(0, max(1, nsze))])
            nlb = random.choice([0, 1, 0xFF, 0xFFFF, random.randint(0, 0xFFFF)])
            # SLBA(8) + NLB(2) + RSVD(2) + EILBRT(4) + ELBATM(2) + ELBAT(2) + RSVD(12) = 32B
            payload += struct.pack('<QHHIHH',
                                   slba & 0xFFFFFFFFFFFFFFFF, nlb, 0, 0, 0, 0)
            payload += b'\x00' * 12
        return payload

    def _mutate_field_by_type(self, f: CDWField, nsze: int) -> int:
        """CDWField 타입별 변형 값 생성."""
        ft = f.ftype
        if ft == FieldType.ENUM:
            pool = list(f.valid)
            if f.reserved:
                pool.append(random.randint(f.reserved[0], f.reserved[1]))
            if f.vendor:
                pool.append(random.randint(f.vendor[0], f.vendor[1]))
            return random.choice(pool) if pool else 0
        elif ft == FieldType.LBA:
            return random.choice([
                0, 1, max(0, nsze - 2), max(0, nsze - 1), nsze, nsze + 1,
                0xFFFF, 0xFFFFFFFF, random.randint(0, max(1, nsze)),
            ])
        elif ft == FieldType.LBA_CNT:
            return random.choice([
                0, 1, 7, 0xFF, 0xFFFF, 0xFFFFFFFF,
                random.randint(0, 0xFFFF),
            ])
        elif ft == FieldType.FLAGS:
            mask = (1 << (f.hi - f.lo + 1)) - 1
            if f.valid:
                return random.choice(f.valid)
            return random.randint(0, mask)
        elif ft == FieldType.SIZE_DW:
            return random.choice([
                0, 1, 0x7F, 0xFF, 0x3FF, 0x7FF, 0xFFFF,
                random.randint(0, 0xFFFF),
            ])
        elif ft == FieldType.OFFSET_DW:
            return random.choice([
                0, 1, 0x100, 0x1000, 0xFFFF, 0xFFFFFFFF,
                random.randint(0, 0xFFFFFF),
            ])
        elif ft == FieldType.SLOT:
            return random.choice([
                0, 1, f.max_val, f.max_val + 1,
                random.randint(0, max(1, f.max_val + 2)),
            ])
        else:  # OPAQUE
            width = f.hi - f.lo + 1
            mask = (1 << width) - 1
            return self._mutate_cdw(0) & mask

    def _mutate_cdw(self, value: int) -> int:
        """AFL++ 스타일 CDW (32-bit) 변형"""
        mut = random.randint(0, 5)

        if mut == 0:
            # bitflip 1~4 bits
            for _ in range(random.randint(1, 4)):
                value ^= (1 << random.randint(0, 31))
        elif mut == 1:
            # arith add/sub
            delta = random.randint(1, self.ARITH_MAX)
            value = (value + random.choice([-delta, delta])) & 0xFFFFFFFF
        elif mut == 2:
            # interesting 32-bit
            value = random.choice(
                self.INTERESTING_8 + self.INTERESTING_16 + self.INTERESTING_32
            ) & 0xFFFFFFFF
        elif mut == 3:
            # random 32-bit
            value = random.randint(0, 0xFFFFFFFF)
        elif mut == 4:
            # byte-level: 32비트 중 랜덤 바이트 1개만 변형
            shift = random.choice([0, 8, 16, 24])
            mask = 0xFF << shift
            new_byte = random.randint(0, 255) << shift
            value = (value & ~mask) | new_byte
        elif mut == 5:
            # endian swap (16-bit 또는 32-bit)
            if random.random() < 0.5:
                value = struct.unpack('>I', struct.pack('<I', value & 0xFFFFFFFF))[0]
            else:
                # 16-bit halves swap
                value = ((value >> 16) & 0xFFFF) | ((value & 0xFFFF) << 16)

        return value & 0xFFFFFFFF

    def _splice(self, seed: Seed) -> Seed:
        """AFL++ splice: 두 시드를 임의 지점에서 합성"""
        _seed_pool = [s for s in self.corpus if isinstance(s, Seed)]
        if len(_seed_pool) < 2 or not seed.data:
            return seed

        other = random.choice(_seed_pool)
        while other is seed and len(_seed_pool) > 1:
            other = random.choice(_seed_pool)

        buf_a = seed.data
        buf_b = other.data if other.data else b'\x00' * 64

        # 랜덤 분할점
        min_len = min(len(buf_a), len(buf_b))
        if min_len < 2:
            return seed

        split = random.randint(1, min_len - 1)
        if random.random() < 0.5:
            new_data = buf_a[:split] + buf_b[split:]
        else:
            new_data = buf_b[:split] + buf_a[split:]

        return Seed(
            data=bytes(new_data[:self.config.max_input_len]),
            cmd=seed.cmd,
            cdw2=seed.cdw2, cdw3=seed.cdw3,
            cdw10=seed.cdw10, cdw11=seed.cdw11,
            cdw12=seed.cdw12, cdw13=seed.cdw13,
            cdw14=seed.cdw14, cdw15=seed.cdw15,
        )

    def _mutate(self, seed: Seed) -> Seed:
        """AFL++ 스타일 Seed 전체 변형: havoc + splice + CDW + 확장 mutation"""
        # 15% 확률로 splice 먼저 적용 (AFL++ splicing stage)
        if random.random() < 0.15:
            seed = self._splice(seed)

        new_data = self._mutate_bytes(seed.data) if seed.data else seed.data

        new_seed = Seed(
            data=new_data,
            cmd=seed.cmd,
            cdw2=seed.cdw2, cdw3=seed.cdw3,
            cdw10=seed.cdw10, cdw11=seed.cdw11,
            cdw12=seed.cdw12, cdw13=seed.cdw13,
            cdw14=seed.cdw14, cdw15=seed.cdw15,
            opcode_override=seed.opcode_override,
            nsid_override=seed.nsid_override,
            force_admin=seed.force_admin,
            data_len_override=seed.data_len_override,
        )

        # 30% 확률로 CDW 필드 변형
        if random.random() < 0.3:
            num_cdw_muts = random.randint(1, 3)
            cdw_fields = ['cdw2', 'cdw3', 'cdw10', 'cdw11',
                          'cdw12', 'cdw13', 'cdw14', 'cdw15']
            for _ in range(num_cdw_muts):
                field = random.choice(cdw_fields)
                old_val = getattr(new_seed, field)
                setattr(new_seed, field, self._mutate_cdw(old_val))

        # --- 확장 mutation (각각 독립 확률) ---

        # [1] opcode mutation — 미정의/vendor-specific opcode로 dispatch 테이블 탐색
        if OPCODE_MUT_PROB > 0 and random.random() < OPCODE_MUT_PROB:
            excluded = set(self.config.excluded_opcodes)
            mut_type = random.randint(0, 3)
            if mut_type == 0:
                # vendor-specific 범위 (0xC0~0xFF for admin, 0x80~0xFF for IO)
                if seed.cmd.cmd_type == NVMeCommandType.ADMIN:
                    new_seed.opcode_override = random.randint(0xC0, 0xFF)
                else:
                    new_seed.opcode_override = random.randint(0x80, 0xFF)
            elif mut_type == 1:
                # 완전 랜덤 opcode
                new_seed.opcode_override = random.randint(0x00, 0xFF)
            elif mut_type == 2:
                # 원본 opcode의 bit flip
                new_seed.opcode_override = seed.cmd.opcode ^ (1 << random.randint(0, 7))
            else:
                # 다른 알려진 명령어의 opcode 가져오기
                other_cmd = random.choice(NVME_COMMANDS)
                new_seed.opcode_override = other_cmd.opcode
            if new_seed.opcode_override is not None and new_seed.opcode_override in excluded:
                new_seed.opcode_override = None

        # [2] nsid mutation — 잘못된 namespace로 에러 핸들링 코드 탐색
        if NSID_MUT_PROB > 0 and random.random() < NSID_MUT_PROB:
            new_seed.nsid_override = random.choice([
                0x00000000,       # nsid=0 (보통 "all namespaces" 또는 invalid)
                0xFFFFFFFF,       # broadcast nsid
                0x00000002,       # 존재하지 않을 가능성 높은 NS
                0xFFFFFFFE,       # boundary
                random.randint(2, 0xFFFF),  # 랜덤 존재하지 않는 NS
                random.randint(0, 0xFFFFFFFF),  # 완전 랜덤
            ])

        # [3] Admin↔IO 교차 전송 — 잘못된 큐로 보내서 디스패치 혼란 유도
        if self.config.admin_swap_prob > 0 and random.random() < self.config.admin_swap_prob:
            # 원래 admin이면 IO로, IO면 admin으로
            new_seed.force_admin = (seed.cmd.cmd_type != NVMeCommandType.ADMIN)

        # 가성 방지(예방): mutation 결과가 (admin + 호스트 전송로 깨는 opcode) 가 되면
        # override/force_admin 을 되돌려 안전한 base 명령으로 복원. send-time 가드는 net 으로 유지.
        _eff_admin = (new_seed.force_admin if new_seed.force_admin is not None
                      else seed.cmd.cmd_type == NVMeCommandType.ADMIN)
        _eff_op = (new_seed.opcode_override if new_seed.opcode_override is not None
                   else seed.cmd.opcode)
        if _eff_admin and _eff_op in BLOCKED_ADMIN_OPCODES:
            new_seed.opcode_override = None
            new_seed.force_admin = None

        # [4] data_len mutation — Phase 1: NLB-relative + MDTS boundary + static fallback
        if DATALEN_MUT_PROB > 0 and random.random() < DATALEN_MUT_PROB:
            _MAX_BUF = 2 * 1024 * 1024
            _lba_sz = self.config.nvme_lba_size or 512
            _data_transfer_cmds = {"Write", "Read", "Compare"}
            _candidates: List[int] = []
            _nlb_set: set = set()
            _mdts_set: set = set()

            if new_seed.cmd.name in _data_transfer_cmds:
                # NLB-relative 후보 (CDW12[15:0] = NLB, 0-based)
                _nlb = new_seed.cdw12 & 0xFFFF
                _expected = (_nlb + 1) * _lba_sz
                _page_sz = _PAGE_SIZE
                _nlb_cands = [c for c in [
                    _expected - 1, _expected, _expected + 1, _expected + _page_sz,
                ] if 0 <= c <= _MAX_BUF]
                _candidates += _nlb_cands
                _nlb_set.update(_nlb_cands)

                # MDTS boundary 후보
                _mdts = self._get_mdts()
                if _mdts > 0:
                    _page_sz = _PAGE_SIZE
                    _max_bytes = (1 << _mdts) * _page_sz
                    _mdts_cands = [c for c in [
                        _max_bytes - 1, _max_bytes, _max_bytes + 1,
                    ] if 0 <= c <= _MAX_BUF]
                    _candidates += _mdts_cands
                    _mdts_set.update(_mdts_cands)

            # static fallback 후보 (항상 포함)
            _candidates += [0, 4, 64, 512, 4096, 8192, 65536,
                            random.randint(1, _MAX_BUF)]

            # 중복 제거 후 선택 → 선택된 값의 출처로 통계 집계
            _candidates = list(dict.fromkeys(_candidates))
            _chosen_dl = random.choice(_candidates)
            new_seed.data_len_override = _chosen_dl

            if _chosen_dl in _nlb_set:
                self.mutation_stats["datalen_nlb"] += 1
            if _chosen_dl in _mdts_set:
                self.mutation_stats["datalen_mdts"] += 1

        # [5] Schema-guided field mutation
        if SCHEMA_MUT_PROB > 0 and random.random() < SCHEMA_MUT_PROB:
            schema = CMD_SCHEMAS.get(new_seed.cmd.name)
            if schema and schema.fields:
                f = random.choice(schema.fields)
                nsze = self._get_nsze()
                new_val = self._mutate_field_by_type(f, nsze)
                cdw_attr = f"cdw{f.word}"
                old = getattr(new_seed, cdw_attr, 0)
                width = f.hi - f.lo + 1
                mask = ((1 << width) - 1) << f.lo
                setattr(new_seed, cdw_attr, (old & ~mask) | ((new_val << f.lo) & mask))
                self.mutation_stats["schema_field"] += 1

        # [6] Phase 2: 64-bit LBA pair mutation (cdw10 + cdw11)
        # 대상: Read/Write/Compare/Verify/Copy — SLBA_LO(cdw10) + SLBA_HI(cdw11) 쌍 변이
        _LBA_PAIR_CMDS = {"Read", "Write", "Compare", "Verify", "Copy"}
        if (LBA_PAIR_MUT_PROB > 0
                and new_seed.cmd.name in _LBA_PAIR_CMDS
                and random.random() < LBA_PAIR_MUT_PROB):
            _nsze = self._get_nsze()
            _slba = random.choice([
                0,
                1,
                max(0, _nsze - 2),
                max(0, _nsze - 1),
                _nsze,
                _nsze + 1,
                0xFFFFFFFF,
                0x100000000,          # cdw10=0, cdw11=1 — high dword 처리 경로
                random.randint(0, max(1, _nsze)),
            ])
            new_seed.cdw10 = _slba & 0xFFFFFFFF
            new_seed.cdw11 = (_slba >> 32) & 0xFFFFFFFF
            self.mutation_stats["lba_pair_64bit"] += 1

        # [7] Phase 2: DSM/Copy structured payload 재구성
        if STRUCT_PAYLOAD_MUT_PROB > 0 and random.random() < STRUCT_PAYLOAD_MUT_PROB:
            _nsze = self._get_nsze()
            _MAX_BUF = 2 * 1024 * 1024

            if new_seed.cmd.name == "DatasetManagement":
                # CDW10[7:0] = NR (0-based, 실제 range 수 = NR+1)
                # mut_type: 0=1 entry, 1=256 entries(max), 2=선언256+payload0(불일치), 3=NR0+payload0
                _mut_type = random.randint(0, 3)
                if _mut_type == 0:
                    _nr, _count = 0x00, 1
                    new_seed.data = self._make_dsm_payload(_count, _nsze)
                    new_seed.cdw10 = (new_seed.cdw10 & ~0xFF) | _nr
                elif _mut_type == 1:
                    _nr, _count = 0xFF, 256
                    new_seed.data = self._make_dsm_payload(_count, _nsze)
                    new_seed.cdw10 = (new_seed.cdw10 & ~0xFF) | _nr
                elif _mut_type == 2:
                    # dsm_decl256_payload1: NR=0xFF 선언, payload=1 entry(16B) — 언더플로 불일치
                    new_seed.data = self._make_dsm_payload(1, _nsze)
                    new_seed.cdw10 = (new_seed.cdw10 & ~0xFF) | 0xFF
                else:
                    # dsm_nr0_payload0: NR=0, payload 0B
                    new_seed.data = b''
                    new_seed.cdw10 = new_seed.cdw10 & ~0xFF
                self.mutation_stats["dsm_structured"] += 1
                new_seed.data_len_override = None  # structured payload 재구성 후 이전 override 제거

            elif new_seed.cmd.name == "Copy":
                # CDW12[11:8] = NR (0-based, 4비트), CDW10/11 = destination SLBA
                # mut_type: 0=1 entry(NR=0), 1=4 entries(NR=3), 2=선언NR3+1 entry(불일치), 3=NR0+payload0
                _mut_type = random.randint(0, 3)
                _dst_slba = random.choice([
                    0, 1, max(0, _nsze - 2), max(0, _nsze - 1),
                    _nsze, _nsze + 1, 0xFFFFFFFF, 0x100000000,
                ])
                new_seed.cdw10 = _dst_slba & 0xFFFFFFFF
                new_seed.cdw11 = (_dst_slba >> 32) & 0xFFFFFFFF
                _nr_mask = 0xF << 8  # CDW12[11:8] = NR (4비트)
                if _mut_type == 0:
                    new_seed.data = self._make_copy_payload(1, _nsze)
                    new_seed.cdw12 = (new_seed.cdw12 & ~_nr_mask) | (0x00 << 8)
                elif _mut_type == 1:
                    new_seed.data = self._make_copy_payload(4, _nsze)
                    new_seed.cdw12 = (new_seed.cdw12 & ~_nr_mask) | (0x03 << 8)
                elif _mut_type == 2:
                    # copy_decl4_payload1: NR=3 선언, payload=1 entry(32B) — 언더플로 불일치
                    new_seed.data = self._make_copy_payload(1, _nsze)
                    new_seed.cdw12 = (new_seed.cdw12 & ~_nr_mask) | (0x03 << 8)
                else:
                    # copy_nr0_payload0
                    new_seed.data = b''
                    new_seed.cdw12 = new_seed.cdw12 & ~_nr_mask
                self.mutation_stats["copy_structured"] += 1
                new_seed.data_len_override = None  # structured payload 재구성 후 이전 override 제거

        return new_seed

    # 반환값 상수: timeout/error를 구분
    RC_TIMEOUT   = -1001   # NVMe 타임아웃 (의미 있는 이벤트)
    RC_ERROR     = -1002   # subprocess 에러 (내부 문제)
    RC_SKIP      = -1003   # 가드가 전송 차단 (가성 유발 admin opcode) — 회계 없이 다음 iteration

    def _load_static_analysis(self) -> None:
        """제품별 BB/func 파일(config.bb_file/func_file) 자동 탐지 후 로드.

        파일명은 fuzzer_config.json 의 제품 항목에서 옴 (제품별 분리 — 펌웨어가 다른
        PM9M1/BM9H1/P9 의 BB 가 섞이지 않게):
          PM9M1=basic_blocks_PM9M1.txt, BM9H1=basic_blocks_BM9H1.txt, P9=basic_blocks_P9.txt
        파일이 없으면 아무것도 하지 않음. Ghidra ghidra_export.py 로 생성한 파일을 기대함.
        """
        script_dir = Path(__file__).parent.resolve()
        bb_file   = script_dir / self.config.bb_file      # 제품별 (profile)
        func_file = script_dir / self.config.func_file

        if not bb_file.exists() and not func_file.exists():
            return  # 파일 없음 — 로그 없이 조용히 넘어감

        # --- basic_blocks.txt ---
        # format: 0xSTART 0xEND  (END is exclusive)
        if bb_file.exists():
            starts: list = []
            ends_bb: list = []
            with open(bb_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            starts.append(int(parts[0], 16))
                            ends_bb.append(int(parts[1], 16))
                        except ValueError:
                            pass
            sorted_pairs = sorted(zip(starts, ends_bb))
            if sorted_pairs:
                self._sa_bb_starts = [p[0] for p in sorted_pairs]
                self._sa_bb_ends   = [p[1] for p in sorted_pairs]
                self._sa_total_bbs = len(self._sa_bb_starts)
                print(f"[StaticAnalysis] {self.config.bb_file}: {self._sa_total_bbs:,}개 BB "
                      f"(0x{self._sa_bb_starts[0]:08x} ~ 0x{self._sa_bb_ends[-1]:08x})")

        # --- functions.txt ---
        if func_file.exists():
            entries: list = []
            ends: list = []
            names: list = []
            with open(func_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(None, 2)
                    if len(parts) >= 2:
                        try:
                            entry = int(parts[0], 16)
                            size  = int(parts[1])
                            name  = parts[2].strip() if len(parts) > 2 else f"FUN_{entry:08x}"
                            entries.append(entry)
                            ends.append(entry + size)
                            names.append(name)
                        except ValueError:
                            pass
            sorted_tuples = sorted(zip(entries, ends, names))
            if sorted_tuples:
                self._sa_func_entries = [t[0] for t in sorted_tuples]
                self._sa_func_ends    = [t[1] for t in sorted_tuples]
                self._sa_func_names   = [t[2] for t in sorted_tuples]
                self._sa_total_funcs  = len(self._sa_func_entries)
                print(f"[StaticAnalysis] {self.config.func_file}: {self._sa_total_funcs:,}개 함수")

        self._sa_loaded = self._sa_total_bbs > 0 or self._sa_total_funcs > 0

        if self._sa_func_entries:
            print(f"[StaticAnalysis] 함수 주소 범위: "
                  f"0x{self._sa_func_entries[0]:08x} ~ 0x{self._sa_func_entries[-1]:08x}")

        self._sa_diag_done = False   # 첫 update 시 1회만 진단 로그 출력

    def _update_static_coverage(self, new_pcs: set) -> None:
        """새로 발견된 PC 집합으로 정적 분석 커버리지를 증분 업데이트.

        BB 커버리지: bisect로 PC가 속한 BB를 O(log N)에 탐색.
        함수 커버리지: bisect로 O(log N) 함수 탐색.
        """
        if not new_pcs:
            return

        # 첫 호출 시 1회 진단: PC 샘플과 BB 범위의 매칭 여부 + Thumb bit 자동 감지
        if not self._sa_diag_done:
            self._sa_diag_done = True
            sample = sorted(new_pcs)[:10]
            if self._sa_bb_starts:
                def _pc_in_bb(pc):
                    idx = bisect.bisect_right(self._sa_bb_starts, pc) - 1
                    return idx >= 0 and pc < self._sa_bb_ends[idx]

                matched       = [pc for pc in sample if _pc_in_bb(pc)]
                matched_thumb = [pc for pc in sample if _pc_in_bb(pc & ~1)]
                log.warning(
                    f"[StatDiag] 첫 new_pcs 샘플(최대10개): "
                    f"{[hex(p) for p in sample]}")
                log.warning(
                    f"[StatDiag] BB 직접 매칭: {len(matched)}/{len(sample)}개  "
                    f"| Thumb bit(bit0) 마스킹 후 매칭: {len(matched_thumb)}/{len(sample)}개")
                if len(matched) == 0 and len(matched_thumb) > 0:
                    log.warning(
                        "[StatDiag] *** Thumb bit 불일치 감지! "
                        "J-Link PC의 bit0이 set된 것으로 보임 → 자동 마스킹 적용 ***")
                    self._sa_thumb_mask = True
                elif len(matched) == 0 and len(matched_thumb) == 0:
                    _pc_min = min(new_pcs)
                    _pc_max = max(new_pcs)
                    log.warning(
                        f"[StatDiag] *** 주소 범위 불일치! "
                        f"PC 범위: 0x{_pc_min:08x}~0x{_pc_max:08x}  "
                        f"BB 범위: 0x{self._sa_bb_starts[0]:08x}~0x{self._sa_bb_ends[-1]:08x} ***")

        mask = self._sa_thumb_mask

        # BB 커버리지 — bisect로 PC가 속한 BB 탐색
        if self._sa_bb_starts is not None:
            for pc in new_pcs:
                pc_key = (pc & ~1) if mask else pc
                idx = bisect.bisect_right(self._sa_bb_starts, pc_key) - 1
                if idx >= 0 and pc_key < self._sa_bb_ends[idx]:
                    self._sa_covered_bbs.add(self._sa_bb_starts[idx])

        # 함수 커버리지 — bisect로 O(log N) 함수 탐색
        if self._sa_func_entries is not None:
            for pc in new_pcs:
                pc_key = (pc & ~1) if mask else pc
                idx = bisect.bisect_right(self._sa_func_entries, pc_key) - 1
                if idx >= 0 and pc_key < self._sa_func_ends[idx]:
                    self._sa_entered_funcs.add(self._sa_func_entries[idx])

    def _pm_set_state(self, ps: int) -> bool:
        """SetFeatures(FID=0x02) 전송 — PM 상태 진입/복귀용.
        반환값: True=성공(rc==0), False=실패(rc!=0 또는 예외).
        실패해도 fuzzing 흐름에 영향 없음.
        """
        sf = next((c for c in NVME_COMMANDS if c.name == "SetFeatures"), None)
        if sf is None:
            return False
        nvme_cmd = [
            'nvme', 'admin-passthru', self.config.nvme_device,
            f'--opcode={sf.opcode:#x}',
            '--namespace-id=0',
            '--cdw2=0x0', '--cdw3=0x0',
            f'--cdw10=0x02',
            f'--cdw11={ps:#x}',
            '--cdw12=0x0', '--cdw13=0x0', '--cdw14=0x0', '--cdw15=0x0',
            '--timeout=3000',
        ]
        label = f"PS{ps}" if ps > 0 else "PS0(복귀)"
        # 재현 TC 히스토리 기록 (PM 진입/복귀도 포함)
        self._cmd_history.append({
            'kind': 'pm',
            'label': f'PM {label}',
            'passthru_type': 'admin-passthru',
            'device': self.config.nvme_device,
            'opcode': sf.opcode,
            'nsid': 0,
            'cdw2': 0, 'cdw3': 0,
            'cdw10': 0x02, 'cdw11': ps,
            'cdw12': 0, 'cdw13': 0, 'cdw14': 0, 'cdw15': 0,
            'data': None, 'data_len': 0, 'is_write': False,
        })
        _pm_t0 = time.monotonic()
        try:
            result = subprocess.run(nvme_cmd, timeout=5.0,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ok = (result.returncode == 0)
            status = "OK" if ok else f"FAIL(rc={result.returncode})"
            _pm_elapsed = time.monotonic() - _pm_t0
            log.warning(f"[PM] SetFeatures cdw11=0x{ps:02x} ({label}) → {status} ({_pm_elapsed:.3f}s)")
            return ok
        except Exception as e:
            _pm_elapsed = time.monotonic() - _pm_t0
            log.warning(f"[PM] SetFeatures cdw11=0x{ps:02x} ({label}) → FAIL(exception: {e}) ({_pm_elapsed:.3f}s)")
            return False

    # ------------------------------------------------------------------
    # ------------------------------------------------------------------

    def _run_cmd(self, cmd: list, timeout: int = 5) -> Optional[subprocess.CompletedProcess]:
        """subprocess.run 래퍼 — returncode != 0 또는 예외 시 None 반환."""
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r if r.returncode == 0 else None
        except Exception:
            return None

    def _setpci_read(self, bdf: str, offset: int, width: str = 'l') -> Optional[int]:
        """setpci로 PCI config 레지스터 읽기. 실패 시 None 반환.
        width: 'b'=1B 'w'=2B 'l'=4B
        """
        r = self._run_cmd(['setpci', '-s', bdf, f'{offset:#x}.{width}'], timeout=3)
        if r and r.stdout.strip():
            return int(r.stdout.strip(), 16)
        return None

    def _setpci_write(self, bdf: str, offset: int, value: int, mask: int,
                      width: str = 'l') -> bool:
        """setpci write-with-mask. mask=1인 비트만 수정, 나머지 보존."""
        nchars = {'b': 2, 'w': 4, 'l': 8}[width]
        spec = f'{offset:#x}.{width}={value & mask:0{nchars}x}:{mask:0{nchars}x}'
        try:
            r = subprocess.run(['setpci', '-s', bdf, spec],
                               timeout=3, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return r.returncode == 0
        except Exception:
            return False

    def _detect_pcie_info(self) -> None:
        """NVMe PCIe BDF + Express/PM/L1SS cap offsets + 루트 포트 탐지.
        실패해도 _pcie_bdf=None → L/D-state 제어 비활성화.
        POR/rescan 후 재탐지 시 stale 캐시 방지: 탐지 전 전체 초기화.
        """
        import re as _re

        # 재탐지 전 캐시 초기화 — 이전 스캔 값이 잔류하면 cap 오판 가능
        self._pcie_bdf              = None
        self._pcie_cap_offset       = None
        self._pcie_pm_cap_offset    = None
        self._pcie_l1ss_cap         = None
        self._pcie_l1ss_offset      = None
        self._pcie_root_bdf         = None
        self._pcie_root_cap_offset  = None
        self._pcie_root_l1ss_offset = None
        self._pcie_root_l1ss_cap    = None
        self._pcie_lnkcap           = None

        dev = os.path.basename(self.config.nvme_device)
        m = _re.match(r'(nvme\d+)', dev)
        if m:
            addr_file = f'/sys/class/nvme/{m.group(1)}/address'
            try:
                self._pcie_bdf = Path(addr_file).read_text().strip()
            except Exception:
                pass
        if not self._pcie_bdf:
            try:
                r = subprocess.run(['lspci'], capture_output=True, text=True, timeout=5)
                for line in r.stdout.splitlines():
                    if 'nvme' in line.lower() or 'non-volatile' in line.lower():
                        bdf = line.split()[0]
                        if bdf.count(':') == 1:
                            bdf = '0000:' + bdf
                        self._pcie_bdf = bdf
                        break
            except Exception:
                pass

        if not self._pcie_bdf:
            log.warning("[PCIe] BDF 탐지 실패 — L/D-state 제어 비활성화")
            return

        def _parse_caps(bdf_str: str) -> dict:
            caps: dict = {}
            try:
                r = subprocess.run(['lspci', '-v', '-s', bdf_str],
                                   capture_output=True, text=True, timeout=5)
                for line in r.stdout.splitlines():
                    mm = _re.search(r'Capabilities: \[([0-9a-fA-F]+)\]\s+(.*)', line)
                    if not mm:
                        continue
                    off  = int(mm.group(1), 16)
                    desc = mm.group(2)
                    if 'Express' in desc and 'exp' not in caps:
                        caps['exp'] = off
                    elif 'Power Management' in desc and 'pm' not in caps:
                        caps['pm'] = off
                    elif ('L1 PM' in desc or 'Substates' in desc) and 'l1ss' not in caps:
                        caps['l1ss'] = off
            except Exception as e:
                log.warning(f"[PCIe] lspci cap 파싱 실패({bdf_str}): {e}")
            return caps

        ep_caps = _parse_caps(self._pcie_bdf)
        self._pcie_cap_offset    = ep_caps.get('exp')
        self._pcie_pm_cap_offset = ep_caps.get('pm')
        self._pcie_l1ss_offset   = ep_caps.get('l1ss')

        #   LNKCAP: PCIe Express cap + 0x0C  (PCI_EXP_LNKCAP)
        #   L1SSCAP: L1SS cap + 0x04         (PCI_L1SS_CAP)
        if self._pcie_cap_offset is not None:
            self._pcie_lnkcap = self._setpci_read(
                self._pcie_bdf, self._pcie_cap_offset + 0x0C)
        if self._pcie_l1ss_offset is not None:
            self._pcie_l1ss_cap = self._setpci_read(
                self._pcie_bdf, self._pcie_l1ss_offset + 0x04)

        #   /sys/bus/pci/devices/<EP_BDF> → realpath → 부모 디렉터리명 = RP BDF
        try:
            ep_real = os.path.realpath(f'/sys/bus/pci/devices/{self._pcie_bdf}')
            parent_bdf = os.path.basename(os.path.dirname(ep_real))
            if _re.match(r'^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f]$',
                         parent_bdf):
                self._pcie_root_bdf = parent_bdf
        except Exception as e:
            log.debug(f"[PCIe] 루트 포트 BDF 탐지 실패: {e}")

        if self._pcie_root_bdf:
            rp_caps = _parse_caps(self._pcie_root_bdf)
            self._pcie_root_cap_offset  = rp_caps.get('exp')
            self._pcie_root_l1ss_offset = rp_caps.get('l1ss')
            if self._pcie_root_l1ss_offset is not None:
                self._pcie_root_l1ss_cap = self._setpci_read(
                    self._pcie_root_bdf, self._pcie_root_l1ss_offset + 0x04)

        #   /sys/module/pcie_aspm/parameters/policy 형식 예:
        #   "default [powersave] performance" → 현재 선택은 [괄호] 안
        try:
            raw = Path('/sys/module/pcie_aspm/parameters/policy').read_text().strip()
            for tok in raw.split():
                if tok.startswith('[') and tok.endswith(']'):
                    self._orig_aspm_policy = tok[1:-1]
                    break
            else:
                self._orig_aspm_policy = raw  # 단일 값이면 그대로
        except Exception:
            self._orig_aspm_policy = 'default'

        rp_lnkcap = None
        if self._pcie_root_bdf and self._pcie_root_cap_offset is not None:
            rp_lnkcap = self._setpci_read(
                self._pcie_root_bdf, self._pcie_root_cap_offset + 0x0C)

        aspm_disabled = False
        try:
            cmdline = Path('/proc/cmdline').read_text()
            if 'pcie_aspm=off' in cmdline or 'pcie_aspm=force_disable' in cmdline:
                aspm_disabled = True
                log.warning("[PCIe] !!! 커널 cmdline에 pcie_aspm=off 감지 — "
                            "LNKCTL 쓰기가 커널에 의해 override될 수 있음 !!!")
        except Exception:
            pass

        aspms    = None if self._pcie_lnkcap is None else (self._pcie_lnkcap >> 10) & 0x3
        cpm      = None if self._pcie_lnkcap is None else (self._pcie_lnkcap >> 18) & 0x1
        rp_aspms = None if rp_lnkcap is None else (rp_lnkcap >> 10) & 0x3
        l1ss_cap_str = (f'{self._pcie_l1ss_cap:#010x}'
                        if self._pcie_l1ss_cap is not None else 'None')

        log.warning(
            f"[PCIe] EP={self._pcie_bdf}  "
            f"EXP={self._pcie_cap_offset!r}  PM={self._pcie_pm_cap_offset!r}  "
            f"L1SS={self._pcie_l1ss_offset!r}  "
            f"ASPMS={aspms!r}  CPM={cpm!r}  L1SSCAP={l1ss_cap_str}")
        log.warning(
            f"[PCIe] RP={self._pcie_root_bdf}  "
            f"RP_EXP={self._pcie_root_cap_offset!r}  "
            f"RP_L1SS={self._pcie_root_l1ss_offset!r}  "
            f"RP_ASPMS={rp_aspms!r}  "
            f"ASPM_policy_orig={self._orig_aspm_policy!r}  "
            f"aspm_disabled={aspm_disabled}")

        if self._pcie_root_bdf is None:
            log.warning("[PCIe] !!! RP BDF 미탐지 — L1/L1.2 진입 불가 (EP만 ASPMC 세팅됨) !!!")
        elif self._pcie_root_cap_offset is None:
            log.warning("[PCIe] !!! RP PCIe cap offset 없음 — RP LNKCTL 세팅 불가 !!!")
        elif aspms is not None and not (aspms & 0x2):
            log.warning(f"[PCIe] !!! EP LNKCAP ASPMS={aspms:#04x} — L1 미지원 !!!")
        elif rp_aspms is not None and not (rp_aspms & 0x2):
            log.warning(f"[PCIe] !!! RP LNKCAP ASPMS={rp_aspms:#04x} — RP L1 미지원 !!!")
        else:
            log.warning("[PCIe] L1 진입 조건 충족 (EP/RP 양측 L1 지원 확인)")

        if not Path(self.config.pmu_script).is_file():
            log.error(
                f"[PMU] 스크립트 없음: {self.config.pmu_script} — "
                "CLKREQ# assert/deassert 불가, L1.2 동작 비보장. "
                "--pmu-script 로 올바른 경로 지정 필요.")

    def _pmu_clkreq_assert(self) -> bool:
        """CLKREQ# assert only. PCIe config cleanup is intentionally separate."""
        t0 = time.monotonic()
        try:
            r = subprocess.run(
                ['python3', self.config.pmu_script,
                 str(self.config.clkreq_assert_pin), '1', '1',
                 str(self.config.clkreq_voltage_mv)],
                timeout=3, capture_output=True, text=True)
            elapsed = (time.monotonic() - t0) * 1000
            log.warning(f"[PMU] CLKREQ# Assert rc={r.returncode} ({elapsed:.1f}ms)"
                        + (f" out={r.stdout.strip()}" if r.stdout.strip() else "")
                        + (f" err={r.stderr.strip()}" if r.stderr.strip() else ""))
            if r.returncode == 0:
                log.warning("[PMU] → clock asserted, waiting for link recovery")
            return r.returncode == 0
        except Exception as e:
            log.warning(f"[PMU] CLKREQ# Assert exception: {e}")
            return False

    def _pmu_clkreq_deassert(self) -> bool:
        """CLKREQ# deassert only. Use after L1SS/LNKCTL/D-state are armed."""
        t0 = time.monotonic()
        try:
            r = subprocess.run(
                ['python3', self.config.pmu_script,
                 str(self.config.clkreq_deassert_pin), '1', '1',
                 str(self.config.clkreq_voltage_mv)],
                timeout=3, capture_output=True, text=True)
            elapsed = (time.monotonic() - t0) * 1000
            log.warning(f"[PMU] CLKREQ# Deassert rc={r.returncode} ({elapsed:.1f}ms)"
                        + (f" out={r.stdout.strip()}" if r.stdout.strip() else "")
                        + (f" err={r.stderr.strip()}" if r.stderr.strip() else ""))
            if r.returncode == 0:
                log.warning("[PMU] → L1.2 live: ref clock removed, config space inaccessible")
            return r.returncode == 0
        except Exception as e:
            log.warning(f"[PMU] CLKREQ# Deassert exception: {e}")
            return False

    # ──────────────────────────────────────────────────────────────────
    # v7.7: S1/S2 PM Robustness Perturbation
    # 기존 PM rotation slot 으로 통합. 변경된 PCIe config 비트는 다음
    # rotation 까지 유지 — fuzz 명령들이 그 PM 상태에서 발화 → PM × fuzz
    # 상호작용 평가. CLKREQ# perturb 는 일회성 timing 이벤트.
    # ──────────────────────────────────────────────────────────────────

    def _pm_perturb_target_cap_offset(self, cap_name: str) -> Optional[int]:
        """PCIE_PM_FUZZ_TARGETS 의 cap_name 을 detect 된 base offset 으로 매핑."""
        if cap_name == 'exp':
            return self._pcie_cap_offset
        if cap_name == 'pm':
            return self._pcie_pm_cap_offset
        if cap_name == 'l1ss':
            return self._pcie_l1ss_offset
        return None

    def _pm_perturb_pcie_bit(self) -> bool:
        """PCIe config bit perturbation slot.
        random 1 target 선택 → setpci write → 다음 rotation 까지 유지.
        forced_one_shot 인 경우 D1/D2 일회성 처리 (50ms 후 D0 자동 복귀).
        """
        if not self._pcie_bdf:
            return False

        # forced slot 은 PCIe bit 분기 안에서 5% 확률로 발화
        forced_targets = [t for t in PCIE_PM_FUZZ_TARGETS if t[5] == 'forced_one_shot']
        normal_targets = [t for t in PCIE_PM_FUZZ_TARGETS if t[5] != 'forced_one_shot']

        if forced_targets and random.random() < 0.05:
            return self._pm_perturb_pmcsr_forced()

        if not normal_targets:
            return False
        target = random.choice(normal_targets)
        cap_name, off_in_cap, bit_lo, bit_w, name, constraint = target
        cap_base = self._pm_perturb_target_cap_offset(cap_name)
        if cap_base is None:
            log.debug(f"[PM] perturb skip: cap {cap_name} 미탐지")
            return False

        abs_offset = cap_base + off_in_cap
        max_val = (1 << bit_w) - 1
        if isinstance(constraint, dict):
            lo = constraint.get('min', 0)
            hi = constraint.get('max', max_val)
        else:
            lo, hi = 0, max_val
        new_val = random.randint(lo, hi)
        mask = max_val << bit_lo
        value = (new_val << bit_lo) & mask

        # L1SS Control1 은 32-bit, 그 외 LNKCTL/DEVCTL2/PMCSR 은 16-bit
        width = 'l' if cap_name == 'l1ss' else 'w'

        log.warning(f"[PM] PCIe bit perturb: {cap_name}+{off_in_cap:#x} "
                    f"{name} = {new_val:#x} (mask={mask:#x}, width={width})")

        # cmd_history 기록 — replay .sh 생성 시 setpci 재현에 활용
        self._cmd_history.append({
            'kind':         'pcie_pm_bit',
            'label':        f'PCIe {cap_name}.{name} = {new_val:#x}',
            'bdf':          self._pcie_bdf,
            'offset':       abs_offset,
            'value':        value,
            'mask':         mask,
            'width':        width,
        })

        ok = self._setpci_write(self._pcie_bdf, abs_offset, value, mask, width)
        if not ok:
            log.warning(f"[PM] setpci_write 실패: {cap_name}+{off_in_cap:#x}")
        return ok

    def _pm_perturb_pmcsr_forced(self) -> bool:
        """PMCSR PowerState D1/D2 일회성 forced slot.
        진입 시도 → 50ms 머묾 → D0 강제 복귀.
        미지원 controller 는 silent reject (D0 유지) — 안전.
        PS3/PS4 forced_idle slot 패턴 차용.

        반환: D0 restore write 성공 시 True. 실패 시 False (이후 NVMe timeout
        이 firmware 가 아닌 host-side restore 실패로 attribution 되지 않게
        호출자가 인지하도록).
        """
        if not self._pcie_bdf or self._pcie_pm_cap_offset is None:
            return False
        pmcsr_offset = self._pcie_pm_cap_offset + 0x04
        target_d = random.choice([1, 2])

        log.warning(f"[PM] PMCSR PowerState→D{target_d} forced slot (50ms)")

        # D1/D2 진입 시도
        self._cmd_history.append({
            'kind':   'pcie_pm_bit',
            'label':  f'PMCSR PowerState=D{target_d}',
            'bdf':    self._pcie_bdf,
            'offset': pmcsr_offset,
            'value':  target_d,
            'mask':   0x3,
            'width':  'w',
        })
        self._setpci_write(self._pcie_bdf, pmcsr_offset, target_d, 0x3, 'w')
        time.sleep(0.05)   # entry/exit latency 마진

        # D0 강제 복귀 — restore 실패는 critical: D-state 가 D1/D2 로 잔류
        # 하면 후속 NVMe timeout 의 attribution 이 firmware 결함으로 오염됨.
        self._cmd_history.append({
            'kind':   'pcie_pm_bit',
            'label':  'PMCSR PowerState=D0 (restore)',
            'bdf':    self._pcie_bdf,
            'offset': pmcsr_offset,
            'value':  0,
            'mask':   0x3,
            'width':  'w',
        })
        ok_restore = self._setpci_write(self._pcie_bdf, pmcsr_offset, 0, 0x3, 'w')
        time.sleep(0.01)
        if not ok_restore:
            log.warning("[PM] PMCSR D0 restore 실패 — controller D-state 잔류 가능. "
                        "후속 timeout 은 host-side restore 실패에 의한 것일 수 있음.")
            return False
        # readback 으로 D0 진입 검증 — write 가 silently dropped 된 경우 잡힘.
        rb = self._setpci_read(self._pcie_bdf, pmcsr_offset, 'w')
        if rb is None or (rb & 0x3) != 0:
            log.warning(f"[PM] PMCSR D0 readback 실패: {rb}. 후속 timeout 주의.")
            return False
        return True

    def _pm_perturb_clkreq(self, mode: Optional[str] = None) -> bool:
        """CLKREQ# timing perturbation (S2).
        4개 mode (missed_wake / extended_wait / short_pulse / rapid_toggle) 중 선택.
        mode=None: 4 mode 중 1개 random (PM rotation 기본 호출).
        mode='<name>': 명시된 mode 강제 (preflight 등 결정적 호출).
        일회성 timing 이벤트 — 다음 rotation 까지 별도 상태 유지 없음.
        """
        if not CLKREQ_FUZZ_MODES:
            return False
        if mode is None:
            mode_name, params = random.choice(CLKREQ_FUZZ_MODES)
        else:
            _entry = next(((m, p) for m, p in CLKREQ_FUZZ_MODES if m == mode), None)
            if _entry is None:
                log.warning(f"[PM] CLKREQ# mode {mode!r} 미정의 — 스킵")
                return False
            mode_name, params = _entry

        # replay .sh 재현 시 필요한 PMU 정보 (entry 마다 동일)
        pmu_ctx = {
            'pmu_script':          self.config.pmu_script,
            'clkreq_assert_pin':   self.config.clkreq_assert_pin,
            'clkreq_deassert_pin': self.config.clkreq_deassert_pin,
            'clkreq_voltage_mv':   self.config.clkreq_voltage_mv,
            'l1_2_settle_s':       self.config.l1_2_settle_s,
        }

        if mode_name == 'short_pulse':
            pulse_us = random.randint(params['pulse_us_min'],
                                      params['pulse_us_max'])
            log.warning(f"[PM] CLKREQ# short_pulse {pulse_us}μs")
            self._cmd_history.append({
                'kind': 'clkreq',
                'label': f'CLKREQ# short_pulse {pulse_us}us',
                'mode': mode_name, 'pulse_us': pulse_us,
                **pmu_ctx,
            })
            self._pmu_clkreq_assert()
            time.sleep(pulse_us / 1e6)
            self._pmu_clkreq_deassert()
            time.sleep(0.001)
            # 정상 동작 상태로 복귀: assert 유지
            self._pmu_clkreq_assert()
            return True

        if mode_name == 'missed_wake':
            delay_ms = random.randint(params['delay_ms_min'],
                                      params['delay_ms_max'])
            log.warning(f"[PM] CLKREQ# missed_wake delay={delay_ms}ms "
                        f"(L1.2 settle {self.config.l1_2_settle_s:.2f}s + delay)")
            self._cmd_history.append({
                'kind': 'clkreq',
                'label': f'CLKREQ# missed_wake delay={delay_ms}ms',
                'mode': mode_name, 'delay_ms': delay_ms,
                **pmu_ctx,
            })
            # L1.2 자연 진입을 위해 deassert + settle
            self._pmu_clkreq_deassert()
            time.sleep(self.config.l1_2_settle_s + 0.01)
            time.sleep(delay_ms / 1e3)
            # 늦은 wake — 정상 assert
            self._pmu_clkreq_assert()
            time.sleep(0.001)
            return True

        if mode_name == 'rapid_toggle':
            count = random.randint(params['count_min'], params['count_max'])
            log.warning(f"[PM] CLKREQ# rapid_toggle ×{count}")
            self._cmd_history.append({
                'kind': 'clkreq',
                'label': f'CLKREQ# rapid_toggle x{count}',
                'mode': mode_name, 'count': count,
                **pmu_ctx,
            })
            for _ in range(count):
                self._pmu_clkreq_assert()
                time.sleep(50e-6)
                self._pmu_clkreq_deassert()
                time.sleep(50e-6)
            # 정상 동작 상태로 복귀
            self._pmu_clkreq_assert()
            time.sleep(0.001)
            return True

        if mode_name == 'extended_wait':
            pct = random.randint(params['pct_min'], params['pct_max'])
            wait_s = self.config.l1_2_settle_s * pct / 100.0
            log.warning(f"[PM] CLKREQ# extended_wait T_POWER_ON {pct}% "
                        f"({wait_s*1000:.0f}ms)")
            self._cmd_history.append({
                'kind': 'clkreq',
                'label': f'CLKREQ# extended_wait pct={pct}',
                'mode': mode_name, 'pct': pct, 'wait_s': wait_s,
                **pmu_ctx,
            })
            self._pmu_clkreq_deassert()
            time.sleep(self.config.l1_2_settle_s + 0.01)
            time.sleep(wait_s)
            self._pmu_clkreq_assert()
            time.sleep(0.001)
            return True

        return False

    def _set_pcie_l_state(self, state: PCIeLState, deassert_l12: bool = True) -> bool:
        """PCIe L-state 설정 (spec r5.0 §5.5.4.1).
        L0=ASPM disable, L1=ASPM L1, L1.2=L1+L1SS. BDF 미탐지 시 False.
        """
        if not self._pcie_bdf or self._pcie_cap_offset is None:
            return False

        ep = self._pcie_bdf
        rp = self._pcie_root_bdf            # None이면 루트 포트 skip
        ec = self._pcie_cap_offset
        rc = self._pcie_root_cap_offset     # None이면 skip
        el = self._pcie_l1ss_offset
        rl = self._pcie_root_l1ss_offset

        # LNKCAP에서 ASPMS(bits[11:10]), CPM(bit18) 파싱
        # LNKCAP 읽기 실패 시 L1 지원(0x2)·CPM 미지원(0) 으로 가정
        aspms = ((self._pcie_lnkcap >> 10) & 0x3) if self._pcie_lnkcap is not None else 0x2
        cpm   = ((self._pcie_lnkcap >> 18) & 0x1) if self._pcie_lnkcap is not None else 0

        if state == PCIeLState.L0:
            # [PMU] CLKREQ# Assert — 클록 복원 먼저, 링크 L0 재진입 후 레지스터 해제
            #   L1.2 상태에서는 클록이 없으므로 setpci(config space write) 전에 반드시 수행.
            #   클록 안정화(T_COMMON_MODE) 대기 후 레지스터 조작.
            if not self._pmu_clkreq_assert():
                log.warning("[PCIe] L0 restore abort: CLKREQ# assert 실패 — clock 없음, register write 불가")
                return False

            # L1.2에서 복귀 시 config space가 0xFFFF일 수 있음 — 응답할 때까지 대기
            _t_assert = time.monotonic()
            _deadline = _t_assert + 5.0
            _poll_n = 0
            while time.monotonic() < _deadline:
                _rb = self._setpci_read(ep, ec + 0x10, 'w')
                _poll_n += 1
                if _rb is not None and _rb != 0xFFFF:
                    _elapsed_ms = (time.monotonic() - _t_assert) * 1000
                    log.warning(f"[PCIe] L0 config space 응답: LNKCTL={_rb:#06x} "
                                f"({_elapsed_ms:.0f}ms 경과, {_poll_n}회 시도)")
                    break
                time.sleep(0.05)
            else:
                _elapsed_ms = (time.monotonic() - _t_assert) * 1000
                log.warning(f"[PCIe] L0 restore timeout: {_elapsed_ms:.0f}ms 후에도 config space 무응답 — register write 중단")
                return False

            # 1. LNKCTL ASPMC = 0b00 (spec: ASPM disable 먼저)
            ok = self._setpci_write(ep, ec + 0x10, 0x0000, 0x0003, 'w')
            if rp and rc:
                self._setpci_write(rp, rc + 0x10, 0x0000, 0x0003, 'w')
            # 2. L1SS enable bits clear (양측)
            if el:
                self._setpci_write(ep, el + 0x08, 0x00000000, 0x0000000F)
            if rp and rl:
                self._setpci_write(rp, rl + 0x08, 0x00000000, 0x0000000F)
            # 3. DEVCTL2 LTRE clear (bit10) — LTR 비활성화
            self._setpci_write(ep, ec + 0x28, 0x0000, 0x0400, 'w')
            if rp and rc:
                self._setpci_write(rp, rc + 0x28, 0x0000, 0x0400, 'w')
            # 4. LNKCTL ECPM clear (bit8)
            self._setpci_write(ep, ec + 0x10, 0x0000, 0x0100, 'w')
            if rp and rc:
                self._setpci_write(rp, rc + 0x10, 0x0000, 0x0100, 'w')
            # 5. ASPM 정책 복원
            try:
                Path('/sys/module/pcie_aspm/parameters/policy').write_text(
                    self._orig_aspm_policy)
            except Exception:
                pass
            # 6. 검증: endpoint LNKCTL ASPMC == 0
            rb = self._setpci_read(ep, ec + 0x10, 'w')
            if rb is not None and (rb & 0x0003) != 0:
                log.debug(f"[PCIe] L0 verify: LNKCTL ASPMC={rb & 0x3:#04x} (expected 0x00)")
            return ok

        elif state == PCIeLState.L1:
            if not (aspms & 0x2):
                log.warning(f"[PCIe] L1 미지원 (LNKCAP.ASPMS={aspms:#04x})")
                return False
            if rp is None:
                log.warning("[PCIe] L1: RP 미탐지 — L1 진입 불가")
                return False
            # 1. 기존 L1SS enable bits 비활성화 (L1.2 잔류 방지)
            if el:
                self._setpci_write(ep, el + 0x08, 0x00000000, 0x0000000F)
            if rp and rl:
                self._setpci_write(rp, rl + 0x08, 0x00000000, 0x0000000F)
            # 2. DEVCTL2 LTRE clear (bit10) — L1.2 잔류 방지
            self._setpci_write(ep, ec + 0x28, 0x0000, 0x0400, 'w')
            if rp and rc:
                self._setpci_write(rp, rc + 0x28, 0x0000, 0x0400, 'w')
            # 3. PMU CLKREQ# Assert — NOPS device의 자연적 deassert 차단
            #    CLKREQ#가 deassert되면 RP가 ref clock을 제거해 L1.2로 진입.
            #    L1 조합에서는 clock을 유지해야 하므로 강제 assert.
            if not self._pmu_clkreq_assert():
                log.warning("[PCIe] L1 abort: CLKREQ# assert 실패 — clock 유지 불가")
                return False
            # 4. 전역 ASPM 정책 → powersave (커널 override 방지)
            try:
                Path('/sys/module/pcie_aspm/parameters/policy').write_text('powersave')
            except Exception:
                pass
            # 4. LNKCTL ASPMC = ASPMS & 0b10 — EP(downstream) 먼저, RP(upstream) 이후
            #    Linux kernel pci-aspm.c 순서: enable 시 EP 먼저, disable 시 RP 먼저
            aspm_val = aspms & 0x2
            ok = self._setpci_write(ep, ec + 0x10, aspm_val, 0x0003, 'w')   # EP 먼저
            if rp and rc:
                self._setpci_write(rp, rc + 0x10, aspm_val, 0x0003, 'w')   # RP 나중
            # 6. Clock PM (LNKCTL ECPM bit8) — CPM 미선언 시도 강제 활성화
            #    LNKCAP CPM=0은 BIOS가 막은 경우가 많으므로 unconditional write
            self._setpci_write(ep, ec + 0x10, 0x0100, 0x0100, 'w')
            if rp and rc:
                self._setpci_write(rp, rc + 0x10, 0x0100, 0x0100, 'w')
            # 7. idle window — LNKCTL 쓴 뒤 PCIe 트래픽 없는 구간 확보
            #    HW가 L1 idle timer 만료 + PM_Request_Ack DLLP 핸드셰이크 처리
            time.sleep(self.config.l1_settle_s)
            return ok

        else:  # PCIeLState.L1_2
            # 전제 조건 확인
            if not (aspms & 0x2):
                log.warning(f"[PCIe] L1.2: L1 미지원 (LNKCAP.ASPMS={aspms:#04x})")
                return False
            if self._pcie_l1ss_cap is None:
                log.warning("[PCIe] L1.2: L1SS cap 없음 — L1.2 불가")
                return False
            if not (self._pcie_l1ss_cap & 0x4):  # ASPM L1.2 Support (bit2)
                log.warning(
                    f"[PCIe] L1.2: ASPM L1.2 미지원 (L1SSCAP={self._pcie_l1ss_cap:#010x})")
                return False
            if rp is None:
                log.warning("[PCIe] L1.2: RP 미탐지 — L1.2 진입 불가")
                return False
            _skip_l1ss_arm = False
            if rl is None:
                # RP L1SS cap 없으면 EP L1SSCTL1 ASPM L1.2 enable bit(bit2) 쓰면 안 됨.
                # EP 컨트롤러가 L1 idle 시 CLKREQ#를 auto-deassert → RP 미설정 → link error → device drop.
                # GPIO deassert는 유지: LNKCTL ASPMC=L1 + GPIO 토글로 수동 테스트와 동일 경로 사용.
                log.warning("[PCIe] L1.2: RP L1SS cap 미탐지 — L1SS arm 스킵, GPIO CLKREQ# 제어만 사용")
                _skip_l1ss_arm = True

            # Step 1: L1SS enable bits 비활성화 (양측) — spec §5.5.4.1 step 2
            if el:
                self._setpci_write(ep, el + 0x08, 0x00000000, 0x0000000F)
            if rp and rl:
                self._setpci_write(rp, rl + 0x08, 0x00000000, 0x0000000F)

            # Step 2: 전역 ASPM 정책
            try:
                Path('/sys/module/pcie_aspm/parameters/policy').write_text('powersave')
            except Exception:
                pass

            # Step 3: L1SSCTL1 enable bits — L1SSCAP 지원 비트만 활성화
            #   bit0: PCI-PM L1.2, bit1: PCI-PM L1.1, bit2: ASPM L1.2, bit3: ASPM L1.1
            #   upstream(RP) 먼저 enable — spec §5.5.4.1 step 5
            # LTRE(LTR Enable) 미사용: PMU GPIO로 CLKREQ#를 직접 제어하므로
            #   RP 자율 판단 메커니즘(LTR) 불필요. LTRE 활성화 시 LTR 메시지 오버헤드 발생.
            # EP와 RP 양측이 지원하는 substate 교집합만 arm — 미지원 bit 기록 방지
            rp_l1ss_cap = self._pcie_root_l1ss_cap if self._pcie_root_l1ss_cap is not None else 0xF
            l1ss_en = self._pcie_l1ss_cap & rp_l1ss_cap & 0xF
            ok = True
            if not _skip_l1ss_arm:
                if rp and rl:
                    self._setpci_write(rp, rl + 0x08, l1ss_en, 0x0000000F)
                if el:
                    ok = self._setpci_write(ep, el + 0x08, l1ss_en, 0x0000000F)
            else:
                l1ss_en = 0  # arm 안 했으므로 검증 기준도 0으로

            # Step 6: LNKCTL ASPMC — upstream(RP) 먼저, endpoint 이후 — spec step 6
            aspm_val = aspms & 0x2
            if rp and rc:
                self._setpci_write(rp, rc + 0x10, aspm_val, 0x0003, 'w')
            ok &= self._setpci_write(ep, ec + 0x10, aspm_val, 0x0003, 'w')

            # Step 7: ECPM (Clock PM)
            if cpm:
                if rp and rc:
                    self._setpci_write(rp, rc + 0x10, 0x0100, 0x0100, 'w')
                self._setpci_write(ep, ec + 0x10, 0x0100, 0x0100, 'w')

            # Step 8: 검증 (endpoint LNKCTL + L1SSCTL1) — CLKREQ# deassert 이전 필수
            #   deassert 후에는 클록이 없어 config space read 불가.
            rb_lnk  = self._setpci_read(ep, ec + 0x10, 'w')
            rb_l1ss = self._setpci_read(ep, el + 0x08) if el else None
            rb_pmcsr = (self._setpci_read(ep, self._pcie_pm_cap_offset + 0x04, 'w')
                        if self._pcie_pm_cap_offset else None)
            log.warning(
                f"[PCIe] L1.2 pre-deassert: "
                f"LNKCTL={_hex_or_na(rb_lnk)} (want bits[1:0]={aspm_val:#04x})  "
                f"L1SSCTL1={_hex_or_na(rb_l1ss, 10)} (want &0xF={l1ss_en:#04x})  "
                f"PMCSR={_hex_or_na(rb_pmcsr)}")
            if rb_lnk is not None and (rb_lnk & 0x0003) != aspm_val:
                log.warning(
                    f"[PCIe] L1.2 LNKCTL mismatch: got={rb_lnk & 0x3:#04x} "
                    f"expected={aspm_val:#04x}")
                ok = False
            if rb_l1ss is not None and (rb_l1ss & 0xF) != l1ss_en:
                log.warning(
                    f"[PCIe] L1.2 L1SSCTL1 mismatch: got={rb_l1ss & 0xF:#04x} "
                    f"expected={l1ss_en:#04x}")
                ok = False

            if not ok:
                # arm 실패: 이미 쓴 L1SS/LNKCTL bits 롤백 (partial arm 방지)
                if el:
                    self._setpci_write(ep, el + 0x08, 0x00000000, 0x0000000F)
                if rp and rl:
                    self._setpci_write(rp, rl + 0x08, 0x00000000, 0x0000000F)
                self._setpci_write(ep, ec + 0x10, 0x0000, 0x0003, 'w')
                if rp and rc:
                    self._setpci_write(rp, rc + 0x10, 0x0000, 0x0003, 'w')
                log.warning("[PCIe] L1.2 arm 실패 — L1SS/LNKCTL bits 롤백 후 중단")
                return False

            # [PMU] CLKREQ# Deassert — 레지스터 설정·검증 완료 후 마지막 수행
            #   루트 포트가 CLKREQ# 비활성 감지 → 레퍼런스 클록 제거 → 실제 L1.2 진입.
            #   deassert 전 link idle window: verify setpci TLP 완료 후 link가
            #   PM_Enter_L1 DLLP 핸드셰이크를 마칠 때까지 대기.
            #   이 sleep 없이 deassert하면 active link에서 clock이 제거되어 link down 발생.
            if deassert_l12:
                time.sleep(self.config.l1_settle_s)
                ok &= self._pmu_clkreq_deassert()
            else:
                log.warning("[PCIe] L1.2 armed; CLKREQ# deassert deferred")

            # idle window — L1 idle timer + L1.2 clock off 완료 대기
            if deassert_l12:
                time.sleep(self.config.l1_settle_s + self.config.l1_2_settle_s)
            return ok

    def _set_pcie_d_state(self, state: PCIeDState) -> bool:
        """setpci로 PMCSR bits[1:0] 설정 (D0=0x00, D3hot=0x03).
        PCI PM cap + 0x04 = PMCSR 레지스터.
        BDF 미탐지 시 False 반환.

        write 후 readback 검증 + 최대 3회 retry.
        """
        if not self._pcie_bdf or self._pcie_pm_cap_offset is None:
            return False
        val    = 3 if state == PCIeDState.D3 else 0
        exp    = val & 0x3
        offset = self._pcie_pm_cap_offset + 0x04
        d_label = 'D3hot' if val else 'D0'

        # D0 복귀 시: L1.2에서 링크 복구까지 config space가 0xFFFF를 반환할 수 있음.
        # PMCSR이 유효한 값(≠0xFFFF)을 반환할 때까지 최대 3초 polling 후 write.
        if state == PCIeDState.D0:
            _t_d0 = time.monotonic()
            deadline = _t_d0 + 3.0
            _d0_n = 0
            while time.monotonic() < deadline:
                rb = self._setpci_read(self._pcie_bdf, offset, 'w')
                _d0_n += 1
                if rb is not None and rb != 0xFFFF:
                    _d0_ms = (time.monotonic() - _t_d0) * 1000
                    log.warning(f"[PCIe] PMCSR D0 pre-write: current={rb:#06x} "
                                f"({_d0_ms:.0f}ms 경과, {_d0_n}회 시도)")
                    break
                time.sleep(0.1)
            else:
                log.warning("[PCIe] D0 복귀 대기 timeout — config space 응답 없음")
                return False
        else:
            cur = self._setpci_read(self._pcie_bdf, offset, 'w')
            log.warning(f"[PCIe] PMCSR {d_label} write: current="
                        f"{_hex_or_na(cur)}, target bits[1:0]={val:#04x}")

        for attempt in range(3):
            ok = self._setpci_write(self._pcie_bdf, offset, val, 0x0003, 'w')
            if not ok:
                time.sleep(0.05)
                continue
            rb = self._setpci_read(self._pcie_bdf, offset, 'w')
            if rb is not None and (rb & 0x3) == exp:
                if attempt > 0:
                    log.warning(f"[PCIe] PMCSR {d_label} 확인 (attempt {attempt+1})")
                else:
                    log.warning(f"[PCIe] PMCSR {d_label} ok: readback={rb:#06x}")
                return True
            time.sleep(0.05)
        log.warning(f"[PCIe] PMCSR {d_label} 진입 실패")
        return False

    def _set_power_combo(self, combo: PowerCombo) -> bool:
        """NVMe PS + PCIe L/D-state 동시 설정 + cmd_history 기록.
        순서: NVMe PS → PS settle → L-state → D3(마지막).
        """
        t0    = time.monotonic()
        ok_ps = self._pm_set_state(combo.nvme_ps)
        if not ok_ps:
            log.warning(f"[PM] {combo.label} PS{combo.nvme_ps} 진입 실패 — L/D-state 진입 중단")
            return False
        # NOPS(PS3/PS4) settle: 실제 NAND 파워다운 완료까지 대기
        # 이후 setpci(config TLP)가 링크를 깨우지 않도록 PS 안정화 후 L-state 진입
        ps_settle = self._ps_settle.get(combo.nvme_ps, 0.05)
        if ps_settle > 0.05:
            time.sleep(ps_settle)
        if combo.pcie_l == PCIeLState.L1_2:
            if combo.pcie_d == PCIeDState.D0:
                # D0가 기본 상태 — clock 제거 후 PMCSR 쓰기 불가, 쓸 필요도 없음
                ok_l = self._set_pcie_l_state(combo.pcie_l)
                ok_d = True
            else:  # D3 + L1.2
                # D3hot PMCSR 쓰기는 clock이 있는 동안 수행 → 그 후 CLKREQ# deassert
                ok_l = self._set_pcie_l_state(combo.pcie_l, deassert_l12=False)
                ok_d = self._set_pcie_d_state(combo.pcie_d)
                if ok_l and ok_d:
                    ok_l = self._pmu_clkreq_deassert() and ok_l
                else:
                    log.warning("[PCIe] D3+L1.2: arm 또는 D3hot 실패 — CLKREQ# deassert 생략, LNKCTL 롤백")
                    # ok_l=True(arm 성공)인데 ok_d 실패면 LNKCTL ASPMC 비트가 남음 → 명시 롤백
                    if ok_l and self._pcie_bdf and self._pcie_cap_offset is not None:
                        self._set_pcie_l_state(PCIeLState.L0)
                time.sleep(self.config.l1_settle_s + self.config.l1_2_settle_s)
        else:
            ok_l = self._set_pcie_l_state(combo.pcie_l)
            ok_d = self._set_pcie_d_state(combo.pcie_d)
            if combo.pcie_d == PCIeDState.D3 and combo.pcie_l == PCIeLState.L1:
                time.sleep(self.config.l1_settle_s)

        elapsed = time.monotonic() - t0
        status  = (f"PS={'OK' if ok_ps else 'FAIL'} "
                   f"L={'OK' if ok_l else 'FAIL'} "
                   f"D={'OK' if ok_d else 'FAIL'}")
        log.warning(f"[PM] → {combo.label}  {status}  ({elapsed:.3f}s)")

        all_ok = ok_ps and ok_l and ok_d
        # PCIe 상태 변화를 별도 항목으로 기록 → replay .sh에서 setpci 재현
        # ok=False 항목은 replay에서 스킵되므로 실패 기록은 남기되 skip 플래그 포함
        if self._pcie_bdf:
            self._cmd_history.append({
                'kind':                  'pcie_state',
                'label':                 f'PCIe {combo.label}',
                'ok':                    all_ok,
                'pcie_l':                int(combo.pcie_l),
                'pcie_d':                int(combo.pcie_d),
                'pcie_bdf':              self._pcie_bdf,
                'pcie_cap_offset':       self._pcie_cap_offset,
                'pcie_pm_cap_offset':    self._pcie_pm_cap_offset,
                'pcie_l1ss_offset':      self._pcie_l1ss_offset,
                'pcie_lnkcap':           self._pcie_lnkcap,
                'pcie_l1ss_cap':         self._pcie_l1ss_cap,
                'pcie_root_bdf':         self._pcie_root_bdf,
                'pcie_root_cap_offset':  self._pcie_root_cap_offset,
                'pcie_root_l1ss_offset': self._pcie_root_l1ss_offset,
                'pmu_script':            self.config.pmu_script,
                'clkreq_assert_pin':     self.config.clkreq_assert_pin,
                'clkreq_deassert_pin':   self.config.clkreq_deassert_pin,
                'clkreq_voltage_mv':     self.config.clkreq_voltage_mv,
            })
        return all_ok

    def _record_setfeature_history(self, fid: int, value: int,
                                   data: Optional[bytes] = None,
                                   label: str = '') -> None:
        """APST/KeepAlive 등 SetFeatures(admin opcode 0x09)를 _cmd_history에 'nvme'
        항목으로 기록 → crash replay.sh가 실제 실행된 SetFeatures를 그대로 재현.
        data가 있으면 write(host→ctrl) 로 기록. 명령 성공(rc==0) 시에만 호출할 것."""
        self._cmd_history.append({
            'kind':          'nvme',
            'label':         label or f'SetFeatures(FID={fid:#04x})',
            'passthru_type': 'admin-passthru',
            'device':        self._ctrl_device(),   # 실제 전송 device(컨트롤러 char)와 일치 → replay 충실
            'opcode':        0x09,
            'nsid':          0,
            'cdw2': 0, 'cdw3': 0,
            'cdw10': fid, 'cdw11': value,
            'cdw12': 0, 'cdw13': 0, 'cdw14': 0, 'cdw15': 0,
            'data':     bytes(data) if data else None,
            'data_len': len(data) if data else 0,
            'is_write': bool(data),
        })

    def _apst_disable(self) -> None:
        """NVMe APST(Autonomous Power State Transition) 비활성화.

        APST 활성화 상태에서는 NVMe 컨트롤러가 자율적으로 PS 전환을 하면서
        PCIe 트래픽을 발생시켜 L1/L1.2 idle window를 깨뜨림.
        퍼징 시작 전 비활성화하여 PM 상태가 fuzzer 제어 하에만 전환되도록 함.

        반복 호출 안전: _orig_apst_cdw11 은 None 일 때만 저장 (이미 캡처된
        '원본' 값을 forced_idle slot 에서 enable→disable 한 후 덮어쓰면 안 됨).
        """
        dev = self._ctrl_device()   # APST 는 컨트롤러 스코프 → 컨트롤러 char device
        # 원본 cdw11 캡처는 첫 호출 1회만 — 이후엔 (이미 disable 또는 enable→disable
        # 가 한 _orig 가 의미 있는) 상태를 건드리지 않음.
        if self._orig_apst_cdw11 is None:
            try:
                r = subprocess.run(
                    ['nvme', 'get-feature', dev, '-n', '0', '-f', '0x0C'],
                    capture_output=True, text=True, timeout=5)
                for line in r.stdout.splitlines():
                    if 'value:' in line.lower() or 'Current value' in line:
                        import re as _re
                        m = _re.search(r'0x([0-9a-fA-F]+)', line)
                        if m:
                            self._orig_apst_cdw11 = int(m.group(1), 16)
                            break
                if self._orig_apst_cdw11 is None:
                    log.warning(f"[APST] get-feature 파싱 실패 (rc={r.returncode}) "
                                f"stdout={r.stdout[:200]!r} stderr={r.stderr.strip()[:200]!r}")
            except Exception as e:
                log.warning(f"[APST] get-feature 실패: {e}")

        if self._orig_apst_cdw11 == 0:
            log.warning("[APST] 이미 비활성화 상태 — skip")
            return

        import tempfile as _tf
        _ok_apst = False
        _fname: Optional[str] = None
        try:
            # delete=False + finally unlink (_apst_enable_short_itpt 와 동일 패턴):
            # subprocess 가 파일을 여는 동안 항상 존재 보장. 인자는 space 구분 — 구버전 nvme-cli 호환.
            with _tf.NamedTemporaryFile(suffix='.apst', delete=False) as _f:
                _f.write(b'\x00' * 256)
                _fname = _f.name
            r = subprocess.run(
                ['nvme', 'set-feature', dev, '-n', '0', '-f', '0x0C', '-v', '0',
                 '--data-len', '256', '--data', _fname],
                capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                log.warning(f"[APST] 비활성화 완료 (원본 CDW11={self._orig_apst_cdw11:#010x})")
                _ok_apst = True
                self._record_setfeature_history(
                    0x0C, 0, b'\x00' * 256, 'APST disable')
            else:
                log.warning(f"[APST] set-feature 실패 (rc={r.returncode}): {r.stderr.strip()}")
        except Exception as e:
            log.warning(f"[APST] set-feature 예외: {e}")
        finally:
            if _fname is not None:
                try:
                    os.unlink(_fname)
                except OSError:
                    pass

        if not _ok_apst and self._pcie_bdf:
            try:
                _ctrl = Path(f'/sys/bus/pci/devices/{self._pcie_bdf}/power/control')
                if _ctrl.exists():
                    _ctrl.write_text('on')
                    log.warning("[APST] sysfs power/control=on 으로 runtime PM 비활성화")
                    _ok_apst = True
            except Exception as e:
                log.warning(f"[APST] sysfs fallback 실패: {e}")

        if not _ok_apst:
            log.warning("[APST] 비활성화 실패 — APST 자율 PS 전환이 MISMATCH 유발할 수 있음")

    def _apst_enable_short_itpt(self, ps3_ms: int = 500, ps4_ms: int = 2000) -> bool:
        """APST 를 짧은 ITPT 로 활성화 — PM rotation forced_idle slot 전용.

        NVMe spec §5.21.1.7 APST table (256B, 32 entries × 8B):
          Entry[N] 은 "현재 PS=N 일 때, ITPT ms idle 이면 ITPS 로 자율 전환".
          bits[7:3] = ITPS (target PS), bits[31:8] = ITPT (ms), 나머지 reserved.

        설정:
          Entry[0]: PS0 idle ps3_ms 후 → PS3
          Entry[3]: PS3 idle ps4_ms 후 → PS4
        결과: 활성화 후 디바이스 가 idle 이면 ps3_ms → PS3 → 추가 ps4_ms → PS4
        로 자율 전환. SetFeatures PS=4 강제 진입보다 실제 OS 동작에 가까움.

        호출 후 슬롯 종료 시 _apst_disable() 로 다시 끄기 — 다른 PM rotation 슬롯
        (POWER_COMBO 등) 의 manual PM 제어가 APST 와 충돌하지 않게.
        """
        dev = self._ctrl_device()   # APST 는 컨트롤러 스코프 → 컨트롤러 char device
        table = bytearray(256)
        # Entry[0] — PS0 → PS3
        _entry0 = (ps3_ms << 8) | (3 << 3)
        table[0:8] = _entry0.to_bytes(8, 'little')
        # Entry[3] — PS3 → PS4
        _entry3 = (ps4_ms << 8) | (4 << 3)
        table[24:32] = _entry3.to_bytes(8, 'little')

        import tempfile as _tf
        _fname: Optional[str] = None
        try:
            with _tf.NamedTemporaryFile(suffix='.apst', delete=False) as _f:
                _f.write(bytes(table))
                _fname = _f.name
            # CDW11 bit0=1 (APSTE) — '-v 1'
            r = subprocess.run(
                ['nvme', 'set-feature', dev, '-n', '0', '-f', '0x0C', '-v', '1',
                 '--data-len', '256', '--data', _fname],
                capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                log.warning(f"[APST] enable: ITPT PS0→PS3={ps3_ms}ms, "
                            f"PS3→PS4={ps4_ms}ms")
                self._record_setfeature_history(
                    0x0C, 1, bytes(table), 'APST enable')
                return True
            log.warning(f"[APST] enable 실패 (rc={r.returncode}): {r.stderr.strip()}")
            return False
        except Exception as e:
            log.warning(f"[APST] enable 예외: {e}")
            return False
        finally:
            if _fname is not None:
                try:
                    os.unlink(_fname)
                except OSError:
                    pass

    def _apst_restore(self) -> None:
        """퍼징 종료 시 원본 APST 상태 복원."""
        if self._orig_apst_cdw11 is None or self._orig_apst_cdw11 == 0:
            return  # 원래 비활성화 상태였으면 복원 불필요
        dev = self._ctrl_device()   # APST 는 컨트롤러 스코프 → 컨트롤러 char device
        try:
            r = subprocess.run(
                ['nvme', 'set-feature', dev, '-n', '0', '-f', '0x0C',
                 '-v', str(self._orig_apst_cdw11)],
                capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                log.warning(f"[APST] 복원 완료 (CDW11={self._orig_apst_cdw11:#010x})")
            else:
                log.warning(f"[APST] 복원 실패 (rc={r.returncode}): {r.stderr.strip()}")
        except Exception as e:
            log.warning(f"[APST] 복원 실패: {e}")

    def _keepalive_disable(self) -> None:
        """NVMe Keep-Alive Timer 비활성화.

        Keep-Alive 활성화 시 드라이버가 주기적으로 NVMe admin command를 전송,
        PS3/PS4 deep sleep에서 컨트롤러를 wake-up시켜 PCIe 트래픽 발생.
        L1/L1.2 idle window를 깨뜨리므로 퍼징 전 비활성화.
        """
        dev = self._ctrl_device()   # KeepAlive 는 컨트롤러 스코프 → 컨트롤러 char device
        try:
            r = subprocess.run(
                ['nvme', 'get-feature', dev, '-n', '0', '-f', '0x0F'],
                capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if 'value:' in line.lower() or 'Current value' in line:
                    import re as _re
                    m = _re.search(r'0x([0-9a-fA-F]+)', line)
                    if m:
                        self._orig_keepalive_val = int(m.group(1), 16)
                        break
        except Exception as e:
            log.warning(f"[KeepAlive] get-feature 실패: {e}")

        if self._orig_keepalive_val == 0:
            log.warning("[KeepAlive] 이미 비활성화 상태 — skip")
            return
        try:
            r = subprocess.run(
                ['nvme', 'set-feature', dev, '-n', '0', '-f', '0x0F', '-v', '0'],
                capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                log.warning(f"[KeepAlive] 비활성화 완료 "
                            f"(원본={self._orig_keepalive_val:#010x})")
                self._record_setfeature_history(0x0F, 0, None, 'KeepAlive disable')
            else:
                log.warning(f"[KeepAlive] 비활성화 실패 (rc={r.returncode}): "
                            f"{r.stderr.strip()}")
        except Exception as e:
            log.warning(f"[KeepAlive] set-feature 실패: {e}")

    def _keepalive_restore(self) -> None:
        """퍼징 종료 시 원본 Keep-Alive 상태 복원."""
        if self._orig_keepalive_val == 0:
            return
        dev = self._ctrl_device()   # KeepAlive 는 컨트롤러 스코프 → 컨트롤러 char device
        try:
            r = subprocess.run(
                ['nvme', 'set-feature', dev, '-n', '0', '-f', '0x0F',
                 '-v', str(self._orig_keepalive_val)],
                capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                log.warning(f"[KeepAlive] 복원 완료 "
                            f"(val={self._orig_keepalive_val:#010x})")
            else:
                log.warning(f"[KeepAlive] 복원 실패 (rc={r.returncode}): "
                            f"{r.stderr.strip()}")
        except Exception as e:
            log.warning(f"[KeepAlive] 복원 실패: {e}")

    def _pm_d3_safe_restore(self) -> bool:
        """D3hot/L1.2+D3 → PS0+L0+D0 복귀. 순서: L0 → D0 → Trst(10ms) → PS0.

        Replay 호환: PS0 SetFeatures 전에 baseline(PS0+L0+D0) pcie_state entry
        를 _cmd_history 에 명시 기록 → replay .sh 가 L0+D0 setpci 시퀀스를
        PS0 SetFeatures 보다 먼저 출력. 그렇지 않으면 _pm_set_state(0) 가
        먼저 'pm' entry 를 추가해버려 replay 가 D3hot 상태에서 PS0 시도 → hang.
        """
        ok = True
        # Step 1: L0 먼저 — L1.2이면 CLKREQ# assert로 clock 복원 (TLP 전 필수)
        if self._pcie_bdf and self._pcie_cap_offset is not None:
            ok &= self._set_pcie_l_state(PCIeLState.L0)
            if not ok:
                log.warning("[PM] D3 restore: L0 복귀 실패 — clock 없음, D0/PS0 중단")
                # 실패해도 부분 복귀 기록 — replay 에서 동일 시도 후 일관된 실패 가능.
                self._record_pcie_state_history(
                    POWER_COMBOS[0], False,
                    'D3 restore L0+D0 (L0 진입 실패)')
                return False
        # Step 2: D3 → D0 (clock 복원 후 config space 접근)
        if self._pcie_bdf and self._pcie_pm_cap_offset is not None:
            ok &= self._set_pcie_d_state(PCIeDState.D0)
        # Step 3: Trst
        time.sleep(0.1)
        # Step 3.5: pcie_state 기록 — PS0 SetFeatures 직전에 추가하여
        # replay 순서가 "setpci L0+D0 → SetFeatures PS0" 가 되게 한다.
        self._record_pcie_state_history(
            POWER_COMBOS[0], ok,
            'D3 restore L0+D0 (pre-PS0)')
        # Step 4: NVMe PS0 — 위 entry 이후에 'pm' entry 추가됨.
        ok &= self._pm_set_state(0)
        return ok

    @staticmethod
    def _is_nonop_combo(combo: PowerCombo) -> bool:
        """D3hot 또는 L1.2 상태 여부 — NVMe 커맨드 전 복귀 필요."""
        return (combo.pcie_d  == PCIeDState.D3
                or combo.pcie_l == PCIeLState.L1_2)

    def _record_pcie_state_history(self, combo: PowerCombo, ok: bool, label: str) -> None:
        """_cmd_history 에 pcie_state entry 추가 — replay .sh 가 setpci 재현 가능하게.
        _set_power_combo 의 인라인 기록과 동일 포맷.
        """
        if not self._pcie_bdf:
            return
        self._cmd_history.append({
            'kind':                  'pcie_state',
            'label':                 label,
            'ok':                    ok,
            'pcie_l':                int(combo.pcie_l),
            'pcie_d':                int(combo.pcie_d),
            'pcie_bdf':              self._pcie_bdf,
            'pcie_cap_offset':       self._pcie_cap_offset,
            'pcie_pm_cap_offset':    self._pcie_pm_cap_offset,
            'pcie_l1ss_offset':      self._pcie_l1ss_offset,
            'pcie_lnkcap':           self._pcie_lnkcap,
            'pcie_l1ss_cap':         self._pcie_l1ss_cap,
            'pcie_root_bdf':         self._pcie_root_bdf,
            'pcie_root_cap_offset':  self._pcie_root_cap_offset,
            'pcie_root_l1ss_offset': self._pcie_root_l1ss_offset,
            'pmu_script':            self.config.pmu_script,
            'clkreq_assert_pin':     self.config.clkreq_assert_pin,
            'clkreq_deassert_pin':   self.config.clkreq_deassert_pin,
            'clkreq_voltage_mv':     self.config.clkreq_voltage_mv,
        })

    def _nonop_restore(self, combo: PowerCombo) -> PowerCombo:
        """D3hot/L1.2 → NVMe 커맨드 가능 상태 복귀. 복귀 후 PowerCombo 반환.
        복귀 실패 시 경고를 남기고 baseline combo를 반환 (호출부가 NVMe 응답으로 최종 확인).

        Replay 호환: 복귀 후 baseline(PS0+L0+D0) 또는 (cur_ps+L0+D0) 를 pcie_state
        entry 로 _cmd_history 에 기록 → replay .sh 가 L0/D0 setpci 를 재생산하여
        후속 NVMe SetFeatures PS0 가 D3hot 상태에서 hang 하는 문제 차단.
        """
        if combo.pcie_d == PCIeDState.D3:
            log.warning(f"[PM] NonOp restore: {combo.label} → D0+L0+PS0")
            # _pm_d3_safe_restore 내부에서 pcie_state(baseline) entry 를
            # PS0 SetFeatures 직전에 기록 — replay 순서 보장.
            ok = self._pm_d3_safe_restore()
            if not ok:
                log.warning("[PM] NonOp restore: D3 복귀 실패 — 장치 응답 불가 상태일 수 있음")
            return POWER_COMBOS[0]  # PS0+L0+D0

        log.warning(f"[PM] NonOp restore: {combo.label} → L0")
        ok = self._set_pcie_l_state(PCIeLState.L0)
        if not ok:
            log.warning("[PM] NonOp restore: L0 복귀 실패 — clock 복원 안 됨")
        # _set_pcie_l_state 의 setpci 변경 ('L1.2→L0' CLKREQ# assert + LNKCTL/L1SS clear)
        # 는 history 미기록 — 보정.
        _restored = PowerCombo(combo.nvme_ps, PCIeLState.L0, PCIeDState.D0)
        self._record_pcie_state_history(
            _restored, ok,
            f'NonOp restore L0 (from {combo.label})')
        return _restored

    def _pm_verify_combo(self, combo: PowerCombo) -> dict:
        """PM 상태 다중 검증 (PMU/PMCSR/LNKCTL/L1SS/sysfs) → dict 반환."""
        res = {}

        # 0. PMU getcurrent — NVMe 커맨드보다 반드시 먼저 측정.
        #    PS3/PS4(NOPS)는 nvme get-feature 같은 Admin 커맨드를 받는 순간
        #    컨트롤러가 강제 wake-up되어 NAND 재초기화 transient 전류가 발생함.
        #    PMU 측정은 JTAG 경로(pmu_4_1.py)이므로 NVMe 링크를 건드리지 않음.
        try:
            r = subprocess.run(
                ['python3', self.config.pmu_script, '3', '1'],
                capture_output=True, text=True, timeout=3)
            raw = r.stdout.strip()
            res['pmu'] = raw if r.returncode == 0 else f"FAIL(rc={r.returncode}) {r.stderr.strip()}"
        except Exception as e:
            res['pmu'] = f"ERR({e})"

        # 1. PMCSR readback — D-state bits[1:0] (NVMe 명령 전 먼저 실행해 link-down 판정)
        #    L1.2+PSx: 클락 off 시 config space = 0xFFFF → link-down으로 판정.
        if self._pcie_bdf and self._pcie_pm_cap_offset is not None:
            v = self._setpci_read(self._pcie_bdf, self._pcie_pm_cap_offset + 0x04, 'w')
            if v is not None and v != 0xFFFF:
                dval  = v & 0x3
                dname = {0: 'D0', 1: 'D1', 2: 'D2', 3: 'D3hot'}.get(dval, 'D?')
                exp   = 3 if combo.pcie_d == PCIeDState.D3 else 0
                chk   = 'OK' if dval == exp else f'MISMATCH(exp={exp})'
                res['d_state'] = f"{dname}(raw={v:#06x}) {chk}"
            elif v == 0xFFFF:
                exp_d = 'D3hot' if combo.pcie_d == PCIeDState.D3 else 'D0'
                res['d_state'] = f'{exp_d}(link-down: clock off)'
            else:
                res['d_state'] = 'read_fail'

        # 2. nvme get-feature FID=0x02 — PS 진입 확인
        #    D3hot / link-down: NVMe BAR 접근 불가 → 커널 드라이버 blocking(30~60s) 방지.
        _link_down = 'link-down' in res.get('d_state', '')
        if combo.pcie_d == PCIeDState.D3:
            res['nvme_ps'] = 'skipped (D3hot: NVMe BAR inaccessible)'
        elif _link_down:
            res['nvme_ps'] = 'skipped (link-down: clock off)'
        else:
            try:
                r = subprocess.run(
                    ['nvme', 'get-feature', self.config.nvme_device, '-f', '0x02'],
                    capture_output=True, text=True, timeout=5)
                if r.returncode == 0:
                    # "get-feature:0x2 (Power Management), Current value:0x00000004"
                    # "get-feature:0x02, Current value: 00000000" 등 다양한 포맷 대응
                    import re as _re_gf
                    raw_gf = (r.stdout + r.stderr).strip()
                    cur_ps = None
                    m = _re_gf.search(
                        r'[Cc]urrent\s+value[:\s]+(?:0x)?([0-9a-fA-F]+)', raw_gf)
                    if m:
                        try:
                            cur_ps = int(m.group(1), 16)
                        except ValueError:
                            pass
                    if cur_ps is not None:
                        exp_ps = combo.nvme_ps
                        chk    = 'OK' if cur_ps == exp_ps else f'MISMATCH(exp=PS{exp_ps})'
                        res['nvme_ps'] = f"PS{cur_ps} {chk}"
                    else:
                        res['nvme_ps'] = f"parse_fail: {raw_gf[:80]}"
                else:
                    res['nvme_ps'] = f"FAIL(rc={r.returncode}) {r.stderr.strip()[:60]}"
            except Exception as e:
                res['nvme_ps'] = f"ERR({e})"


        # 3. LNKCTL readback — EP ASPM bits[1:0]
        if self._pcie_bdf and self._pcie_cap_offset is not None:
            v = self._setpci_read(self._pcie_bdf, self._pcie_cap_offset + 0x10, 'w')
            if v is not None and v != 0xFFFF:
                aspm  = v & 0x3
                aname = {0: 'L0/disabled', 1: 'L0s', 2: 'L1', 3: 'L0s+L1'}.get(aspm, '?')
                exp   = 0 if combo.pcie_l == PCIeLState.L0 else 2
                chk   = 'OK' if aspm == exp else f'MISMATCH(exp={exp})'
                res['l_state_ep'] = f"EP ASPM={aname}(raw={aspm:#04x}) {chk}"
            elif _link_down:
                res['l_state_ep'] = 'EP(link-down: clock off)'
            else:
                res['l_state_ep'] = 'read_fail'

        # 3b. RP LNKCTL readback — L1은 EP+RP 양측 모두 설정되어야 진입 가능
        if self._pcie_root_bdf and self._pcie_root_cap_offset is not None:
            v = self._setpci_read(self._pcie_root_bdf,
                                  self._pcie_root_cap_offset + 0x10, 'w')
            if v is not None:
                aspm  = v & 0x3
                aname = {0: 'L0/disabled', 1: 'L0s', 2: 'L1', 3: 'L0s+L1'}.get(aspm, '?')
                exp   = 0 if combo.pcie_l == PCIeLState.L0 else 2
                chk   = 'OK' if aspm == exp else f'MISMATCH(exp={exp})'
                res['l_state_rp'] = f"RP ASPM={aname}(raw={aspm:#04x}) {chk}"
            else:
                res['l_state_rp'] = 'read_fail'
        else:
            res['l_state_rp'] = f"RP not detected (bdf={self._pcie_root_bdf!r} cap={self._pcie_root_cap_offset!r})"

        # 3c. ASPM 정책 실제값 확인 (커널 override 감지)
        try:
            raw = Path('/sys/module/pcie_aspm/parameters/policy').read_text().strip()
            res['aspm_policy'] = raw
        except Exception:
            res['aspm_policy'] = 'N/A'

        # 3d. lspci -vv 로 실제 링크 ASPM 상태 확인 (LnkCtl: ASPM ... line)
        if self._pcie_bdf:
            try:
                r = subprocess.run(
                    ['lspci', '-vv', '-s', self._pcie_bdf],
                    capture_output=True, text=True, timeout=5)
                for line in r.stdout.splitlines():
                    if 'LnkCtl' in line and 'ASPM' in line:
                        res['lspci_lnkctl'] = line.strip()
                        break
            except Exception:
                pass

        # 4. L1SSCTL1 readback — enable bits[3:0] (cap 있을 때만)
        if self._pcie_bdf and self._pcie_l1ss_offset is not None:
            v = self._setpci_read(self._pcie_bdf, self._pcie_l1ss_offset + 0x08, 'l')
            if v is not None and v != 0xFFFFFFFF:
                l1ss_en = v & 0xF
                # RP L1SS offset 없으면 _skip_l1ss_arm=True로 arm 자체를 스킵했으므로
                # 기댓값도 0x0. _rp_cap 기본값을 0xF로 두면 잘못된 MISMATCH 발생.
                _skip_l1ss_arm = (self._pcie_root_l1ss_offset is None)
                if combo.pcie_l != PCIeLState.L1_2 or _skip_l1ss_arm:
                    exp_en = 0x0
                else:
                    _ep_cap = self._pcie_l1ss_cap if self._pcie_l1ss_cap is not None else 0xF
                    _rp_cap = self._pcie_root_l1ss_cap if self._pcie_root_l1ss_cap is not None else 0xF
                    exp_en  = _ep_cap & _rp_cap & 0xF
                chk     = 'OK' if l1ss_en == exp_en else f'MISMATCH(exp={exp_en:#03x})'
                res['l1ss'] = f"L1SS_EN={l1ss_en:#03x} {chk}"
            elif combo.pcie_l == PCIeLState.L1_2:
                res['l1ss'] = "L1SS(link-down: clock off)"

        # sysfs power_state는 커널 PM 뷰 — setpci 직접 write 시 하드웨어와 불일치.
        # PMCSR readback(d_state)이 실제 하드웨어 레지스터 기준이므로 sysfs는 생략.

        return res

    def _init_ps_settle(self) -> None:
        """nvme id-ctrl 텍스트 출력에서 PS별 enlat/exlat(μs) 파싱 → preflight settle 계산.

        formula: settle = (enlat_us + exlat_us) / 1_000_000 * 2 + 0.05
                 PS3 최소값: 0.5s (NAND 캐시 플러시 + retention 진입 대기)
                 PS4 최소값: 2.0s (더 깊은 sleep → NAND flush 완료까지 추가 대기)
        파싱 실패 시 _PS_SETTLE_FALLBACK 유지.
        """
        import re as _re
        NOPS_MIN_SETTLE  = 0.5   # PS3: NAND retention 진입까지 최소 대기
        PS4_MIN_SETTLE   = 2.0   # PS4: 더 깊은 sleep → NAND flush 완료까지 더 긴 대기
        parsed: dict[int, float] = {}
        try:
            r = subprocess.run(
                ['nvme', 'id-ctrl', self.config.nvme_device],
                capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                m = _re.search(r'ps\s+(\d+)\s*:.*enlat:(\d+)\s+exlat:(\d+)', line)
                if m:
                    ps    = int(m.group(1))
                    enlat = int(m.group(2))
                    exlat = int(m.group(3))
                    settle = (enlat + exlat) / 1_000_000 * 2 + 0.05
                    # NOPS 여부: 같은 줄에 'non-operational' 포함 여부로 판단
                    is_nops = 'non-operational' in line.lower()
                    if is_nops:
                        min_settle = PS4_MIN_SETTLE if ps >= 4 else NOPS_MIN_SETTLE
                        settle = max(settle, min_settle)
                    parsed[ps] = max(settle, 0.05)
        except Exception as e:
            log.warning(f"[PS-Settle] id-ctrl 파싱 예외: {e} → fallback 유지")

        if parsed:
            self._ps_settle.update(parsed)
            log.warning("[PS-Settle] id-ctrl 기반 settle 계산: " +
                        ", ".join(f"PS{k}={v*1000:.0f}ms"
                                  for k, v in sorted(self._ps_settle.items())))
        else:
            log.warning("[PS-Settle] id-ctrl 파싱 실패 → fallback: " +
                        ", ".join(f"PS{k}={v*1000:.0f}ms"
                                  for k, v in sorted(self._ps_settle.items())))

    def _pm_preflight_check(self) -> bool:
        """전체 30개 PowerCombo 사전 검증 (enter → restore → nvme id-ctrl). 경고만 출력."""
        if self.config.pm_inject_prob <= 0:
            return True

        # id-ctrl에서 enlat/exlat 읽어 PS별 settle 시간 동적 계산
        self._init_ps_settle()

        # preflight + 메인 퍼징 공통 settle — 전역 상수 사용
        RESTORE_SETTLE     = RESTORE_SETTLE_S
        D3_RESTORE_SETTLE  = D3_RESTORE_SETTLE_S
        D3_EXTRA           = D3_EXTRA_S
        PROBE_TIMEOUT = 5.0   # nvme id-ctrl 타임아웃

        baseline = POWER_COMBOS[0]  # PS0+L0+D0

        log.warning("=" * 60)
        log.warning(f"[PM-Preflight] 전체 PowerCombo 사전 검증 시작 "
                    f"({len(POWER_COMBOS)}개 조합)")
        log.warning("=" * 60)

        # (combo, ok_set, ok_restore, ok_nvme, elapsed)
        results: list = []
        failed_labels: list = []

        # D0 먼저 전체 L×PS, 그 다음 D3 전체 L×PS
        _preflight_order = sorted(
            POWER_COMBOS,
            key=lambda c: (int(c.pcie_d), int(c.pcie_l), c.nvme_ps)
        )

        for i, combo in enumerate(_preflight_order):
            log.warning(f"  [{i+1:2d}/{len(_preflight_order)}] {combo.label} 진입 중...")
            t0 = time.monotonic()

            # 1. 상태 진입
            ok_set = True
            try:
                ok_set = self._set_power_combo(combo)
            except Exception as e:
                log.warning(f"    → _set_power_combo 예외: {e}")
                ok_set = False

            # 2. 정착 대기
            #    L1/L1.2 settle은 _set_pcie_l_state() 내부에서 이미 처리됨
            #    PS settle은 id-ctrl enlat/exlat 기반으로 동적 계산 (_init_ps_settle)
            settle = self._ps_settle.get(combo.nvme_ps, 0.05)
            if combo.pcie_d == PCIeDState.D3:
                settle += D3_EXTRA
            time.sleep(settle)

            # 3. PM 상태 다중 검증 (진입 직후, 복귀 전)
            #    - PMU getcurrent (pmu_4_1.py 3 1)
            #    - setpci PMCSR / LNKCTL / L1SSCTL1 readback
            #    - sysfs power_state
            verify = {}
            if ok_set:
                verify = self._pm_verify_combo(combo)
                log.warning(f"    [verify] PMU        : {verify.get('pmu', 'N/A')}")
                if 'nvme_ps' in verify:
                    log.warning(f"    [verify] NVMe PS    : {verify['nvme_ps']}")
                if 'd_state' in verify:
                    log.warning(f"    [verify] D-state(HW): {verify['d_state']}")
                if 'l_state_ep' in verify:
                    log.warning(f"    [verify] L-state EP : {verify['l_state_ep']}")
                if 'l_state_rp' in verify:
                    log.warning(f"    [verify] L-state RP : {verify['l_state_rp']}")
                if 'aspm_policy' in verify:
                    log.warning(f"    [verify] ASPM policy: {verify['aspm_policy']}")
                if 'lspci_lnkctl' in verify:
                    log.warning(f"    [verify] lspci      : {verify['lspci_lnkctl']}")
                if 'l1ss' in verify:
                    log.warning(f"    [verify] L1SS       : {verify['l1ss']}")

            # 4. PS0+L0+D0 복귀
            #    D3 포함 combo: D0 먼저(setpci) → Trst → L0 → PS0 순서 필수.
            #    L1.2+D0 combo: CLKREQ# assert(L0) 먼저 → PS0 나중.
            #      clock 없는 상태에서 NVMe SetFeature 먼저 보내면 hang 발생.
            ok_restore = True
            try:
                if combo.pcie_d == PCIeDState.D3:
                    ok_restore = self._pm_d3_safe_restore()
                    time.sleep(D3_RESTORE_SETTLE)
                elif combo.pcie_l == PCIeLState.L1_2:
                    if not self._set_pcie_l_state(PCIeLState.L0):  # CLKREQ# assert → clock 복원
                        log.warning("    → L0 복귀 실패 (CLKREQ# assert 실패)")
                        ok_restore = False
                    time.sleep(0.2)
                    if not self._pm_set_state(0):                  # clock 복원 후 PS0
                        log.warning("    → PS0 복귀 실패")
                        ok_restore = False
                    time.sleep(RESTORE_SETTLE)
                else:
                    if not self._set_power_combo(baseline):
                        log.warning("    → baseline 복귀 실패")
                        ok_restore = False
                    time.sleep(RESTORE_SETTLE)
            except Exception as e:
                log.warning(f"    → baseline 복귀 예외: {e}")
                ok_restore = False

            # 5. 복귀 검증 — PMU current + get-feature(PS0 확인)
            #    PMU: PS0 복귀 후 정상 전류 확인
            #    get-feature: PS0(0x00) 반환 여부 — MISMATCH면 이전 PS가 남아있는 것
            ok_nvme   = False
            rv_verify = {}
            if ok_restore:
                rv_verify = self._pm_verify_combo(baseline)
                rv_pmu = rv_verify.get('pmu', 'N/A')
                log.warning(f"    [restore] PMU       : {rv_pmu}")
                if 'nvme_ps' in rv_verify:
                    rv_ps = rv_verify['nvme_ps']
                    log.warning(f"    [restore] NVMe PS   : {rv_ps}")
                    if 'MISMATCH' in rv_ps:
                        log.warning(f"    → 복귀 실패: PS0으로 돌아오지 않음")
                        ok_restore = False
                # get-feature 성공 = NVMe 응답 정상
                ok_nvme = ('nvme_ps' in rv_verify and
                           'ERR' not in rv_verify['nvme_ps'] and
                           'FAIL' not in rv_verify['nvme_ps'])
            if not ok_nvme:
                # fallback: nvme id-ctrl 로 생존만 확인
                try:
                    r = subprocess.run(
                        ['nvme', 'id-ctrl', self.config.nvme_device],
                        timeout=PROBE_TIMEOUT,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    ok_nvme = (r.returncode == 0)
                except Exception as e:
                    log.warning(f"    → nvme id-ctrl 예외: {e}")

            elapsed  = time.monotonic() - t0
            # pmu 출력은 멀티라인 (CLI 경로 echo 포함) — 숫자만 있는 줄을 추출
            _pmu_raw = verify.get('pmu', 'N/A')
            pmu_val  = 'N/A'
            for _line in _pmu_raw.splitlines():
                _tok = _line.strip()
                if _tok and _tok.lstrip('-').replace('.', '', 1).isdigit():
                    pmu_val = _tok
                    break
            if pmu_val == 'N/A' and _pmu_raw not in ('N/A', ''):
                pmu_val = _pmu_raw.strip().splitlines()[-1].strip() or 'N/A'
            results.append((combo, ok_set, ok_restore, ok_nvme, elapsed, pmu_val))

            ok_all = ok_set and ok_restore and ok_nvme
            mark   = "OK  " if ok_all else "FAIL"
            log.warning(f"    → SET={'OK' if ok_set else 'FAIL'} "
                        f"RESTORE={'OK' if ok_restore else 'FAIL'} "
                        f"NVMe={'OK' if ok_nvme else 'FAIL'} "
                        f"[{mark}]  ({elapsed:.2f}s)")
            if not ok_all:
                failed_labels.append(combo.label)

        # 최종 baseline 복귀 보장
        try:
            self._pm_d3_safe_restore()
            time.sleep(D3_RESTORE_SETTLE)
        except Exception:
            pass

        log.warning("=" * 60)
        log.warning("[PM-Preflight] 결과 요약")
        log.warning(f"  {'Combo':<20} {'PMU(mA)':>9} {'SET':>5} {'RESTORE':>8} {'NVMe':>6} {'Time':>7}  ")
        log.warning("  " + "-" * 60)
        for combo, ok_set, ok_restore, ok_nvme, elapsed, pmu_val in results:
            mark = "✓" if (ok_set and ok_restore and ok_nvme) else "✗"
            log.warning(
                f"  {combo.label:<20} "
                f"{pmu_val:>9} "
                f"{'OK' if ok_set else 'FAIL':>5} "
                f"{'OK' if ok_restore else 'FAIL':>8} "
                f"{'OK' if ok_nvme else 'FAIL':>6} "
                f"{elapsed:>6.2f}s  {mark}")
        log.warning("  " + "-" * 60)
        passed = len(results) - len(failed_labels)
        log.warning(f"[PM-Preflight] 통과: {passed}/{len(POWER_COMBOS)}")
        if failed_labels:
            log.warning(f"[PM-Preflight] 실패 조합: {', '.join(failed_labels)}")
            log.warning("[PM-Preflight] 실패 조합은 퍼징 중 예상치 못한 동작 유발 가능 — 확인 권장")
        else:
            log.warning("[PM-Preflight] 모든 조합 정상 — PM 퍼징 준비 완료")
        log.warning("=" * 60)

        # 실패 조합이 있어도 fuzzing 계속 (abort하지 않음)
        return True

    def _pm_preflight_s1_s2(self) -> bool:
        """v7.7 S1/S2 preflight — 모든 PCIE_PM_FUZZ_TARGETS 비트 + CLKREQ_FUZZ_MODES
        를 1회씩 결정적으로 적용하여 NVMe 응답성 검증.
        POWER_COMBOS preflight 직후 호출. 실패해도 fuzzing 계속.
        """
        if not self._pcie_bdf or self._pcie_cap_offset is None:
            log.warning("[PM-Preflight S1/S2] PCIe BDF/cap 미탐지 — 스킵")
            return True

        log.warning("=" * 60)
        log.warning(f"[PM-Preflight S1/S2] PCIe bit {len(PCIE_PM_FUZZ_TARGETS)}개 + "
                    f"CLKREQ# {len(CLKREQ_FUZZ_MODES)}개 검증 시작")
        log.warning("=" * 60)

        results: list = []   # (label, status, elapsed) — status ∈ {'OK','FAIL','SKIP'}
        PROBE_TIMEOUT = 5.0

        def _nvme_alive() -> bool:
            """NVMe id-ctrl 로 controller 응답성 확인."""
            try:
                r = subprocess.run(
                    ['nvme', 'id-ctrl', self.config.nvme_device],
                    timeout=PROBE_TIMEOUT,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return r.returncode == 0
            except Exception:
                return False

        # ── S1: PCIe config bit 13개 ──────────────────────────────────────
        for i, target in enumerate(PCIE_PM_FUZZ_TARGETS):
            cap_name, off_in_cap, bit_lo, bit_w, name, constraint = target
            label = f"{cap_name}.{name}"
            log.warning(f"  S1 [{i+1:2d}/{len(PCIE_PM_FUZZ_TARGETS)}] {label}")
            t0 = time.monotonic()
            status = 'FAIL'

            try:
                if constraint == 'forced_one_shot':
                    # PMCSR D1/D2 forced slot — 진입 + 50ms + D0 복귀 자체 검증.
                    ok_p = self._pm_perturb_pmcsr_forced()
                    status = 'OK' if (ok_p and _nvme_alive()) else 'FAIL'
                else:
                    cap_base = self._pm_perturb_target_cap_offset(cap_name)
                    if cap_base is None:
                        status = 'SKIP'
                        log.warning(f"    → cap {cap_name!r} 미탐지, 스킵")
                    else:
                        abs_offset = cap_base + off_in_cap
                        width = 'l' if cap_name == 'l1ss' else 'w'
                        max_val = (1 << bit_w) - 1
                        # constraint 가 range dict 이면 max 적용, 아니면 전체 비트
                        if isinstance(constraint, dict):
                            hi = constraint.get('max', max_val)
                            test_val = hi & max_val
                        else:
                            test_val = max_val   # stress: 해당 필드 전체 1
                        mask = max_val << bit_lo
                        orig = self._setpci_read(self._pcie_bdf, abs_offset, width)
                        if orig is None:
                            status = 'SKIP'
                            log.warning("    → setpci_read 실패, 스킵")
                        else:
                            ok_w = self._setpci_write(
                                self._pcie_bdf, abs_offset,
                                (test_val << bit_lo) & mask, mask, width)
                            ok_alive = _nvme_alive() if ok_w else False
                            # 원복 — perturb 후 baseline 영향 없게.
                            self._setpci_write(
                                self._pcie_bdf, abs_offset,
                                orig & mask, mask, width)
                            status = 'OK' if (ok_w and ok_alive) else 'FAIL'
            except Exception as e:
                log.warning(f"    → 예외: {e}")

            elapsed = time.monotonic() - t0
            results.append(('S1', label, status, elapsed))
            log.warning(f"    → {status}  ({elapsed:.2f}s)")

        # ── S2: CLKREQ# timing 4 mode ─────────────────────────────────────
        for i, (mode_name, _params) in enumerate(CLKREQ_FUZZ_MODES):
            log.warning(f"  S2 [{i+1}/{len(CLKREQ_FUZZ_MODES)}] CLKREQ# {mode_name}")
            t0 = time.monotonic()
            status = 'FAIL'
            try:
                ok_p = self._pm_perturb_clkreq(mode=mode_name)
                status = 'OK' if (ok_p and _nvme_alive()) else 'FAIL'
            except Exception as e:
                log.warning(f"    → 예외: {e}")
            elapsed = time.monotonic() - t0
            results.append(('S2', f'clkreq.{mode_name}', status, elapsed))
            log.warning(f"    → {status}  ({elapsed:.2f}s)")

        # 결과 요약
        log.warning("=" * 60)
        log.warning("[PM-Preflight S1/S2] 결과 요약")
        log.warning(f"  {'Kind':<4} {'Target':<28} {'Status':>6} {'Time':>7}")
        log.warning("  " + "-" * 60)
        n_ok = n_fail = n_skip = 0
        for kind, label, status, elapsed in results:
            mark = {'OK':'✓', 'FAIL':'✗', 'SKIP':'-'}.get(status, '?')
            log.warning(f"  {kind:<4} {label:<28} {status:>6} {elapsed:>6.2f}s  {mark}")
            if status == 'OK':   n_ok   += 1
            elif status == 'FAIL': n_fail += 1
            else:                  n_skip += 1
        log.warning("  " + "-" * 60)
        log.warning(f"[PM-Preflight S1/S2] OK={n_ok}  FAIL={n_fail}  SKIP={n_skip}  "
                    f"(total {len(results)})")
        if n_fail > 0:
            log.warning("[PM-Preflight S1/S2] 실패 항목은 퍼징 중 attribution 어려울 수 있음 — 확인 권장")
        else:
            log.warning("[PM-Preflight S1/S2] 모든 perturbation 정상 — S1/S2 준비 완료")
        log.warning("=" * 60)
        return n_fail == 0

    # ------------------------------------------------------------------
    # v8.4: IO 워크로드 엔진
    #   fuzz IO_WL_FUZZ_GAP 명령마다 rc=0 보장 Write/Read IO_WL_BLOCK_SIZE 블록 주입.
    #   rc=0 경계는 Identify(nsze/mdts/lba) 런타임 자동 유도. 패턴은 round_robin.
    #   source='workload' 로 회계 → state 캡처 허용(C2 재사용), C1/C2 reward·MOpt 무오염.
    # ------------------------------------------------------------------

    _WL_READ_DISTURB_SPAN = 64   # read_disturb 가 hammer 하는 고정 LBA 창 (작게 = per-page read↑)

    def _io_workload_limits(self) -> dict:
        """워크로드 rc=0 경계를 device Identify 에서 유도(캐싱). nsze/lba/mdts → max LBA·max NLB."""
        lba  = self.config.nvme_lba_size or 512
        nsze = self._get_nsze()                       # 총 LBA 수
        mdts = self._get_mdts()                       # raw exponent (0=무제한)
        page = _PAGE_SIZE if _PAGE_SIZE else 4096      # MPSMIN 근사
        max_xfer = (1 << mdts) * page if (mdts and mdts > 0) else IO_WL_MDTS_FALLBACK
        max_xfer = min(max_xfer, 2 * 1024 * 1024)     # _send_nvme_command MAX_DATA_BUF 와 일치
        max_nlb  = max(0, max_xfer // lba - 1)         # 0-based
        lim = {
            'lba': lba, 'nsze': nsze, 'max_nlb': max_nlb,
            'working_set_lbas': max(1, int(nsze * IO_WL_WORKING_FRAC)),
            'hot_lbas':  max(1, IO_WL_HOT_WINDOW_B // lba),
        }
        self._wl_limits = lim
        return lim

    def _wl_rand_data(self, nbytes: int) -> bytes:
        """사전생성 랜덤 버퍼에서 슬라이스(dedup 회피 — 호출마다 offset 변경). per-cmd urandom 회피."""
        buf = self._wl_rand_buf
        if not buf:
            return os.urandom(nbytes)
        if nbytes <= len(buf):
            off = random.randint(0, len(buf) - nbytes)
            return buf[off:off + nbytes]
        return (buf * (nbytes // len(buf) + 1))[:nbytes]

    @staticmethod
    def _wl_clamp(slba: int, nlb: int, nsze: int) -> int:
        """SLBA + (NLB+1) <= nsze 보장 (rc=0)."""
        hi = nsze - 1 - nlb
        if hi <= 0:
            return 0
        return max(0, min(slba, hi))

    def _gen_workload_block(self, pattern: str, lim: dict) -> list:
        """패턴별 (op, slba, nlb) 리스트 생성. op in ('w','r'). 모두 in-range/in-MDTS → rc=0."""
        n     = IO_WL_BLOCK_SIZE
        nsze  = lim['nsze']
        big   = lim['max_nlb']          # 대량 write NLB
        small = 0                        # 단일 블록 (NLB=0)
        ws    = lim['working_set_lbas']
        hot   = lim['hot_lbas']
        clamp = self._wl_clamp
        cmds: list = []

        if pattern == 'seq_write':
            step = big + 1
            for _i in range(n):
                cmds.append(('w', clamp(self._wl_base, big, nsze), big))
                self._wl_base = (self._wl_base + step) % max(1, nsze)
        elif pattern == 'rand_write':
            for _i in range(n):
                cmds.append(('w', clamp(random.randint(0, max(0, nsze - 1)), small, nsze), small))
        elif pattern == 'overwrite_churn':
            base = self._wl_base % max(1, nsze)
            for _i in range(n):
                off = random.randint(0, max(0, ws - 1))
                cmds.append(('w', clamp(base + off, small, nsze), small))
            self._wl_base = (self._wl_base + ws) % max(1, nsze)
        elif pattern == 'hot_cold':
            for _i in range(n):
                if random.random() < 0.8:
                    s = random.randint(0, max(0, hot - 1))
                else:
                    s = random.randint(0, max(0, nsze - 1))
                cmds.append(('w', clamp(s, small, nsze), small))
        elif pattern == 'read_disturb':
            span = min(self._WL_READ_DISTURB_SPAN, max(1, nsze))
            for i in range(n):
                cmds.append(('r', clamp(i % span, small, nsze), small))
        elif pattern == 'pingpong_write':
            a = 0
            b = clamp(nsze // 2, big, nsze)
            for i in range(n):
                cmds.append(('w', clamp(a if i % 2 == 0 else b, big, nsze), big))
        elif pattern == 'pingpong_read':
            a = 0
            b = clamp(nsze // 2, small, nsze)
            for i in range(n):
                cmds.append(('r', a if i % 2 == 0 else b, small))
        elif pattern == 'subpage_rmw':
            for _i in range(n):
                cmds.append(('w', clamp(random.randint(0, max(0, nsze - 1)), small, nsze), small))
        elif pattern == 'single_lba_hammer':
            target = clamp(self._wl_base % max(1, nsze), small, nsze)
            for _i in range(n):
                cmds.append(('w', target, small))
        elif pattern == 'strided_write':
            for i in range(n):
                cmds.append(('w', clamp(self._wl_base + (i % IO_WL_STRIDE_LBAS), small, nsze), small))
            self._wl_base = (self._wl_base + IO_WL_STRIDE_LBAS) % max(1, nsze)
        elif pattern == 'reverse_seq':
            step = big + 1
            base = clamp(self._wl_base, big, nsze)
            for i in range(n):
                cmds.append(('w', clamp(base - i * step, big, nsze), big))
            self._wl_base = (self._wl_base + n * step) % max(1, nsze)
        elif pattern == 'boundary':
            edges = [0, max(0, nsze - 1), nsze // 2]
            for i in range(n):
                cmds.append(('w', clamp(edges[i % len(edges)], small, nsze), small))
        elif pattern == 'bursty_mixed_size':
            for i in range(n):
                nlb = big if i % 2 == 0 else small
                cmds.append(('w', clamp(random.randint(0, max(0, nsze - 1)), nlb, nsze), nlb))
        elif pattern == 'mixed_rw':
            for _i in range(n):
                op  = 'w' if random.random() < 0.5 else 'r'
                nlb = random.choice([small, big])
                cmds.append((op, clamp(random.randint(0, max(0, nsze - 1)), nlb, nsze), nlb))
        else:
            # 미지원/trim 미구현 → rand_write fallback (rc=0 유지)
            for _i in range(n):
                cmds.append(('w', clamp(random.randint(0, max(0, nsze - 1)), small, nsze), small))
        return cmds

    def _wl_send_one(self, op: str, slba: int, nlb: int, lba: int) -> int:
        """워크로드 단일 명령 전송 + 회계(source='workload'). 반환 rc."""
        cmd_obj = self._wl_write_cmd if op == 'w' else self._wl_read_cmd
        data = self._wl_rand_data((nlb + 1) * lba) if op == 'w' else b''
        seed = Seed(
            data=data, cmd=cmd_obj,
            cdw10=slba & 0xFFFFFFFF, cdw11=(slba >> 32) & 0xFFFFFFFF,
            cdw12=nlb & 0xFFFF, found_at=self.executions,
        )
        self._current_mutations = []   # MOpt 무오염
        rc = self._send_nvme_command(data, seed, record_history=True)
        last_samples = self.sampler.stop_sampling()
        _i, _np, _action = self._account_command(seed, data, rc, last_samples, source='workload')
        return rc if _action != 'break' else self.RC_TIMEOUT

    def _wl_prewrite_read_targets(self, lim: dict, pattern: str) -> None:
        """read_disturb/pingpong_read 의 read 타겟을 1회 write 해 mapped 상태로 만든다.
        unmapped read 의 zero-page 단축 응답으로 NAND 미접근 → disturb 0 방지."""
        nsze = lim['nsze']
        if pattern == 'pingpong_read':
            targets = [(0, 1), (min(nsze // 2, max(0, nsze - 1)), 1)]
        else:  # read_disturb
            targets = [(0, min(self._WL_READ_DISTURB_SPAN, max(1, nsze)))]
        for base, span in targets:
            covered = 0
            while covered < span:
                this = min(lim['max_nlb'] + 1, span - covered)
                slba = base + covered
                if slba + this > nsze:
                    break
                if self._wl_send_one('w', slba, this - 1, lim['lba']) == self.RC_TIMEOUT:
                    return
                covered += this
        log.info(f"[IO-WL] read 타겟 pre-write 완료 (pattern={pattern})")

    def _run_io_workload_block(self) -> None:
        """fuzz 사이에 주입되는 워크로드 블록 1개 실행 (IO_WL_BLOCK_SIZE 명령)."""
        if self._wl_write_cmd is None or self._wl_read_cmd is None or not IO_WL_PATTERNS:
            return
        lim = self._io_workload_limits()
        if lim['nsze'] <= 1:
            log.warning("[IO-WL] nsze 비정상 — 워크로드 블록 skip")
            return
        # PM non-operational(D3/L1.2) 상태면 명령 전 복귀 (hang 방지) — 기존 헬퍼 재사용
        if self.config.pm_inject_prob > 0 and self._is_nonop_combo(self._current_combo):
            restored = self._nonop_restore(self._current_combo)
            self._current_combo = restored
            self._current_ps    = restored.nvme_ps
        # 패턴 선택
        if IO_WL_SELECTION == 'round_robin':
            pattern = IO_WL_PATTERNS[self._wl_pattern_idx % len(IO_WL_PATTERNS)]
            self._wl_pattern_idx += 1
        else:
            pattern = random.choice(IO_WL_PATTERNS)
        self._wl_active_pattern = pattern
        # overwrite_churn 가드: 드라이브 안 찼으면 GC 미발생 경고
        if pattern == 'overwrite_churn' and not self.config.prefill:
            log.warning("[IO-WL] overwrite_churn — prefill off → GC 미발생 가능 (--prefill 권장)")
        # read 패턴: 타겟 1회 pre-write (prefill 이면 이미 mapped → skip)
        if (pattern in ('read_disturb', 'pingpong_read')
                and not self.config.prefill and not self._wl_read_target_written):
            self._wl_prewrite_read_targets(lim, pattern)
            self._wl_read_target_written = True

        cmds = self._gen_workload_block(pattern, lim)
        n_ok = 0
        for (op, slba, nlb) in cmds:
            if self._timeout_crash:
                break
            if self._wl_send_one(op, slba, nlb, lim['lba']) == 0:
                n_ok += 1
            if self._timeout_crash:
                break
        self._wl_blocks_done += 1
        self._wl_active_pattern = None
        log.warning(f"[IO-WL] block#{self._wl_blocks_done} pattern={pattern} "
                    f"cmds={len(cmds)} rc0={n_ok} max_nlb={lim['max_nlb']} nsze={lim['nsze']:,}")

    # NVMe CQE Status Code Type (SCT, bits[10:8]) → 이름. SC(bits[7:0])는 nvme-cli stderr 의
    # 이름 문자열을 그대로 사용(자체 테이블 유지 불필요).
    _SCT_NAMES = {0: 'Generic', 1: 'CmdSpecific', 2: 'Media/DataIntegrity',
                  3: 'Path', 7: 'Vendor'}

    @staticmethod
    def _parse_nvme_status(text: str):
        """nvme-cli stderr 에서 'NVMe status: <NAME>(0xVAL)' 의 full status·이름 추출.
        exit code(rc)는 8비트 절단으로 SC 만 남지만, stderr 는 SCT 포함 full status 를 담는다.
        반환 (full_status:int, name:str) 또는 None."""
        if not text:
            return None
        m = re.search(r'NVMe status:\s*([^\n(]*?)\s*\(\s*0x([0-9a-fA-F]+)\s*\)',
                      text, re.IGNORECASE)
        if not m:
            return None
        name = m.group(1).strip().split(':')[0].strip()   # 'NAME: 설명' → 'NAME'
        return int(m.group(2), 16), name

    def _fmt_nvme_status(self, stderr_text: str) -> str:
        """rc 옆에 붙일 ' status=0x.. SCT=..(..) SC=0x.. [NAME]' 문자열. 없으면 ''."""
        st = self._parse_nvme_status(stderr_text)
        if st is None:
            return ""
        full, name = st
        sc  = full & 0xFF
        sct = (full >> 8) & 0x7
        flags = ''.join(f for b, f in ((14, ' DNR'), (13, ' More')) if (full >> b) & 1)
        return (f" status=0x{full:04x} SCT={sct}({self._SCT_NAMES.get(sct, '?')}) "
                f"SC=0x{sc:02x}{flags} [{name}]")

    def _send_nvme_command(self, data: bytes, seed: Seed,
                           record_history: bool = True) -> int:
        """subprocess(nvme-cli) 기반 NVMe passthru 명령 전송.
        반환값:
          >= 0: nvme-cli returncode (0=성공, 양수=NVMe 에러)
          RC_TIMEOUT(-1001): NVMe 타임아웃
          RC_ERROR(-1002): 내부 에러
        record_history=False: replay 경로에서 _cmd_history를 오염시키지 않을 때 사용.
        """
        cmd = seed.cmd
        MAX_DATA_BUF = 2 * 1024 * 1024  # 2MB 상한

        # --- override 필드 적용 ---
        actual_opcode = seed.opcode_override if seed.opcode_override is not None else cmd.opcode
        actual_nsid = seed.nsid_override if seed.nsid_override is not None else (
            self.config.nvme_namespace if cmd.needs_namespace else 0
        )

        # --- passthru 타입 결정 (admin vs io) ---
        if seed.force_admin is not None:
            passthru_type = "admin-passthru" if seed.force_admin else "io-passthru"
        else:
            passthru_type = "admin-passthru" if cmd.cmd_type == NVMeCommandType.ADMIN else "io-passthru"

        # 가성 불량 방지 가드: host(kernel) 소유 전송로를 깨는 admin opcode 는 전송하지 않는다.
        # (Delete/Create I/O SQ·CQ, AER, Doorbell Buffer Config — admin 일 때만. IO 동명령은 정상)
        # mutation/seed/replay/sequence 모든 경로가 여기를 지나므로 단일 chokepoint.
        if passthru_type == "admin-passthru" and actual_opcode in BLOCKED_ADMIN_OPCODES:
            log.warning(f"[GUARD] admin opcode 0x{actual_opcode:02x} 전송 차단 — "
                        f"가성 timeout 방지 (cmd={cmd.name})")
            self.stats['blocked_admin_opcode'] = self.stats.get('blocked_admin_opcode', 0) + 1
            return self.RC_SKIP

        # device 잠금 방지 가드: SecuritySend(0x81) 의 SECP(CDW10[31:24])가 잠금성
        # 프로토콜(예: 0xEF ATA Security SET PASSWORD)이면 전송 차단. 보내면 password 가
        # 설정돼 host I/O 가 잠기고 후속 명령 전부 실패(영구적 가성 불량). mutation 으로
        # opcode 가 0x81 로 바뀐 경우도 actual_opcode 로 잡힌다 — 단일 chokepoint.
        if (passthru_type == "admin-passthru"
                and actual_opcode == _SECURITY_SEND_OPCODE
                and ((seed.cdw10 >> 24) & 0xFF) in BLOCKED_SECURITY_SEND_SECP):
            _secp = (seed.cdw10 >> 24) & 0xFF
            log.warning(f"[GUARD] SecuritySend SECP=0x{_secp:02x} 전송 차단 — "
                        f"device 잠금 방지 (cdw10=0x{seed.cdw10:08x})")
            self.stats['blocked_security_send'] = self.stats.get('blocked_security_send', 0) + 1
            return self.RC_SKIP

        # NamespaceManagement Delete(SEL=1) 차단 — namespace 영구 파괴(복구 어려움, 상단 상수 참조).
        if (passthru_type == "admin-passthru" and BLOCK_NS_DELETE
                and actual_opcode == _NS_MGMT_OPCODE and (seed.cdw10 & 0xF) == 1):
            log.warning(f"[GUARD] NamespaceManagement Delete(SEL=1) 전송 차단 — "
                        f"namespace 파괴 방지 (nsid={actual_nsid} cdw10=0x{seed.cdw10:08x})")
            self.stats['blocked_ns_delete'] = self.stats.get('blocked_ns_delete', 0) + 1
            return self.RC_SKIP

        # Admin 명령어별 고정 응답 크기
        ADMIN_FIXED_RESPONSE = {
            "Identify": 4096,
            "GetFeatures": 4096,
            "TelemetryHostInitiated": 4096,
            "DeviceSelfTest": 0,       # 데이터 전송 없음
        }

        # IO 명령어 중 NLB 기반 data_len 계산을 생략할 명령어
        # (데이터 전송 자체가 없거나 별도 처리하는 명령어)
        IO_NO_NLB_DATA = ("Flush", "DatasetManagement",
                          "WriteZeroes", "WriteUncorrectable", "Verify")

        # --- data_len 결정 ---
        data_len = 0
        write_data = False  # 호스트→SSD 데이터 전송 여부

        if seed.data_len_override is not None:
            data_len = min(max(0, seed.data_len_override), MAX_DATA_BUF)
            if cmd.needs_data and data:
                write_data = True
        elif cmd.needs_data and data:
            data_len = len(data)
            write_data = True
        elif cmd.cmd_type == NVMeCommandType.IO and cmd.name not in IO_NO_NLB_DATA:
            # Read / Compare / Write 계열: CDW12[15:0] = NLB → 전송 크기 산출
            # nvme_lba_size는 run() 시작 시 blockdev --getss 로 자동 감지 (기본 512)
            _lba_sz = self.config.nvme_lba_size or 512
            nlb = seed.cdw12 & 0xFFFF
            data_len = min(max(_lba_sz, (nlb + 1) * _lba_sz), MAX_DATA_BUF)
        elif cmd.name == "GetLogPage":
            numdl = (seed.cdw10 >> 16) & 0x7FF
            data_len = min(max(4, (numdl + 1) * 4), MAX_DATA_BUF)
        elif cmd.name == "SecurityReceive":
            # CDW11 = AL (Allocation Length, bytes)
            data_len = min(max(512, seed.cdw11), MAX_DATA_BUF)
        elif cmd.name == "GetLBAStatus":
            # CDW12 = MNDW (Max Number of Dwords, 0-based) → bytes = (MNDW+1)*4
            data_len = min(max(8, (seed.cdw12 + 1) * 4), MAX_DATA_BUF)
        elif cmd.name in ADMIN_FIXED_RESPONSE:
            data_len = ADMIN_FIXED_RESPONSE[cmd.name]

        # --- 입력 데이터 파일 준비 (Write 계열) ---
        input_file = None
        if write_data and data_len > 0:
            if self._nvme_input_path is None:
                self._nvme_input_path = str(self.output_dir / '.nvme_input.bin')
            with open(self._nvme_input_path, 'wb') as f:
                if seed.data_len_override is not None:
                    f.write(data[:data_len].ljust(data_len, b'\x00'))
                else:
                    # LBA 크기와 data 길이가 불일치하면 data_len에 맞게 조정
                    # (예: Write 시드가 512B 고정인데 LBA=4096인 경우 패딩)
                    f.write(data[:data_len].ljust(data_len, b'\x00'))
            input_file = self._nvme_input_path

        # --- 타임아웃 --- (퍼저가 "crash"로 판단하는 창)
        # mutation 으로 실제 전송 opcode/타입이 바뀌면 원본 timeout_group 무효 →
        # 실제 (opcode, 타입) 명령으로 재해석. 미지 opcode 는 'command' 기본값.
        actual_type_val = "admin" if passthru_type == "admin-passthru" else "io"
        if (actual_opcode, actual_type_val) == (cmd.opcode, cmd.cmd_type.value):
            eff_cmd = cmd
        else:
            eff_cmd = _OPCODE_TO_CMD.get((actual_opcode, actual_type_val))
        effective_tg = eff_cmd.timeout_group if eff_cmd is not None else "command"
        # DeviceSelfTest: CDW10[3:0] STC 값으로 Short(0x1)/Extended(0x2) 구분
        if eff_cmd is not None and eff_cmd.name == "DeviceSelfTest":
            stc = seed.cdw10 & 0xF  # CDW10[3:0]
            if stc == 0x2:
                effective_tg = "selftest_ext"
            else:
                effective_tg = "selftest_short"  # 0x1 또는 기타 → short 기본값
        timeout_ms = self.config.nvme_timeouts.get(
            effective_tg,
            self.config.nvme_timeouts.get('command', 8000)
        )
        # PS entry/exit latency 마진: 어떤 PS 상태에서든 복귀 지연을 흡수
        timeout_ms += PS_ENTRY_EXIT_MARGIN_MS
        # nvme-cli --timeout: 커널이 NVMe 명령을 포기하는 시점 (v4.6: 분리)
        # 이 값을 길게 유지하면 crash 시 커널이 controller reset을 하지 않아
        # SSD 펌웨어 상태를 그대로 보존할 수 있다 (JTAG 분석 용이).
        passthru_timeout_ms = self.config.nvme_passthru_timeout_ms

        # --- nvme CLI 명령 구성 ---
        # io-passthru를 char device(/dev/nvme0)에 보내면
        # "using deprecated NVME_IOCTL_IO_CMD ioctl on the char device!" 경고 발생.
        # IO 명령은 namespace block device(/dev/nvme0n1)를 사용해야 한다.
        # Admin 명령은 char device 그대로 사용.
        if passthru_type == "io-passthru":
            target_device = self._io_device()
        else:
            target_device = self.config.nvme_device

        nvme_cmd = [
            'nvme', passthru_type, target_device,
            f'--opcode={actual_opcode:#x}',
            f'--namespace-id={actual_nsid}',
            f'--cdw2={seed.cdw2:#x}',
            f'--cdw3={seed.cdw3:#x}',
            f'--cdw10={seed.cdw10:#x}',
            f'--cdw11={seed.cdw11:#x}',
            f'--cdw12={seed.cdw12:#x}',
            f'--cdw13={seed.cdw13:#x}',
            f'--cdw14={seed.cdw14:#x}',
            f'--cdw15={seed.cdw15:#x}',
            f'--timeout={passthru_timeout_ms}',
        ]

        if data_len > 0:
            nvme_cmd.append(f'--data-len={data_len}')
            if input_file:
                nvme_cmd.extend([f'--input-file={input_file}', '-w'])
            else:
                nvme_cmd.append('-r')

        # 재현 TC 히스토리 기록 (crash 시 replay .sh 생성에 사용)
        # replay 경로(record_history=False)에서는 _cmd_history를 오염시키지 않음.
        if record_history:
            self._cmd_history.append({
                'kind': 'nvme',
                'label': cmd.name,
                'passthru_type': passthru_type,
                'device': target_device,
                'opcode': actual_opcode,
                'nsid': actual_nsid,
                'cdw2': seed.cdw2, 'cdw3': seed.cdw3,
                'cdw10': seed.cdw10, 'cdw11': seed.cdw11,
                'cdw12': seed.cdw12, 'cdw13': seed.cdw13,
                'cdw14': seed.cdw14, 'cdw15': seed.cdw15,
                'data': bytes(data[:data_len]) if (write_data and data_len > 0 and data) else None,
                'data_len': data_len,
                'is_write': bool(write_data and data_len > 0),
            })

        # 로그: mutation된 필드는 별도 표시
        mut_flags = []
        if seed.opcode_override is not None:
            mut_flags.append(f"opcode=0x{actual_opcode:02x}(was 0x{cmd.opcode:02x})")
        if seed.nsid_override is not None:
            mut_flags.append(f"nsid=0x{actual_nsid:x}(mut)")
        if seed.force_admin is not None:
            mut_flags.append(f"force_{'admin' if seed.force_admin else 'io'}")
        if seed.data_len_override is not None:
            mut_flags.append(f"data_len={data_len}(override)")
        mut_str = f" MUT[{','.join(mut_flags)}]" if mut_flags else ""

        log.info(f"[NVMe] {passthru_type} {cmd.name} opcode=0x{actual_opcode:02x} "
                 f"nsid={actual_nsid} timeout={timeout_ms}ms({effective_tg}) "
                 f"cdw10=0x{seed.cdw10:08x} cdw11=0x{seed.cdw11:08x} "
                 f"cdw12=0x{seed.cdw12:08x} data_len={data_len}"
                 f" data={data[:16].hex() if data else 'N/A'}"
                 f"{'...' if data and len(data) > 16 else ''}"
                 f"{mut_str}")

        # "덫 놓기" 전략: subprocess 전에 샘플링 시작
        # NOTE: stop_sampling()은 메인 루프(run)에서 호출 — 여기서는 하지 않음
        self.sampler.start_sampling()

        process = None
        try:
            process = subprocess.Popen(
                nvme_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,  # v4.6: setsid() — 부모 종료/SIGHUP 후에도 생존
            )

            # subprocess 타임아웃 = NVMe 타임아웃 + 여유 2초
            timeout_sec = timeout_ms / 1000.0 + 2.0
            try:
                stdout, stderr = process.communicate(timeout=timeout_sec)
            except subprocess.TimeoutExpired:
                # kill → fd 닫힘 → 커널 abort → controller reset → SSD 상태 소멸.
                # nvme-cli를 살려두면 fd가 유지되어 커널은 --timeout(30일)까지 대기.
                # → SSD 펌웨어 상태가 장기간 보존됨.
                #
                # nvme-cli는 D-state(ioctl 대기)이므로 stdout/stderr에 쓰지 않음.
                # 파이프 부모 쪽만 닫아 나중에 SIGPIPE로 조용히 처리.
                try:
                    if process.stdout:
                        process.stdout.close()
                    if process.stderr:
                        process.stderr.close()
                except OSError:
                    pass
                self._crash_nvme_pid = process.pid
                log.warning(f"[NVMe TIMEOUT] {cmd.name} (>{timeout_sec:.0f}s) "
                            f"— nvme-cli PID={process.pid} 보존 (fd 유지 → SSD 상태 보존)")
                return self.RC_TIMEOUT

            rc = process.returncode

            # SSD 내부에서 명령 완료 후에도 후처리(캐시 플러시, 로그 기록 등)가
            # 진행될 수 있으므로, 해당 시간만큼 샘플링을 계속 유지
            if self.config.post_cmd_delay_ms > 0:
                time.sleep(self.config.post_cmd_delay_ms / 1000.0)

            # rc(exit code)는 SC 하위 8비트만 → 추가 정보 출력.
            #  · NVMe 완료 에러: stderr/stdout 의 'NVMe status: NAME(0xVAL)' → full status(SCT 포함).
            #  · errno/내부 실패(예: rc=1 Invalid argument, NVMe 제출 전 거부): status 없음 →
            #    stderr 원문 일부를 대신 표시(rc=1 이 SC=0x01 인지 errno 인지 구분됨).
            _status_info = ""
            if rc > 0:
                _err_txt = stderr.decode(errors='replace') if stderr else ""
                _out_txt = stdout.decode(errors='replace') if stdout else ""
                _status_info = (self._fmt_nvme_status(_err_txt)
                                or self._fmt_nvme_status(_out_txt))
                if not _status_info:
                    _raw = [l for l in (_err_txt or _out_txt).splitlines() if l.strip()]
                    _status_info = (f" msg=\"{_raw[0].strip()[:120]}\"" if _raw
                                    else " (NVMe status 없음 — errno/내부 실패)")
            log.info(f"[NVMe RET] rc={rc}{_status_info}")

            # Detach(SEL=1) 성공 시 즉시 재부착 — NS 보존이라 inverse(Attach)로 device 복구.
            if (AUTO_REATTACH_NS and rc == 0 and passthru_type == "admin-passthru"
                    and actual_opcode == _NS_ATTACH_OPCODE and (seed.cdw10 & 0xF) == 1):
                self._reattach_namespace(actual_nsid)

            return rc

        except KeyboardInterrupt:
            if process:
                try:
                    process.kill()
                    process.communicate(timeout=2)
                except Exception:
                    pass
            raise

        except Exception as e:
            log.error(f"NVMe subprocess error ({cmd.name}): {e}")
            if process:
                try:
                    process.kill()
                    process.communicate(timeout=2)
                except Exception:
                    pass
            return self.RC_ERROR

    def _seed_meta(self, seed: Seed) -> dict:
        """Seed의 전체 메타데이터를 dict로 반환 (재현용)"""
        meta = {
            "command": seed.cmd.name,
            "opcode": hex(seed.cmd.opcode),
            "type": seed.cmd.cmd_type.value,
            "cdw2": seed.cdw2, "cdw3": seed.cdw3,
            "cdw10": seed.cdw10, "cdw11": seed.cdw11,
            "cdw12": seed.cdw12, "cdw13": seed.cdw13,
            "cdw14": seed.cdw14, "cdw15": seed.cdw15,
        }
        # 확장 mutation 필드 (None이 아닌 경우만 기록)
        if seed.opcode_override is not None:
            meta["opcode_override"] = hex(seed.opcode_override)
        if seed.nsid_override is not None:
            meta["nsid_override"] = hex(seed.nsid_override)
        if seed.force_admin is not None:
            meta["force_admin"] = seed.force_admin
        if seed.data_len_override is not None:
            meta["data_len_override"] = seed.data_len_override
        return meta

    def _configure_nvme_timeouts(self) -> None:
        """nvme_core admin/io_timeout 을 크게 설정 → crash 후 커널 reset 유예."""
        params = [
            '/sys/module/nvme_core/parameters/admin_timeout',
            '/sys/module/nvme_core/parameters/io_timeout',
        ]
        value = self.config.nvme_kernel_timeout_sec
        for path in params:
            p = Path(path)
            if not p.exists():
                log.warning(f"[TimeoutCfg] {path} 없음 — 건너뜀")
                continue
            try:
                original = p.read_text().strip()
                p.write_text(str(value))
                self._nvme_timeout_originals[path] = original
                log.warning(f"[TimeoutCfg] {path}: {original}s → {value}s")
            except PermissionError:
                log.warning(f"[TimeoutCfg] {path} 쓰기 권한 없음 — root 필요")
            except OSError as e:
                log.warning(f"[TimeoutCfg] {path} 설정 실패: {e}")

        if self._nvme_timeout_originals:
            log.warning(
                f"[TimeoutCfg] crash 발생 시 커널 reset까지 최대 {value}초 유예 "
                f"(단, 현재 in-flight AER는 기존 timeout 유지)")

    def _restore_nvme_timeouts(self) -> None:
        """퍼저 종료 시 nvme_core 타임아웃 파라미터를 원래 값으로 복원한다."""
        for path, original in self._nvme_timeout_originals.items():
            try:
                Path(path).write_text(original)
                log.warning(f"[TimeoutCfg] {path} 복원: {original}s")
            except OSError as e:
                log.warning(f"[TimeoutCfg] {path} 복원 실패: {e}")

    def _get_nvme_pcie_bus(self) -> Optional[str]:
        """NVMe PCIe bus 번호 탐지 (sysfs → lspci fallback). 실패 시 None."""
        import re as _re
        dev_name = os.path.basename(self.config.nvme_device)  # e.g. "nvme0" or "nvme0n1"
        log.warning(f"[UFAS] PCIe bus 탐지 시작: nvme_device={self.config.nvme_device}")
        m = _re.match(r'(nvme\d+)', dev_name)
        if m:
            ctrl = m.group(1)  # "nvme0"
            addr_file = f'/sys/class/nvme/{ctrl}/address'
            log.warning(f"[UFAS] sysfs 경로 시도: {addr_file}")
            try:
                addr = Path(addr_file).read_text().strip()  # e.g. "0000:01:00.0"
                parts = addr.split(':')
                if len(parts) >= 3:
                    # sysfs/lspci 의 bus 는 hex(예 "81"=0x81). ufas 인자는 decimal 기대 →
                    # hex→decimal 변환("81"→"129"). 0x01 은 hex/dec 동일해 기존 01:00.0 무영향.
                    bus = str(int(parts[-2], 16))
                    log.warning(f"[UFAS] sysfs 탐지 성공: {addr} → bus={bus} (0x{parts[-2]})")
                    return bus
                else:
                    log.warning(f"[UFAS] sysfs 주소 형식 이상: '{addr}' — lspci fallback")
            except Exception as e:
                log.warning(f"[UFAS] sysfs read 실패: {e} — lspci fallback")
        else:
            log.warning(f"[UFAS] 디바이스명에서 nvme 컨트롤러 파싱 실패: '{dev_name}' — lspci fallback")

        # fallback: lspci
        log.warning("[UFAS] lspci로 NVMe 장치 탐색 중...")
        try:
            result = subprocess.run(['lspci'], capture_output=True, text=True, timeout=5)
            nvme_lines = [l for l in result.stdout.splitlines()
                          if 'nvme' in l.lower() or 'non-volatile' in l.lower()]
            if nvme_lines:
                log.warning(f"[UFAS] lspci NVMe 장치 목록:")
                for line in nvme_lines:
                    log.warning(f"  {line.strip()}")
                bus_hex = nvme_lines[0].split(':')[0]
                bus = str(int(bus_hex, 16))   # hex→decimal (sysfs 경로와 동일 규칙)
                log.warning(f"[UFAS] lspci 탐지 성공: bus={bus} (0x{bus_hex})")
                return bus
            else:
                log.warning("[UFAS] lspci에서 NVMe 장치를 찾지 못함")
        except Exception as e:
            log.warning(f"[UFAS] lspci 실행 실패: {e}")

        log.warning("[UFAS] PCIe bus 번호 자동 탐지 실패 — UFAS 덤프 건너뜀")
        return None

    def _shutdown_openocd_for_jlink(self) -> None:
        """OpenOCD를 정상 shutdown 하여 J-Link USB 점유를 해제한다.

        shutdown 없이 process kill만 하면 libjaylink가 USB를 잠근 채 종료되어
        후속 JLinkExe 호출(메모리 덤프, PC 모니터링)이 실패한다.

        멱등 동작: 호출 시점의 OpenOCD 살아있음 여부 (sampler._openocd_alive())
        기준으로 판단. 이전 _openocd_shutdown_done flag 방식은 recovery 후 OpenOCD
        가 재시작되어도 reset 안 되어 두 번째 J-Link dump 가 OpenOCD 와 USB 충돌
        하는 버그가 있었음 — flag 제거.
        """
        sampler = self.sampler
        # v8.1: J-Link halt 샘플러(P9)는 pylink 가 USB 를 in-process 점유 — OpenOCD 가 없으므로
        # shutdown 대상도 없고, JLinkExe 핸드오프도 안 함(stuck PC 는 sampler 경유로 읽음).
        if isinstance(sampler, JLinkHaltSampler):
            return
        if not sampler._openocd_alive():
            log.info("[JLINK] OpenOCD 이미 종료 상태 — shutdown 생략")
            return
        log.warning("[JLINK] OpenOCD shutdown (J-Link USB 해제)...")
        if sampler._sock:
            try:
                sampler._sock.sendall(b'shutdown\n')
                time.sleep(1.5)
            except Exception:
                pass
        sampler._close_telnet()
        sampler._terminate_proc()
        log.warning("[JLINK] OpenOCD 종료 완료")

    def _run_jlink_dump(self) -> None:
        """crash 발생 시 JLink 메모리 덤프를 실행한다.

        실행 파일: fuzzer 스크립트와 같은 디렉토리의 ./run_smi_mem_dump_JLINK_USB.sh
        호출 전에 _shutdown_openocd_for_jlink() 로 J-Link 점유가 해제되어 있어야 한다
        (timeout crash 핸들러가 항상 먼저 호출함).
        """
        TIMEOUT = 300   # 5분

        # 방어적 — caller가 누락한 경우 대비.
        self._shutdown_openocd_for_jlink()

        script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        sh_path = os.path.join(script_dir, JLINK_DUMP_SCRIPT)

        if not os.path.isfile(sh_path):
            log.warning("[JLINK DUMP] 스크립트 없음 — 건너뜀")
            return
        if not os.access(sh_path, os.X_OK):
            log.warning("[JLINK DUMP] 실행 권한 없음 (chmod +x 필요) — 건너뜀")
            return

        # 시분초까지 포함된 timestamp 를 env var + argv 양쪽으로 전달.
        # shell script 측에서 ${DUMP_TIMESTAMP} 또는 "$1" 으로 받아 dump 파일명에 반영하면
        # 동일 일자 다중 crash 시 파일 덮어쓰기 방지.
        ts_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        cmd = ['bash', sh_path, ts_str]
        env = os.environ.copy()
        env['DUMP_TIMESTAMP'] = ts_str
        log.warning(f"[JLINK DUMP] 실행: {sh_path} (DUMP_TIMESTAMP={ts_str})")

        try:
            proc = subprocess.Popen(
                cmd, cwd=script_dir, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
            )
        except Exception as e:
            log.warning(f"[JLINK DUMP] Popen 실패: {e}")
            return

        log.warning(f"[JLINK DUMP] PID={proc.pid} — 최대 {TIMEOUT}초 대기")

        import threading
        _result: dict = {}

        def _communicate():
            try:
                out, err = proc.communicate()
                _result['stdout'] = out
                _result['stderr'] = err
                _result['rc'] = proc.returncode
            except Exception as ex:
                _result['error'] = ex

        t = threading.Thread(target=_communicate, daemon=True)
        t.start()

        POLL_INTERVAL = 30
        waited = 0
        while waited < TIMEOUT:
            t.join(timeout=POLL_INTERVAL)
            if not t.is_alive():
                break
            waited += POLL_INTERVAL
            log.warning(f"[JLINK DUMP] 진행 중... {waited}s 경과")

        if t.is_alive():
            log.warning(f"[JLINK DUMP] {TIMEOUT}초 timeout — SIGKILL (PID={proc.pid})")
            try:
                proc.kill()
            except Exception:
                pass
            t.join(timeout=5)
            # bash를 SIGKILL로 종료하면 자식 JLinkExe가 고아로 남아 USB를 점유할 수 있음.
            # 여기서만 pkill — rc!=0 정상 종료 경로는 JLinkExe가 이미 종료된 상태.
            try:
                subprocess.run(['pkill', '-9', '-x', JLINK_BINARY],
                               capture_output=True, timeout=5)
            except Exception:
                pass
            return

        if 'error' in _result:
            log.warning(f"[JLINK DUMP] 오류: {_result['error']}")
            return

        rc = _result.get('rc', -1)
        out = _result.get('stdout', b'').decode(errors='replace').strip()
        err = _result.get('stderr', b'').decode(errors='replace').strip()
        # 길고 verbose 한 JLinkExe 출력은 파일 로그에만 (INFO) — 터미널은 summary 만.
        if out:
            log.info(f"[JLINK DUMP] stdout:\n{out}")
        if err:
            log.info(f"[JLINK DUMP] stderr:\n{err}")
        log.warning(f"[JLINK DUMP] 완료 (rc={rc})")

    # ──────────────────────────────────────────────────────────────────
    # v7.8: EngineErrInt 기반 미지원 명령 자동 skip
    # ──────────────────────────────────────────────────────────────────

    def _find_latest_jlink_dump(self, script_dir: str,
                                 after_t: float) -> Optional[str]:
        """script_dir 안 mtime ≥ (after_t - 5초) 인 .bin 중 가장 최근 1개. 없으면 None.
        after_t = time.time() 의 Unix epoch (st_mtime 과 동일 도메인).
        .zip / .txt 는 제외 (parser 가 sibling 으로 함께 생성하지만 dump 본체는 .bin).
        """
        cand: list = []
        try:
            for entry in os.scandir(script_dir):
                if not entry.is_file():
                    continue
                if not entry.name.lower().endswith('.bin'):
                    continue
                try:
                    mt = entry.stat().st_mtime
                except OSError:
                    continue
                if mt >= after_t - 5:
                    cand.append((mt, entry.path))
        except OSError as e:
            log.warning(f"[UnsupChk] script_dir 스캔 실패: {e}")
            return None
        if not cand:
            return None
        cand.sort(reverse=True)
        if len(cand) > 1:
            log.warning(f"[UnsupChk] dump .bin 후보 {len(cand)}개 — 최신 mtime 선택: "
                        f"{os.path.basename(cand[0][1])}  (나머지: "
                        f"{[os.path.basename(c[1]) for c in cand[1:]]})")
        return cand[0][1]

    def _check_unsupported_after_jlink_dump(self, dump_start_t: float) -> bool:
        """customer parser 실행 → g16arEventLog*.txt 의 EngineErrInt count delta 판정.
        True = 신규 검출 (미지원), False = 미검출/검사 불가. 자세한 사양은 md 참조.
        """
        if not self.config.unsupported_skip:
            return False

        script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        parser_dir = os.path.join(script_dir, *DEBUG_PACKAGE_DIR.split('/'))
        parser_sh  = os.path.join(parser_dir, PARSER_SCRIPT_SH)
        parser_py  = os.path.join(parser_dir, PARSER_SCRIPT_PY)
        # .sh 우선 — PYTHONPATH / python interpreter 선택을 wrapper 가 처리.
        # 없으면 .py 직접 호출 + PYTHONPATH env 로 fallback.
        if os.path.isfile(parser_sh):
            _cmd_mode = 'sh'
        elif os.path.isfile(parser_py):
            _cmd_mode = 'py'
        else:
            log.warning(f"[UnsupChk] parser 없음 ({parser_sh} / {parser_py}) — 검사 건너뜀")
            return False

        # 1) dump 파일 탐색 (J-Link dump 는 script_dir 에 생성됨)
        dump_path = self._find_latest_jlink_dump(script_dir, dump_start_t)
        if dump_path is None:
            log.warning("[UnsupChk] J-Link dump 파일 미발견 — 검사 건너뜀")
            return False
        log.warning(f"[UnsupChk] 검사 대상 dump: {dump_path}")

        # 2) parsing tool 실행 (timeout 120s).
        if _cmd_mode == 'sh':
            # .sh 가 내부에서 cd + PYTHONPATH + python interpreter 모두 처리.
            _cmd = ['bash', parser_sh, dump_path]
            _env = os.environ.copy()    # .sh 가 자체 env 설정하므로 그대로 전달
            log.info(f"[UnsupChk] parser 실행: bash {parser_sh} {dump_path}")
        else:
            # Fallback: .py 직접 + PYTHONPATH 명시.
            _debug_pkg = os.path.dirname(parser_dir)   # DebugPackage/
            _env = os.environ.copy()
            _env['PYTHONPATH'] = _debug_pkg + os.pathsep + _env.get('PYTHONPATH', '')
            _cmd = ['python3', parser_py, dump_path]
            log.info(f"[UnsupChk] parser 실행 (fallback): python3 {parser_py} {dump_path}")
        try:
            r = subprocess.run(
                _cmd, cwd=parser_dir, env=_env, timeout=120,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.TimeoutExpired:
            log.warning("[UnsupChk] parsing tool 120초 timeout — 검사 건너뜀")
            return False
        except Exception as e:
            log.warning(f"[UnsupChk] parsing tool 예외: {e}")
            return False

        if r.returncode != 0:
            _err = r.stderr.decode(errors='replace').strip()
            log.warning(f"[UnsupChk] parsing tool rc={r.returncode} — 검사 건너뜀: "
                        f"{_err[:200]}")
            return False
        # parser stdout 은 파일 로그에만
        _out = r.stdout.decode(errors='replace').strip()
        if _out:
            log.info(f"[UnsupChk] parser stdout:\n{_out}")

        # 3) 분석 폴더 검증 — parser 가 생성하는 폴더 위치/이름이 환경마다 다를 수 있어
        # 2가지 이름 (확장자 제거 vs 포함) × 3개 위치 = 6개 후보 검색.
        _dump_p = Path(dump_path)
        _analysis_name_candidates = [
            f"{_dump_p.stem}_customer_analysis",   # 'foo' (.bin 제거) — 실제 parser 동작
            f"{_dump_p.name}_customer_analysis",   # 'foo.bin' (확장자 포함) — 대안
        ]
        _candidates: list = []
        for _aname in _analysis_name_candidates:
            _candidates += [
                _dump_p.parent / _aname,           # dump 파일 옆 (가장 일반적)
                Path(parser_dir) / _aname,         # parser 폴더 안
                Path(script_dir) / _aname,         # fuzzer 폴더 (script_dir)
            ]
        analysis_dir = next((p for p in _candidates if p.is_dir()), None)
        if analysis_dir is None:
            log.warning(f"[UnsupChk] 분석 폴더 미생성. 후보: "
                        f"{[str(p) for p in _candidates]} — 검사 건너뜀")
            return False
        log.warning(f"[UnsupChk] 분석 폴더: {analysis_dir}")

        # 4) 이벤트 로그 — EngineErrInt 누적 count 집계 (두 파일 합산)
        # firmware event log 는 NAND/NVRAM 기반 persistent. power cycle 후에도
        # 직전 entry 가 그대로 남으므로 단순 'in' 매칭은 false positive.
        # → baseline count 와의 delta 로 신규 entry 여부 판정.
        current_count = 0
        _found_files: list = []
        for log_name in ENGINE_ERRINT_LOGS:
            log_path = analysis_dir / log_name
            if not log_path.is_file():
                continue
            try:
                content = log_path.read_text(errors='replace')
            except Exception as e:
                log.warning(f"[UnsupChk] {log_path} 읽기 실패: {e}")
                continue
            _n = content.count('EngineErrInt')
            current_count += _n
            _found_files.append((log_path, _n))

        prev = self._engineerrint_baseline
        # 판정:
        #   current > prev  → 새 entry 추가됨 (NEW)
        #   current < prev  → 로그 wrap / clear → current > 0 이면 NEW, 아니면 X
        #   current == prev → 변화 없음 → 기존 entry (skip 안 함)
        if current_count > prev:
            is_new = True
        elif current_count < prev:
            is_new = current_count > 0
        else:
            is_new = False
        self._engineerrint_baseline = current_count

        _summary = ", ".join(f"{p.name}={n}" for p, n in _found_files) if _found_files else "(파일 없음)"
        if is_new:
            log.warning(f"[UnsupChk] EngineErrInt 신규 검출 — prev={prev}, current={current_count} "
                        f"[{_summary}] → 미지원 명령 처리로 판정, skip + power cycle")
            return True
        log.warning(f"[UnsupChk] EngineErrInt 신규 없음 — prev={prev}, current={current_count} "
                    f"[{_summary}] → 기존 timeout crash 흐름 진행")
        return False

    def _probe_device(self, label: str) -> None:
        """SSD 상태 진단 — sysfs only. 어느 단계에서 device sysfs 가 변하는지 추적.

        IMPORTANT: nvme id-ctrl 같은 ioctl 은 호출 안 함. 이전엔 daemon thread 로
        시도했지만, device 가 hung 상태일 때 subprocess 도 D-state 로 좀비가 되어
        kernel FD 를 점유 → 후속 PCIe remove 가 영구 block 되는 부작용.
        """
        parts: list = []
        # 1) /dev/nvmeXnY block 존재?
        parts.append(f"dev={'exist' if os.path.exists(self.config.nvme_device) else 'gone'}")
        # 2) PCIe BDF sysfs entry + link 상태
        bdf = self._pcie_bdf
        if bdf:
            bdf_dir = f"/sys/bus/pci/devices/{bdf}"
            if os.path.isdir(bdf_dir):
                parts.append("bdf=exist")
                try:
                    _spd = Path(f"{bdf_dir}/current_link_speed").read_text().strip()
                    _wid = Path(f"{bdf_dir}/current_link_width").read_text().strip()
                    parts.append(f"link={_spd}/{_wid}")
                except OSError:
                    pass
            else:
                parts.append("bdf=gone")
        else:
            parts.append("bdf=N/A")
        log.warning(f"[Probe-{label}] {' '.join(parts)}")

    def _recover_after_unsupported_skip(self) -> bool:
        """미지원 명령 skip 후 SSD 정상 복귀 (SIGKILL → PMU off → remove → PMU on →
        boot wait → rescan → 재초기화). 실패 시 False (호출자가 break). 단계별
        sequence + 시행착오는 md 참조.
        """
        log.warning("[UnsupChk] === Power Off → On + PCIe rescan ===")
        self._probe_device("recovery_start")   # 진입 시점 상태
        self.sampler._stop_worker()            # always-on 워커 정지(POR 중 소켓 경합 방지)

        # 0) 정지 중인 nvme-cli child 명시 종료 — PCIe remove 가 자연 종료시키지만
        # explicit SIGKILL 로 D-state 잔류 / 좀비 방지. PID 가 이미 죽었으면 무시.
        if self._crash_nvme_pid is not None:
            import signal as _signal
            try:
                os.kill(self._crash_nvme_pid, _signal.SIGKILL)
                log.warning(f"[UnsupChk] nvme-cli PID={self._crash_nvme_pid} SIGKILL")
            except (OSError, ProcessLookupError):
                pass   # 이미 종료된 경우
            self._crash_nvme_pid = None

        # NOTE: nvme_core timeout 은 손대지 않음 — 단축하면 recovery 후 id-ctrl polling
        # 까지 그 값에 갇혀 device boot 안에 응답 못 받음. PMU off 가 link down →
        # AER 가 in-flight ioctl 자동 abort.
        self._probe_device("after_sigkill")

        # 복구 sequence: PMU OFF → 방전 → PCIe remove → PMU ON → boot wait → rescan.
        # remove 가 필수 — 안 하면 wedged driver state 에 새 device 가 붙어 id-ctrl
        # 단계에서 admin queue hang. 시행착오 상세는 md 참조.

        if not os.path.isfile(self.config.pmu_script):
            log.error(f"[UnsupChk] PMU script 없음: {self.config.pmu_script}")
            return False

        # 1-a) PMU 전원 OFF
        log.warning("[POR] (recovery) PMU 전원 OFF 시작...")
        _off_cmd = ['python3', self.config.pmu_script, '7', '1']
        try:
            _r = subprocess.run(_off_cmd, capture_output=True, timeout=10)
            log.warning(f"[POR] PowerOff rc={_r.returncode} "
                        f"stderr={_r.stderr.decode(errors='replace').strip()!r}")
        except Exception as e:
            log.error(f"[POR] PowerOff 실패: {e}")
            return False
        log.warning(f"[POR] 전원 OFF — {self.config.por_poweroff_wait:.1f}초 방전 대기...")
        time.sleep(self.config.por_poweroff_wait)
        self._probe_device("after_power_off")   # device gone 상태 확인

        # 1-b) PCIe 장치 제거 — link down 후라 in-flight ioctl 없음 → sysfs write
        # 빠르게 통과. driver unbind + BDF entry 정리 → PMU on 시 fresh bind.
        if self._pcie_bdf:
            _remove_path = f"/sys/bus/pci/devices/{self._pcie_bdf}/remove"
            try:
                _r = subprocess.run(
                    ['bash', '-c', f'echo 1 > {_remove_path}'],
                    timeout=10, capture_output=True)
                if _r.returncode == 0:
                    log.warning(f"[POR] PCIe 장치 제거 (driver unbind): {self._pcie_bdf}")
                else:
                    log.warning(f"[POR] PCIe remove rc={_r.returncode}: "
                                f"{_r.stderr.decode(errors='replace').strip()} — 무시")
            except subprocess.TimeoutExpired:
                log.warning("[POR] PCIe remove timeout 10s — 무시 진행 "
                            "(power off 가 이미 link down 시킴)")
            except Exception as e:
                log.warning(f"[POR] PCIe remove 예외: {e} — 무시")
        self._probe_device("after_remove")

        # 1-c) PMU 전원 ON
        log.warning("[POR] PMU 전원 ON 시작...")
        _on_cmd = ['python3', self.config.pmu_script, '4', '1',
                   str(self.config.clkreq_voltage_mv), '0', '12000', '0', '0']
        try:
            _r = subprocess.run(_on_cmd, capture_output=True, timeout=15)
            log.warning(f"[POR] PowerOn rc={_r.returncode} "
                        f"stderr={_r.stderr.decode(errors='replace').strip()!r}")
        except Exception as e:
            log.error(f"[POR] PowerOn 실패: {e}")
            return False
        log.warning("[POR] 전원 ON 완료")
        self._probe_device("after_power_on")   # 부팅 시작 시점

        # 1-d) SSD boot 대기 — recovery 에선 초기 POR 의 boot_sweep wait 가 없어 rescan
        # 이 link training 전에 실행되면 device miss. 명시 대기 필요.
        _boot_wait = max(self.config.boot_sweep_s, 5.0)
        log.warning(f"[POR] SSD boot 대기 {_boot_wait:.1f}초...")
        time.sleep(_boot_wait)
        self._probe_device("after_boot_wait")

        # 2) PCIe rescan + NVMe probe
        if not self._por_pcie_rescan():
            log.warning("[UnsupChk] PCIe rescan / NVMe probe 실패")
            self._probe_device("rescan_failed")
            return False
        self._probe_device("after_rescan_ok")

        # 3) 상태 재초기화 (run() POR Phase 2 와 동일)
        if self.config.pm_inject_prob > 0:
            try:
                self._detect_pcie_info()
                self._set_pcie_l_state(PCIeLState.L0)
            except Exception as e:
                log.warning(f"[UnsupChk] PCIe 상태 재초기화 예외: {e}")
        self._apst_disable()
        self._keepalive_disable()

        # 4) OpenOCD 재연결 — J-Link 사용 중이었다면
        if not self.config.no_jlink:
            try:
                if not self.sampler._reconnect():
                    log.warning("[UnsupChk] OpenOCD 재연결 실패 — coverage 만 영향, fuzz 계속")
            except Exception as e:
                log.warning(f"[UnsupChk] OpenOCD 재연결 예외: {e}")

        log.warning("[UnsupChk] 복구 완료 — 메인 루프 재개")
        return True

    def _run_ufas_dump(self) -> None:
        """crash 발생 시 UFAS 펌웨어 덤프를 실행한다.

        실행 파일: fuzzer 스크립트와 같은 디렉토리의 ./ufas
        명령: sudo ./ufas <pcie_bus> 1 <YYYYMMDD>_UFAS_Dump.bin --ini=./SnapShot/PM9M1_A815.ini
        Popen으로 PID 추적, timeout 후 D-state 대비 포기 처리.
        """
        TIMEOUT = 600   # 10분 — 펌웨어 덤프는 수 분 소요됨

        script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        ufas_path = os.path.join(script_dir, UFAS_BINARY)

        log.warning(f"[UFAS] 실행 파일 경로: {ufas_path}")
        if not os.path.isfile(ufas_path):
            log.warning("[UFAS] 실행 파일 없음 — 덤프 건너뜀")
            return
        if not os.access(ufas_path, os.X_OK):
            log.warning("[UFAS] 실행 권한 없음 (chmod +x 필요) — 덤프 건너뜀")
            return
        log.warning("[UFAS] 실행 파일 확인 OK")

        pcie_bus = self._get_nvme_pcie_bus()
        if pcie_bus is None:
            return

        # 시분초까지 포함 — 동일 일자 다중 crash 시 파일 덮어쓰기 방지
        ts_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        dump_filename = f"{ts_str}_UFAS_Dump.bin"
        dump_path = os.path.join(script_dir, dump_filename)

        # v8.0: ini 는 product profile 에서 (ufas_ini=None 이면 --ini 생략)
        _ini = self.config.ufas_ini
        cmd = ['sudo', ufas_path, pcie_bus, '1', dump_path]
        if _ini:
            cmd.append(f'--ini={_ini}')
        log.warning(f"[UFAS] 실행 명령: {' '.join(cmd)}")
        log.warning(f"[UFAS] 작업 디렉토리: {script_dir}")
        log.warning(f"[UFAS] 덤프 출력 파일: {dump_path}")

        try:
            proc = subprocess.Popen(
                cmd, cwd=script_dir,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,  # sudo 패스워드 프롬프트 방지
            )
        except Exception as e:
            log.warning(f"[UFAS] Popen 실패: {e}")
            return

        log.warning(f"[UFAS] 프로세스 시작 PID={proc.pid} — 최대 {TIMEOUT}초 대기")

        # communicate()는 블로킹이라 진행 상황을 알 수 없으므로
        # 30초마다 파일 크기를 확인해 진행 중임을 표시
        import threading

        _result: dict = {}

        def _communicate():
            try:
                out, err = proc.communicate()
                _result['stdout'] = out
                _result['stderr'] = err
                _result['rc'] = proc.returncode
            except Exception as ex:
                _result['error'] = ex

        t = threading.Thread(target=_communicate, daemon=True)
        t.start()

        POLL_INTERVAL = 30
        waited = 0
        while waited < TIMEOUT:
            t.join(timeout=POLL_INTERVAL)
            if not t.is_alive():
                break
            waited += POLL_INTERVAL
            # 덤프 파일이 생성 중이면 크기 확인
            if os.path.exists(dump_path):
                fsize = os.path.getsize(dump_path)
                log.warning(f"[UFAS] 진행 중... {waited}s 경과, "
                             f"덤프 파일 크기: {fsize:,} bytes")
            else:
                log.warning(f"[UFAS] 진행 중... {waited}s 경과 (덤프 파일 미생성)")

        if t.is_alive():
            # timeout 초과
            log.warning(f"[UFAS] {TIMEOUT}초 timeout — SIGKILL 전송 (PID={proc.pid})")
            try:
                proc.kill()
            except Exception as e:
                log.warning(f"[UFAS] kill 실패: {e}")
            t.join(timeout=5)
            if t.is_alive():
                log.warning("[UFAS] kill 후에도 프로세스 미종료 — D-state 의심, 포기")
            else:
                log.warning("[UFAS] kill 후 프로세스 종료 확인")
            return

        # 정상 완료
        if 'error' in _result:
            log.warning(f"[UFAS] communicate 오류: {_result['error']}")
            return

        rc = _result.get('rc', -1)
        out = _result.get('stdout', b'').decode(errors='replace').strip()
        err = _result.get('stderr', b'').decode(errors='replace').strip()
        # UFAS 실행 출력도 verbose 하므로 파일 로그에만 (INFO).
        if out:
            log.info(f"[UFAS] stdout:\n{out}")
        if err:
            log.info(f"[UFAS] stderr:\n{err}")
        if rc == 0:
            log.warning(f"[UFAS] 덤프 완료 (rc=0) → {dump_path}")
        else:
            log.warning(f"[UFAS] 덤프 실패 (rc={rc})")

    def _collect_crash_artifacts(self, crash_time: datetime) -> None:
        """JLink/UFAS dump 완료 후 관련 파일을 날짜 폴더에 모아 복사한다.

        수집 대상:
          - crashes_dir/ 내 crash_{name} 바이너리·JSON·dmesg 파일 (crash_time 이후 생성)
          - script_dir/ 내 *.bin 및 *dump* 파일 (dump 시작 시각 기준 60초 여유)
          - fuzzer 로그 파일 (self._log_file)
          - 현재 dmesg 스냅샷
        """
        import shutil

        ts = crash_time.strftime('%Y%m%d_%H%M%S')
        dest = self.crashes_dir / f"crash_{ts}"
        dest.mkdir(parents=True, exist_ok=True)
        log.warning(f"[ARTIFACT] 수집 폴더: {_logname(dest)}")

        crash_epoch = crash_time.timestamp()
        script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))

        # 1) crashes_dir 내 crash 파일 (crash_time 5초 전부터)
        try:
            for p in sorted(self.crashes_dir.iterdir()):
                if p.is_dir():
                    continue
                if p.stat().st_mtime >= crash_epoch - 5:
                    shutil.copy2(p, dest / p.name)
                    log.warning(f"[ARTIFACT] 복사: {p.name}")
        except Exception as e:
            log.warning(f"[ARTIFACT] crashes_dir 복사 오류: {e}")

        # 2) script_dir 내 dump 파일 (crash_time 60초 전부터 — dump에 시간 소요)
        try:
            for entry in sorted(os.scandir(script_dir), key=lambda e: e.name):
                if not entry.is_file():
                    continue
                name_lower = entry.name.lower()
                if not (name_lower.endswith('.bin') or 'dump' in name_lower):
                    continue
                if entry.stat().st_mtime >= crash_epoch - 60:
                    dst = dest / entry.name
                    shutil.copy2(entry.path, dst)
                    log.warning(f"[ARTIFACT] dump 복사: {entry.name} "
                                f"({entry.stat().st_size:,} bytes)")
        except Exception as e:
            log.warning(f"[ARTIFACT] script_dir 복사 오류: {e}")

        # 3) 로그 파일 (flush 후 복사)
        if self._log_file and os.path.isfile(self._log_file):
            for h in log.handlers:
                try:
                    h.flush()
                except Exception:
                    pass
            try:
                shutil.copy2(self._log_file, dest / os.path.basename(self._log_file))
                log.warning(f"[ARTIFACT] 로그 복사: {os.path.basename(self._log_file)}")
            except Exception as e:
                log.warning(f"[ARTIFACT] 로그 복사 실패: {e}")

        # 4) dmesg 최신본 저장
        try:
            dmesg = self._capture_dmesg(lines=200)
            (dest / f"dmesg_{ts}.txt").write_text(dmesg)
            log.warning(f"[ARTIFACT] dmesg 저장: dmesg_{ts}.txt")
        except Exception as e:
            log.warning(f"[ARTIFACT] dmesg 저장 실패: {e}")

        log.warning(f"[ARTIFACT] 수집 완료 → {_logname(dest)}/")

    def _generate_state_replay_sh(self, entry: 'StateCorpusEntry') -> None:
        """state corpus entry의 100개 명령 시퀀스를 replay .sh로 저장.
        기존 _generate_replay_sh를 재사용 — _cmd_history를 임시 교체."""
        tag = f"state_{entry.found_at}"
        orig = self._cmd_history
        self._cmd_history = deque(entry.sequence, maxlen=len(entry.sequence))
        try:
            self._generate_replay_sh(self.state_corpus_dir, tag)
        except Exception as e:
            log.debug(f"[State] replay .sh 생성 실패: {e}")
        finally:
            self._cmd_history = orig

    def _generate_seq_replay_sh(self, seq_seed: 'SequenceSeed') -> None:
        """SequenceSeed의 명령 시퀀스를 seq_corpus/ 에 replay .sh로 저장.
        Seed 목록을 _cmd_history dict 포맷으로 변환 후 _generate_replay_sh 재사용."""
        tag = f"seq_{seq_seed.found_at}"
        ns = self.config.nvme_namespace or 1
        history = []
        for seed in seq_seed.commands:
            cmd = seed.cmd
            opcode = seed.opcode_override if seed.opcode_override is not None else cmd.opcode
            nsid   = seed.nsid_override   if seed.nsid_override   is not None else ns
            if seed.force_admin is not None:
                passthru_type = 'admin-passthru' if seed.force_admin else 'io-passthru'
            else:
                passthru_type = ('admin-passthru' if cmd.cmd_type == NVMeCommandType.ADMIN
                                 else 'io-passthru')
            device = (self.config.nvme_device if passthru_type == 'admin-passthru'
                      else self._io_device())
            data = seed.data
            _lba_sz = self.config.nvme_lba_size or 512
            _IO_NO_NLB = ("Flush", "DatasetManagement",
                          "WriteZeroes", "WriteUncorrectable", "Verify")
            _ADMIN_FIXED = {"Identify": 4096, "GetFeatures": 4096,
                            "TelemetryHostInitiated": 4096, "DeviceSelfTest": 0}
            _MAX_BUF = 2 * 1024 * 1024
            if seed.data_len_override is not None:
                data_len = min(max(0, seed.data_len_override), _MAX_BUF)
            elif cmd.needs_data and data:
                data_len = len(data)
            elif cmd.cmd_type == NVMeCommandType.IO and cmd.name not in _IO_NO_NLB:
                _nlb = seed.cdw12 & 0xFFFF
                data_len = min(max(_lba_sz, (_nlb + 1) * _lba_sz), _MAX_BUF)
            elif cmd.name == "GetLogPage":
                _numdl = (seed.cdw10 >> 16) & 0x7FF
                data_len = min(max(4, (_numdl + 1) * 4), _MAX_BUF)
            elif cmd.name == "SecurityReceive":
                data_len = min(max(512, seed.cdw11), _MAX_BUF)
            elif cmd.name == "GetLBAStatus":
                data_len = min(max(8, (seed.cdw12 + 1) * 4), _MAX_BUF)
            elif cmd.name in _ADMIN_FIXED:
                data_len = _ADMIN_FIXED[cmd.name]
            else:
                data_len = 0
            is_write = bool(data and data_len > 0 and cmd.needs_data)
            history.append({
                'kind': 'nvme',
                'label': cmd.name,
                'passthru_type': passthru_type,
                'device': device,
                'opcode': opcode,
                'nsid': nsid,
                'cdw2': seed.cdw2,  'cdw3':  seed.cdw3,
                'cdw10': seed.cdw10, 'cdw11': seed.cdw11,
                'cdw12': seed.cdw12, 'cdw13': seed.cdw13,
                'cdw14': seed.cdw14, 'cdw15': seed.cdw15,
                'data': bytes(data[:data_len]) if (is_write and data) else None,
                'data_len': data_len,
                'is_write': is_write,
            })
        if not history:
            return
        orig = self._cmd_history
        self._cmd_history = deque(history, maxlen=len(history))
        try:
            self._generate_replay_sh(self.seq_corpus_dir, tag)
            log.info(f"[SeqSeed] replay .sh 저장: {_logname(self.seq_corpus_dir / ('replay_' + tag + '.sh'))}")
        except Exception as e:
            log.debug(f"[SeqSeed] replay .sh 생성 실패: {e}")
        finally:
            self._cmd_history = orig

    def _remove_seq_replay_artifacts(self, seq_seed: 'SequenceSeed') -> None:
        """cull로 제거되는 SequenceSeed의 replay .sh 와 data 폴더 제거 (디스크 누수 방지)."""
        tag = f"seq_{seq_seed.found_at}"
        sh_path  = self.seq_corpus_dir / f"replay_{tag}.sh"
        data_dir = self.seq_corpus_dir / f"replay_data_{tag}"
        try:
            if sh_path.exists():
                sh_path.unlink()
            if data_dir.exists():
                shutil.rmtree(data_dir, ignore_errors=True)
        except Exception as e:
            log.debug(f"[SeqCull] artifact 제거 실패 {tag}: {e}")

    def _finalize_seq_sink(self) -> None:
        """_seq_sink에 누적된 시퀀스를 SequenceSeed로 corpus에 추가하고 replay .sh 저장.
        interesting 여부와 무관하게 _seq_sink를 None으로 리셋."""
        if self._seq_sink is None:
            return
        if self._seq_sink['interesting']:
            _n = max(len(self._seq_sink['commands']), 1)
            _seq_seed = SequenceSeed(
                commands=self._seq_sink['commands'],
                new_pcs=self._seq_sink['new_pcs'],
                energy=MAX_ENERGY / _n,
                found_at=self.executions,
                covered_pcs=self._seq_sink['covered_pcs'],
            )
            self.corpus.append(_seq_seed)
            _cov_label = "BB" if (self._sa_loaded and self._sa_bb_starts) else "PC"
            log.warning(
                f"[+][SeqSeed] cmds={_n}  "
                f"new_{_cov_label}={_seq_seed.new_pcs}  "
                f"corpus={len(self.corpus)}  exec={self.executions:,}")
            self._generate_seq_replay_sh(_seq_seed)
        self._seq_sink = None

    def _generate_replay_sh(self, crash_dir: Path, tag: str) -> None:
        """crash 발생 직전 최대 100개 명령어(PM 포함)를 재현 가능한 .sh 파일로 저장.

        쓰기 데이터가 있는 명령은 replay_data_<tag>/ 하위에 바이너리 파일로 함께 저장.
        생성된 .sh는 chmod +x 로 바로 실행 가능.
        """
        history = list(self._cmd_history)
        if not history:
            log.warning("[REPLAY] 히스토리 없음 — replay .sh 생성 건너뜀")
            return

        sh_path  = crash_dir / f"replay_{tag}.sh"
        data_dir = crash_dir / f"replay_data_{tag}"
        data_dir.mkdir(exist_ok=True)
        # data 파일 write 는 절대경로 사용 (file I/O 안전).
        # .sh 안에서는 스크립트 자신의 디렉토리로 cd → 상대경로 ${SCRIPT_DIR}/<...> 로 접근.
        # → crashes/ 폴더만 통째로 다른 곳에 옮겨도 replay 동작.
        data_dir_abs = data_dir.resolve()
        data_dir_rel = data_dir.name   # 'replay_data_<tag>' — sh_path 와 같은 디렉토리

        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # nvme_core 모듈 타임아웃 — 퍼저와 동일한 값
        _kt_sec = self.config.nvme_kernel_timeout_sec
        lines = [
            "#!/bin/bash",
            f"# Auto-generated replay script — {len(history)} commands before crash",
            f"# Generated : {now_str}",
            f"# Device    : {self.config.nvme_device}",
            f"# Tag       : {tag}",
            "#",
            "# 실행 방법:",
            f"#   sudo bash {sh_path.name}",
            "#",
            # set -e 대신 set +e — rc를 직접 캡처하기 위해 오류 즉시 종료 비활성화
            "set +e",
            "",
            "# 스크립트 자신의 디렉토리로 cd — replay_data_<tag>/ 를 상대경로로 접근 가능",
            'SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"',
            'cd "${SCRIPT_DIR}"',
            "",
            "# ── nvme_core 커널 timeout 설정 ─────────────────────────────────────",
            "# crash 발생 후 커널이 abort/reset_controller 를 수행하지 않도록",
            "# admin_timeout / io_timeout 을 큰 값으로 설정한다.",
            "# (기본값: admin=60s / io=30s → crash 후 60초면 커널이 상태 소멸)",
            f"_NVME_KT={_kt_sec}",
            "_set_kernel_timeout() {",
            "    for _p in /sys/module/nvme_core/parameters/admin_timeout \\",
            "               /sys/module/nvme_core/parameters/io_timeout; do",
            "        [ -f \"$_p\" ] || continue",
            "        _old=$(cat \"$_p\" 2>/dev/null)",
            "        echo \"$1\" > \"$_p\" 2>/dev/null \\",
            "            && echo \"  [TimeoutCfg] $_p : ${_old}s -> $1 s\" \\",
            "            || echo \"  [TimeoutCfg] $_p 설정 실패 (root 필요)\"",
            "    done",
            "}",
            "echo '>>> [SETUP] nvme_core kernel timeout 설정 (crash 상태 보존)'",
            "_set_kernel_timeout ${_NVME_KT}",
            "",
            "# ────────────────────────────────────────────────────────────────────",
            "",
        ]

        for i, entry in enumerate(history, 1):
            label = entry['label']
            is_last = (i == len(history))
            marker = "  <- CRASH CMD" if is_last else ""
            step_str = f"[{i:03d}/{len(history)}] {label}{marker}"
            lines.append(f"# {step_str}")

            if entry.get('kind') == 'pcie_state':
                # 진입 실패한 combo는 replay에서 재현 불가 — 스킵
                if not entry.get('ok', True):
                    lines.append(f'# [SKIP] {step_str} — 진입 실패, replay 생략')
                    lines.append("")
                    continue

                bdf      = entry.get('pcie_bdf', '')
                pcie_l   = PCIeLState(entry.get('pcie_l', 0))
                pcie_d   = PCIeDState(entry.get('pcie_d', 0))
                cap_off  = entry.get('pcie_cap_offset')
                pm_off   = entry.get('pcie_pm_cap_offset')
                l1ss_off = entry.get('pcie_l1ss_offset')
                lnkcap   = entry.get('pcie_lnkcap')
                l1ss_cap = entry.get('pcie_l1ss_cap')
                r_bdf    = entry.get('pcie_root_bdf', '')
                r_cap    = entry.get('pcie_root_cap_offset')
                r_l1ss   = entry.get('pcie_root_l1ss_offset')
                pmu_scr  = entry.get('pmu_script', _PMU_SCRIPT)
                assert_pin   = entry.get('clkreq_assert_pin', 16)
                deassert_pin = entry.get('clkreq_deassert_pin', 15)
                voltage_mv   = entry.get('clkreq_voltage_mv', 3300)

                aspms    = ((lnkcap >> 10) & 0x3) if lnkcap else 0x2
                cpm      = ((lnkcap >> 18) & 0x1) if lnkcap else 0
                aspm_val = aspms & 0x2

                lines.append(f'echo ">>> {step_str}"')
                pcmds: list = []  # 이 항목의 커맨드 목록
                pmu_tail: str = ''  # L1.2 진입 완료 후 마지막에 추가할 PMU deassert

                if bdf and cap_off is not None:
                    if pcie_l == PCIeLState.L0:
                        # clock restore 먼저 — setpci 전 필수
                        pcmds.append(
                            f"python3 {pmu_scr} {assert_pin} 1 1 {voltage_mv}"
                            f"  # CLKREQ# assert (clock restore)")
                        pcmds += [
                            f"sudo setpci -s {bdf} {cap_off+0x10:#x}.w=0000:0003"
                            f"  # EP LNKCTL ASPMC=00 (L0)",
                            f"sudo setpci -s {bdf} {cap_off+0x10:#x}.w=0000:0100"
                            f"  # EP LNKCTL ECPM=0",
                        ]
                        if l1ss_off:
                            pcmds.append(
                                f"sudo setpci -s {bdf} {l1ss_off+0x8:#x}.l=00000000:0000000f"
                                f"  # EP L1SSCTL1 enable bits=0")
                        pcmds.append(
                            f"sudo setpci -s {bdf} {cap_off+0x28:#x}.w=0000:0400"
                            f"  # EP DEVCTL2 LTRE=0")
                        if r_bdf and r_cap:
                            pcmds += [
                                f"sudo setpci -s {r_bdf} {r_cap+0x10:#x}.w=0000:0003"
                                f"  # RP LNKCTL ASPMC=00",
                                f"sudo setpci -s {r_bdf} {r_cap+0x10:#x}.w=0000:0100"
                                f"  # RP LNKCTL ECPM=0",
                            ]
                            if r_l1ss:
                                pcmds.append(
                                    f"sudo setpci -s {r_bdf} {r_l1ss+0x8:#x}.l=00000000:0000000f"
                                    f"  # RP L1SSCTL1 enable bits=0")

                    elif pcie_l == PCIeLState.L1:
                        pcmds.append("# echo powersave > /sys/module/pcie_aspm/parameters/policy")
                        if r_bdf and r_cap:
                            pcmds.append(
                                f"sudo setpci -s {r_bdf} {r_cap+0x10:#x}.w={aspm_val:04x}:0003"
                                f"  # RP LNKCTL ASPMC=L1")
                        pcmds.append(
                            f"sudo setpci -s {bdf} {cap_off+0x10:#x}.w={aspm_val:04x}:0003"
                            f"  # EP LNKCTL ASPMC=L1")
                        if cpm:
                            if r_bdf and r_cap:
                                pcmds.append(
                                    f"sudo setpci -s {r_bdf} {r_cap+0x10:#x}.w=0100:0100"
                                    f"  # RP LNKCTL ECPM=1")
                            pcmds.append(
                                f"sudo setpci -s {bdf} {cap_off+0x10:#x}.w=0100:0100"
                                f"  # EP LNKCTL ECPM=1")

                    else:  # L1.2 — runtime sequence와 동일: L1SS/LNKCTL arm → [D3hot] → deassert
                        # LTRE/LTR threshold 미사용: runtime도 미사용 (PMU GPIO 직접 제어)
                        l1ss_en = (l1ss_cap & 0xF) if l1ss_cap else 0x5
                        pcmds.append("# echo powersave > /sys/module/pcie_aspm/parameters/policy")
                        # Step1: L1SS disable
                        if l1ss_off:
                            pcmds.append(
                                f"sudo setpci -s {bdf} {l1ss_off+0x8:#x}.l=00000000:0000000f"
                                f"  # Step1 EP L1SSCTL1 enable bits=0")
                        if r_bdf and r_l1ss:
                            pcmds.append(
                                f"sudo setpci -s {r_bdf} {r_l1ss+0x8:#x}.l=00000000:0000000f"
                                f"  # Step1 RP L1SSCTL1 enable bits=0")
                        # Step3: L1SS enable (RP 먼저)
                        if r_bdf and r_l1ss:
                            pcmds.append(
                                f"sudo setpci -s {r_bdf} {r_l1ss+0x8:#x}.l={l1ss_en:08x}:0000000f"
                                f"  # Step3 RP L1SSCTL1 enable={l1ss_en:#04x}")
                        if l1ss_off:
                            pcmds.append(
                                f"sudo setpci -s {bdf} {l1ss_off+0x8:#x}.l={l1ss_en:08x}:0000000f"
                                f"  # Step3 EP L1SSCTL1 enable={l1ss_en:#04x}")
                        # Step4: LNKCTL ASPMC (RP 먼저)
                        if r_bdf and r_cap:
                            pcmds.append(
                                f"sudo setpci -s {r_bdf} {r_cap+0x10:#x}.w={aspm_val:04x}:0003"
                                f"  # Step4 RP LNKCTL ASPMC=L1")
                        pcmds.append(
                            f"sudo setpci -s {bdf} {cap_off+0x10:#x}.w={aspm_val:04x}:0003"
                            f"  # Step4 EP LNKCTL ASPMC=L1")
                        if cpm:
                            if r_bdf and r_cap:
                                pcmds.append(
                                    f"sudo setpci -s {r_bdf} {r_cap+0x10:#x}.w=0100:0100"
                                    f"  # RP LNKCTL ECPM=1")
                            pcmds.append(
                                f"sudo setpci -s {bdf} {cap_off+0x10:#x}.w=0100:0100"
                                f"  # EP LNKCTL ECPM=1")
                        # PMU deassert는 D-state write 후 맨 마지막에 추가
                        pmu_tail = (f"python3 {pmu_scr} {deassert_pin} 1 1 {voltage_mv}"
                                    f"  # CLKREQ# deassert (clock off — L1.2 active)")

                # D-state (L1.2+D3의 경우 PMCSR write는 deassert 전에 위치)
                if bdf and pm_off is not None:
                    dval = 3 if pcie_d == PCIeDState.D3 else 0
                    pcmds.append(
                        f"sudo setpci -s {bdf} {pm_off+0x4:#x}.w={dval:04x}:0003"
                        f"  # PMCSR D-state={'D3hot' if dval else 'D0'}")

                # L1.2 PMU deassert — L1SS/LNKCTL arm + D-state write 완료 후 마지막
                if pmu_tail:
                    pcmds.append(pmu_tail)

                for pcmd in pcmds:
                    lines.append(f'echo "    {pcmd}"')
                    lines.append(pcmd)
                    lines.append('echo "    rc=$?"')
                lines.append("sleep 0.1")
                lines.append("")
                continue

            # v7.7: PCIe config 단일 비트 perturbation (S1) — setpci 한 줄로 재현
            if entry.get('kind') == 'pcie_pm_bit':
                bdf    = entry.get('bdf', '')
                offset = entry.get('offset')
                value  = entry.get('value', 0)
                mask   = entry.get('mask', 0)
                width  = entry.get('width', 'w')
                if not bdf or offset is None or not mask:
                    lines.append(f'# [SKIP] {step_str} — bdf/offset/mask 부재, replay 생략')
                    lines.append("")
                    continue
                nchars = {'b': 2, 'w': 4, 'l': 8}.get(width, 4)
                spec = (f'{offset:#x}.{width}='
                        f'{(value & mask):0{nchars}x}:{mask:0{nchars}x}')
                pcmd = f'sudo setpci -s {bdf} {spec}'
                lines.append(f'echo ">>> {step_str}"')
                lines.append(f'echo "    {pcmd}"')
                lines.append(pcmd)
                lines.append('echo "    rc=$?"')
                lines.append("sleep 0.05")
                lines.append("")
                continue

            # v7.7: CLKREQ# timing perturbation (S2) — PMU GPIO 토글 재현
            if entry.get('kind') == 'clkreq':
                mode = entry.get('mode', '')
                pmu_scr      = entry.get('pmu_script', _PMU_SCRIPT)
                assert_pin   = entry.get('clkreq_assert_pin', 16)
                deassert_pin = entry.get('clkreq_deassert_pin', 15)
                voltage_mv   = entry.get('clkreq_voltage_mv', 3300)
                l1_2_settle  = entry.get('l1_2_settle_s', 0.05)
                _asrt = f'python3 {pmu_scr} {assert_pin} 1 1 {voltage_mv}'
                _dasrt = f'python3 {pmu_scr} {deassert_pin} 1 1 {voltage_mv}'
                pcmds: list = []

                if mode == 'short_pulse':
                    pulse_us = int(entry.get('pulse_us', 50))
                    pcmds.append(f'{_asrt}  # CLKREQ# assert (pulse start)')
                    pcmds.append(f'sleep {pulse_us/1e6:.6f}  # pulse_us={pulse_us}')
                    pcmds.append(f'{_dasrt}  # CLKREQ# deassert (pulse end)')
                    pcmds.append('sleep 0.001')
                    pcmds.append(f'{_asrt}  # CLKREQ# assert (normal state restore)')

                elif mode == 'missed_wake':
                    delay_ms = int(entry.get('delay_ms', 100))
                    pcmds.append(f'{_dasrt}  # CLKREQ# deassert (L1.2 entry)')
                    pcmds.append(f'sleep {l1_2_settle + 0.01:.4f}  # L1.2 settle')
                    pcmds.append(f'sleep {delay_ms/1e3:.4f}  # missed_wake delay_ms={delay_ms}')
                    pcmds.append(f'{_asrt}  # CLKREQ# assert (late wake)')
                    pcmds.append('sleep 0.001')

                elif mode == 'rapid_toggle':
                    count = int(entry.get('count', 5))
                    for _ in range(count):
                        pcmds.append(f'{_asrt}  # CLKREQ# assert (toggle)')
                        pcmds.append('sleep 0.00005')
                        pcmds.append(f'{_dasrt}  # CLKREQ# deassert (toggle)')
                        pcmds.append('sleep 0.00005')
                    pcmds.append(f'{_asrt}  # CLKREQ# assert (normal state restore)')
                    pcmds.append('sleep 0.001')

                elif mode == 'extended_wait':
                    wait_s = float(entry.get('wait_s', l1_2_settle))
                    pcmds.append(f'{_dasrt}  # CLKREQ# deassert (L1.2 entry)')
                    pcmds.append(f'sleep {l1_2_settle + 0.01:.4f}  # L1.2 settle')
                    pcmds.append(f'sleep {wait_s:.4f}  # extended_wait')
                    pcmds.append(f'{_asrt}  # CLKREQ# assert (wake)')
                    pcmds.append('sleep 0.001')
                else:
                    lines.append(f'# [SKIP] {step_str} — unknown clkreq mode={mode!r}')
                    lines.append("")
                    continue

                lines.append(f'echo ">>> {step_str}"')
                for pcmd in pcmds:
                    lines.append(f'echo "    {pcmd}"')
                    lines.append(pcmd)
                    lines.append('echo "    rc=$?"')
                lines.append("sleep 0.05")
                lines.append("")
                continue

            # device path 방어 정규화 — 과거 corpus / cmd_history 에 잘못 저장된
            # /dev/nvme0n1n1 같은 중복 nN 접미사를 replay 시점에 한 번 더 정리.
            _entry_dev = self._normalize_nvme_path(entry['device'])
            cmd_parts = [
                "nvme", entry['passthru_type'], _entry_dev,
                f"--opcode={entry['opcode']:#x}",
                f"--namespace-id={entry['nsid']}",
                f"--cdw2={entry['cdw2']:#x}",
                f"--cdw3={entry['cdw3']:#x}",
                f"--cdw10={entry['cdw10']:#x}",
                f"--cdw11={entry['cdw11']:#x}",
                f"--cdw12={entry['cdw12']:#x}",
                f"--cdw13={entry['cdw13']:#x}",
                f"--cdw14={entry['cdw14']:#x}",
                f"--cdw15={entry['cdw15']:#x}",
                "--timeout=3600000",  # 1시간: crash 시 blocking 유지 (커널 abort 방지), 분석 후 Ctrl+C
            ]

            if entry['is_write'] and entry['data']:
                # data bin 파일은 절대경로로 write (file I/O), .sh 안에선 상대경로로 참조.
                # 스크립트 시작 시 SCRIPT_DIR 로 cd 했으므로 ./replay_data_<tag>/data_NNN.bin 으로 접근.
                _data_filename = f"data_{i:03d}.bin"
                data_file_abs = data_dir_abs / _data_filename
                data_file_abs.write_bytes(entry['data'])
                _data_rel = f"./{data_dir_rel}/{_data_filename}"
                cmd_parts += [f"--data-len={entry['data_len']}",
                               f"--input-file={_data_rel}", "-w"]
            elif entry['data_len'] > 0:
                cmd_parts += [f"--data-len={entry['data_len']}", "-r"]

            # CLI 한 줄로 echo (인수를 공백으로 이어서 출력)
            cmd_oneline = "sudo " + " ".join(cmd_parts)
            lines.append(f'echo ">>> {step_str}"')
            lines.append(f'echo "    {cmd_oneline}"')
            # stdout(response buffer)은 /dev/null 억제, stderr(에러 메시지)만 출력
            lines.append("sudo " + " \\\n  ".join(cmd_parts) + " > /dev/null")
            lines.append('echo "    rc=$?"')
            lines.append("sleep 0.1")
            lines.append("")

        lines.append('echo "Replay complete."')

        sh_path.write_text("\n".join(lines) + "\n")
        sh_path.chmod(0o755)
        log.warning(f"[REPLAY] 재현 스크립트 → {_logname(sh_path)}  ({len(history)}개 명령)")
        log.warning(f"[REPLAY] 실행: sudo bash {_logname(sh_path)}")

    def _capture_dmesg(self, lines: int = 80) -> str:
        """v4.4: 커널 로그(dmesg) 마지막 N줄을 캡처한다.
        timeout 시 커널 NVMe 드라이버의 동작(abort, reset, FLR 등)을
        확인하기 위한 진단 데이터."""
        try:
            result = subprocess.run(
                ['dmesg', '--time-format=iso', '-T'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                # --time-format 미지원 커널 fallback
                result = subprocess.run(
                    ['dmesg', '-T'],
                    capture_output=True, text=True, timeout=5
                )
            all_lines = result.stdout.strip().splitlines()
            return '\n'.join(all_lines[-lines:])
        except Exception as e:
            return f"(dmesg capture failed: {e})"

    def _save_crash(self, data: bytes, seed: Seed, reason: str = "timeout",
                    stuck_pcs: Optional[List[Tuple[int, ...]]] = None,
                    dmesg_snapshot: Optional[str] = None):
        """crash 메타데이터를 .json 1개만 저장.

        raw fuzz_data binary 와 별도 .dmesg.txt 는 더 이상 저장하지 않음:
          - 명령 데이터: replay_data_<tag>/data_NNN.bin 에 이미 포함됨
          - dmesg: .json 의 dmesg_snapshot 필드 + dmesg_<ts>.txt (수집 시점) 으로 충분
        """
        input_hash = hashlib.md5(data).hexdigest()[:12]
        filename = f"crash_{seed.cmd.name}_{hex(seed.cmd.opcode)}_{input_hash}"
        filepath = self.crashes_dir / filename

        meta = self._seed_meta(seed)
        meta["crash_reason"] = reason
        meta["timestamp"] = datetime.now().isoformat()

        if stuck_pcs:
            from collections import Counter
            n_cores = len(stuck_pcs[0]) if stuck_pcs else 0
            meta["stuck_pcs_count"] = len(stuck_pcs)
            # 샘플별 코어 PC 목록: [[core0, core1, ...], ...]
            meta["stuck_pcs"] = [[hex(pc) for pc in sample] for sample in stuck_pcs]
            # 코어별 top-5 빈도 PC
            per_core_top = []
            for i in range(n_cores):
                cc = Counter(t[i] for t in stuck_pcs)
                per_core_top.append([
                    {"pc": hex(pc), "count": cnt,
                     "ratio": f"{cnt/len(stuck_pcs):.0%}"}
                    for pc, cnt in cc.most_common(5)
                ])
            meta["stuck_pc_top5_per_core"] = per_core_top

        if dmesg_snapshot:
            meta["dmesg_snapshot"] = dmesg_snapshot

        with open(str(filepath) + '.json', 'w') as f:
            json.dump(meta, f, indent=2)

    def _handle_timeout_crash(self, seed: Seed, fuzz_data: bytes) -> None:
        """RC_TIMEOUT 발생 시 공통 처리 (Calibration/Main loop 공용).

        stuck PC 분석 → dmesg 캡처 → crash 저장 → _timeout_crash 플래그 설정.
        호출 후 caller는 break로 현재 루프를 탈출해야 한다.
        """
        from collections import Counter

        # stderr 복원 최우선 (calibration 구간 /dev/null 리다이렉트 해제 → 로그가 터미널에 보이게).
        if self._cal_saved_stderr_fd is not None:
            os.dup2(self._cal_saved_stderr_fd, 2)
            self._cal_saved_stderr_fd = None   # finally 블록의 이중 복원 방지

        # always-on 샘플링 워커 정지 — 이하 _reinit_target / POR / reconnect 가 디버그 소켓을
        # 만지므로 워커와의 경합 방지. 복구 후 다음 명령의 start_sampling 이 재가동.
        self.sampler._stop_worker()

        cmd = seed.cmd
        actual_opcode = (seed.opcode_override if seed.opcode_override is not None
                         else cmd.opcode)

        # ignore-list: 지정 opcode 의 timeout 은 크래시로 취급하지 않고 POR 복구 후 계속.
        # (알려진 hang opcode 를 흘려보내고 나머지는 정상 크래시 헌팅.) repro 게이트보다 먼저 검사.
        if actual_opcode in self.config.ignore_opcodes:
            log.warning(f"[IGN] opcode 0x{actual_opcode:02x} ({cmd.name}) timeout "
                        f"— ignore-list → POR 복구 후 계속")
            self.stats['ignored_timeout'] = self.stats.get('ignored_timeout', 0) + 1
            if self._recover_after_unsupported_skip():
                return   # _timeout_crash 미설정 → caller 가 continue
            log.error("[IGN] POR 복구 실패 — 중단 (POR/PMU 사용 가능해야 함)")
            self._timeout_crash = True
            return

        # 재현 모드: 타겟 opcode 가 아닌 timeout 은 무거운 dump/artifact 없이 POR 로 복구하고 계속.
        # (타겟이면 아래 전체 크래시 캡처로 진행.) unsupported-skip 의 POR 복구 로직 재사용 —
        # 복구 함수가 device 재생+sampler 재연결까지 수행하므로 메인 루프가 그대로 이어진다.
        if (self.config.repro_opcodes
                and actual_opcode not in self.config.repro_opcodes):
            _tgts = ','.join(f'0x{o:02x}' for o in self.config.repro_opcodes)
            log.warning(f"[REPRO] 비타겟 opcode 0x{actual_opcode:02x} ({cmd.name}) timeout "
                        f"— 타겟[{_tgts}] 아님 → POR 복구 후 계속")
            self.stats['repro_skipped'] = self.stats.get('repro_skipped', 0) + 1
            if self._recover_after_unsupported_skip():
                return   # _timeout_crash 미설정 → caller 가 continue
            log.error("[REPRO] POR 복구 실패 — 중단 (POR/PMU 사용 가능해야 함)")
            self._timeout_crash = True
            return
        if self.config.repro_opcodes:
            log.warning(f"[REPRO] 타겟 opcode 0x{actual_opcode:02x} ({cmd.name}) timeout "
                        f"— 크래시 캡처 진입")

        _crash_time = datetime.now()   # artifact 폴더 타임스탬프 기준
        # crash 산출물 통합 폴더 — replay.sh, replay_data/, dump, log, dmesg 모두 여기로.
        _crash_dir = self.crashes_dir / f"crash_{_crash_time.strftime('%Y%m%d_%H%M%S')}"
        _crash_dir.mkdir(parents=True, exist_ok=True)

        # 1) 디버그 인프라 상태 확인 후 stuck PC 읽기
        # OpenOCD/J-Link 문제면 stuck PC를 읽을 수 없어 펌웨어 hang 판단 불가
        _nvme_dev = self.config.nvme_device
        log.warning("[TIMEOUT] 디버그 인프라 상태 확인 중...")
        _infra_ok = self.sampler._reinit_target()
        if not _infra_ok:
            log.error("[TIMEOUT] 디버그 인프라 접근 불가 — 펌웨어 hang 여부 자동 판단 불가")
            log.error("[TIMEOUT] ── 수동 확인 절차 ──────────────────────────────────")
            log.error(f"[TIMEOUT]  1) sudo pkill -9 openocd")
            log.error(f"[TIMEOUT]  2) nvme id-ctrl {_nvme_dev}")
            log.error(f"[TIMEOUT]     응답 있음  → SSD 생존 (인프라 문제였을 가능성)")
            log.error(f"[TIMEOUT]     응답 없음  → SSD 사망 (펌웨어 crash 가능성)")
            log.error(f"[TIMEOUT]  3) J-Link 재연결 후 PC 확인:")
            log.error(f"[TIMEOUT]     같은 PC 반복 → 펌웨어 hang 확정")
            log.error(f"[TIMEOUT]     PC 변화 중  → 인프라 문제였음")
            log.error("[TIMEOUT] ────────────────────────────────────────────────────")
            stuck_pcs = []
        else:
            log.warning("[TIMEOUT] 인프라 정상 — SSD 펌웨어 hang 지점 확인을 위해 PC를 읽습니다...")
            stuck_pcs = self.sampler.read_stuck_pcs(count=1000)

        if stuck_pcs:
            idle_pcs    = self.sampler.idle_pcs
            n_samples   = len(stuck_pcs)

            # 코어별 Counter 분리 (실제 코어 수 기반)
            _n_cores = len(stuck_pcs[0]) if stuck_pcs else 0
            core_counters = [Counter(t[i] for t in stuck_pcs) for i in range(_n_cores)]

            log.error(
                f"[TIMEOUT CRASH] {cmd.name} "
                f"actual_opcode=0x{actual_opcode:02x} "
                f"timeout_group={cmd.timeout_group} "
                f"({n_samples} samples)")

            core_verdicts = []
            for core_idx, cc in enumerate(core_counters):
                if not cc:
                    continue
                top_pc, top_cnt = cc.most_common(1)[0]
                top_ratio  = top_cnt / n_samples
                unique_pcs = set(cc.keys())
                non_idle   = unique_pcs - idle_pcs

                log.error(f"  [Core{core_idx}] {len(unique_pcs)} unique PCs "
                          f"(non-idle={len(non_idle)}):")
                for pc, cnt in cc.most_common(3):
                    in_range = " [IN RANGE]" if self.sampler._in_range(pc) else " [OUT]"
                    idle_tag = " [IDLE]" if pc in idle_pcs else " [NON-IDLE]"
                    log.error(f"    {hex(pc)}: {cnt}/{n_samples} "
                              f"({100*cnt/n_samples:.0f}%){in_range}{idle_tag}")

                # 코어별 판정
                if len(non_idle) == 0:
                    verdict = "정상 idle"
                elif top_ratio >= 0.70 and top_pc not in idle_pcs:
                    verdict = f"HANG — {hex(top_pc)} 집중도 {top_ratio:.0%}"
                elif top_ratio >= 0.40:
                    verdict = f"busy-wait/에러루프 — {hex(top_pc)} {top_ratio:.0%}"
                else:
                    verdict = f"PC 분산 ({top_ratio:.0%}) — 복구 중 또는 정상"
                log.error(f"  [Core{core_idx}] 판정: {verdict}")
                core_verdicts.append((core_idx, verdict))
        else:
            log.error(
                f"[TIMEOUT CRASH] {cmd.name} "
                f"actual_opcode=0x{actual_opcode:02x} "
                f"— J-Link PC 읽기 실패 (JTAG 연결 확인 필요)")

        # 2) dmesg 캡처
        log.warning("[TIMEOUT] 커널 로그(dmesg)를 캡처합니다...")
        dmesg_snapshot = self._capture_dmesg(lines=80)
        nvme_lines = [l for l in dmesg_snapshot.splitlines()
                      if 'nvme' in l.lower() or 'blk_update' in l.lower()
                      or 'reset' in l.lower() or 'timeout' in l.lower()]
        if nvme_lines:
            log.error(f"  dmesg NVMe 관련 ({len(nvme_lines)}줄):")
            for line in nvme_lines[-10:]:
                log.error(f"    {line}")
        else:
            log.error("  dmesg에 NVMe 관련 메시지 없음")

        # 2.5) FAIL CMD — 실패한 명령어 및 파라미터 전체 출력
        _nsid_str = (f"0x{seed.nsid_override:x} (override)"
                     if seed.nsid_override is not None else "1 (default)")
        _mut_parts = []
        if seed.opcode_override is not None:
            _mut_parts.append(f"opcode_override=0x{seed.opcode_override:02x}")
        if seed.nsid_override is not None:
            _mut_parts.append(f"nsid_override=0x{seed.nsid_override:x}")
        if seed.force_admin is not None:
            _mut_parts.append(f"force_admin={seed.force_admin}")
        if seed.data_len_override is not None:
            _mut_parts.append(f"data_len_override={seed.data_len_override}")
        _data_hex = fuzz_data[:64].hex() if fuzz_data else "N/A"
        _data_suffix = "..." if fuzz_data and len(fuzz_data) > 64 else ""
        _sep = "=" * 64
        log.error(_sep)
        log.error("  !! FAIL CMD !!")
        log.error(f"  cmd       : {cmd.name} ({cmd.cmd_type.name})")
        log.error(f"  opcode    : 0x{actual_opcode:02x}")
        log.error(f"  device    : {self.config.nvme_device}")
        log.error(f"  nsid      : {_nsid_str}")
        log.error(f"  cdw2      : 0x{seed.cdw2:08x}")
        log.error(f"  cdw3      : 0x{seed.cdw3:08x}")
        log.error(f"  cdw10     : 0x{seed.cdw10:08x}")
        log.error(f"  cdw11     : 0x{seed.cdw11:08x}")
        log.error(f"  cdw12     : 0x{seed.cdw12:08x}")
        log.error(f"  cdw13     : 0x{seed.cdw13:08x}")
        log.error(f"  cdw14     : 0x{seed.cdw14:08x}")
        log.error(f"  cdw15     : 0x{seed.cdw15:08x}")
        log.error(f"  data_len  : {len(fuzz_data) if fuzz_data else 0} bytes")
        log.error(f"  data(hex) : {_data_hex}{_data_suffix}")
        if _mut_parts:
            log.error(f"  mutations : {', '.join(_mut_parts)}")
        log.error(_sep)

        # 3) crash 저장
        self.crash_inputs.append((fuzz_data, cmd))
        try:
            self._save_crash(fuzz_data, seed, reason="timeout",
                             stuck_pcs=stuck_pcs, dmesg_snapshot=dmesg_snapshot)
            # 경로(버전 폴더 포함)는 로그에 남기지 않음 — 위치는 OUTPUT_DIR 로 알 수 있음.
            log.error("  Crash 데이터 저장 완료")
        except Exception as _save_exc:
            log.error(f"  Crash 데이터 저장 실패: {_save_exc}")

        # 3.5) 재현 TC replay 스크립트 생성 — crash_<ts>/ 안에 직접 생성하여
        # replay_<tag>.sh + replay_data_<tag>/ 가 함께 self-contained.
        _replay_tag = hashlib.md5(fuzz_data).hexdigest()[:8]
        log.warning(f"[TIMEOUT] 재현 TC 스크립트를 생성합니다 → {_logname(_crash_dir)}/")
        try:
            self._generate_replay_sh(_crash_dir, _replay_tag)
        except Exception as _replay_exc:
            log.warning(f"[REPLAY] replay .sh 생성 실패: {_replay_exc}")

        # 3.6) JLink 사용 전 OpenOCD를 항상 종료 — J-Link USB 점유 해제.
        # dump를 스킵하더라도 후속 JLink PC 모니터링 루프가 J-Link에 접근하므로
        # 여기서 shutdown이 누락되면 "Cannot connect to J-Link" 오류 발생.
        try:
            self._shutdown_openocd_for_jlink()
        except Exception as _sd_exc:
            log.warning(f"[JLINK] OpenOCD shutdown 예외: {_sd_exc}")

        # 3.7) JLink 메모리 덤프 (UFAS 이전)
        # st_mtime (Unix epoch) 과 비교할 거라 time.time() 사용.
        # time.monotonic() 은 uptime 기준이라 비교 시 항상 통과되어 filter 무력화됨.
        _dump_start_t = time.time()
        if self.config.enable_jlink_dump:
            log.warning("[TIMEOUT] JLink 메모리 덤프를 실행합니다...")
            try:
                self._run_jlink_dump()
            except Exception as _jlink_exc:
                log.warning(f"[JLINK DUMP] 예기치 않은 예외: {_jlink_exc}")
            if self.config.unsupported_skip:
                self._probe_device("after_jlink_dump")
        else:
            log.warning("[TIMEOUT] JLink 덤프 건너뜀 (--no-jlink-dump)")

        # v7.8: J-Link dump 직후 EngineErrInt 검사 → 미지원 명령이면 UFAS / artifact
        # 건너뛰고 power cycle 후 메인 루프 재개.
        if (self.config.unsupported_skip
                and self.config.enable_jlink_dump):
            _is_unsupported = False
            try:
                _is_unsupported = self._check_unsupported_after_jlink_dump(_dump_start_t)
            except Exception as _chk_exc:
                log.warning(f"[UnsupChk] 검사 중 예외: {_chk_exc}")
            self._probe_device("after_parser")
            if _is_unsupported:
                # SKIPPED.marker — crashes/crash_<ts>/ 안에 audit 파일
                try:
                    _marker_path = _crash_dir / "SKIPPED.marker"
                    _marker_path.write_text(
                        f"skipped_at  : {datetime.now().isoformat()}\n"
                        f"reason      : EngineErrInt detected in J-Link dump event log\n"
                        f"command     : {cmd.name} (opcode=0x{actual_opcode:02x})\n"
                        f"fuzz_data_md5: {hashlib.md5(fuzz_data).hexdigest()}\n"
                    )
                    log.warning(f"[UnsupChk] SKIPPED.marker 작성 → {_logname(_marker_path)}")
                except Exception as _mk_exc:
                    log.warning(f"[UnsupChk] SKIPPED.marker 작성 실패: {_mk_exc}")
                # 복구
                _rc_ok = self._recover_after_unsupported_skip()
                self.stats['unsupported_skipped'] = self.stats.get('unsupported_skipped', 0) + 1
                log.warning(f"[UnsupChk] unsupported_skipped 누적: "
                            f"{self.stats['unsupported_skipped']}회")
                if not _rc_ok:
                    log.error("[UnsupChk] 복구 실패 — _timeout_crash 로 메인 루프 종료")
                    self._timeout_crash = True
                # _timeout_crash 안 set → caller 가 ('continue',) 로 다음 mutation
                return

        # 3.7) UFAS 펌웨어 덤프
        if self.config.enable_ufas:
            log.warning("[TIMEOUT] UFAS 펌웨어 덤프를 실행합니다...")
            try:
                self._run_ufas_dump()
            except Exception as _ufas_exc:
                log.warning(f"[UFAS] _run_ufas_dump 예기치 않은 예외: {_ufas_exc}")
            log.warning("[UFAS] _run_ufas_dump 반환")
        else:
            log.warning("[TIMEOUT] UFAS 덤프 건너뜀 (--no-ufas)")

        # 3.8) 모든 dump 완료 후 artifact 수집 (crash 폴더에 날짜 폴더 생성)
        log.warning("[TIMEOUT] Crash artifact 수집을 시작합니다...")
        try:
            self._collect_crash_artifacts(_crash_time)
        except Exception as _art_exc:
            log.warning(f"[ARTIFACT] 수집 중 예외: {_art_exc}")

        # 4) SSD 펌웨어를 resume 상태로 유지 (불량 현상 보존)
        log.error(
            "  SSD 펌웨어를 resume 상태로 유지합니다. "
            "(halt하지 않음 — 불량 현상 보존)")

        # 5) nvme-cli PID 기록
        log.error("")
        if self._crash_nvme_pid is not None:
            pid_file = self.crashes_dir / "crash_nvme_pid.txt"
            try:
                pid_file.write_text(f"{self._crash_nvme_pid}\n")
            except OSError:
                pass
            log.error(
                f"  [참고] nvme-cli PID={self._crash_nvme_pid} "
                f"(D-state 대기 중)")
        timeout_val = self.config.nvme_kernel_timeout_sec
        log.error(
            f"  커널 reset까지 최대 {timeout_val}초 유예 "
            f"(nvme_core admin/io_timeout 설정값)")
        log.error("")

        # 6) PC 분석 완료 — OpenOCD + telnet 유지 (hang 상태 보존)
        # run()의 모니터링 루프에서 10초 간격으로 PC를 계속 찍기 위해
        # 여기서는 telnet을 닫지 않는다. OpenOCD kill 시 J-Link가 nSRST를
        # assert할 수 있어 펌웨어 상태가 바뀌므로 OpenOCD도 종료하지 않는다.
        if self.sampler._openocd_alive():
            log.warning("[TIMEOUT] OpenOCD + telnet 유지 — 시각화 후 PC 모니터링 진입")

        # 7) 플래그 설정 — caller가 break로 루프 탈출
        self._timeout_crash = True
        log.error(
            "  퍼징을 중단합니다. SSD와 NVMe 장치 상태를 "
            "그대로 유지합니다.")

    def _save_per_command_data(self):
        """명령어별 PC/trace 데이터를 JSON 파일로 저장"""
        graph_dir = self.output_dir / 'graphs'
        graph_dir.mkdir(parents=True, exist_ok=True)

        for cmd_name in self.cmd_pcs:
            pcs = self.cmd_pcs[cmd_name]
            traces = self.cmd_traces[cmd_name]

            if not pcs:
                continue

            # edges를 traces에서 도출
            edges: Set[Tuple[int, int]] = set()
            for trace in traces:
                for i in range(len(trace) - 1):
                    edges.add((trace[i], trace[i + 1]))

            data = {
                "command": cmd_name,
                "total_pcs": len(pcs),
                "total_edges": len(edges),
                "total_traces": len(traces),
                "pcs": sorted([hex(pc) for pc in pcs]),
                "edges": sorted([[hex(p), hex(c)] for p, c in edges]),
                "traces": [[hex(pc) for pc in trace] for trace in list(traces)[-50:]],
            }

            out_file = graph_dir / f"{cmd_name}_edges.json"
            with open(out_file, 'w') as f:
                json.dump(data, f, indent=2)
            log.info(f"[Graph] Saved {cmd_name}: {len(edges)} edges (from traces), "
                     f"{len(pcs)} PCs → {out_file}")

        # 전체 통합 데이터도 저장
        all_data = {}
        for cmd_name in self.cmd_pcs:
            if self.cmd_pcs[cmd_name]:
                edges_from_traces: Set[Tuple[int, int]] = set()
                for trace in self.cmd_traces[cmd_name]:
                    for i in range(len(trace) - 1):
                        edges_from_traces.add((trace[i], trace[i + 1]))
                all_data[cmd_name] = {
                    "pcs": len(self.cmd_pcs[cmd_name]),
                    "edges": len(edges_from_traces),
                }
        with open(graph_dir / 'summary.json', 'w') as f:
            json.dump(all_data, f, indent=2)

    def _generate_graphs(self):
        """그래프 생성 진입점.

        v7.6+: 명령별 CFG(.dot/.png)는 edge 수가 많아지면 가독성이 떨어져 의미를
        잃으므로 생성하지 않는다. 명령간 비교 차트만 생성.
        """
        graph_dir = self.output_dir / 'graphs'
        graph_dir.mkdir(parents=True, exist_ok=True)

        # 명령어 간 비교 차트 (matplotlib)
        self._generate_comparison_chart(graph_dir)

    def _generate_comparison_chart(self, graph_dir: Path):
        """명령어별 PC 수 / 실행 횟수 / global coverage 기여율 / RC 오류율 비교 차트 생성.

        v7.6: unknown_{admin|io}_op0x.. 라벨이 opcode마다 따로 잡혀 차트가 노이즈로
        가득 차는 문제를 해결하기 위해 unknown(admin)/unknown(io) 두 버킷으로 합산.
        개별 unknown opcode hit 통계는 _format_unknown_opcode_summary()에서 텍스트로 별도 보고.
        """
        try:
            _setup_matplotlib_chart_env()
            import matplotlib.pyplot as plt
        except ImportError:
            log.warning("[Graph] matplotlib 미설치 — 비교 차트 생략. "
                        "'pip install matplotlib' 로 설치 가능")
            return

        # --- v7.6: unknown 라벨 버킷팅 ---
        # 입력: cmd_pcs/cmd_stats/rc_stats 의 키 (track_key 단위)
        # 출력: known 키는 그대로 + unknown(admin)/unknown(io) 두 통합 키
        def _bucket(track_key: str) -> str:
            if track_key.startswith('unknown_admin_op0x'):
                return 'unknown(admin)'
            if track_key.startswith('unknown_io_op0x'):
                return 'unknown(io)'
            return track_key

        from collections import defaultdict as _dd
        bucket_pcs:   dict = _dd(set)      # bucket → unique PC set
        bucket_exec:  dict = _dd(int)      # bucket → 실행 횟수 합
        bucket_rc:    dict = _dd(lambda: _dd(int))   # bucket → {rc: count}
        bucket_has_trace: dict = _dd(bool) # bucket → has any traces

        for _k, _pcs in self.cmd_pcs.items():
            _b = _bucket(_k)
            if _pcs:
                bucket_pcs[_b] |= _pcs
        for _k in self.cmd_traces:
            if self.cmd_traces[_k]:
                bucket_has_trace[_bucket(_k)] = True
        for _k, _st in self.cmd_stats.items():
            bucket_exec[_bucket(_k)] += _st.get("exec", 0)
        for _k, _rd in self.rc_stats.items():
            _b = _bucket(_k)
            for _rc, _c in _rd.items():
                bucket_rc[_b][_rc] += _c

        cmd_names = []
        pc_counts = []
        trace_counts = []
        pc_pcts = []       # 명령어별 PC 수 / global_coverage 전체 * 100
        error_rates = []   # rc != 0 비율 (%)

        global_total = len(self.sampler.global_coverage) or 1

        # known 키 알파벳 정렬, unknown 두 버킷은 끝으로 고정
        _all_buckets = set(bucket_pcs) | set(bucket_has_trace)
        _known = sorted(b for b in _all_buckets
                        if not b.startswith('unknown('))
        _unknown = sorted(b for b in _all_buckets
                          if b.startswith('unknown('))
        for cmd_name in _known + _unknown:
            if bucket_pcs.get(cmd_name) or bucket_has_trace.get(cmd_name):
                cmd_names.append(cmd_name)
                n_pcs = len(bucket_pcs.get(cmd_name, set()))
                pc_counts.append(n_pcs)
                trace_counts.append(bucket_exec.get(cmd_name, 0))
                pc_pcts.append(100.0 * n_pcs / global_total)
                # RC 오류율
                rc_dist = bucket_rc.get(cmd_name, {})
                total_rc = sum(rc_dist.values())
                error_rc = sum(v for k, v in rc_dist.items() if k != 0)
                error_rates.append(100.0 * error_rc / total_rc if total_rc > 0 else 0.0)

        if not cmd_names:
            return

        fig, axes = plt.subplots(1, 4, figsize=(20, max(4, len(cmd_names) * 0.5 + 1.5)))
        fig.suptitle('Coverage per NVMe Command', fontsize=14, fontweight='bold')

        # 1) PC 수
        bars1 = axes[0].barh(cmd_names, pc_counts, color='steelblue')
        axes[0].set_xlabel('Unique PCs')
        axes[0].set_title('PCs per Command')
        _max1 = max(pc_counts) if pc_counts else 1
        for bar, val in zip(bars1, pc_counts):
            axes[0].text(bar.get_width() + _max1 * 0.01,
                         bar.get_y() + bar.get_height() / 2,
                         str(val), va='center', fontsize=9)

        # 2) Trace 수 (실행 횟수)
        bars2 = axes[1].barh(cmd_names, trace_counts, color='mediumseagreen')
        axes[1].set_xlabel('Traces Recorded')
        axes[1].set_title('Executions per Command')
        _max2 = max(trace_counts) if trace_counts else 1
        for bar, val in zip(bars2, trace_counts):
            axes[1].text(bar.get_width() + _max2 * 0.01,
                         bar.get_y() + bar.get_height() / 2,
                         str(val), va='center', fontsize=9)

        # 3) 명령어별 PC % (global_coverage 대비)
        bars3 = axes[2].barh(cmd_names, pc_pcts, color='coral')
        axes[2].set_xlabel('% of Global Coverage')
        axes[2].set_title(f'PC Coverage %\n(cmd PCs / global {global_total} PCs)')
        axes[2].set_xlim(0, max(max(pc_pcts) * 1.2, 1))
        for bar, val in zip(bars3, pc_pcts):
            axes[2].text(bar.get_width() + max(pc_pcts) * 0.01,
                         bar.get_y() + bar.get_height() / 2,
                         f'{val:.1f}%', va='center', fontsize=9)

        # 4) RC 오류율 (rc != 0 비율 %)
        # 색상: 오류율이 높을수록 붉은색 (0%=초록, 100%=빨강)
        bar_colors4 = [
            (min(1.0, r / 50.0), max(0.0, 1.0 - r / 50.0), 0.2)
            for r in error_rates
        ]
        bars4 = axes[3].barh(cmd_names, error_rates, color=bar_colors4)
        axes[3].set_xlabel('Error Rate (%)')
        axes[3].set_title('RC Error Rate\n(rc≠0 / total rc tracked)')
        axes[3].set_xlim(0, max(max(error_rates) * 1.2, 5))
        for bar, val in zip(bars4, error_rates):
            axes[3].text(bar.get_width() + 0.3,
                         bar.get_y() + bar.get_height() / 2,
                         f'{val:.1f}%', va='center', fontsize=9)

        plt.tight_layout()
        chart_file = graph_dir / 'command_comparison.png'
        plt.savefig(chart_file, dpi=150, bbox_inches='tight')
        plt.close()
        log.info(f"[Graph] 명령어 비교 차트 → {_logname(chart_file)}")

    def _generate_static_coverage_graphs(self):
        """정적 분석 커버리지 시각화 3종 생성 (파일 미로드 시 조용히 스킵).

        1. coverage_growth.png  — 성장 곡선 (code_cov% / funcs_cov% vs executions)
        2. firmware_map.png     — 펌웨어 주소 공간 커버리지 맵
        3. uncovered_funcs.png  — 미커버 함수 Top-30 (크기 순)
        """
        if not self._sa_loaded:
            return

        try:
            _setup_matplotlib_chart_env()
            import matplotlib.pyplot as plt
            import matplotlib.patches as mpatches
        except ImportError:
            log.warning("[StatGraph] matplotlib 미설치 — 정적 분석 그래프 생략")
            return

        graph_dir = self.output_dir / 'graphs'
        graph_dir.mkdir(parents=True, exist_ok=True)

        # ------------------------------------------------------------------ #
        # 1. Coverage growth curve  (v7.6: velocity + plateau + milestones)
        # ------------------------------------------------------------------ #
        if len(self._sa_cov_history) >= 2:
            execs    = [h[0] for h in self._sa_cov_history]
            elapsed  = [h[1] for h in self._sa_cov_history]   # wall-clock seconds
            c_pcts   = [h[2] for h in self._sa_cov_history]
            f_pcts   = [h[3] for h in self._sa_cov_history]

            # 상단: 누적 % 곡선, 하단: BB velocity bar (height_ratios로 비례)
            fig, (ax_top, ax_bot) = plt.subplots(
                2, 1, figsize=(12, 6.5),
                gridspec_kw={'height_ratios': [3, 1], 'hspace': 0.35},
                sharex=True,
            )
            if self._sa_total_bbs > 0:
                ax_top.plot(execs, c_pcts, color='steelblue', linewidth=1.7,
                            label=f'Basic Blocks ({self._sa_total_bbs:,})')
            if self._sa_total_funcs > 0:
                ax_top.plot(execs, f_pcts, color='coral', linewidth=1.7,
                            label=f'Functions ({self._sa_total_funcs:,})')

            ax_top.set_ylabel('Coverage (%)')
            ax_top.set_title('Coverage Growth')
            ax_top.legend(loc='lower right')
            _ymax = max(max(c_pcts, default=0), max(f_pcts, default=0)) * 1.15 + 1
            ax_top.set_ylim(0, _ymax)
            ax_top.grid(True, alpha=0.3)

            # --- 마일스톤 annotation (25/50/75% BB 도달 시점) ---
            if self._sa_total_bbs > 0 and c_pcts:
                milestones = [25.0, 50.0, 75.0, 90.0]
                _ms_label_y = _ymax * 0.95
                for ms in milestones:
                    if c_pcts[-1] < ms:
                        continue
                    # 최초로 ms를 넘긴 지점 찾기
                    for i, v in enumerate(c_pcts):
                        if v >= ms:
                            _ms_exec = execs[i]
                            _ms_t = elapsed[i]
                            _t_str = (f'{_ms_t/60:.1f}m' if _ms_t < 3600
                                      else f'{_ms_t/3600:.1f}h')
                            ax_top.axvline(_ms_exec, color='gray',
                                           linestyle=':', linewidth=0.7,
                                           alpha=0.55)
                            ax_top.annotate(
                                f'{int(ms)}%\n{_t_str}',
                                xy=(_ms_exec, ms),
                                xytext=(4, 0), textcoords='offset points',
                                color='dimgray', fontsize=7,
                                va='center')
                            break

            # --- Plateau 하이라이트 ---
            # window별로 BB% 증가량이 임계 미만이면 plateau로 표시.
            # window = 전체 길이의 5% (최소 3개 샘플)
            if self._sa_total_bbs > 0 and len(execs) >= 6:
                _win = max(3, len(execs) // 20)
                _plateau_thresh_pct = 0.5   # 0.5% 미만 증가 = plateau
                _in_plateau = False
                _plateau_start_idx = 0
                for i in range(_win, len(execs)):
                    _delta = c_pcts[i] - c_pcts[i - _win]
                    if _delta < _plateau_thresh_pct:
                        if not _in_plateau:
                            _in_plateau = True
                            _plateau_start_idx = i - _win
                    else:
                        if _in_plateau:
                            _in_plateau = False
                            ax_top.axvspan(execs[_plateau_start_idx], execs[i],
                                           color='#ffd966', alpha=0.18, zorder=0)
                if _in_plateau:
                    ax_top.axvspan(execs[_plateau_start_idx], execs[-1],
                                   color='#ffd966', alpha=0.18, zorder=0)

            # 최종 값 annotation
            if c_pcts:
                ax_top.annotate(f'{c_pcts[-1]:.1f}%',
                                xy=(execs[-1], c_pcts[-1]),
                                xytext=(8, 4), textcoords='offset points',
                                color='steelblue', fontsize=9, fontweight='bold')
            if f_pcts:
                ax_top.annotate(f'{f_pcts[-1]:.1f}%',
                                xy=(execs[-1], f_pcts[-1]),
                                xytext=(8, -12), textcoords='offset points',
                                color='coral', fontsize=9, fontweight='bold')

            # --- 하단: Coverage velocity (window별 새로 발견한 BB%) ---
            # 의미: 직전 snapshot 이후 추가된 BB 커버율 (BB% increment per window).
            # 막대 높이가 클수록 그 시간 동안 진행이 빨랐다는 뜻.
            # 0에 가까우면 포화 — 위 plateau 음영과 같은 정보를 다른 형태로 보여줌.
            if self._sa_total_bbs > 0 and len(execs) >= 2:
                _bar_x = execs[1:]
                _bar_w_arr = [execs[i] - execs[i-1] for i in range(1, len(execs))]
                _vel = [(c_pcts[i] - c_pcts[i-1]) for i in range(1, len(execs))]
                ax_bot.bar(
                    [_bar_x[i] - _bar_w_arr[i] / 2 for i in range(len(_bar_x))],
                    _vel,
                    width=[max(w, 1) * 0.9 for w in _bar_w_arr],
                    color='steelblue', alpha=0.55, edgecolor='none',
                )
                ax_bot.set_ylabel('New BB %\nper window', fontsize=8)
                ax_bot.set_title(
                    'Coverage velocity — new BB % discovered per window '
                    '(0 = saturated)',
                    fontsize=9, loc='left', pad=2)
                ax_bot.axhline(0, color='gray', linewidth=0.6)
                ax_bot.grid(True, alpha=0.25)
                ax_bot.tick_params(labelsize=8)

            ax_bot.set_xlabel('Executions')

            # --- 상단 X축: wall-clock time (twiny) ---
            ax_time = ax_top.twiny()
            ax_time.set_xlim(ax_top.get_xlim())

            total_elapsed = elapsed[-1] if elapsed[-1] > 0 else 1
            if total_elapsed < 3600:
                _unit, _div = 'min', 60.0
            else:
                _unit, _div = 'hr', 3600.0

            n_ticks = 6
            tick_execs = [execs[0] + (execs[-1] - execs[0]) * i / (n_ticks - 1)
                          for i in range(n_ticks)]
            import bisect as _bisect
            def _interp_elapsed(target_exec):
                if target_exec <= execs[0]:
                    return elapsed[0]
                if target_exec >= execs[-1]:
                    return elapsed[-1]
                idx = _bisect.bisect_left(execs, target_exec)
                t0, t1 = execs[idx - 1], execs[idx]
                e0, e1 = elapsed[idx - 1], elapsed[idx]
                frac = (target_exec - t0) / (t1 - t0) if t1 != t0 else 0
                return e0 + frac * (e1 - e0)

            tick_labels = [f'{_interp_elapsed(e) / _div:.1f}' for e in tick_execs]
            ax_time.set_xticks(tick_execs)
            ax_time.set_xticklabels(tick_labels, fontsize=8)
            ax_time.set_xlabel(f'Elapsed time ({_unit})', fontsize=9)

            # plateau / 마일스톤 범례 — 처음부터 다시 빌드 (matplotlib 버전 호환성)
            _legend_handles = []
            if self._sa_total_bbs > 0:
                _legend_handles.append(plt.Line2D(
                    [], [], color='steelblue', linewidth=1.7,
                    label=f'Basic Blocks ({self._sa_total_bbs:,})'))
            if self._sa_total_funcs > 0:
                _legend_handles.append(plt.Line2D(
                    [], [], color='coral', linewidth=1.7,
                    label=f'Functions ({self._sa_total_funcs:,})'))
            _legend_handles.append(mpatches.Patch(
                color='#ffd966', alpha=0.4, label='Plateau (Δ<0.5%/window)'))
            ax_top.legend(handles=_legend_handles, loc='lower right', fontsize=8)

            growth_file = graph_dir / 'coverage_growth.png'
            plt.savefig(growth_file, dpi=150, bbox_inches='tight')
            plt.close()
            log.info(f"[StatGraph] 성장 곡선 → {_logname(growth_file)}")

        # ------------------------------------------------------------------ #
        # 2. Firmware address-space map  (v7.6: BB gradient + 전체 함수 + Top-N)
        # ------------------------------------------------------------------ #
        if self._sa_func_entries and self._sa_total_funcs > 0:
            entries = self._sa_func_entries
            ends    = self._sa_func_ends
            names   = self._sa_func_names
            entered = self._sa_entered_funcs
            import bisect as _bisect_fm
            import numpy as _np_fm
            from matplotlib import cm as _cm_fm
            from matplotlib.colors import LinearSegmentedColormap as _LSC

            # --- 함수별 BB 커버율 계산 ---
            # 0.0 = not entered  /  0.0~1.0 = partial  /  1.0 = full
            # BB 파일 없으면 진입 여부만으로 0/1 fallback
            # 동시에 BB-weighted 평균을 위한 함수 내 total/covered BB 수도 누적.
            func_cov_pct: list = []
            _total_bbs_in_funcs = 0
            _cov_bbs_in_funcs   = 0
            _has_bb = self._sa_bb_starts is not None and self._sa_total_bbs > 0
            for i in range(len(entries)):
                entry = entries[i]
                end   = ends[i]
                _is_entered = entry in entered

                if _has_bb:
                    lo = _bisect_fm.bisect_left(self._sa_bb_starts, entry)
                    hi = _bisect_fm.bisect_left(self._sa_bb_starts, end)
                    _n_total = hi - lo
                    _n_cov = sum(1 for bb in self._sa_bb_starts[lo:hi]
                                 if bb in self._sa_covered_bbs)
                else:
                    _n_total = 0
                    _n_cov = 0

                _total_bbs_in_funcs += _n_total
                _cov_bbs_in_funcs   += _n_cov

                if not _is_entered:
                    func_cov_pct.append(0.0)
                elif not _has_bb:
                    func_cov_pct.append(1.0)            # BB 정보 없음 → 진입=full
                elif _n_total == 0:
                    func_cov_pct.append(1.0)            # BB 0개 함수 → 진입=full
                else:
                    func_cov_pct.append(_n_cov / _n_total)

            n_funcs = len(entries)

            # --- treemap 격자: 전체 함수를 cols × rows 배치 ---
            # 함수 수에 따라 적응형 cols 선택 — 가로세로 비율 ~2:1 유지
            cols = max(20, int(_np_fm.ceil(_np_fm.sqrt(n_funcs * 2))))
            rows = (n_funcs + cols - 1) // cols

            # cell 크기 (인치) — 함수 1000개 이상이면 작게
            _cell = 0.20 if n_funcs > 1500 else (0.28 if n_funcs > 500 else 0.42)
            fig_w = max(8.0, cols * _cell + 1.0)
            fig_h = max(4.0, rows * _cell + 1.5)

            fig, ax = plt.subplots(figsize=(fig_w, fig_h))
            ax.set_xlim(0, cols)
            ax.set_ylim(0, rows)
            ax.set_aspect('equal')
            ax.axis('off')

            fig.patch.set_facecolor('#1a1a2e')
            ax.set_facecolor('#1a1a2e')

            # 색상 그라데이션: 미진입(어두운 보라) → 부분(노랑) → 풀(밝은 초록)
            cmap_fm = _LSC.from_list(
                'cov_grad',
                ['#444466', '#e07a3a', '#e9c46a', '#52b788', '#00c875'])

            # 각 함수 cell 그리기 (entry 순으로 좌→우, 위→아래)
            for func_i in range(n_funcs):
                row = func_i // cols
                col = func_i % cols
                y   = rows - 1 - row

                pct = func_cov_pct[func_i]
                if pct == 0.0:
                    color = '#444466'      # 미진입 — 어두운 회보라
                elif pct >= 0.999:
                    color = '#00c875'      # 완전 커버 — 밝은 초록
                else:
                    color = cmap_fm(0.1 + 0.85 * pct)   # partial: 그라데이션

                # cell 크기는 함수 크기와 약간 비례(가독성 유지 위해 변동 작게)
                func_size = ends[func_i] - entries[func_i]
                w = 0.92
                h = 0.5 + min(0.42, func_size / 4096.0)
                rect = mpatches.Rectangle(
                    (col + (1 - w) / 2, y + (1 - h) / 2), w, h,
                    facecolor=color, edgecolor='none', alpha=0.92,
                    linewidth=0)
                ax.add_patch(rect)

            # --- Top-N 라벨: 가장 큰 미진입 + 가장 큰 진입 (각 5개) ---
            _top_n = 5 if n_funcs < 800 else 4
            # 미진입 중 사이즈 상위
            _unentered = [(i, ends[i] - entries[i]) for i in range(n_funcs)
                          if func_cov_pct[i] == 0.0]
            _unentered.sort(key=lambda x: x[1], reverse=True)
            for rank, (func_i, sz) in enumerate(_unentered[:_top_n]):
                row = func_i // cols
                col = func_i % cols
                y   = rows - 1 - row
                _short_name = names[func_i][:18]
                ax.annotate(
                    f'{_short_name}\n({sz}B)',
                    xy=(col + 0.5, y + 0.5),
                    xytext=(min(cols + 1, col + 1.2),
                            max(0, min(rows - 1, y - 0.8 - rank * 0.4))),
                    fontsize=6.5, color='#ffb4b4',
                    arrowprops=dict(arrowstyle='-', color='#ffb4b4',
                                    lw=0.5, alpha=0.6))

            # 진입했으나 사이즈 크고 BB 커버 낮은 함수 상위
            _partial = [(i, ends[i] - entries[i], func_cov_pct[i])
                        for i in range(n_funcs)
                        if 0.0 < func_cov_pct[i] < 0.5]
            _partial.sort(key=lambda x: x[1], reverse=True)
            for rank, (func_i, sz, pct) in enumerate(_partial[:_top_n]):
                row = func_i // cols
                col = func_i % cols
                y   = rows - 1 - row
                _short_name = names[func_i][:18]
                ax.annotate(
                    f'{_short_name}\n({sz}B, {int(pct*100)}%)',
                    xy=(col + 0.5, y + 0.5),
                    xytext=(max(-2, col - 4.2),
                            max(0, min(rows - 1, y + 0.8 + rank * 0.4))),
                    fontsize=6.5, color='#ffe4a3',
                    arrowprops=dict(arrowstyle='-', color='#ffe4a3',
                                    lw=0.5, alpha=0.6))

            n_cov   = len(entered)
            n_uncov = n_funcs - n_cov
            cov_pct = 100.0 * n_cov / n_funcs
            # 함수 내 전체 BB 대비 커버된 BB 비율 — 진짜 BB-weighted.
            # (함수별 % 단순 평균이 아닌 Σ covered / Σ total 가중 평균)
            _avg_bb_pct = (100.0 * _cov_bbs_in_funcs / _total_bbs_in_funcs
                           if _total_bbs_in_funcs > 0 else 0.0)

            # 그라데이션 범례
            _sm = _cm_fm.ScalarMappable(cmap=cmap_fm,
                                        norm=plt.Normalize(vmin=0.0, vmax=1.0))
            _sm.set_array([])
            cbar = fig.colorbar(_sm, ax=ax, shrink=0.4, pad=0.01,
                                orientation='vertical')
            cbar.set_label('BB coverage / func', color='white', fontsize=8)
            cbar.ax.tick_params(colors='white', labelsize=7)
            cbar.outline.set_edgecolor('gray')

            ax.set_title(
                f'Firmware Function Map  —  '
                f'entered {cov_pct:.1f}% ({n_cov}/{n_funcs})  '
                f'·  BB-weighted {_avg_bb_pct:.1f}%',
                color='white', fontsize=11, pad=8)

            map_file = graph_dir / 'firmware_map.png'
            plt.savefig(map_file, dpi=160, bbox_inches='tight',
                        facecolor=fig.get_facecolor())
            plt.close()
            log.info(f"[StatGraph] 펌웨어 맵 → {_logname(map_file)} "
                     f"({n_funcs} funcs / {cols}×{rows} grid)")

        # v7.6: uncovered_funcs.png 제거. firmware_map의 Top-N 라벨 + 그라데이션이
        # 같은 정보를 더 효율적으로 보여주고, 우선순위 분석은 텍스트 로그가 더 효과적.
        # 종료 summary에서 _collect_uncov_funcs()로 동일한 데이터를 텍스트로 출력함.

    def _collect_uncov_funcs(self):
        """미진입(not_entered) + 부분커버(partial) 함수 목록을 크기 내림차순으로 수집.
        return: (not_entered_list, partial_list)
          not_entered_list: [(name, size, entry), ...]
          partial_list:     [(name, size, entry, bb_cov_pct), ...]   (pct는 0~100)

        v7.6: 기존 uncovered_funcs.png 생성용 로직을 헬퍼로 추출 — 종료 summary
        텍스트 출력에서 재사용.
        """
        if not (self._sa_func_entries and self._sa_total_funcs > 0):
            return [], []
        import bisect as _bisect_sc
        entered = self._sa_entered_funcs
        not_entered_list = []
        partial_list = []
        for i in range(len(self._sa_func_entries)):
            entry = self._sa_func_entries[i]
            end   = self._sa_func_ends[i]
            name  = self._sa_func_names[i]
            size  = end - entry
            if entry not in entered:
                not_entered_list.append((name, size, entry))
                continue
            if self._sa_bb_starts is not None and self._sa_total_bbs > 0:
                lo = _bisect_sc.bisect_left(self._sa_bb_starts, entry)
                hi = _bisect_sc.bisect_left(self._sa_bb_starts, end)
                func_bbs = self._sa_bb_starts[lo:hi]
                if func_bbs:
                    n_cov_bb = sum(1 for bb in func_bbs if bb in self._sa_covered_bbs)
                    bb_pct = 100.0 * n_cov_bb / len(func_bbs)
                    if bb_pct < 100.0:
                        partial_list.append((name, size, entry, bb_pct))
            elif self._sa_total_bbs == 0:
                partial_list.append((name, size, entry, float('nan')))
        not_entered_list.sort(key=lambda x: x[1], reverse=True)
        partial_list.sort(key=lambda x: x[1], reverse=True)
        return not_entered_list, partial_list

    def _generate_heatmaps(self):
        """1D 주소 커버리지 히트맵 + 2D edge 히트맵 생성"""
        try:
            _setup_matplotlib_chart_env()
            import matplotlib.pyplot as plt
            import numpy as np
        except ImportError:
            log.warning("[Heatmap] matplotlib/numpy 미설치 — 히트맵 생략. "
                        "'pip install matplotlib numpy' 로 설치 가능")
            return

        graph_dir = self.output_dir / 'graphs'
        graph_dir.mkdir(parents=True, exist_ok=True)

        addr_start = self.config.addr_range_start if self.config.addr_range_start is not None else 0
        addr_end = self.config.addr_range_end if self.config.addr_range_end is not None else 0x147FFF
        addr_range = addr_end - addr_start + 1

        if not self.sampler.global_coverage:
            log.warning("[Heatmap] No coverage data to visualize")
            return

        # Bin 크기 결정 — 1D heatmap만 (v7.6: per-cmd / 2D edge 제거)
        bin_size_1d = max(256, addr_range // 512)
        n_bins_1d = (addr_range + bin_size_1d - 1) // bin_size_1d

        # 1D Global Address Coverage Heatmap
        # v7.6: per-command strip과 2D edge heatmap은 제거.
        # - per-command: command_comparison/firmware_map에서 더 명확하게 보여줌
        # - 2D edge: PC 샘플링은 sequential trace가 아니라 "샘플 인접" 이라 진짜 edge가 아님 — 노이즈
        fig, ax = plt.subplots(figsize=(18, 3.2))

        fig.suptitle(
            f'Firmware Coverage Heatmap  '
            f'(bin size = {bin_size_1d:,} B = {bin_size_1d // 4} instrs, '
            f'range 0x{addr_start:X}–0x{addr_end:X})',
            fontsize=13, fontweight='bold')

        def _hex_formatter(x, pos):
            return f'0x{int(x):X}'

        # Global (전체 명령어 합산)
        global_bins = np.zeros(n_bins_1d)
        for pc in self.sampler.global_coverage:
            if addr_start <= pc <= addr_end:
                idx = (pc - addr_start) // bin_size_1d
                if 0 <= idx < n_bins_1d:
                    global_bins[idx] += 1

        covered_bins = int(np.count_nonzero(global_bins))
        im = ax.imshow(global_bins.reshape(1, -1), aspect='auto', cmap='YlOrRd',
                       extent=[addr_start, addr_end, 0, 1], interpolation='nearest')
        ax.set_yticks([])
        ax.set_title(
            f'ALL  —  {len(self.sampler.global_coverage)} PCs, '
            f'{covered_bins}/{n_bins_1d} bins covered '
            f'({100 * covered_bins / n_bins_1d:.1f}%)',
            fontsize=9, loc='left')
        ax.xaxis.set_major_formatter(plt.FuncFormatter(_hex_formatter))
        ax.tick_params(axis='x', labelsize=7)
        cb = fig.colorbar(im, ax=ax, orientation='vertical',
                          fraction=0.012, pad=0.008, shrink=0.85)
        cb.set_label('PC hits/bin', fontsize=7)
        cb.ax.tick_params(labelsize=6)

        # --- v7.6: Hot spot 라벨 — 가장 활발한 top-3 bin 주소 표시 ---
        # 가독성을 위해 strip 위에 점선 + 화살표로 주소 annotation
        _ymax_val = float(global_bins.max()) if global_bins.size > 0 else 0
        if _ymax_val > 0:
            _top3_idx = sorted(np.argsort(global_bins)[-3:][::-1])  # 주소 순 정렬
            for _rank, _bi in enumerate(_top3_idx):
                if global_bins[_bi] == 0:
                    continue
                _bin_addr = addr_start + int(_bi) * bin_size_1d
                # strip 안에서의 x 위치 (extent 기반)
                ax.annotate(
                    f'hot #{_rank + 1}: 0x{_bin_addr:X}\n({int(global_bins[_bi])} PCs)',
                    xy=(_bin_addr + bin_size_1d / 2, 1.0),
                    xytext=(_bin_addr + bin_size_1d / 2, 1.4 + 0.25 * _rank),
                    fontsize=7, color='#5a2d0c',
                    ha='center',
                    arrowprops=dict(arrowstyle='->', color='#a04020',
                                    lw=0.6, alpha=0.7),
                    annotation_clip=False)

        heatmap_file = graph_dir / 'coverage_heatmap_1d.png'
        plt.savefig(heatmap_file, dpi=150, bbox_inches='tight')
        plt.close()
        log.info(f"[Heatmap] 1D global coverage heatmap → {_logname(heatmap_file)} "
                 f"(bin={bin_size_1d}B)")

    def _generate_mutation_chart(self):
        """MOpt operator 효율 + 입력 소스 분포 차트 생성 → graphs/mutation_chart.png"""
        try:
            _setup_matplotlib_chart_env()
            import matplotlib.pyplot as plt
            import numpy as np
        except ImportError:
            log.warning("[MutChart] matplotlib/numpy 미설치 — mutation 차트 생략.")
            return

        graph_dir = self.output_dir / 'graphs'
        graph_dir.mkdir(parents=True, exist_ok=True)

        op_names = ['bitflip1', 'int8', 'int16', 'int32',
                    'arith8', 'arith16', 'arith32', 'randbyte',
                    'byteswap', 'delete', 'insert', 'overwrite',
                    'splice', 'shuffle', 'blockfill', 'asciiint']

        # --- 데이터 준비 ---
        active_ops = [(op_names[i], self.mopt_finds[i], self.mopt_uses[i])
                      for i in range(self.NUM_MUTATION_OPS)
                      if self.mopt_uses[i] > 0]

        ms = self.mutation_stats
        total_execs = self.executions or 1

        fig, axes = plt.subplots(1, 3, figsize=(18, max(4, len(active_ops) * 0.32 + 2.0)))
        fig.suptitle('Mutation Effectiveness',
                     fontsize=13, fontweight='bold')

        # ---- subplot 1: MOpt operator efficiency (finds / uses ratio) ----
        if active_ops:
            # 효율 기준 내림차순 정렬
            active_ops_s = sorted(active_ops, key=lambda x: x[1] / x[2], reverse=True)
            names_s  = [o[0] for o in active_ops_s]
            finds_s  = [o[1] for o in active_ops_s]
            uses_s   = [o[2] for o in active_ops_s]
            ratios_s = [f / u for f, u in zip(finds_s, uses_s)]

            ax1 = axes[0]
            colors_r = plt.cm.RdYlGn(  # type: ignore[attr-defined]
                [min(1.0, r / (max(ratios_s) + 1e-9)) for r in ratios_s])
            bars_r = ax1.barh(range(len(names_s)), ratios_s,
                              color=colors_r, edgecolor='none', height=0.7)
            ax1.set_yticks(range(len(names_s)))
            ax1.set_yticklabels(names_s, fontsize=9)
            ax1.invert_yaxis()
            ax1.set_xlabel('finds / uses  (coverage gain rate)')
            ax1.set_title('MOpt Operator Efficiency')
            ax1.grid(True, axis='x', alpha=0.3)
            _max_r = max(ratios_s) if ratios_s else 1
            for bar, val in zip(bars_r, ratios_s):
                ax1.text(bar.get_width() + _max_r * 0.01,
                         bar.get_y() + bar.get_height() / 2,
                         f'{val:.4f}', va='center', fontsize=8)
        else:
            axes[0].text(0.5, 0.5, 'No MOpt data yet',
                         ha='center', va='center', transform=axes[0].transAxes)
            axes[0].set_title('MOpt Operator Efficiency')

        # ---- subplot 2: MOpt operator uses count (log scale) ----
        if active_ops:
            # 사용 횟수 기준 정렬 (내림차순)
            active_ops_u = sorted(active_ops, key=lambda x: x[2], reverse=True)
            names_u  = [o[0] for o in active_ops_u]
            uses_u   = [o[2] for o in active_ops_u]
            finds_u  = [o[1] for o in active_ops_u]

            ax2 = axes[1]
            x_pos = np.arange(len(names_u))
            w = 0.38
            ax2.barh(x_pos + w / 2, uses_u, height=w,
                     color='steelblue', alpha=0.8, label='uses')
            ax2.barh(x_pos - w / 2, finds_u, height=w,
                     color='tomato', alpha=0.8, label='finds (new cov)')
            ax2.set_yticks(x_pos)
            ax2.set_yticklabels(names_u, fontsize=9)
            ax2.invert_yaxis()
            ax2.set_xscale('log')
            ax2.set_xlabel('Count (log scale)')
            ax2.set_title('MOpt Uses vs Finds')
            ax2.legend(fontsize=9, loc='lower right')
            ax2.grid(True, axis='x', alpha=0.3)
        else:
            axes[1].text(0.5, 0.5, 'No MOpt data yet',
                         ha='center', va='center', transform=axes[1].transAxes)
            axes[1].set_title('MOpt Uses vs Finds')

        # ---- subplot 3: 입력 소스 분포 + mutation 유형 분포 ----
        ax3 = axes[2]

        # 입력 소스
        src_labels = ['corpus\nmutated', 'random\ngen']
        src_values = [ms.get('corpus_mutated', 0), ms.get('random_gen', 0)]

        # mutation 유형 (소스 외 필드)
        mut_labels = ['opcode\noverride', 'nsid\noverride', 'admin↔io\nswap',
                      'datalen\noverride', 'schema\nfield',
                      'datalen\nnlb', 'datalen\nmdts',
                      'lba_pair\n64bit', 'dsm\nstructured', 'copy\nstructured',
                      'seq\nbuiltin']
        mut_values = [ms.get('opcode_override', 0), ms.get('nsid_override', 0),
                      ms.get('force_admin_swap', 0), ms.get('data_len_override', 0),
                      ms.get('schema_field', 0),
                      ms.get('datalen_nlb', 0), ms.get('datalen_mdts', 0),
                      ms.get('lba_pair_64bit', 0), ms.get('dsm_structured', 0),
                      ms.get('copy_structured', 0), ms.get('seq_builtin', 0)]

        all_labels = src_labels + mut_labels
        all_values = src_values + mut_values
        all_colors = ['#4e9af1', '#a8d8ea',  # 소스 (파란 계열)
                      '#f4a261', '#e76f51', '#e9c46a', '#2a9d8f', '#8ecae6',  # 기존 mutation
                      '#b5e48c', '#95d5b2', '#74c69d', '#52b788',             # v7.4 신규
                      '#1a936f']

        bars3 = ax3.barh(range(len(all_labels)), all_values,
                         color=all_colors, edgecolor='none', height=0.65)
        ax3.set_yticks(range(len(all_labels)))
        ax3.set_yticklabels(all_labels, fontsize=9)
        ax3.invert_yaxis()
        ax3.set_xlabel('Count')
        ax3.set_title(f'Input Source & Mutation Distribution\n'
                      f'(total execs: {total_execs:,})')
        ax3.grid(True, axis='x', alpha=0.3)

        _max_v = max(all_values) if all_values else 1
        for bar, val in zip(bars3, all_values):
            pct = 100.0 * val / total_execs
            ax3.text(bar.get_width() + _max_v * 0.01,
                     bar.get_y() + bar.get_height() / 2,
                     f'{val:,}  ({pct:.1f}%)', va='center', fontsize=8)

        # 소스 / mutation 구분선
        ax3.axhline(len(src_labels) - 0.5, color='gray', linestyle='--',
                    linewidth=0.8, alpha=0.6)
        ax3.text(0, len(src_labels) - 0.5, '  ▲ source  /  mutation ▼ ',
                 va='center', fontsize=7, color='gray')

        plt.tight_layout()
        chart_file = graph_dir / 'mutation_chart.png'
        plt.savefig(chart_file, dpi=150, bbox_inches='tight')
        plt.close()
        log.info(f"[MutChart] mutation 차트 → {_logname(chart_file)}")

    def _generate_csfuzz_dynamics(self):
        """CSFuzz §III-C/D 동역학 시각화 — graphs/csfuzz_dynamics.png.

        3-panel 세로 구성 (sharex):
          1. p 값 추이 + P_MIN/P_MAX guideline
          2. 누적 corpus 크기 (NC1=edge, NC2=state)
          3. m1 (edge per-cmd) vs m2 (state per-cmd normalized) 비교

        데이터: self._csfuzz_history = [(exec, p, m1, m2_norm, NC1, NC2), ...]
        --no-state 시 history가 비어있으므로 호출 자체를 스킵한다.
        """
        if not self.config.state_enabled:
            return
        if not self._csfuzz_history or len(self._csfuzz_history) < 2:
            return

        try:
            _setup_matplotlib_chart_env()
            import matplotlib.pyplot as plt
        except ImportError:
            log.warning("[CSFuzzViz] matplotlib 미설치 — csfuzz 동역학 그래프 생략")
            return

        graph_dir = self.output_dir / 'graphs'
        graph_dir.mkdir(parents=True, exist_ok=True)

        execs = [h[0] for h in self._csfuzz_history]
        p_vals = [h[1] for h in self._csfuzz_history]
        m1_vals = [h[2] for h in self._csfuzz_history]
        m2_vals = [h[3] for h in self._csfuzz_history]
        nc1_vals = [h[4] for h in self._csfuzz_history]
        nc2_vals = [h[5] for h in self._csfuzz_history]

        fig, axes = plt.subplots(
            3, 1, figsize=(11, 8),
            gridspec_kw={'height_ratios': [1.2, 1.0, 1.0], 'hspace': 0.3},
            sharex=True,
        )
        fig.suptitle('CSFuzz Dynamics  (edge C1 vs state C2)',
                     fontsize=12, fontweight='bold', y=0.995)

        # --- Panel 1: p 추이 ---
        ax_p = axes[0]
        ax_p.plot(execs, p_vals, color='#1a936f', linewidth=1.8,
                  marker='o', markersize=3,
                  label='p (state corpus selection prob.)')
        # P_MIN / P_MAX guideline — 코드 내 clamp 범위(0.1, 0.9)
        ax_p.axhline(0.1, color='#cc6666', linestyle=':', linewidth=0.8,
                     alpha=0.7, label='P_MIN = 0.1')
        ax_p.axhline(0.9, color='#cc6666', linestyle=':', linewidth=0.8,
                     alpha=0.7, label='P_MAX = 0.9')
        ax_p.axhline(0.5, color='gray', linestyle='--', linewidth=0.6,
                     alpha=0.5)
        ax_p.set_ylabel('p', fontsize=9)
        ax_p.set_ylim(0.0, 1.0)
        ax_p.set_title(f'p evolution  ·  final p = {p_vals[-1]:.3f}',
                       fontsize=10, loc='left')
        ax_p.legend(loc='best', fontsize=7, ncol=2)
        ax_p.grid(True, alpha=0.3)

        # --- Panel 2: corpus 크기 ---
        ax_n = axes[1]
        ax_n.plot(execs, nc1_vals, color='steelblue', linewidth=1.7,
                  marker='o', markersize=3, label='NC1 (edge corpus)')
        ax_n.plot(execs, nc2_vals, color='coral', linewidth=1.7,
                  marker='s', markersize=3, label='NC2 (state corpus)')
        ax_n.fill_between(execs, nc1_vals, alpha=0.15, color='steelblue')
        ax_n.fill_between(execs, nc2_vals, alpha=0.15, color='coral')
        ax_n.set_ylabel('Corpus size', fontsize=9)
        ax_n.set_title(
            f'Corpus growth  ·  NC1={nc1_vals[-1]}  NC2={nc2_vals[-1]}',
            fontsize=10, loc='left')
        ax_n.legend(loc='best', fontsize=8)
        ax_n.grid(True, alpha=0.3)

        # --- Panel 3: m1 vs m2 (per-command 스케일) ---
        ax_m = axes[2]
        ax_m.plot(execs, m1_vals, color='steelblue', linewidth=1.5,
                  marker='o', markersize=3, label='m1 (edge per-cmd)')
        ax_m.plot(execs, m2_vals, color='coral', linewidth=1.5,
                  marker='s', markersize=3,
                  label='m2 (state per-cmd, normalized)')
        # 0 reference
        ax_m.axhline(0, color='gray', linestyle='-', linewidth=0.5, alpha=0.5)
        ax_m.set_xlabel('Executions')
        ax_m.set_ylabel('Reward rate', fontsize=9)
        ax_m.set_title('m1 vs m2  (δ ∝ m1·NC1⁻¹ - m2·NC2⁻¹ → p update)',
                       fontsize=10, loc='left')
        ax_m.legend(loc='best', fontsize=8)
        ax_m.grid(True, alpha=0.3)

        out_file = graph_dir / 'csfuzz_dynamics.png'
        plt.savefig(out_file, dpi=150, bbox_inches='tight')
        plt.close()
        log.info(f"[CSFuzzViz] CSFuzz dynamics → {_logname(out_file)} "
                 f"({len(self._csfuzz_history)} updates)")

    def _collect_stats(self) -> dict:
        elapsed = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        return {
            'version': self.VERSION,
            'executions': self.executions,
            'corpus_size': len(self.corpus),
            'crashes': len(self.crash_inputs),
            'coverage_unique_pcs': len(self.sampler.global_coverage),
            'total_samples': self.sampler.total_samples,
            'interesting_inputs': self.sampler.interesting_inputs,
            'elapsed_seconds': elapsed,
            'exec_per_sec': self.executions / elapsed if elapsed > 0 else 0,
            'command_stats': self.cmd_stats,
            'rc_stats': {k: dict(v) for k, v in self.rc_stats.items()},
            'mutation_stats': dict(self.mutation_stats),
            'actual_opcode_dist': dict(self.actual_opcode_dist),
            'passthru_stats': dict(self.passthru_stats),
        }

    def _print_status(self, stats: dict, last_samples: int = 0,
                      window_eps: float = 0.0):
        ps_tag = f" | {self._current_combo.label}" if self.config.pm_inject_prob > 0 else ""
        state_tag = (f" | state-cov: {len(self.state_cov_map)} "
                     f"state-corpus: {len(self.state_corpus)}"
                     if self.config.state_enabled else "")
        _seq_cnt = sum(1 for s in self.corpus if isinstance(s, SequenceSeed))
        _seq_run = self.mutation_stats.get('seq_builtin', 0)
        log.warning(f"[Stats] exec: {stats['executions']:,} | "
                 f"corpus: {stats['corpus_size']}(seq:{_seq_cnt}) | "
                 f"pcs: {stats['coverage_unique_pcs']:,} | "
                 f"exec/s: {window_eps:.1f} | "
                 f"seq_run: {_seq_run}"
                 f"{ps_tag}{state_tag}")
        if self._sa_loaded:
            sa_parts = []
            if self._sa_total_bbs > 0:
                n_bb = len(self._sa_covered_bbs)
                pct  = 100.0 * n_bb / self._sa_total_bbs
                sa_parts.append(f"BB: {pct:.1f}% ({n_bb:,}/{self._sa_total_bbs:,})")
            if self._sa_total_funcs > 0:
                n_f  = len(self._sa_entered_funcs)
                fpct = 100.0 * n_f / self._sa_total_funcs
                sa_parts.append(f"funcs: {n_f}/{self._sa_total_funcs} ({fpct:.1f}%)")
            if sa_parts:
                log.warning(f"[StatCov] {' | '.join(sa_parts)}")

    def _run_pm_openocdless_test(self):
        """OpenOCD 없이 PCIe/NVMe PM 조합만 독립 검증한다."""
        if self.config.pm_inject_prob <= 0:
            log.error("[PM-Test] --allow-no-openocd 는 --pm 과 함께 사용해야 합니다.")
            return

        log.warning("=" * 60)
        log.warning("[PM-Test] OpenOCD 없이 PM 조합 테스트 모드 진입")
        log.warning("[PM-Test] coverage/diagnose/fuzzing loop는 실행하지 않습니다.")
        log.warning("=" * 60)

        if self.config.enable_por:
            log.warning("[PM-Test] POR 이후 PCIe rescan/L0 초기화를 수행합니다.")
            self._por_pcie_rescan()

        self._detect_pcie_info()
        if self._pcie_bdf and self._pcie_cap_offset is not None:
            self._set_pcie_l_state(PCIeLState.L0)

        self._apst_disable()
        self._keepalive_disable()

        preflight_ok = self._pm_preflight_check()
        if not preflight_ok:
            log.warning("[PM-Test] PM preflight에서 실패 조합이 감지되었습니다.")

        # v7.7: S1/S2 perturbation preflight — POWER_COMBOS 검증 직후 실행
        self._pm_preflight_s1_s2()

        if self.config.pm_test_cycles <= 0:
            log.warning("[PM-Test] 추가 cycle 없음 (--pm-test-cycles N 으로 활성화)")
            return

        log.warning(f"[PM-Test] 랜덤 PM cycle {self.config.pm_test_cycles}회 시작")
        baseline = POWER_COMBOS[0]
        for idx in range(self.config.pm_test_cycles):
            combo = random.choice(POWER_COMBOS)
            log.warning(f"[PM-Test] cycle {idx + 1}/{self.config.pm_test_cycles}: {combo.label}")
            try:
                if not self._set_power_combo(combo):
                    log.warning(f"[PM-Test] {combo.label} 진입 실패 — 스킵 (rollback 자동 수행)")
                    # 진입 실패 시 _set_pcie_l_state 내 rollback이 이미 수행됨.
                    # _nonop_restore 호출 금지 — CLKREQ# deassert가 된 적 없는데
                    # assert를 시도하게 되는 부작용 발생.
                    continue
                settle = self._ps_settle.get(combo.nvme_ps, 0.05)
                if combo.pcie_d == PCIeDState.D3:
                    settle += D3_EXTRA_S
                time.sleep(settle)

                verify = self._pm_verify_combo(combo)
                for key in ("pmu", "nvme_ps", "d_state", "l_state_ep", "l_state_rp", "l1ss"):
                    if key in verify:
                        log.warning(f"    [verify] {key:<10}: {verify[key]}")

                if self._is_nonop_combo(combo):
                    restored = self._nonop_restore(combo)
                    self._current_combo = restored
                    self._current_ps = restored.nvme_ps
                else:
                    self._set_power_combo(baseline)
                    self._current_combo = baseline
                    self._current_ps = baseline.nvme_ps
                time.sleep(RESTORE_SETTLE_S)
            except Exception as e:
                log.warning(f"[PM-Test] cycle 예외: {e}")

        log.warning("[PM-Test] 완료")

    def _settle_sweep_run_reps(
        self, combo_list, baseline, reps: int
    ) -> tuple[int, int, dict]:
        """settle_val이 config에 세팅된 상태로 reps회 PM 진입/verify/복귀 반복.
        반환: (pass_cnt, total_cnt, per_combo_stats)
          per_combo_stats: {combo: {'pass': int, 'total': int}}
        """
        pass_cnt   = 0
        total      = 0
        per_combo: dict = {}
        for rep in range(reps):
            combo = combo_list[rep % len(combo_list)]
            total += 1
            cs = per_combo.setdefault(combo, {'pass': 0, 'total': 0})
            cs['total'] += 1

            if not self._set_power_combo(baseline):
                log.warning(f"  rep{rep+1}: [FAIL] baseline 진입 실패")
                self._nonop_restore(baseline)
                time.sleep(RESTORE_SETTLE_S)
                continue
            time.sleep(RESTORE_SETTLE_S)

            ok = self._set_power_combo(combo)
            if not ok:
                log.warning(f"  rep{rep+1}: [FAIL] {combo} 진입 실패")
                self._nonop_restore(combo)
                self._current_combo = baseline
                time.sleep(RESTORE_SETTLE_S)
                continue

            verify  = self._pm_verify_combo(combo)
            pmu_raw = verify.get('pmu', '')
            pmu_ok  = bool(pmu_raw) and 'FAIL' not in pmu_raw and 'ERR' not in pmu_raw
            l_ok    = 'OK' in verify.get('l_state_ep', '')
            passed  = pmu_ok and l_ok
            result  = 'PASS' if passed else f'FAIL(pmu={pmu_ok},l={l_ok})'
            log.warning(
                f"  rep{rep+1}: [{result}]  {combo}  "
                f"pmu={pmu_raw!r}  l_ep={verify.get('l_state_ep','?')}")
            if passed:
                pass_cnt    += 1
                cs['pass']  += 1

            self._nonop_restore(combo)
            self._current_combo = baseline
            self._current_ps    = baseline.nvme_ps
            time.sleep(RESTORE_SETTLE_S)

        return pass_cnt, total, per_combo

    def _run_settle_sweep(self):
        """L1.2 pre-deassert settle 최솟값 통계 탐색.

        Phase 1: sweep_values 전체를 reps회씩 완주 — 성공률(%) 테이블 출력.
                 첫 실패에서 중단하지 않고 모든 값을 측정해 전체 분포를 파악.
        Phase 2: 100% 구간의 마지막 값(lo)과 첫 실패 값(hi) 사이를
                 이진 탐색(최대 6회, reps*2 샘플)으로 정밀 탐색.
        최종: 100% 신뢰 최솟값 권장.
        """
        cfg = self.config

        self._detect_pcie_info()
        if self._pcie_bdf and self._pcie_cap_offset is not None:
            self._set_pcie_l_state(PCIeLState.L0)
        self._apst_disable()
        self._keepalive_disable()

        sweep_combos = [c for c in POWER_COMBOS if c.pcie_l != PCIeLState.L0]
        if not sweep_combos:
            log.error("[SettleSweep] 비-L0 combo 없음 — 종료")
            return

        baseline     = POWER_COMBOS[0]
        sweep_values = cfg.settle_sweep_values
        reps         = cfg.settle_sweep_reps

        log.warning("=" * 70)
        log.warning("[SettleSweep] ══ Phase 1: 전체 sweep (성공률 측정) ══")
        log.warning(f"  sweep 값  : {sweep_values}")
        log.warning(f"  반복 횟수 : {reps}회/값  ({len(sweep_combos)}개 조합 순환)")
        log.warning(f"  l1_2_settle: {cfg.l1_2_settle_s}s (고정)")
        log.warning("=" * 70)

        # (settle_val, pass, total, rate_pct, per_combo_stats)
        p1_results: list[tuple[float, int, int, float, dict]] = []

        for settle_val in sweep_values:
            self.config.l1_settle_s = settle_val
            log.warning(f"\n[SettleSweep] ── l1_settle={settle_val:.4f}s ({reps}회) ──")
            pc, tc, per_combo = self._settle_sweep_run_reps(sweep_combos, baseline, reps)
            rate = pc / tc * 100 if tc else 0.0
            p1_results.append((settle_val, pc, tc, rate, per_combo))
            log.warning(f"  → {pc}/{tc} pass  ({rate:.1f}%)")

        # Phase 1 요약 테이블 — 전체 및 조합별 성공률
        log.warning("\n" + "=" * 70)
        log.warning("[SettleSweep] ── Phase 1 결과 (전체) ──")
        log.warning(f"  {'settle(s)':>10}  {'pass':>5}  {'total':>5}  {'성공률':>7}  {'판정':>6}")
        log.warning("  " + "-" * 42)
        for sv, pc, tc, rate, _ in p1_results:
            verdict = '100%' if rate == 100.0 else (f'{rate:.0f}%' if rate > 0 else 'FAIL')
            flag    = ' ◀' if rate == 100.0 else ''
            log.warning(f"  {sv:>10.4f}  {pc:>5}  {tc:>5}  {rate:>6.1f}%  {verdict:>6}{flag}")

        # 조합별 상세 테이블
        log.warning(f"\n[SettleSweep] ── Phase 1 조합별 성공률 ──")
        combo_col = max(len(str(c)) for c in sweep_combos) + 2
        header = f"  {'조합':<{combo_col}}" + "".join(f"  {sv:.4f}s" for sv, *_ in p1_results)
        log.warning(header)
        log.warning("  " + "-" * (len(header) - 2))
        for combo in sweep_combos:
            row = f"  {str(combo):<{combo_col}}"
            for sv, pc, tc, rate, per_combo in p1_results:
                cs   = per_combo.get(combo, {'pass': 0, 'total': 0})
                ct   = cs['total']
                cp   = cs['pass']
                cell = f"{cp}/{ct}" if ct else "  - "
                row += f"  {cell:>8}"
            log.warning(row)

        # 100% 구간 경계 파악
        full_pass = [sv for sv, pc, tc, rate, _ in p1_results if rate == 100.0]
        not_full  = [sv for sv, pc, tc, rate, _ in p1_results if rate < 100.0]

        if not full_pass:
            log.warning("\n[SettleSweep] 100% 성공 값 없음 — sweep 범위 확장 필요")
            self.config.l1_settle_s = sweep_values[0]
            return

        best_100 = min(full_pass)   # 100% 중 최솟값
        lo       = best_100
        below_failures = [sv for sv in not_full if sv < best_100]
        hi = max(below_failures) if below_failures else None

        # Phase 2: hi ↔ lo 이진 탐색 (hi < lo)
        p2_results: list[tuple[float, int, int, float]] = []
        if hi is not None:
            lo_p2 = hi   # 실패 하한
            hi_p2 = lo   # 100% 상한
        else:
            lo_p2 = None

        if lo_p2 is not None:
            log.warning(f"\n[SettleSweep] ══ Phase 2: 정밀 이진 탐색 [{lo_p2:.4f}s ~ {hi_p2:.4f}s] ══")
            log.warning(f"  샘플 수: {reps * 2}회/값  최대 6회 탐색")
            bsearch_lo = lo_p2
            bsearch_hi = hi_p2
            for biter in range(6):
                mid = round((bsearch_lo + bsearch_hi) / 2, 4)
                if abs(bsearch_hi - bsearch_lo) < 0.005:
                    log.warning(f"  [이진탐색] 수렴 ({bsearch_lo:.4f}~{bsearch_hi:.4f}s < 5ms) — 종료")
                    break
                self.config.l1_settle_s = mid
                log.warning(f"  [이진탐색 {biter+1}] mid={mid:.4f}s ({reps*2}회)")
                pc, tc, _ = self._settle_sweep_run_reps(sweep_combos, baseline, reps * 2)
                rate   = pc / tc * 100 if tc else 0.0
                p2_results.append((mid, pc, tc, rate))
                log.warning(f"  → {pc}/{tc} ({rate:.1f}%) {'✓ 100%' if rate == 100.0 else '✗'}")
                if rate == 100.0:
                    best_100    = mid
                    bsearch_hi  = mid
                else:
                    bsearch_lo  = mid

        # 최종 권장값
        self.config.l1_settle_s = sweep_values[0]  # 원복
        log.warning("\n" + "=" * 70)
        log.warning("[SettleSweep] ── 최종 결과 ──")
        if p2_results:
            log.warning(f"  Phase 2 탐색 결과:")
            for sv, pc, tc, rate in p2_results:
                log.warning(f"    {sv:.4f}s → {pc}/{tc} ({rate:.1f}%)")
        log.warning(f"\n  ★ 권장 l1_settle : {best_100:.4f}s  "
                    f"(100% 신뢰 최솟값; l1_2_settle={cfg.l1_2_settle_s}s 고정)")
        log.warning(f"  사용법: --l1-settle {best_100}")
        log.warning("=" * 70)

    def run(self):
        global log

        self._setup_directories()
        log, log_file = setup_logging(self.config.output_dir)
        self._log_file = log_file   # 내부 artifact 복사용 (콘솔엔 경로 미출력)

        # --settle-sweep: OpenOCD/fuzzing loop 없이 settle 최솟값만 탐색
        if self.config.settle_sweep:
            self._run_settle_sweep()
            return

        log.warning("=" * 60)
        log.warning(" PC Sampling SSD Fuzzer"
                    + (" [NO-JLINK MODE]" if self.config.no_jlink else ""))
        log.warning("=" * 60)
        log.warning(f"NVMe device : {self.config.nvme_device}")
        log.warning(f"Commands    : {[c.name for c in self.commands]}")
        if self.config.no_jlink:
            log.warning("OpenOCD     : DISABLED (--no-jlink) — coverage 수집 안 함, "
                        "NVMe fuzz + state + PM 만 동작")
        else:
            log.warning(f"OpenOCD     : {self.config.openocd_binary} / {self.config.openocd_config} "
                        f"(telnet {self.config.openocd_host}:{self.config.openocd_port})")
        if self.config.addr_range_start is not None:
            log.warning(f"Addr filter : {hex(self.config.addr_range_start)}"
                     f" - {hex(self.config.addr_range_end)}")
        else:
            log.warning("Addr filter : NONE (all PCs collected - noisy!)")
        log.warning(f"Sampling    : interval={self.config.sample_interval_us}us (PCSR, no-halt), "
                 f"max={self.config.max_samples_per_run}/run, "
                 f"idle_sat={SATURATION_LIMIT}, "
                 f"global_sat={GLOBAL_SATURATION_LIMIT}, "
                 f"post_cmd={self.config.post_cmd_delay_ms}ms")
        _diag_worst = self.config.diagnose_max * self.config.diagnose_sample_ms / 1000
        log.warning(f"Diagnose    : stability={self.config.diagnose_stability}, "
                    f"max={self.config.diagnose_max}, "
                    f"sleep={self.config.diagnose_sample_ms}ms, "
                    f"worst={_diag_worst:.0f}s")
        log.warning(f"PCIe settle : L1={self.config.l1_settle_s*1000:.0f}ms, "
                    f"L1.2+={self.config.l1_2_settle_s*1000:.0f}ms")
        log.warning(f"PM settle   : restore={RESTORE_SETTLE_S}s, "
                    f"d3_restore={D3_RESTORE_SETTLE_S}s, "
                    f"d3_extra={D3_EXTRA_S}s")
        log.warning(f"Power Sched : max_energy={MAX_ENERGY}")
        log.warning(f"NVMe I/O    : subprocess (nvme-cli passthru)")
        if self.config.pm_inject_prob > 0:
            self._detect_pcie_info()
            log.warning(f"PM Rotate   : interval={PM_ROTATE_INTERVAL}cmds, "
                        f"combos={len(POWER_COMBOS)}개(PS0~4×L0/L1/L1.2×D0/D3), "
                        f"timeout_margin=+{PS_ENTRY_EXIT_MARGIN_MS}ms(entry/exit latency)")
        if self._sa_loaded:
            sa_info = []
            if self._sa_total_bbs > 0:
                sa_info.append(f"basic_blocks={self._sa_total_bbs:,}")
            if self._sa_total_funcs > 0:
                sa_info.append(f"funcs={self._sa_total_funcs:,}")
            log.warning(f"StaticAnalysis: {', '.join(sa_info)}")
        else:
            log.warning(f"StaticAnalysis: not loaded ({self.config.bb_file} / {self.config.func_file} 없음)")
        log.warning(f"Random gen  : {self.config.random_gen_ratio:.0%}")
        timeout_str = ", ".join(f"{k}={v}ms" for k, v in self.config.nvme_timeouts.items())
        log.warning(f"Timeouts    : subprocess={timeout_str}")
        passthru_days = self.config.nvme_passthru_timeout_ms / 86_400_000
        log.warning(f"Passthru TO : {self.config.nvme_passthru_timeout_ms}ms "
                    f"({passthru_days:.1f}일, nvme-cli --timeout)")
        log.warning(f"Kernel TO   : {self.config.nvme_kernel_timeout_sec}s "
                    f"(crash 후 커널 reset 유예, nvme_core admin/io_timeout)")
        # Output 경로는 로그에 남기지 않음 — 폴더명에 버전이 들어가 노출되므로. (위치는 사용자가 앎)
        log.warning("=" * 60)

        # 이전 실행의 corpus/graphs/state_corpus 폴더 비우기
        # crashes/는 분석 증거이므로 보존한다.
        for subdir in ('corpus', 'graphs', 'state_corpus', 'seq_corpus'):
            target = self.output_dir / subdir
            if target.exists():
                shutil.rmtree(target)
                log.info(f"[Cleanup] {_logname(target)} 삭제 완료")
            target.mkdir(parents=True, exist_ok=True)

        self._load_seeds()

        nvme_dev = self.config.nvme_device
        # 사용자가 --nvme /dev/nvmeXnY 처럼 namespace 경로를 직접 명시했을 때,
        # path 의 ns id 와 config.nvme_namespace 가 불일치하면 path 기준으로 보정.
        # 그렇지 않으면 nvme-cli 가 ns mismatch 로 EINVAL("Invalid argument") 반환.
        _m_path_ns = re.search(r'n(\d+)$', nvme_dev)
        if _m_path_ns:
            _path_ns = int(_m_path_ns.group(1))
            if _path_ns != self.config.nvme_namespace:
                log.warning(f"[Pre-flight] --nvme path '{nvme_dev}' 의 ns={_path_ns} 가 "
                            f"--namespace {self.config.nvme_namespace} 와 불일치 → "
                            f"path 기준으로 보정 (namespace := {_path_ns})")
                self.config.nvme_namespace = _path_ns
        if not os.path.exists(nvme_dev):
            # WSL2 / 일부 인클로저 환경: controller char device(/dev/nvme0)는 없고
            # namespace block device(/dev/nvme0nN)만 노출됨. namespace 번호는
            # 1 일 수도 있고 (대부분) 2/3/... 일 수도 있음 (vendor format 후 등).
            # nvme-cli 는 namespace device 로 admin/io 모두 동작 가능 → 자동 fallback.
            _ns_dev = None
            _ns_id  = None
            if _NVME_NS_SUFFIX_RE.search(nvme_dev):
                # 이미 namespace 경로 — 그대로 사용, namespace id 도 path 에서 추출
                _ns_dev = nvme_dev
                _m = re.search(r'n(\d+)$', nvme_dev)
                if _m:
                    _ns_id = int(_m.group(1))
            else:
                # 우선 configured namespace 시도, 없으면 동일 controller 의 다른 namespace glob.
                _ctrl = os.path.basename(nvme_dev)   # e.g. "nvme0"
                _ns   = self.config.nvme_namespace or 1
                _cand = f"{nvme_dev}n{_ns}"
                if os.path.exists(_cand):
                    _ns_dev, _ns_id = _cand, _ns
                else:
                    # glob 으로 동일 controller 의 노출된 namespace 검색
                    import glob as _glob
                    _hits = sorted(_glob.glob(f"{nvme_dev}n*"))
                    # nvme0n1, nvme0n2 ... 형태만 — 다른 device(예: nvme0_1) 배제
                    _hits = [p for p in _hits
                             if re.match(rf"^{re.escape(nvme_dev)}n\d+$", p)]
                    if _hits:
                        # 숫자 가장 작은 것 우선
                        _hits.sort(key=lambda p: int(re.search(r'n(\d+)$', p).group(1)))
                        _ns_dev = _hits[0]
                        _ns_id  = int(re.search(r'n(\d+)$', _ns_dev).group(1))
            if _ns_dev and os.path.exists(_ns_dev):
                log.warning(f"[Pre-flight] controller {nvme_dev} 없음 → "
                            f"namespace device {_ns_dev} 로 fallback "
                            "(admin/io 모두 동일 경로 사용)")
                self.config.nvme_device = _ns_dev
                if _ns_id is not None and _ns_id != self.config.nvme_namespace:
                    log.warning(f"[Pre-flight] nvme_namespace 자동 보정: "
                                f"{self.config.nvme_namespace} → {_ns_id} "
                                "(검출된 device 의 namespace id 와 일치)")
                    self.config.nvme_namespace = _ns_id
                nvme_dev = _ns_dev
            else:
                log.error(f"[Pre-flight] NVMe 디바이스 {nvme_dev} 가 존재하지 않습니다.")
                log.error(f"  같은 controller 의 namespace device 도 못 찾음. "
                          f"nvme list / ls /dev/nvme* 로 확인.")
                return
        if not os.access(nvme_dev, os.R_OK | os.W_OK):
            log.error(f"[Pre-flight] NVMe 디바이스 {nvme_dev} 에 대한 읽기/쓰기 권한이 없습니다.")
            log.error("  sudo로 실행하거나 권한을 확인하세요.")
            return
        log.info(f"[Pre-flight] NVMe 디바이스 확인: {nvme_dev} ✓")

        # LBA 크기 자동 감지 (0 = auto)
        if self.config.nvme_lba_size == 0:
            self.config.nvme_lba_size = self._detect_lba_size()
            log.warning(f"[Pre-flight] LBA size 자동 감지: {self.config.nvme_lba_size}B "
                        f"(변경: --lba-size 로 수동 지정)")
        else:
            log.warning(f"[Pre-flight] LBA size 수동 지정: {self.config.nvme_lba_size}B")

        # 컨트롤러 정보 스냅샷 (CNTLID=NS 재부착용, OACS=NS Mgmt 지원 여부)
        self._snapshot_ctrl_info()

        # 이전 커버리지 로드 (resume)
        if self.config.resume_coverage:
            self.sampler.load_coverage(self.config.resume_coverage)

        # POR: OpenOCD 연결 전에 SSD 전원 사이클 수행
        # (이전 실행의 디버그 도메인 전원이 SSD PM 상태에 영향을 줄 수 있음)
        if self.config.enable_por:
            if self._pcie_bdf is None:
                # PCIe BDF가 아직 감지되지 않은 경우 먼저 감지 시도
                self._detect_pcie_info()
            por_ok = self._power_cycle_ssd()
            if not por_ok:
                log.warning("[POR] 전원 사이클 실패 — 계속 진행하지만 상태가 불안정할 수 있습니다")
        else:
            log.info("[POR] 비활성화됨 (--no-por)")

        # OpenOCD 연결: 전원 ON 직후부터 SWD 준비될 때까지 즉시 재시도.
        # 상한을 boot_sweep_s로 통합 — SWD가 올라오는 즉시 연결 성공 후 남은 시간은
        # boot sweep PC 수집에 사용. 별도 swd_wait 파라미터 없음.
        _swd_deadline = time.monotonic() + (
            self.config.boot_sweep_s if self.config.enable_por else 0
        )
        _connect_ok = False
        while True:
            if self.sampler.connect():
                _connect_ok = True
                break
            if time.monotonic() >= _swd_deadline:
                break
            log.warning("[POR] SWD 준비 안 됨 — 0.5초 후 재시도...")
            self.sampler._terminate_proc()
            time.sleep(0.5)
        if not _connect_ok:
            if self.config.allow_no_openocd and self.config.pm_inject_prob > 0:
                log.warning("[OpenOCD] 연결 실패: --allow-no-openocd --pm 이므로 PM 테스트만 수행합니다.")
                self.sampler._terminate_proc()
                self._run_pm_openocdless_test()
                return
            if self.config.allow_no_openocd:
                log.error("J-Link connection failed; --allow-no-openocd requires --pm")
                return
            log.error("J-Link connection failed, aborting")
            return

        # Boot-phase PC 수집: connect() 성공 시점부터 남은 boot_sweep_s 창 동안 수집.
        # firmware 부팅 중 초기화 경로(FTL 테이블 로드 등) PC를 global_coverage에 반영.
        # 이 시점은 PCIe rescan 전이므로 NVMe 명령 없이 순수 PCSR 폴링만 수행.
        # --no-jlink 모드면 J-Link 없이 PCSR 못 읽으므로 boot sweep 건너뜀.
        if not self.config.no_jlink:
            _sweep_remaining = max(0.0, _swd_deadline - time.monotonic())
            self._collect_boot_coverage(_sweep_remaining)

        # POR Phase 2: boot sweep 완료 후 PCIe rescan + NVMe 응답 확인
        # firmware 부팅이 완료됐을 것으로 기대하므로 대부분 즉시 성공.
        if self.config.enable_por:
            self._por_pcie_rescan()
            # rescan 후 PCIe capability offset 재탐지 — 커널이 장치를 재초기화하면서
            # L1SS 레지스터가 리셋될 수 있으므로 재탐지 후 L0으로 명시 초기화.
            if self.config.pm_inject_prob > 0:
                self._detect_pcie_info()
                self._set_pcie_l_state(PCIeLState.L0)
                log.warning("[POR] PCIe rescan 후 L0 초기화 완료")

        # APST / Keep-Alive 비활성화 — NVMe 접근 가능 상태에서 실행
        # APST: 자율 PS 전환 → PCIe 트래픽 → L1/L1.2 idle window 방해
        # Keep-Alive: 주기적 admin cmd → PS3/PS4 wake-up → L1 진입 불가
        self._apst_disable()
        self._keepalive_disable()

        # J-Link PC 읽기 진단 + idle PC 감지 — POR + APST/Keep-Alive disable 직후의
        # 가장 깨끗한 idle 상태에서 수집. PM preflight (30 PowerCombo + 17 S1/S2
        # perturb) 직후엔 firmware cleanup/recovery PC 가 idle universe 에 오염
        # 들어갈 수 있으므로 이 시점이 적절.
        if not self.sampler.diagnose():
            log.error("J-Link PC read diagnosis failed, aborting")
            return

        if self.sampler.idle_pcs:
            # idle_pcs를 BB/func 커버리지에 반영 (global_coverage엔 추가 안 함 — saturation 설계 유지)
            self._update_static_coverage(self.sampler.idle_pcs)
            pcs_str = ', '.join(hex(p) for p in sorted(self.sampler.idle_pcs))
            log.warning(f"Idle PCs    : {pcs_str} ({len(self.sampler.idle_pcs)} addrs)")
        else:
            log.warning("Idle PCs    : not detected (saturation = global PC only)")

        # idle 유니버스 수집 완료 → 디바이스 정보 한 번에 출력
        self._log_device_info()

        # PM preflight: idle 유니버스 수집 직후 전체 PowerCombo 검증.
        # --pm 활성화 시에만 실행. 실패 조합 있어도 abort하지 않고 경고만 출력.
        self._pm_preflight_check()

        # v7.7: S1/S2 perturbation preflight — PCIe bit + CLKREQ# 1회씩 검증.
        if self.config.pm_inject_prob > 0:
            self._pm_preflight_s1_s2()

        # nvme_core 모듈 타임아웃 파라미터 설정 (crash 상태 보존).
        # _log_smart() 이후에 설정: 이전에 실행하면 admin_timeout=30일 상태에서
        # smart-log ioctl이 제출되어, SSD 응답이 조금 느릴 때 커널이 계속 기다리고
        # Python 10초 timeout이 먼저 터지는 문제 방지.
        self._configure_nvme_timeouts()

        # FormatNVM + Sanitize 1회 실행 — calibration 직전 FTL 상태 초기화
        # Read/Write로 쌓인 mapping 복잡도를 알려진 깨끗한 상태로 리셋한 뒤 fuzzing 시작.
        # 이후 self.commands에서 제거 → 메인 루프에서는 절대 선택되지 않음.
        _fmt_cmd = next((c for c in NVME_COMMANDS if c.name == "FormatNVM"), None)
        if _fmt_cmd and any(c.name == "FormatNVM" for c in self.commands):
            log.warning("[Calibration] FormatNVM 1회 실행 (SES=0, FTL 리셋) ...")
            _fmt_seed = Seed(data=b'', cmd=_fmt_cmd, cdw10=0x0000)
            _fmt_rc = self._send_nvme_command(b'', _fmt_seed)
            log.warning(f"[Calibration] FormatNVM 완료 (rc={_fmt_rc})")
            _san_cmd = next((c for c in NVME_COMMANDS if c.name == "Sanitize"), None)
            if _san_cmd:
                log.warning("[Calibration] Sanitize 1회 실행 (SANACT=001, Exit Failure Mode) ...")
                _san_seed = Seed(data=b'', cmd=_san_cmd, cdw10=0x04)
                _san_rc = self._send_nvme_command(b'', _san_seed)
                log.warning(f"[Calibration] Sanitize 완료 (rc={_san_rc})")
            # 메인 루프에서 재실행되지 않도록 제거
            self.commands = [c for c in self.commands if c.name not in ("FormatNVM", "Sanitize")]
            log.info("[Calibration] FormatNVM/Sanitize self.commands에서 제거됨")

        # config fw_bin 을 (쓰기 가능) 모든 firmware slot 에 프리로드 → 이후 FWCommit 이 어떤 슬롯을
        # 활성화(CA=2/3)해도 같은 이미지 → 다른 FW 활성화 방지. FWCommit fuzz + fw_bin 있을 때만.
        if self._fw_chunks and any(c.name == 'FWCommit' for c in self.commands):
            self._preload_fw_slots()

        # Prefill: FormatNVM/Sanitize 이후 드라이브 전체 쓰기 (Verify 등이 참조할 데이터 확보)
        # FormatNVM이 LBA 맵핑을 초기화하므로 prefill은 반드시 format 완료 후 실행해야 의미 있음.
        if self.config.prefill:
            self._prefill_drive()
        else:
            log.info("[Prefill] 비활성화됨 (--prefill 로 활성화)")

        if self.config.calibration_runs > 0:
            total_seeds = len(self.corpus)
            log.warning(f"[Calibration] {total_seeds} seeds × "
                        f"{self.config.calibration_runs} runs each ...")
            calibrated_corpus = []
            cal_results = []  # (index, cmd_name, stability, stable_pcs, all_pcs)

            # J-Link DLL이 stderr로 직접 출력하는 "CPU is not halted" 등의
            # 타이밍 경고를 calibration 구간에서만 fd 수준으로 억제한다.
            devnull_fd = os.open(os.devnull, os.O_WRONLY)
            saved_stderr_fd = os.dup(2)
            os.dup2(devnull_fd, 2)
            # devnull_fd를 닫지 않고 유지 → 루프 중 [Cal] 로그 출력 후 재억제에 재사용
            # _handle_timeout_crash()이 log.error() 전에 stderr를 복원할 수 있도록
            # 인스턴스 변수에 보관 (fd 수명: finally의 os.close까지)
            self._cal_saved_stderr_fd = saved_stderr_fd
            _cal_idx_w = len(str(total_seeds))  # 숫자 폭 (예: 총 47개 → 폭 2)
            try:
                for i, seed in enumerate(self.corpus):
                    if not isinstance(seed, Seed):
                        calibrated_corpus.append(seed)
                        continue
                    seed = self._calibrate_seed(seed)
                    calibrated_corpus.append(seed)
                    stable_cnt = len(seed.stable_pcs) if seed.stable_pcs else 0
                    all_cnt    = len(seed.covered_pcs) if seed.covered_pcs else 0
                    cal_results.append((i + 1, seed.cmd.name, seed.stability,
                                        stable_cnt, all_cnt))

                    # 시드별 진행 로그 ─────────────────────────────────────────
                    # stderr가 억제된 상태이므로 출력 전에 복원 후 다시 억제
                    _rc = getattr(self, '_cal_last_rc', 0)
                    _rc_str = (f"rc=TIMEOUT" if _rc == self.RC_TIMEOUT
                               else f"rc=ERR"    if _rc == self.RC_ERROR
                               else f"rc={_rc}")
                    _tag = " ← FAIL" if _rc not in (0,) else ""
                    os.dup2(saved_stderr_fd, 2)   # stderr 복원
                    log.warning(
                        f"[Cal {i+1:{_cal_idx_w}}/{total_seeds}] "
                        f"{seed.cmd.name:<20} "
                        f"cdw10=0x{seed.cdw10:08x}  "
                        f"stab={seed.stability*100:3.0f}%  "
                        f"pcs={all_cnt:5}  "
                        f"{_rc_str}{_tag}"
                    )
                    os.dup2(devnull_fd, 2)        # 다시 억제

                    if self._timeout_crash:
                        os.dup2(saved_stderr_fd, 2)
                        log.error("[Calibration] timeout during calibration — aborting")
                        return
            finally:
                self._cal_saved_stderr_fd = None
                os.dup2(saved_stderr_fd, 2)
                os.close(devnull_fd)
                os.close(saved_stderr_fd)

            self.corpus = calibrated_corpus

            avg_stab = sum(r[2] for r in cal_results) / max(len(cal_results), 1)
            log.warning(f"[Calibration] Done — "
                        f"Seeds: {total_seeds}  |  "
                        f"Global PCs: {len(self.sampler.global_coverage)}  |  "
                        f"Avg stability: {avg_stab*100:.1f}%")

            for seed in self.corpus:
                if not isinstance(seed, Seed):
                    continue
                if not seed.det_done:
                    gen = self._deterministic_stage(seed)
                    self._det_queue.append((seed, gen))
            log.warning(f"[Det] Queued {len(self._det_queue)} seeds for deterministic stage")

            # calibration 중 SetFeatures(APST/KeepAlive) 시드가 실행되면
            # preflight의 _apst_disable()/_keepalive_disable() 효과가 무력화됨.
            # → calibration 완료 후 다시 비활성화하여 퍼징 중 자율 PS 전환 방지.
            # SetFeatures PS 시드(PS0~PS2)가 실행된 후 컨트롤러가 PS0이 아닌 상태일
            # 수 있으므로 명시적으로 PS0으로 복구.
            self._apst_disable()
            self._keepalive_disable()
            self._pm_set_state(0)   # calibration 중 PS 변경 → PS0 복구
            log.warning("[Calibration] Complete. Starting fuzzing...\n")
        else:
            log.info("[Calibration] Disabled (calibration_runs=0)")

        self.start_time = datetime.now()
        self._window_t0 = self.start_time          # 구간별 exec/s 계산용
        self._window_exec0: int = 0
        # calibration 실행 횟수를 제외하고 main loop 기준으로 카운트 재시작
        self.executions = 0

        # 퍼징 시작 직전 초기 상태 스냅샷
        self._log_smart()
        if self.config.state_enabled:
            self._log_state_snapshot()

        # 메인 퍼징 루프 진입 — 터미널 출력을 [Stats]/[PM]/[+]/CRASH 로만 제한
        for _h in log.handlers:
            if isinstance(_h, logging.StreamHandler) and not isinstance(_h, logging.FileHandler):
                _h.addFilter(_FuzzingTerminalFilter())

        try:
            while True:
                if self._timeout_crash:
                    break

                elapsed = (datetime.now() - self.start_time).total_seconds()
                if elapsed >= self.config.total_runtime_sec:
                    log.info("Runtime limit reached")
                    break

                # v7.2: MOpt operator 기록 초기화 — iteration 시작 시점에 수행.
                # 기존 코드는 _mutate() 호출 이후에 = []로 비워서 MOpt reward(line ~7962)에
                # 항상 빈 리스트가 전달되어 mopt_finds/mopt_uses가 누적되지 않는 버그가 있었음.
                self._current_mutations = []

                # v8.4: IO 워크로드 주입 — fuzz IO_WL_FUZZ_GAP 명령마다 워크로드 블록 1개.
                # 카운터는 fuzz iteration 에서만 증가(워크로드 cmd 제외) → fuzz:workload 비율 고정.
                if (self.config.io_workload_enabled and IO_WL_ENABLED
                        and self._fuzz_since_workload >= IO_WL_FUZZ_GAP):
                    self._run_io_workload_block()
                    self._fuzz_since_workload = 0
                    if self._timeout_crash:
                        break
                    continue
                self._fuzz_since_workload += 1

                # PM rotation (PM_ROTATE_INTERVAL 마다): 60% combo / 10% forced_idle /
                # 20% S1 pcie_bit / 10% S2 clkreq. PM 전이 후 seed 선택.
                if (self.config.pm_inject_prob > 0
                        and self.executions % PM_ROTATE_INTERVAL == 0):
                    _next_combo = None
                    _r = random.random()
                    if   _r < 0.60:
                        _pm_slot = 'combo'
                        _next_combo = random.choice(POWER_COMBOS)
                    elif _r < 0.70:
                        _pm_slot = 'forced_idle'
                    elif _r < 0.90:
                        _pm_slot = 'pcie_bit'
                    else:
                        _pm_slot = 'clkreq'

                    # ── forced_idle slot — APST autonomous PS3→PS4 ───────
                    # 강제 SetFeatures PS=4 대신 APST 짧은 ITPT 활성 → 자율 전환.
                    # 슬롯 종료 시 APST 다시 disable → 다른 PM rotation 슬롯
                    # (POWER_COMBO/pcie_bit/clkreq) 의 manual PM 제어와 충돌 X.
                    if _pm_slot == 'forced_idle':
                        _ps3_ms = 500       # PS0 → PS3 ITPT (0.5초)
                        _ps4_ms = 2000      # PS3 → PS4 ITPT (2.0초)
                        _idle_total_s = (_ps3_ms + _ps4_ms) / 1000.0 + 1.0  # 여유 1초
                        log.warning(f"[PM] APST 자율 idle 진입 "
                                    f"(PS0→PS3 {_ps3_ms}ms, PS3→PS4 {_ps4_ms}ms, "
                                    f"total {_idle_total_s:.1f}s)")
                        _apst_ok = self._apst_enable_short_itpt(_ps3_ms, _ps4_ms)
                        if _apst_ok:
                            self.sampler.start_sampling()
                            time.sleep(_idle_total_s)     # 자율 PS3 → PS4 진입 대기
                            self.sampler.stop_sampling()
                            _pm_new_set = self.sampler.current_trace - self.sampler.global_coverage
                            _pm_new_cnt = len(_pm_new_set)
                            self.sampler.global_coverage.update(self.sampler.current_trace)
                            if _pm_new_cnt > 0:
                                if self._sa_loaded:
                                    self._update_static_coverage(_pm_new_set)
                                log.info(f"[+][PM-Cov] APST-idle (PS3→PS4) +{_pm_new_cnt} new PCs")
                            # APST 다시 disable — 다음 PM rotation 슬롯이 manual 제어
                            # 가능하도록. 다음 NVMe 명령이 디바이스를 자연 wake.
                            self._apst_disable()
                            self.ps_enter_counts[3] += 1
                            self.ps_enter_counts[4] += 1
                        else:
                            log.warning("[PM] APST enable 실패 — forced_idle slot skip")
                        # current_combo 는 다음 명령 송신 직전 _nonop_restore 가 정리
                        self._current_combo = POWER_COMBOS[0]
                        self._current_ps    = 0

                    # ── PCIe config bit perturb slot (v7.7 S1) ──────────
                    elif _pm_slot == 'pcie_bit':
                        self.sampler.start_sampling()
                        self._pm_perturb_pcie_bit()
                        self.sampler.stop_sampling()
                        _pm_new_set = self.sampler.current_trace - self.sampler.global_coverage
                        _pm_new_cnt = len(_pm_new_set)
                        self.sampler.global_coverage.update(self.sampler.current_trace)
                        if _pm_new_cnt > 0:
                            if self._sa_loaded:
                                self._update_static_coverage(_pm_new_set)
                            log.info(f"[+][PM-Cov] pcie_bit +{_pm_new_cnt} new PCs")

                    # ── CLKREQ# timing slot (v7.7 S2, 4 mode random) ─────
                    elif _pm_slot == 'clkreq':
                        self.sampler.start_sampling()
                        self._pm_perturb_clkreq()
                        self.sampler.stop_sampling()
                        _pm_new_set = self.sampler.current_trace - self.sampler.global_coverage
                        _pm_new_cnt = len(_pm_new_set)
                        self.sampler.global_coverage.update(self.sampler.current_trace)
                        if _pm_new_cnt > 0:
                            if self._sa_loaded:
                                self._update_static_coverage(_pm_new_set)
                            log.info(f"[+][PM-Cov] clkreq +{_pm_new_cnt} new PCs")

                    # ── POWER_COMBO slot (기존) ──────────────────────────
                    if _next_combo is not None:
                        if _next_combo.nvme_ps not in (3, 4):
                            self._prev_op_ps    = _next_combo.nvme_ps
                            self._prev_op_combo = _next_combo
                        # PM combo 진입 중 PC sampling — 커버리지 수집 (corpus 판정 제외)
                        # _sampling_worker()가 current_trace를 리셋하므로 NVMe window와 독립.
                        # stop 후 global_coverage에만 반영 → 이후 NVMe evaluate_coverage()가
                        # PM PCs를 "이미 알려진 PC"로 취급 → corpus 오염 없음.
                        self.sampler.start_sampling()
                        _set_ok = self._set_power_combo(_next_combo)
                        if not _set_ok:
                            log.warning(f"[PM] {_next_combo.label} 진입 실패 — _current_combo 유지")
                        self.sampler.stop_sampling()
                        _pm_new_set = self.sampler.current_trace - self.sampler.global_coverage
                        _pm_new_cnt = len(_pm_new_set)
                        self.sampler.global_coverage.update(self.sampler.current_trace)
                        if _pm_new_cnt > 0:
                            if self._sa_loaded:
                                self._update_static_coverage(_pm_new_set)
                            log.info(
                                f"[+][PM-Cov] {_next_combo.label} "
                                f"+{_pm_new_cnt} new PCs "
                                f"(global={len(self.sampler.global_coverage)})")
                        # 실패 시 _current_combo를 갱신하지 않음 — HW 실제 상태 불명확
                        if _set_ok:
                            self._current_combo = _next_combo
                            self._current_ps    = _next_combo.nvme_ps
                        self.ps_enter_counts[_next_combo.nvme_ps] += 1
                        self.combo_enter_counts[_next_combo] += 1

                    # Non-Operational PM 상태 복귀 — 이후 어떤 NVMe(C2 state-replay /
                    # sequence / 단일 명령)보다 *먼저* 수행해야 함. D3hot / L1.2(CLKREQ#
                    # deasserted)는 컨트롤러가 명령 처리 불가 상태라 복귀 없이 명령을 던지면
                    # D-state hang. PS3/PS4(NOPS)는 컨트롤러 자동 wake — 복귀 불필요.
                    # (이전엔 seed 선택/C2 replay 뒤에 복귀해서, replay가 죽은 장치에
                    #  명령을 발사하는 순서 버그가 있었음.)
                    if self._is_nonop_combo(self._current_combo):
                        restored = self._nonop_restore(self._current_combo)
                        self._current_combo = restored
                        self._current_ps    = restored.nvme_ps

                is_det_stage = False
                _used_seq = False   # 매 iteration 초기화 — det-stage가 가로채면 False 유지
                # sequence 진행 중에는 det-stage / C2 scheduler를 스킵:
                # 명령 사이에 다른 NVMe 명령이 끼어들면 firmware 상태가 바뀌어
                # Write→Compare 등 의존 시퀀스의 결과가 달라짐.
                _seq_in_progress = bool(self._pending_sequence or self._pending_seq_seeds)
                # v7.2: DET_BUDGET 비율만큼만 det stage 소비.
                # 기존 구조는 _det_queue가 있으면 무조건 소비해서
                # Write seed가 coverage를 내면 ~400회 Write 전용 실행이 연속으로 발생,
                # havoc/random/admin 경로가 완전히 차단되는 다양성 편향 문제가 있었음.
                if not _seq_in_progress and self._det_queue and random.random() < DET_BUDGET:
                    det_seed, det_gen = self._det_queue[0]
                    try:
                        mutated_seed = next(det_gen)
                        fuzz_data = mutated_seed.data
                        cmd = mutated_seed.cmd
                        is_det_stage = True
                    except StopIteration:
                        self._det_queue.popleft()
                        det_seed.det_done = True
                        log.info(f"[Det] Completed deterministic stage for {det_seed.cmd.name}")
                        # 이번 iteration은 havoc으로 fallthrough
                        is_det_stage = False

                if not is_det_stage:
                    # CSFuzz §III-C: corpus selection probability
                    self._csfuzz_pre_c1_size = len(self.corpus)
                    self._csfuzz_pre_c2_size = len(self.state_corpus)
                    _avg_seq = (sum(len(e.sequence) for e in self.state_corpus)
                                / len(self.state_corpus)) if self.state_corpus else 1.0
                    _p_c2 = (1.0 - self._csfuzz_p) / max(_avg_seq, 1.0)
                    if (not _seq_in_progress
                            and self.config.state_enabled
                            and self.state_corpus
                            and random.random() < _p_c2):
                        # C2(state corpus) 선택 → 시퀀스 replay 후 정상 seed 선택
                        # 주의: _replay_state_sequence는 entry.sequence(최대 100개)의 모든 명령을
                        # 순차 실행하므로 이 iteration에서 100+개의 NVMe 명령이 발행될 수 있다.
                        # 각 명령은 _account_command로 executions/coverage가 정상 회계되며,
                        # replay 종료 후 본 iteration의 단일 seed 실행이 추가로 진행된다.
                        # _seq_in_progress=True일 때는 진입하지 않으므로 sequence atomicity 보장.
                        self._csfuzz_last_from = 'c2'
                        _sc_entry = self._select_state_entry_csfuzz()
                        if _sc_entry is not None:
                            if not self._replay_state_sequence(_sc_entry):
                                break  # replay 중 timeout → _timeout_crash=True, 루프 탈출
                    else:
                        self._csfuzz_last_from = 'c1'

                    # Phase 3: pending sequence 또는 신규 sequence 시작
                    _used_seq = False

                    # [3a] corpus SequenceSeed replay continuation
                    if self._pending_seq_seeds:
                        _next_seed = self._pending_seq_seeds.pop(0)
                        log.debug(f"[Seq/Corp] continuation: cmd={_next_seed.cmd.name} "
                                  f"remaining={len(self._pending_seq_seeds)}")
                        mutated_seed = self._mutate(_next_seed)
                        if self._pending_seq_ctx:
                            mutated_seed = self._apply_seq_ctx(mutated_seed, self._pending_seq_ctx)
                        if not self._pending_seq_seeds:
                            self._pending_seq_ctx = None
                        fuzz_data = mutated_seed.data
                        cmd = mutated_seed.cmd
                        self._seq_cmds_in_window += 1
                        self.mutation_stats["seq_builtin"] += 1
                        _used_seq = True

                    # [3b] builtin sequence continuation
                    elif self._pending_sequence:
                        _seq_cmd = self._pending_sequence.pop(0)
                        mutated_seed = self._pick_seq_seed(_seq_cmd, self._pending_seq_ctx)
                        fuzz_data = mutated_seed.data
                        cmd = mutated_seed.cmd
                        self._seq_cmds_in_window += 1
                        self.mutation_stats["seq_builtin"] += 1
                        if not self._pending_sequence:
                            self._pending_seq_ctx = None
                        _used_seq = True

                    # [3c] 신규 builtin sequence 시작
                    elif (SEQ_PROB > 0
                          and BUILTIN_SEQUENCES
                          and self._seq_cmds_in_window < SEQ_MAX_PER_100
                          and random.random() < SEQ_PROB):
                        _enabled_names = {c.name for c in self.commands}
                        _valid_seqs = [s for s in BUILTIN_SEQUENCES
                                       if all(n in _enabled_names for n in s)]
                        if _valid_seqs:
                            _seq = list(random.choice(_valid_seqs))
                            _seq_cmd = _seq.pop(0)
                            self._pending_sequence = _seq if _seq else None
                            _full_seq = tuple([_seq_cmd] + (_seq or []))
                            # 새 시퀀스 시작 시 _seq_sink 초기화
                            self._seq_sink = {
                                'commands': [], 'new_pcs': 0,
                                'covered_pcs': set(), 'interesting': False,
                            }
                            log.debug(f"[Seq/Builtin] 시작: {_full_seq}")
                            mutated_seed = self._pick_seq_seed(_seq_cmd, ctx=None)
                            _ctx_mode = self._CTX_SEQUENCES.get(_full_seq)
                            if _ctx_mode is not None:
                                # 첫 명령 mutation 결과에서 ctx 파생
                                self._pending_seq_ctx = {
                                    'slba': (mutated_seed.cdw11 << 32) | mutated_seed.cdw10,
                                    'nlb':  mutated_seed.cdw12 & 0xFFFF,
                                    'data': mutated_seed.data if _ctx_mode == 'full' else None,
                                }
                            else:
                                self._pending_seq_ctx = None
                            fuzz_data = mutated_seed.data
                            cmd = mutated_seed.cmd
                            self._seq_cmds_in_window += 1
                            self.mutation_stats["seq_builtin"] += 1
                            _used_seq = True

                    if not _used_seq:
                        # v4: Power Schedule 기반 시드 선택 + CDW 변형
                        if self.corpus and random.random() >= self.config.random_gen_ratio:
                            base_seed = self._select_seed()
                            if base_seed is None:
                                cmd = random.choice(self.commands)
                                fuzz_data = os.urandom(random.randint(64, 512))
                                mutated_seed = Seed(data=fuzz_data, cmd=cmd)
                                self.mutation_stats["random_gen"] += 1
                            elif isinstance(base_seed, SequenceSeed):
                                if self._seq_cmds_in_window < SEQ_MAX_PER_100:
                                    # corpus SequenceSeed → 시퀀스 replay 시작
                                    _cs_cmds = list(base_seed.commands)
                                    _cs_names = tuple(s.cmd.name for s in base_seed.commands)
                                    log.debug(f"[Seq/Corp] replay 시작: cmds={_cs_names} "
                                              f"new_pcs={base_seed.new_pcs}")
                                    _first = self._mutate(_cs_cmds.pop(0))
                                    _ctx_mode = self._CTX_SEQUENCES.get(_cs_names)
                                    if _ctx_mode is not None:
                                        # 첫 명령 mutation 결과에서 ctx 파생
                                        self._pending_seq_ctx = {
                                            'slba': (_first.cdw11 << 32) | _first.cdw10,
                                            'nlb': _first.cdw12 & 0xFFFF,
                                            'data': _first.data if _ctx_mode == 'full' else None,
                                        }
                                    else:
                                        self._pending_seq_ctx = None
                                    self._pending_seq_seeds = _cs_cmds if _cs_cmds else None
                                    if not self._pending_seq_seeds:
                                        self._pending_seq_ctx = None
                                    self._seq_sink = {
                                        'commands': [], 'new_pcs': 0,
                                        'covered_pcs': set(), 'interesting': False,
                                    }
                                    mutated_seed = _first
                                    fuzz_data = mutated_seed.data
                                    cmd = mutated_seed.cmd
                                    self._seq_cmds_in_window += 1
                                    self.mutation_stats["seq_builtin"] += 1
                                    _used_seq = True
                                else:
                                    # window 초과: 첫 명령만 단독 실행 (시퀀스 미시작)
                                    # _select_seed가 SequenceSeed의 exec_count를 이미 증가시켰지만
                                    # 실제 시퀀스 replay가 일어나지 않으므로 보정 — 다음 window에서
                                    # 동일 SequenceSeed가 다시 선택될 기회를 보존.
                                    base_seed.exec_count = max(0, base_seed.exec_count - 1)
                                    log.debug(f"[Seq/Corp] window 초과 → 단독 실행: "
                                              f"cmd={base_seed.commands[0].cmd.name}")
                                    mutated_seed = self._mutate(base_seed.commands[0])
                                    fuzz_data = mutated_seed.data
                                    cmd = mutated_seed.cmd
                                    self.mutation_stats["corpus_mutated"] += 1
                            else:
                                mutated_seed = self._mutate(base_seed)
                                fuzz_data = mutated_seed.data
                                cmd = mutated_seed.cmd
                                self.mutation_stats["corpus_mutated"] += 1
                        else:
                            cmd = random.choice(self.commands)
                            fuzz_data = os.urandom(random.randint(64, 512))
                            mutated_seed = Seed(data=fuzz_data, cmd=cmd)
                            self.mutation_stats["random_gen"] += 1

                if mutated_seed.opcode_override is not None:
                    self.mutation_stats["opcode_override"] += 1
                    self.actual_opcode_dist[mutated_seed.opcode_override] += 1
                if mutated_seed.nsid_override is not None:
                    self.mutation_stats["nsid_override"] += 1
                if mutated_seed.force_admin is not None:
                    self.mutation_stats["force_admin_swap"] += 1
                if mutated_seed.data_len_override is not None:
                    self.mutation_stats["data_len_override"] += 1

                # 실제 명령 전송 상태 기준 실행 카운트 (nonop restore 반영)
                # 복귀는 PM rotation 직후(seed 선택 전)로 이동됨 — 위 블록 참조.
                if self.config.pm_inject_prob > 0:
                    self.ps_exec_counts[self._current_ps] += 1
                    self.combo_exec_counts[self._current_combo] += 1

                # NVMe 커맨드 전송
                # timeout은 _send_nvme_command 내부에서 PS_ENTRY_EXIT_MARGIN_MS(105ms) 고정 가산
                # FWDownload + 실제 청크 목록이 있으면 전체 청크를 순서대로 전송,
                # exec 카운터는 1만 증가 (CLI 기준 1회 실행)
                # 회계/리포트(FAIL CMD·crash·replay)용 "실제 전송된" seed/data.
                # FWDownload 멀티청크는 원본 청크를 보내므로 실패 청크로 회계해야
                # [NVMe TIMEOUT] 로그와 FAIL CMD 가 일치(미일치 버그 수정).
                _acct_seed, _acct_data = mutated_seed, fuzz_data
                if cmd.name == "FWDownload" and self._fw_chunks:
                    rc = self.RC_ERROR
                    for _chunk_seed in self._fw_chunks:
                        rc = self._send_nvme_command(_chunk_seed.data, _chunk_seed)
                        # 청크 중간에 타임아웃/에러 발생 시 즉시 중단 — 그 청크로 회계
                        if rc in (self.RC_TIMEOUT, self.RC_ERROR):
                            _acct_seed, _acct_data = _chunk_seed, _chunk_seed.data
                            break
                    last_samples = self.sampler.stop_sampling()
                else:
                    rc = self._send_nvme_command(fuzz_data, mutated_seed)
                    last_samples = self.sampler.stop_sampling()

                # OpenOCD 연속 실패 감지 → 2단계 복구
                # 1단계: 타겟 재초기화 (OpenOCD 유지, 전원 레지스터 재활성화)
                # 2단계: OpenOCD 완전 재시작
                if self.sampler.openocd_error.is_set():
                    self.sampler.openocd_error.clear()
                    if not self.sampler._reinit_target():
                        log.warning("[OpenOCD] 타겟 재초기화 실패 — OpenOCD 재시작 시도...")
                        if not self.sampler._reconnect():
                            log.error("[OpenOCD] 재시작 실패 — 퍼저를 종료합니다.")
                            break
                        log.warning("[OpenOCD] OpenOCD 재시작 성공 — 퍼징 재개")
                    else:
                        log.warning("[OpenOCD] 타겟 재초기화 성공 — 퍼징 재개")

                is_interesting, new_pcs, _action = self._account_command(
                    _acct_seed, _acct_data, rc, last_samples,
                    source='c1' if is_det_stage else self._csfuzz_last_from,
                    is_det_stage=is_det_stage,
                    seq_member=_used_seq,
                )
                if _action == 'break':
                    self._seq_sink = None
                    self._pending_seq_seeds = None
                    self._pending_sequence = None
                    break
                if _action == 'continue':
                    if (self._seq_sink is not None
                            and not self._pending_sequence
                            and not self._pending_seq_seeds):
                        self._finalize_seq_sink()
                    continue

                # 시퀀스 완료 시 SequenceSeed 저장
                if (self._seq_sink is not None
                        and not self._pending_sequence
                        and not self._pending_seq_seeds):
                    self._finalize_seq_sink()


        except KeyboardInterrupt:
            log.warning("Interrupted by user — 정리 작업 완료 후 종료합니다 (잠시 대기)...")

        finally:
            # Ctrl+C가 정리 작업을 중단하지 않도록 SIGINT 임시 무시.
            # finally 블록이 KeyboardInterrupt로 중단되면 그래프/통계 저장이
            # 스킵되므로, 정리가 끝날 때까지 추가 시그널을 억제한다.
            import signal as _signal
            _old_sigint = None
            try:
                _old_sigint = _signal.signal(_signal.SIGINT, _signal.SIG_IGN)
            except (OSError, ValueError):
                pass  # 메인 스레드가 아닌 경우 무시

            # timeout crash 시 NVMe 장치가 D-state → nvme-cli가 영구 블로킹될 수 있으므로 스킵
            if not self._timeout_crash:
                try:
                    self._log_smart()
                except Exception:
                    pass

            # 각 단계를 독립적으로 보호하여 하나가 실패해도 나머지 실행
            try:
                stats = self._collect_stats()
                summary_lines = [
                    "=" * 60,
                    " Fuzzing Complete",
                    "=" * 60,
                    f"Total executions : {stats['executions']:,}",
                    f"Elapsed          : {stats['elapsed_seconds']:.1f}s",
                    f"Exec/s           : {stats['exec_per_sec']:.1f}",
                    f"Corpus size      : {stats['corpus_size']}",
                    f"Crashes          : {stats['crashes']}",
                    f"Total samples    : {stats['total_samples']:,}",
                    f"Interesting      : {stats['interesting_inputs']}",
                    f"Coverage (PCs)   : {stats['coverage_unique_pcs']:,}",
                    "Per-command stats:",
                ]
                # v7.6: unknown_{admin|io}_op0x.. 라벨을 unknown(admin)/unknown(io) 두
                # 버킷으로 합산. 개별 unknown opcode 통계는 아래 별도 섹션에 출력.
                def _bucket_track(_k: str) -> str:
                    if _k.startswith('unknown_admin_op0x'):
                        return 'unknown(admin)'
                    if _k.startswith('unknown_io_op0x'):
                        return 'unknown(io)'
                    return _k

                from collections import defaultdict as _dd_sum
                _cs_bucket = _dd_sum(lambda: {'exec': 0, 'interesting': 0})
                for _k, _st in stats['command_stats'].items():
                    _b = _bucket_track(_k)
                    _cs_bucket[_b]['exec']        += _st.get('exec', 0)
                    _cs_bucket[_b]['interesting'] += _st.get('interesting', 0)
                _known   = sorted(b for b in _cs_bucket if not b.startswith('unknown('))
                _unknown_b = sorted(b for b in _cs_bucket if b.startswith('unknown('))
                for _b in _known + _unknown_b:
                    _agg = _cs_bucket[_b]
                    summary_lines.append(
                        f"  {_b}: exec={_agg['exec']}, "
                        f"interesting={_agg['interesting']}")

                # Top unknown opcodes — 개별 hit이 큰 unknown opcode top-5 (별도 신호)
                _unknown_entries = []
                for _k, _st in stats['command_stats'].items():
                    if _k.startswith('unknown_admin_op0x') or _k.startswith('unknown_io_op0x'):
                        _unknown_entries.append((_k, _st.get('exec', 0),
                                                 _st.get('interesting', 0)))
                if _unknown_entries:
                    _unknown_entries.sort(key=lambda x: x[1], reverse=True)
                    summary_lines.append(
                        f"Top unknown opcodes (unique={len(_unknown_entries)}, exec 내림차순):")
                    for _k, _ex, _int in _unknown_entries[:5]:
                        _typ = 'admin' if _k.startswith('unknown_admin') else 'io'
                        _opc = _k.rsplit('op0x', 1)[-1]
                        summary_lines.append(
                            f"  unknown({_typ}) op=0x{_opc}: exec={_ex}, "
                            f"interesting={_int}")

                summary_lines.append("Return code distribution:")
                _rc_bucket = _dd_sum(lambda: _dd_sum(int))
                for _k, _rd in self.rc_stats.items():
                    _b = _bucket_track(_k)
                    for _rc, _c in _rd.items():
                        _rc_bucket[_b][_rc] += _c
                _known_rc   = sorted(b for b in _rc_bucket if not b.startswith('unknown('))
                _unknown_rc = sorted(b for b in _rc_bucket if b.startswith('unknown('))
                for _b in _known_rc + _unknown_rc:
                    rc_dist = _rc_bucket[_b]
                    rc_summary = ", ".join(f"rc={rc}:{cnt}"
                                           for rc, cnt in sorted(rc_dist.items()))
                    summary_lines.append(f"  {_b}: {rc_summary}")

                ms = stats['mutation_stats']
                total = stats['executions'] or 1
                summary_lines.append("Mutation stats:")
                summary_lines.append(
                    f"  Input source   : corpus_mutated={ms['corpus_mutated']} "
                    f"({100*ms['corpus_mutated']/total:.1f}%), "
                    f"random_gen={ms['random_gen']} "
                    f"({100*ms['random_gen']/total:.1f}%)")
                summary_lines.append(
                    f"  opcode_override: {ms['opcode_override']} "
                    f"({100*ms['opcode_override']/total:.1f}%)")
                summary_lines.append(
                    f"  nsid_override  : {ms['nsid_override']} "
                    f"({100*ms['nsid_override']/total:.1f}%)")
                summary_lines.append(
                    f"  admin↔io swap  : {ms['force_admin_swap']} "
                    f"({100*ms['force_admin_swap']/total:.1f}%)")
                summary_lines.append(
                    f"  data_len_override: {ms['data_len_override']} "
                    f"({100*ms['data_len_override']/total:.1f}%)")
                summary_lines.append(
                    f"  datalen_nlb      : {ms['datalen_nlb']} "
                    f"({100*ms['datalen_nlb']/total:.1f}%)"
                    f"  datalen_mdts: {ms['datalen_mdts']} "
                    f"({100*ms['datalen_mdts']/total:.1f}%)")
                summary_lines.append(
                    f"  lba_pair_64bit   : {ms['lba_pair_64bit']} "
                    f"({100*ms['lba_pair_64bit']/total:.1f}%)")
                summary_lines.append(
                    f"  dsm_structured   : {ms['dsm_structured']} "
                    f"  copy_structured: {ms['copy_structured']}"
                    f"  seq_builtin: {ms['seq_builtin']} "
                    f"({100*ms['seq_builtin']/total:.1f}%)")

                # 실제 전송된 opcode 분포 (변형된 것만)
                if stats['actual_opcode_dist']:
                    sorted_opcodes = sorted(stats['actual_opcode_dist'].items(),
                                            key=lambda x: x[1], reverse=True)
                    top_opcodes = sorted_opcodes[:15]
                    opcode_str = ", ".join(
                        f"0x{opc:02x}:{cnt}" for opc, cnt in top_opcodes)
                    summary_lines.append(
                        f"  Mutated opcodes (top {len(top_opcodes)}): {opcode_str}")
                    if len(sorted_opcodes) > 15:
                        summary_lines.append(
                            f"    ... and {len(sorted_opcodes) - 15} more unique opcodes")

                # passthru 타입 분포
                pt = stats['passthru_stats']
                summary_lines.append(
                    f"  Passthru type  : admin={pt.get('admin-passthru', 0)}, "
                    f"io={pt.get('io-passthru', 0)}")
                if self.config.pm_inject_prob > 0:
                    summary_lines.append(
                        f"PM Rotate interval: {PM_ROTATE_INTERVAL}cmds "
                        f"(Power Combo: {len(POWER_COMBOS)}개 조합)")
                    # Power Combo 통계 (실행 횟수 내림차순)
                    combo_rows = sorted(
                        self.combo_exec_counts.items(),
                        key=lambda x: x[1], reverse=True)
                    for combo, cnt in combo_rows:
                        if cnt == 0:
                            continue
                        enters = self.combo_enter_counts.get(combo, 0)
                        pct    = 100 * cnt / total
                        summary_lines.append(
                            f"  {combo.label:<18}: 실행 {cnt}회 ({pct:.1f}%), "
                            f"진입 {enters}회")

                if self._sa_loaded:
                    if self._sa_total_bbs > 0:
                        n_bb = len(self._sa_covered_bbs)
                        pct  = 100.0 * n_bb / self._sa_total_bbs
                        summary_lines.append(
                            f"BB Coverage      : {pct:.2f}%"
                            f" ({n_bb:,} / {self._sa_total_bbs:,} basic blocks)")
                    if self._sa_total_funcs > 0:
                        n_f  = len(self._sa_entered_funcs)
                        fpct = 100.0 * n_f / self._sa_total_funcs
                        summary_lines.append(
                            f"Func Coverage    : {fpct:.2f}%"
                            f" ({n_f} / {self._sa_total_funcs} functions)")

                    # v7.6: Top 미진입/부분커버 함수 텍스트 출력 (uncovered_funcs.png 대체)
                    _ne_list, _pt_list = self._collect_uncov_funcs()
                    _TOP_N_TXT = 20
                    if _ne_list:
                        summary_lines.append(
                            f"Top {min(_TOP_N_TXT, len(_ne_list))} not-entered functions "
                            f"(total {len(_ne_list)}, by size):")
                        for _name, _sz, _addr in _ne_list[:_TOP_N_TXT]:
                            summary_lines.append(
                                f"  0x{_addr:08x}  size={_sz:>6}  {_name}")
                    if _pt_list:
                        summary_lines.append(
                            f"Top {min(_TOP_N_TXT, len(_pt_list))} partially-covered functions "
                            f"(total {len(_pt_list)}, by size):")
                        for _name, _sz, _addr, _pct in _pt_list[:_TOP_N_TXT]:
                            _pct_str = f"{_pct:5.1f}% BB" if _pct == _pct else "  BB?  "
                            summary_lines.append(
                                f"  0x{_addr:08x}  size={_sz:>6}  [{_pct_str}]  {_name}")

                op_names = ['bitflip1', 'int8', 'int16', 'int32',
                            'arith8', 'arith16', 'arith32', 'randbyte',
                            'byteswap', 'delete', 'insert', 'overwrite',
                            'splice', 'shuffle', 'blockfill', 'asciiint']
                # v7.8: unsupported_skip 누적 카운트
                _unsup = self.stats.get('unsupported_skipped', 0)
                if _unsup > 0 or self.config.unsupported_skip:
                    summary_lines.append(f"Unsupported skipped: {_unsup}회 (EngineErrInt)")
                # v8.0: 가성 유발 admin opcode 전송 차단 누적
                _blk = self.stats.get('blocked_admin_opcode', 0)
                if _blk > 0:
                    summary_lines.append(f"Blocked admin opcode: {_blk}회 "
                                         f"(큐관리/AER/DBBUF 가성 방지)")
                summary_lines.append(f"MOpt mode        : {self.mopt_mode}")
                mopt_detail = []
                for i in range(self.NUM_MUTATION_OPS):
                    if self.mopt_uses[i] > 0:
                        rate = self.mopt_finds[i] / self.mopt_uses[i]
                        mopt_detail.append(f"{op_names[i]}={self.mopt_finds[i]}/"
                                           f"{self.mopt_uses[i]}({rate:.3f})")
                if mopt_detail:
                    summary_lines.append(f"MOpt finds/uses  : {', '.join(mopt_detail)}")

                summary_lines.append("=" * 60)

                for line in summary_lines:
                    print(line)
                for line in summary_lines:
                    log.info(line)
            except Exception as e:
                print(f"\n[Summary error] {e}")

            try:
                self.sampler.save_coverage(str(self.output_dir))
            except Exception as e:
                log.error(f"Coverage save failed: {e}")

            try:
                self._save_per_command_data()
                self._generate_graphs()
                self._generate_heatmaps()
            except Exception as e:
                log.error(f"Graph/heatmap generation failed: {e}")

            try:
                self._generate_static_coverage_graphs()
            except Exception as e:
                log.error(f"Static coverage graph generation failed: {e}")

            try:
                self._generate_mutation_chart()
            except Exception as e:
                log.error(f"Mutation chart generation failed: {e}")

            try:
                self._generate_csfuzz_dynamics()
            except Exception as e:
                log.error(f"CSFuzz dynamics graph generation failed: {e}")

            try:
                for h in log.handlers:
                    h.flush()
                    if isinstance(h, logging.FileHandler) and h.stream:
                        os.fsync(h.stream.fileno())
            except Exception:
                pass

            # timeout crash: JLink 기반 PC 모니터링 루프 (30초 간격, Ctrl+C로 종료)
            # OpenOCD는 JLink dump 전에 이미 종료됨 → JLink 직접 연결로 PC 읽기
            if self._timeout_crash:
                import threading as _threading
                import re as _re

                _jlink_if = 'JTAG' if self.config.interface == 'jtag' else 'SWD'
                _jlink_dev = self.config.jlink_device
                idle_pcs = self.sampler.idle_pcs

                def _read_pc_via_jlink() -> Optional[List[int]]:
                    # v8.1: J-Link halt 샘플러(P9)는 pylink 가 USB 를 점유 중 → JLinkExe spawn 시
                    # USB 충돌. sampler 핸들을 직접 경유해 stuck PC 를 읽는다.
                    if isinstance(self.sampler, JLinkHaltSampler):
                        try:
                            stuck = self.sampler.read_stuck_pcs(count=1)
                            return [t[0] for t in stuck if t] or None
                        except Exception as e:
                            log.warning(f"[MONITOR] pylink stuck PC 읽기 예외: {e}")
                            return None
                    # OpenOCD 미사용 환경 — JLinkExe로 Core0만 읽기
                    argv = [JLINK_BINARY, '-if', _jlink_if, '-speed', '4000',
                            '-device', _jlink_dev, '-autoconnect', '1']
                    cmd_input = b'h\nregs\ngo\nexit\n'
                    log.debug(f"[MONITOR] JLink cmd: {' '.join(argv)}")
                    try:
                        proc = subprocess.run(
                            argv,
                            input=cmd_input,
                            capture_output=True, timeout=15
                        )
                        out = proc.stdout.decode(errors='replace')
                        if proc.stderr.strip():
                            log.debug(f"[MONITOR] JLink stderr:\n{proc.stderr.decode(errors='replace')}")
                        _pc_re = r'\bPC\s*(?::\s*\([^)]*\)\s*)?=\s*(?:0x)?([0-9A-Fa-f]+)'
                        pcs = [int(p, 16) & ~1 for p in _re.findall(_pc_re, out)]
                        if pcs:
                            return pcs[:1]
                        # JLinkExe 전체 출력은 verbose → 파일 로그에만 (INFO).
                        # 터미널 에는 짧은 실패 마커 만 표시.
                        log.info(f"[MONITOR] JLink PC 미검출. 전체 출력:\n{out}")
                        log.warning("[MONITOR] JLink PC 미검출 (전체 출력은 로그 파일 참조)")
                        return None
                    except Exception as e:
                        log.warning(f"[MONITOR] JLink 예외: {e}")
                        return None

                log.warning("[MONITOR] JLink PC 모니터링 시작 (30초 간격)")
                log.warning("[MONITOR] Ctrl+C → 모니터링 종료")

                _monitor_stop = _threading.Event()

                def _sigint_monitor(sig, frame):
                    _monitor_stop.set()

                try:
                    _signal.signal(_signal.SIGINT, _sigint_monitor)
                except Exception:
                    pass

                while not _monitor_stop.is_set():
                    pcs = _read_pc_via_jlink()
                    if pcs:
                        pc = pcs[0]
                        tag = "[IDLE]" if pc in idle_pcs else "[NON-IDLE]"
                        log.warning(f"[MONITOR] Core0={hex(pc)} {tag}")
                    else:
                        log.warning("[MONITOR] JLink PC 읽기 실패")
                    _monitor_stop.wait(30.0)

                log.warning("[MONITOR] 모니터링 종료")
            else:
                try:
                    self.sampler.close()
                except Exception:
                    pass
                # timeout crash가 아닌 정상 종료 시에만 타임아웃/APST 복원
                self._apst_restore()
                self._keepalive_restore()
                self._restore_nvme_timeouts()

            # 정리 완료 — SIGINT 핸들러 복원
            if _old_sigint is not None:
                try:
                    _signal.signal(_signal.SIGINT, _old_sigint)
                except (OSError, ValueError):
                    pass

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='PC Sampling SSD Fuzzer')
    # 설정 파일 (실제 로드는 import 시점 _early_config_path 에서 이미 처리됨 — 여기선 --help 문서화용)
    parser.add_argument('--config', default=None,
                        help='설정 JSON 경로 (default: 스크립트 디렉토리의 fuzzer_config.json)')
    # 제품/타겟
    parser.add_argument('--product', choices=list(PRODUCT_CONFIGS.keys()), default=None,
                        help=f'제품 선택 (interface/cfg 자동 설정). '
                             f'선택지: {", ".join(PRODUCT_CONFIGS.keys())}. '
                             f'--interface보다 우선 적용')
    parser.add_argument('--interface', choices=['swd', 'jtag'], default='swd',
                        help='디버그 transport (swd: r8_pcsr.cfg, jtag: r8_pcsr_jtag.cfg). '
                             '--product 지정 시 무시됨')
    parser.add_argument('--sampler', choices=['pcsr', 'halt', 'jlink_halt', 'null'], default=None,
                        help='coverage 수집 방식 override (기본: product profile 값). '
                             'pcsr=비침습 PCSR, halt=OpenOCD halt→reg pc→resume, '
                             'jlink_halt=pylink 직접 halt(P9 권장, telnet desync 없음), null=수집안함')
    parser.add_argument('--go-settle', type=int, default=None, dest='go_settle',
                        help='halt 샘플러: resume 후 다음 halt 까지 최소 실행시간(ms). '
                             '기본: profile 값(P9=50). NVMe timeout 나면 올릴 것')
    parser.add_argument('--pc-reg-index', type=int, default=None, dest='pc_reg_index',
                        help='jlink_halt 샘플러: PC(R15) 레지스터 인덱스 강제 지정 '
                             '(기본: connect 시 자동 탐지). jlink_reg_diag.py 로 확인 가능')
    parser.add_argument('--nvme', default=NVME_DEVICE, help='NVMe device')
    parser.add_argument('--namespace', type=int, default=NVME_NAMESPACE)

    # 명령어 선택
    parser.add_argument('--commands', nargs='+', default=[],
                        help='Commands to use (e.g., Read Write GetFeatures FormatNVM)')
    parser.add_argument('--all-commands', action='store_true', default=False,
                        help='Enable ALL commands including destructive ones '
                             '(FormatNVM, Sanitize, FWCommit, etc.)')
    parser.add_argument('--exclude-opcodes', type=str, default='',
                        help='Comma-separated hex opcodes to exclude from fuzzing, '
                             'e.g. "0xC1,0xC0" or "C1,C0"')

    # 커버리지 resume
    parser.add_argument('--resume-coverage', default=RESUME_COVERAGE,
                        help='Path to previous coverage.txt')

    # FW Download/Commit
    parser.add_argument('--fw-bin', default=_FW_BIN_PATH,
                        help='[v4.7] 펌웨어 바이너리 경로 (FWDownload 실제 시드 생성, '
                             '없으면 더미 1KB 시드). 기본값: FW_BIN_FILENAME 설정')
    parser.add_argument('--fw-xfer', type=int, default=FW_XFER_SIZE,
                        help=f'[v4.7] FWDownload 청크 크기(바이트) (default: {FW_XFER_SIZE})')
    parser.add_argument('--fw-slot', type=int, default=FW_SLOT,
                        help=f'[v4.7] FWCommit 슬롯 번호 (default: {FW_SLOT})')

    # PM
    parser.add_argument('--pm', action='store_true', default=False,
                        help=f'PM 로테이션 활성화: {PM_ROTATE_INTERVAL}명령마다 PS0→PS1→PS2→PS3→PS4 순환. '
                             f'timeout +{PS_ENTRY_EXIT_MARGIN_MS}ms 고정 마진 적용')
    parser.add_argument('--allow-no-openocd', action='store_true', default=False,
                        help='OpenOCD 연결 실패 시 --pm 전용 PM preflight/cycle 테스트만 수행하고 종료')
    parser.add_argument('--no-jlink', action='store_true', default=False,
                        help='J-Link 없이 NVMe fuzz 만 수행 (coverage 수집 안 함). '
                             'PM rotation / state telemetry / mutation / crash detection(timeout) 은 모두 동작.')
    parser.add_argument('--unsupported-skip', action='store_true', default=False,
                        help='timeout 후 J-Link dump 의 event log 에서 EngineErrInt 검출 시 '
                             '미지원 명령으로 간주, power cycle 후 메인 루프 계속. '
                             'customer_parsing_dump.py 는 fuzzer 와 같은 위치의 '
                             'DebugPackage/smi_mem_parsing/ 에 있어야 함.')
    parser.add_argument('--repro-opcode', type=str, default='',
                        help='재현 모드: 지정 opcode 가 timeout 날 때만 크래시 캡처+중단, 다른 opcode '
                             'timeout 은 POR 로 복구 후 계속(POR/PMU 필요). 여러 개는 콤마로 '
                             '(예: 0x84,0x80,0x0d). unsupported-skip 의 복구 로직 재사용.')
    parser.add_argument('--ignore-opcodes', type=str, default='',
                        help='denylist: 이 opcode(들) 가 timeout 나도 크래시로 안 치고 POR 복구 후 '
                             '계속(알려진 hang opcode 흘려보내기). 여러 개는 콤마로 '
                             '(예: 0x84,0x0d). repro-opcode 보다 우선.')

    # 토글
    parser.add_argument('--no-por', action='store_true', default=False,
                        help='시작 시 SSD POR(전원 사이클) 건너뜀 (기본: POR 수행)')
    parser.add_argument('--no-ufas', action='store_true', default=False,
                        help='crash 시 UFAS 펌웨어 덤프 건너뜀 (기본: ./ufas 파일이 있으면 자동 실행)')
    parser.add_argument('--no-jlink-dump', action='store_true', default=False,
                        help='crash 시 JLink 메모리 덤프 건너뜀 (기본: run_smi_mem_dump_JLINK_USB.sh가 있으면 자동 실행)')
    parser.add_argument('--no-state', action='store_true', default=False,
                        help='State monitoring 비활성화 (기본: 100회마다 nvme smart-log / get-log 실행)')
    parser.add_argument('--prefill', action='store_true', default=False,
                        help='POR 전 드라이브 전체 랜덤 쓰기 수행 (GC/Wear Leveling 트리거, 수 분 소요)')
    parser.add_argument('--prefill-bs', type=int, default=PREFILL_BS,
                        help='prefill dd 블록 크기 (바이트, 기본: 4194304 = 4MB)')

    # v8.4: IO 워크로드 엔진 토글 (기본: config io_workload.enabled)
    parser.add_argument('--io-workload', action='store_true', default=False,
                        help='IO 워크로드 엔진 강제 활성 (fuzz 사이 rc=0 Write/Read 블록 주입)')
    parser.add_argument('--no-io-workload', action='store_true', default=False,
                        help='IO 워크로드 엔진 비활성 (기본: config io_workload.enabled)')

    args = parser.parse_args()

    # CLI에서 지정한 제외 opcode 파싱 (상단 EXCLUDED_OPCODES 기본값 + CLI 추가분 병합)
    excluded_opcodes = list(EXCLUDED_OPCODES)
    if args.exclude_opcodes.strip():
        for tok in args.exclude_opcodes.split(','):
            tok = tok.strip()
            if tok:
                val = int(tok, 16) if tok.startswith(('0x', '0X')) else int(tok, 16)
                if val not in excluded_opcodes:
                    excluded_opcodes.append(val)

    # 재현 모드 타겟 opcode 파싱 (--repro-opcode, hex, 콤마로 여러 개)
    repro_opcodes = []
    if args.repro_opcode.strip():
        for _tok in args.repro_opcode.split(','):
            _tok = _tok.strip()
            if _tok and int(_tok, 16) not in repro_opcodes:
                repro_opcodes.append(int(_tok, 16))
    repro_opcodes = tuple(repro_opcodes)

    # ignore-list opcode 파싱 (--ignore-opcodes, hex, 콤마로 여러 개)
    ignore_opcodes = []
    if args.ignore_opcodes.strip():
        for _tok in args.ignore_opcodes.split(','):
            _tok = _tok.strip()
            if _tok and int(_tok, 16) not in ignore_opcodes:
                ignore_opcodes.append(int(_tok, 16))
    ignore_opcodes = tuple(ignore_opcodes)

    # NVMe 타임아웃 — 그룹별 조정은 코드 상단 NVME_TIMEOUTS 상수에서 직접 수정
    nvme_timeouts = NVME_TIMEOUTS.copy()

    # 활성화될 명령어 결정
    if args.commands:
        active_cmds = [c for c in NVME_COMMANDS if c.name in args.commands]
    elif args.all_commands:
        active_cmds = NVME_COMMANDS
    else:
        active_cmds = NVME_COMMANDS_DEFAULT

    print("Default commands (safe):")
    for cmd in NVME_COMMANDS_DEFAULT:
        tg = cmd.timeout_group
        tms = nvme_timeouts.get(tg, nvme_timeouts['command'])
        marker = " *" if cmd in active_cmds else ""
        print(f"  {cmd.name}: opcode={hex(cmd.opcode)}, type={cmd.cmd_type.value}, "
              f"timeout={tg}({tms}ms){marker}")
    print("Extended commands (destructive, use --all-commands or --commands):")
    for cmd in NVME_COMMANDS_EXTENDED:
        tg = cmd.timeout_group
        tms = nvme_timeouts.get(tg, nvme_timeouts['command'])
        marker = " *" if cmd in active_cmds else ""
        print(f"  {cmd.name}: opcode={hex(cmd.opcode)}, type={cmd.cmd_type.value}, "
              f"timeout={tg}({tms}ms){marker}")
    print(f"\nActive: {[c.name for c in active_cmds]}")
    print()
    if excluded_opcodes:
        print(f"Excluded opcodes: {[hex(o) for o in excluded_opcodes]}")
    if repro_opcodes:
        print(f"[REPRO] 재현 모드: 타겟 opcode {[hex(o) for o in repro_opcodes]} timeout 만 크래시 "
              f"캡처, 나머지 opcode timeout 은 POR 복구 후 계속 (POR/PMU 필요)")
    if ignore_opcodes:
        print(f"[IGN] ignore-list: opcode {[hex(o) for o in ignore_opcodes]} timeout 은 "
              f"크래시로 안 치고 POR 복구 후 계속 (POR/PMU 필요)")
    print("\nFeatures:")
    print("  - subprocess (nvme-cli) NVMe passthru")
    print("  - Global PC saturation (configurable) + idle PC detection")
    print("  - Per-execution prev_pc reset (no cross-execution false edges)")
    print("  - AFL++ havoc/splice mutation engine + MOpt scheduling")
    print("  - Per-opcode NVMe spec seed templates")
    print()

    # --product → 전체 target profile 자동 결정 (v8.0)
    if args.product is not None:
        _profile = PRODUCT_PROFILES[args.product]
        resolved_interface = _profile['interface']
        # v8.2: OpenOCD/PCSR 전용 키(openocd_config/tcl_prefix/pcsr_addrs/power_*/ufas_ini)는
        # J-Link halt 제품(P9)에선 N/A → profile 에서 생략 가능. 읽기는 .get(기본값)으로 관용.
        resolved_cfg = _profile.get('openocd_config', OPENOCD_CONFIG)
        _ncore = len(_profile.get('pcsr_addrs') or []) or '?'
        print(f"Product={args.product}: interface={resolved_interface}, "
              f"cfg={resolved_cfg}, jlink={_profile.get('jlink_device', JLINK_DEVICE)}, "
              f"cores={_ncore}")
        # bring-up 검증: PCSR 샘플러(sampler_type='pcsr')만 pcsr_addrs 필수.
        # halt 샘플러는 reg pc 로 읽어 pcsr_addrs 불필요. --no-jlink/null 도 통과.
        # fw_addr_*(coverage 주소필터)는 없어도 동작(전부 카운트) → 경고만.
        _st = args.sampler or _profile.get('sampler_type', 'pcsr')
        if not args.no_jlink and _st != 'null':
            if _st == 'pcsr' and _profile.get('pcsr_addrs') is None:
                print(f"\n[ERROR] Product '{args.product}' bring-up 미완: pcsr_addrs 비어 있음.")
                print(f"        PRODUCT_PROFILES['{args.product}']['pcsr_addrs'] 를 채우거나 "
                      "--no-jlink / --sampler halt 로 테스트하세요. (P9_BRINGUP.md)")
                sys.exit(2)
            _soft = [k for k in ('fw_addr_start', 'fw_addr_end') if _profile.get(k) is None]
            if _soft:
                print(f"[WARN] {args.product}: {', '.join(_soft)} 미지정 → "
                      "coverage 주소필터 없이 전체 PC 카운트 (bring-up 후 .text 범위 입력 권장).")
    else:
        # 구식 경로(--interface only): R8 기본 profile 합성 (하위호환)
        resolved_interface = args.interface
        resolved_cfg = OPENOCD_CONFIG_JTAG if args.interface == 'jtag' else OPENOCD_CONFIG
        _profile = {
            'jlink_device':      JLINK_DEVICE,
            'tcl_prefix':        'r8',
            'pcsr_addrs':        PCSR_ADDRS_JTAG if args.interface == 'jtag' else PCSR_ADDRS_SWD,
            'power_addr':        PCSR_POWER_ADDR,
            'power_mask':        PCSR_POWER_MASK,
            'invalid_pc_vals':   R8_DPIDR_VALS,
            'fw_addr_start':     FW_ADDR_START,
            'fw_addr_end':       FW_ADDR_END,
            'bb_file':           'basic_blocks.txt',
            'func_file':         'functions.txt',
            'enable_ufas':       True,
            'ufas_ini':          'PM9M1_A815.ini',
            'enable_jlink_dump': True,
            'sampler_type':      'pcsr',
            'go_settle_ms':      0,
        }

    # sampler_type / go_settle 해석: CLI override > profile. --no-jlink 면 null 강제.
    _resolved_sampler = ('null' if args.no_jlink
                         else (args.sampler or _profile.get('sampler_type', 'pcsr')))
    _resolved_go_settle = (args.go_settle if args.go_settle is not None
                           else _profile.get('go_settle_ms', 0))

    # v8.3: 제품별 timeout override — global(NVME_TIMEOUTS) 기본값 위에 제품 항목을 덮어씀.
    #   nvme_timeouts: 제품의 부분/전체 dict 로 그룹별 갱신. passthru/kernel: 제품 키 있으면 우선.
    _prod_timeouts = _profile.get('nvme_timeouts')
    if _prod_timeouts:
        nvme_timeouts.update(_prod_timeouts)
    _resolved_passthru_ms = _profile.get('nvme_passthru_timeout_ms', NVME_PASSTHRU_TIMEOUT_MS)
    _resolved_kernel_sec  = _profile.get('nvme_kernel_timeout_sec', NVME_KERNEL_TIMEOUT_SEC)

    # v8.3: 제품별 state 관측 필드 세트 해석 (제품의 state_fields 키 = 세트명, 기본 r8).
    _sf_setname = _profile.get('state_fields', 'r8')
    _resolved_state_fields = STATE_FIELD_SETS.get(_sf_setname)
    if _resolved_state_fields is None:
        print(f"[WARN] state_fields 세트 '{_sf_setname}' 없음 → 'r8' 사용")
        _resolved_state_fields = STATE_FIELD_SETS.get('r8', [])

    config = FuzzConfig(
        openocd_config=resolved_cfg,
        interface=resolved_interface,
        # v8.0: target profile 주입. v8.2: OpenOCD/PCSR/UFAS 전용 키는 .get(기본값) — J-Link
        # halt 제품(P9)이 해당 키를 생략해도 동작(값은 어차피 미사용).
        jlink_device=_profile.get('jlink_device', JLINK_DEVICE),
        tcl_prefix=_profile.get('tcl_prefix', 'r8'),
        pcsr_addrs=_profile.get('pcsr_addrs'),
        power_addr=_profile.get('power_addr'),
        power_mask=_profile.get('power_mask'),
        invalid_pc_vals=tuple(_profile['invalid_pc_vals']) if _profile.get('invalid_pc_vals') else (),
        ufas_ini=_profile.get('ufas_ini'),
        addr_range_start=_profile.get('fw_addr_start'),
        addr_range_end=_profile.get('fw_addr_end'),
        bb_file=_profile.get('bb_file', 'basic_blocks.txt'),
        func_file=_profile.get('func_file', 'functions.txt'),
        sampler_type=_resolved_sampler,
        go_settle_ms=_resolved_go_settle,
        # v8.1: JLinkHaltSampler(P9) 파라미터 — profile 기본값, pc_reg_index 는 CLI override 우선
        jlink_speed=_profile.get('jlink_speed', 4000),
        jlink_ap_index=_profile.get('jlink_ap_index', 0),
        pc_reg_index=(args.pc_reg_index if args.pc_reg_index is not None
                      else _profile.get('pc_reg_index')),
        nvme_device=args.nvme,
        nvme_namespace=args.namespace,
        nvme_timeouts=nvme_timeouts,
        nvme_passthru_timeout_ms=_resolved_passthru_ms,
        nvme_kernel_timeout_sec=_resolved_kernel_sec,
        enabled_commands=args.commands,
        all_commands=args.all_commands,
        resume_coverage=args.resume_coverage,
        excluded_opcodes=excluded_opcodes,
        # FW
        fw_bin=args.fw_bin,
        fw_xfer_size=args.fw_xfer,
        fw_slot=args.fw_slot,
        # PM
        pm_inject_prob=1.0 if args.pm else 0.0,
        allow_no_openocd=args.allow_no_openocd,
        no_jlink=args.no_jlink,
        unsupported_skip=args.unsupported_skip,
        repro_opcodes=repro_opcodes,
        ignore_opcodes=ignore_opcodes,
        # 토글
        enable_por=not args.no_por,
        # v8.0: profile 이 끈 제품(P9)은 CLI 와 무관하게 비활성 유지
        enable_ufas=_profile['enable_ufas'] and not args.no_ufas,
        enable_jlink_dump=_profile['enable_jlink_dump'] and not args.no_jlink_dump,
        state_enabled=not args.no_state,
        state_fields=_resolved_state_fields,
        prefill=args.prefill,
        prefill_bs=args.prefill_bs,
        # v8.4: IO 워크로드 — --no-io-workload 우선, 그다음 --io-workload, 없으면 config 기본
        io_workload_enabled=(False if args.no_io_workload
                             else True if args.io_workload
                             else IO_WL_ENABLED),
    )

    fuzzer = NVMeFuzzer(config)
    fuzzer.run()
