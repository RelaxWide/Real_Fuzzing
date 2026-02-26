#!/usr/bin/env python3
"""
PC Sampling 기반 SSD 펌웨어 Coverage-Guided Fuzzer v4.3

J-Link V9 Halt-Sample-Resume 방식으로 커버리지를 수집하고,
subprocess(nvme-cli)를 통해 SSD에 퍼징 입력을 전달합니다.

v4.3 변경사항:
- [BugFix] 로그 메시지 불일치 수정: "ioctl direct" → "subprocess (nvme-cli)"
- [BugFix] 글로벌 포화 임계값을 하드코딩(20) → 설정값(global_saturation_limit)으로 분리
- [BugFix] 실행 간 prev_pc 캐리오버 제거: 매 실행마다 sentinel로 리셋하여 교차 edge 방지
- [BugFix] post_cmd_delay_ms 미사용 수정: 명령 완료 후 추가 샘플링 대기 구현
- [Perf] cmd_traces를 collections.deque로 교체 (pop(0) O(n) → popleft O(1))
- [Perf] 샘플 간격 체크포인트를 frozenset으로 교체 (O(1) lookup 보장)
- [Clarity] 20% 완전 랜덤 생성 비율을 설정값(random_gen_ratio)으로 분리
- [Feature] Summary에 Mutation 통계 추가: opcode/nsid/admin↔io/data_len 변형 횟수,
  실제 전송된 opcode 분포, passthru 타입 비율, 입력 소스(corpus vs random) 비율
- [Feature] Timeout crash 시 불량 현상 보존: J-Link로 stuck PC를 읽고 crash에 기록,
  SSD 펌웨어를 resume 상태로 유지 (halt하지 않음), J-Link 연결도 유지,
  reconnect/continue/rescan 없이 퍼징 중단하여 불량 현상 그대로 보존
- [BugFix] subprocess kill 후 D state 블로킹 방지: communicate()에 타임아웃 추가

v4.2 변경사항:
- subprocess + 샘플링 연동: idle/포화 감지 시 프로세스 kill → 즉시 다음 실행
- 글로벌 기준 포화 판정 (global_edges 대비 새 edge 체크)
- idle PC 감지: diagnose에서 가장 빈도 높은 PC를 idle로 설정,
  연속 N회 idle PC일 때만 샘플링 조기 중단

v4.1 변경사항:
- Seed dataclass에 CDW2~CDW15 필드 추가
- Opcode별 NVMe 스펙 기반 정상 명령어를 초기 시드로 자동 생성
- AFL++ havoc/splice 기반 mutation 전략
- 명령어별 edge/PC 추적 및 CFG 그래프 생성

v4 변경사항:
- Sampled Edge 커버리지: (prev_pc, cur_pc) 튜플 기반
- Power Schedule: AFLfast explore 방식 에너지 기반 시드 선택
- Seed dataclass 도입
"""

from __future__ import annotations

import pylink
import struct
import time
import threading
import subprocess
import os
import shutil
import json
import hashlib
import random
import logging
import math
from collections import defaultdict, deque
from typing import Set, List, Optional, Tuple, Dict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from enum import Enum
import contextlib

# 버전
FUZZER_VERSION = "4.5"

# =============================================================================
# USER CONFIGURATION - 여기만 수정하세요
# =============================================================================

# Ghidra에서 확인한 펌웨어 코드(.text) 영역 주소
FW_ADDR_START = 0x00000000
FW_ADDR_END   = 0x00147FFF

# J-Link / JTAG 설정
JLINK_DEVICE  = 'Cortex-R8'
JLINK_SPEED   = 12000          # kHz

# NVMe 장치 설정
NVME_DEVICE    = '/dev/nvme0'
NVME_NAMESPACE = 1

# NVMe 명령어 그룹별 타임아웃 (ms)
# 그룹에 속하지 않는 명령어는 모두 'command'에 해당
NVME_TIMEOUTS = {
    'command':      8_000,     # 일반 명령어 (Identify, GetLogPage, GetFeatures, Read, Write 등)
    'format':       600_000,   # Format NVM — 전체 미디어 포맷, 수 분 소요 가능
    'sanitize':     600_000,   # Sanitize — 보안 삭제, 수 분~수십 분 소요
    'fw_commit':    120_000,   # Firmware Commit — 펌웨어 슬롯 활성화, 리셋 포함 가능
    'telemetry':    30_000,    # Telemetry Host/Controller — 대용량 로그 수집
    'dsm':          30_000,    # Dataset Management (TRIM/Deallocate)
    'flush':        30_000,    # Flush — 캐시 플러시, 미디어 기록 완료 대기
}

# PC 샘플링 설정
SAMPLE_INTERVAL_US    = 0     # 샘플 간격 (us), 0 = halt 직후 바로 다음 halt
MAX_SAMPLES_PER_RUN   = 500   # NVMe 커맨드 1회당 최대 샘플 수 (상한)
SATURATION_LIMIT      = 10    # idle PC 연속 N회 감지 시 샘플링 조기 종료
GLOBAL_SATURATION_LIMIT = 20  # v4.3: 글로벌 edge 기준 연속 N회 새 edge 없으면 조기 종료
POST_CMD_DELAY_MS     = 0     # 커맨드 완료 후 tail 샘플링 (ms)

# 퍼징 설정
MAX_INPUT_LEN     = 4096      # 최대 입력 바이트
TOTAL_RUNTIME_SEC = 3600      # 총 퍼징 시간 (초)
OUTPUT_DIR        = f'./output/pc_sampling_v{FUZZER_VERSION}/'
SEED_DIR          = None      # 시드 폴더 경로 (없으면 None)
RESUME_COVERAGE   = None      # 이전 coverage.txt 경로 (없으면 None)

# Power Schedule 설정 (v4 추가)
MAX_ENERGY        = 16.0      # 최대 에너지 값

# v4.3: 완전 랜덤 생성 비율 (0.0~1.0, 기본 0.2 = 20%)
RANDOM_GEN_RATIO  = 0.2

# v4.3: 제외할 opcode 목록 (e.g. [0xC1, 0xC0] — 디바이스 탈락 유발 opcode)
EXCLUDED_OPCODES: List[int] = []

# v4.3: 확장 mutation 확률 (0.0 = 비활성화)
OPCODE_MUT_PROB   = 0.10   # opcode override 확률 (기본 10%)
NSID_MUT_PROB     = 0.10   # namespace ID override 확률 (기본 10%)
ADMIN_SWAP_PROB   = 0.05   # Admin↔IO 교차 전송 확률 (기본 5%)
DATALEN_MUT_PROB  = 0.08   # data_len 불일치 확률 (기본 8%)

# v4.5: Calibration 설정
CALIBRATION_RUNS  = 3      # 초기 시드당 calibration 실행 횟수 (0 = 비활성화)

# v4.5: Deterministic stage 설정
DETERMINISTIC_ENABLED = True
DETERMINISTIC_ARITH_MAX = 10  # 결정론적 단계 arithmetic 최대 delta

# v4.5: MOpt (mutation operator scheduling) 설정
MOPT_ENABLED      = True
MOPT_PILOT_PERIOD = 5000   # pilot 단계 실행 횟수
MOPT_CORE_PERIOD  = 50000  # core 단계 실행 횟수

# v4.5+: Edge Confirmation — PC 샘플링 타이밍 아티팩트 필터링
# 처음 관측된 edge를 즉시 global_edges에 추가하지 않고 pending pool에서
# EDGE_CONFIRM_THRESHOLD회 이상 관측된 경우에만 global_edges로 승격.
# 타이밍 노이즈(1회성 edge)를 걸러 corpus 폭발을 방지한다.
EDGE_CONFIRM_THRESHOLD = 2  # pending → global_edges 승격에 필요한 최소 관측 횟수

# v4.5+: Corpus 하드 상한 (안전망)
# 0 = 무제한. 양수로 설정하면 culling 후에도 상한을 초과할 경우
# exec_count가 높은(많이 실행된) 비선호 seed부터 강제 제거한다.
MAX_CORPUS_HARD_LIMIT = 0

# =============================================================================


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


# 기본 활성화 (비파괴, 빠른 응답) — --commands 없이 실행 시 이것만 사용
NVME_COMMANDS_DEFAULT = [
    # ── Admin Commands (읽기 전용) ──
    NVMeCommand("Identify", 0x06, NVMeCommandType.ADMIN, needs_data=False,
                description="장치/네임스페이스 정보 조회"),
    NVMeCommand("GetLogPage", 0x02, NVMeCommandType.ADMIN, needs_data=False,
                description="로그 페이지 조회"),
    NVMeCommand("GetFeatures", 0x0A, NVMeCommandType.ADMIN, needs_data=False,
                description="기능 조회"),
    # ── I/O Commands ──
    NVMeCommand("Read", 0x02, NVMeCommandType.IO, needs_data=False,
                description="데이터 읽기"),
    NVMeCommand("Write", 0x01, NVMeCommandType.IO,
                description="데이터 쓰기"),
]

# 전체 명령어 (위험/파괴적 포함) — --commands 또는 --all-commands로 활성화
NVME_COMMANDS_EXTENDED = [
    NVMeCommand("SetFeatures", 0x09, NVMeCommandType.ADMIN,
                description="기능 설정"),
    NVMeCommand("FWDownload", 0x11, NVMeCommandType.ADMIN,
                description="펌웨어 이미지 다운로드"),
    NVMeCommand("FWCommit", 0x10, NVMeCommandType.ADMIN,
                timeout_group="fw_commit",
                description="펌웨어 슬롯 활성화/커밋"),
    NVMeCommand("FormatNVM", 0x80, NVMeCommandType.ADMIN,
                timeout_group="format",
                description="NVM 포맷 (미디어 초기화)"),
    NVMeCommand("Sanitize", 0x84, NVMeCommandType.ADMIN, needs_namespace=False,
                timeout_group="sanitize",
                description="보안 삭제 (전체 미디어)"),
    NVMeCommand("TelemetryHostInitiated", 0x02, NVMeCommandType.ADMIN, needs_data=False,
                timeout_group="telemetry",
                description="텔레메트리 로그 (호스트 개시)"),
    NVMeCommand("Flush", 0x00, NVMeCommandType.IO, needs_data=False,
                timeout_group="flush",
                description="캐시 플러시"),
    NVMeCommand("DatasetManagement", 0x09, NVMeCommandType.IO,
                timeout_group="dsm",
                description="데이터셋 관리 (TRIM/Deallocate)"),
]

# 전체 명령어 (이름으로 조회용)
NVME_COMMANDS = NVME_COMMANDS_DEFAULT + NVME_COMMANDS_EXTENDED

# v4.4: opcode → 명령어 이름 역방향 매핑 (NVMe 스펙 기준)
# (opcode, cmd_type) → name. 동일 opcode라도 Admin/IO 구분.
_OPCODE_TO_NAME: dict[tuple[int, str], str] = {}
for _c in NVME_COMMANDS:
    _key = (_c.opcode, _c.cmd_type.value)
    if _key not in _OPCODE_TO_NAME:
        _OPCODE_TO_NAME[_key] = _c.name


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
    new_edges: int = 0           # 발견한 새 edge 수
    energy: float = 1.0          # 계산된 에너지
    covered_edges: Optional[set] = None  # v4.3: 이 시드 실행 시 발견된 edge set (culling용)
    is_favored: bool = False     # v4.3: corpus culling에서 선정된 favored seed
    # v4.5: Calibration
    is_calibrated: bool = False  # calibration 완료 여부
    stability: float = 1.0      # 0.0~1.0, edge 안정성 비율
    stable_edges: Optional[set] = None  # calibration에서 모든 실행에 등장한 edge
    # v4.5: Deterministic stage
    det_done: bool = False       # deterministic stage 완료 여부


@dataclass
class FuzzConfig:
    device_name: str = JLINK_DEVICE
    interface: int = pylink.enums.JLinkInterfaces.JTAG
    jtag_speed: int = JLINK_SPEED

    nvme_device: str = NVME_DEVICE
    nvme_namespace: int = NVME_NAMESPACE
    nvme_timeouts: dict = field(default_factory=lambda: NVME_TIMEOUTS.copy())

    enabled_commands: List[str] = field(default_factory=list)
    all_commands: bool = False   # True면 위험(파괴적) 명령어 포함 전체 활성화

    # 샘플링 설정
    sample_interval_us: int = SAMPLE_INTERVAL_US
    max_samples_per_run: int = MAX_SAMPLES_PER_RUN
    saturation_limit: int = SATURATION_LIMIT

    # v4.3: 글로벌 포화 임계값 (이전 v4.2에서는 하드코딩 20)
    global_saturation_limit: int = GLOBAL_SATURATION_LIMIT

    # NVMe 커맨드 완료 후 추가 샘플링 시간 (ms)
    post_cmd_delay_ms: int = POST_CMD_DELAY_MS

    # 퍼징 설정
    max_input_len: int = MAX_INPUT_LEN
    total_runtime_sec: int = TOTAL_RUNTIME_SEC
    seed_dir: Optional[str] = SEED_DIR
    output_dir: str = OUTPUT_DIR

    # 주소 필터 (펌웨어 .text 섹션 범위)
    addr_range_start: Optional[int] = FW_ADDR_START
    addr_range_end: Optional[int] = FW_ADDR_END

    # 이전 세션 커버리지 파일 (resume용)
    resume_coverage: Optional[str] = RESUME_COVERAGE

    # Power Schedule 설정 (v4 추가)
    max_energy: float = MAX_ENERGY

    # v4.3: 완전 랜덤 생성 비율
    random_gen_ratio: float = RANDOM_GEN_RATIO

    # v4.3: 제외할 opcode 목록
    excluded_opcodes: List[int] = field(default_factory=lambda: EXCLUDED_OPCODES.copy())

    # v4.3: 확장 mutation 확률
    opcode_mut_prob: float = OPCODE_MUT_PROB
    nsid_mut_prob: float = NSID_MUT_PROB
    admin_swap_prob: float = ADMIN_SWAP_PROB
    datalen_mut_prob: float = DATALEN_MUT_PROB

    # v4.5: Calibration
    calibration_runs: int = CALIBRATION_RUNS

    # v4.5: Deterministic stage
    deterministic_enabled: bool = DETERMINISTIC_ENABLED
    deterministic_arith_max: int = DETERMINISTIC_ARITH_MAX

    # v4.5: MOpt
    mopt_enabled: bool = MOPT_ENABLED
    mopt_pilot_period: int = MOPT_PILOT_PERIOD
    mopt_core_period: int = MOPT_CORE_PERIOD

    # v4.5+: Edge Confirmation (타이밍 아티팩트 필터)
    edge_confirm_threshold: int = EDGE_CONFIRM_THRESHOLD

    # v4.5+: Corpus 하드 상한 (0 = 무제한)
    max_corpus_hard_limit: int = MAX_CORPUS_HARD_LIMIT


def setup_logging(output_dir: str) -> Tuple[logging.Logger, str]:
    """파일 + 콘솔 동시 로깅 설정 (실행마다 날짜시간 로그 파일 생성)"""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(output_dir, f'fuzzer_{timestamp}.log')

    logger = logging.getLogger('pcfuzz')
    logger.setLevel(logging.DEBUG)

    # 이전 핸들러 제거 (중복 방지)
    logger.handlers.clear()

    fmt = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # 파일: 매 실행마다 새 파일 생성
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.INFO)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    # 콘솔
    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    return logger, log_file


# 모듈 레벨 로거 (setup_logging 호출 전까지 콘솔만 사용)
log = logging.getLogger('pcfuzz')


def _count_to_bucket(count: int) -> int:
    """v4.5: AFL++ 스타일 로그 버켓팅 — hit count를 8단계 bucket으로 변환.
    1, 2, 3, 4-7, 8-15, 16-31, 32-127, 128+"""
    if count == 0:   return 0
    if count == 1:   return 1
    if count == 2:   return 2
    if count == 3:   return 4
    if count <= 7:   return 8
    if count <= 15:  return 16
    if count <= 31:  return 32
    if count <= 127: return 64
    return 128


class JLinkPCSampler:
    """J-Link Halt-Sample-Resume 기반 PC 수집기 (v4.5: hit count bucketing 추가)"""

    # v4.3: 샘플 간격 체크포인트 (frozenset으로 O(1) lookup 보장)
    _INTERVAL_CHECKPOINTS = frozenset({10, 25, 50, 100, 200, 500})

    def __init__(self, config: FuzzConfig):
        self.config = config
        self.jlink: Optional[pylink.JLink] = None
        self._pc_reg_index: int = 9  # Cortex-R8: R15(PC)의 J-Link 레지스터 인덱스

        # v4: Edge 기반 커버리지
        self.global_edges: Set[Tuple[int, int]] = set()  # (prev_pc, cur_pc) 튜플
        self.current_edges: Set[Tuple[int, int]] = set()
        # sentinel: 유효 주소 범위 밖의 값으로 초기화하여 가짜 edge 방지
        self.prev_pc: int = 0xFFFFFFFF

        # v4.5: Hit count bucketing
        self.global_edge_counts: Dict[Tuple[int, int], int] = {}   # edge → 누적 hit count
        self.global_edge_buckets: Dict[Tuple[int, int], int] = {}  # edge → 현재 bucket 값
        self.current_edge_counts: Dict[Tuple[int, int], int] = {}  # 이번 실행의 edge hit count
        self._last_bucket_changes: int = 0                          # 마지막 evaluate에서의 bucket 변화 수

        # v4.5+: Edge Confirmation — 타이밍 아티팩트 필터
        # pending pool: edge → 관측 횟수 (아직 global_edges로 승격 안 됨)
        # EDGE_CONFIRM_THRESHOLD 이상 관측 시 global_edges로 이동
        self.global_edge_pending: Dict[Tuple[int, int], int] = {}

        # 기존 PC 기반 커버리지 (비교용으로 유지)
        self.global_coverage: Set[int] = set()
        self.current_trace: Set[int] = set()

        self.stop_event = threading.Event()
        self.sample_thread: Optional[threading.Thread] = None
        self.total_samples = 0
        self.interesting_inputs = 0
        self._last_raw_pcs: List[int] = []
        self._out_of_range_count = 0

        # v4.2: idle PC — diagnose()에서 가장 빈도 높은 PC로 설정
        self.idle_pc: Optional[int] = None

    def connect(self) -> bool:
        try:
            if self.jlink and self.jlink.opened():
                self.jlink.close()

            self.jlink = pylink.JLink()
            self.jlink.open()
            self.jlink.set_tif(self.config.interface)
            self.jlink.connect(self.config.device_name, speed=self.config.jtag_speed)

            log.warning(f"[J-Link] Connected: {self.config.device_name} @ {self.config.jtag_speed}kHz")

            # R15(PC)의 실제 레지스터 인덱스를 동적으로 탐색
            self._pc_reg_index = self._find_pc_register_index()
            log.warning(f"[J-Link] PC register index: {self._pc_reg_index} "
                     f"(name: {self.jlink.register_name(self._pc_reg_index)})")

            # DLL 함수 참조 캐싱 (pylink wrapper 우회, 매 호출 attribute lookup 제거)
            self._halt_func = self.jlink._dll.JLINKARM_Halt
            self._read_reg_func = self.jlink._dll.JLINKARM_ReadReg
            self._go_func = self.jlink._dll.JLINKARM_Go

            return True
        except Exception as e:
            log.error(f"[J-Link Error] {e}")
            return False

    def _find_pc_register_index(self) -> int:
        """register_list()에서 R15(PC)의 실제 인덱스를 찾는다.
        Cortex-R8 등에서는 레지스터 인덱스가 0-15 순서가 아닐 수 있음."""
        try:
            for idx in self.jlink.register_list():
                name = self.jlink.register_name(idx)
                if 'R15' in name or name.upper() == 'PC':
                    return idx
        except Exception as e:
            log.warning(f"[J-Link] register_list() 탐색 실패: {e}")
        log.warning("[J-Link] R15 인덱스를 찾지 못함, 기본값 15 사용")
        return 15

    def diagnose(self, count: int = 20) -> bool:
        """시작 전 PC 읽기 진단 — J-Link 동작 검증 + idle PC 감지 (v4.2)"""
        log.warning(f"[Diagnose] PC를 {count}회 읽어서 J-Link 상태를 확인합니다...")
        pcs = []
        failures = 0
        for i in range(count):
            pc = self._read_pc()
            if pc is not None:
                pcs.append(pc)
                in_range = ""
                if self.config.addr_range_start is not None and self.config.addr_range_end is not None:
                    if self.config.addr_range_start <= pc <= self.config.addr_range_end:
                        in_range = " [IN RANGE]"
                    else:
                        in_range = " [OUT OF RANGE]"
                log.warning(f"  [{i+1:2d}] PC = {hex(pc)}{in_range}")
            else:
                failures += 1
                log.warning(f"  [{i+1:2d}] PC read FAILED")
            time.sleep(0.05)

        if not pcs:
            log.error("[Diagnose] PC를 한 번도 읽지 못했습니다. JTAG 연결을 확인하세요.")
            return False

        unique_pcs = set(pcs)
        log.warning(f"[Diagnose] 결과: {len(pcs)}/{count} 성공, "
                 f"failures={failures}, unique PCs={len(unique_pcs)}")

        # v4.2: 가장 빈도 높은 PC를 idle PC로 설정
        from collections import Counter
        pc_counts = Counter(pcs)
        most_common_pc, most_common_count = pc_counts.most_common(1)[0]
        idle_ratio = most_common_count / len(pcs)

        if idle_ratio >= 0.3:
            # 30% 이상 동일 PC면 idle로 판정
            self.idle_pc = most_common_pc
            log.warning(f"[Diagnose] idle PC 감지: {hex(most_common_pc)} "
                        f"(빈도: {most_common_count}/{len(pcs)} = {idle_ratio:.0%})")
        else:
            self.idle_pc = None
            log.warning(f"[Diagnose] idle PC 없음 (최다 PC {hex(most_common_pc)}: "
                        f"{idle_ratio:.0%} < 30% 임계값)")

        if len(unique_pcs) <= 1:
            log.warning(f"[Diagnose] PC가 항상 같은 값입니다 ({hex(pcs[0])}). "
                        f"CPU가 멈춰있거나 idle loop에 있을 수 있습니다.")
        return True

    def _read_pc(self) -> Optional[int]:
        try:
            self._halt_func()
            pc = self._read_reg_func(self._pc_reg_index)
            return pc
        except Exception:
            return None
        finally:
            try:
                self._go_func()
            except Exception:
                pass

    def read_stuck_pcs(self, count: int = 10) -> List[int]:
        """v4.3: timeout/crash 후 SSD 펌웨어가 멈춘 PC를 읽는다.
        halt→read→go를 반복하여 현재 펌웨어 위치를 여러 번 샘플링.
        동일 PC가 반복되면 해당 주소에서 hang (무한루프/대기) 상태.
        서로 다른 PC가 나오면 펌웨어가 에러 핸들링 루프 등을 돌고 있는 것."""
        pcs = []
        for _ in range(count):
            try:
                self._halt_func()
                pc = self._read_reg_func(self._pc_reg_index)
                pcs.append(pc)
            except Exception:
                pass
            finally:
                try:
                    self._go_func()
                except Exception:
                    pass
            time.sleep(0.05)
        return pcs

    def _in_range(self, pc: int) -> bool:
        """PC가 펌웨어 주소 범위 내인지 확인"""
        if self.config.addr_range_start is None or self.config.addr_range_end is None:
            return True
        return self.config.addr_range_start <= pc <= self.config.addr_range_end

    def _sampling_worker(self):
        """v4.5: hit count tracking 추가 + 글로벌 포화 임계값 설정 분리 + prev_pc 실행 간 리셋"""
        self.current_edges = set()
        self.current_trace = set()
        self.current_edge_counts = {}   # v4.5: 이번 실행 hit count
        self._last_raw_pcs = []
        self._out_of_range_count = 0
        self._last_new_at = 0
        self._unique_at_intervals = {}
        self._stopped_reason = ""

        sample_count = 0
        since_last_global_new = 0   # v4.2: 글로벌 기준 카운터
        consecutive_idle = 0         # v4.2: 연속 idle PC 카운터
        interval = self.config.sample_interval_us / 1_000_000
        sat_limit = self.config.saturation_limit
        global_sat_limit = self.config.global_saturation_limit  # v4.3: 설정값 사용
        idle_pc = self.idle_pc       # v4.2: 로컬 캐싱

        # v4.2: 글로벌 edge의 참조 캐싱 (thread safety)
        # 메인 스레드가 evaluate_coverage()에서 update()하더라도
        # CPython set.__contains__는 GIL 하에서 안전하지만,
        # 명시적 참조 캐싱으로 attribute lookup도 제거
        global_edges_ref = self.global_edges

        # v4.3: 매 실행마다 prev_pc를 sentinel로 리셋
        # → 서로 다른 NVMe 명령어 간의 교차 edge 방지
        prev_pc = 0xFFFFFFFF

        while not self.stop_event.is_set() and sample_count < self.config.max_samples_per_run:
            pc = self._read_pc()
            if pc is not None:
                self._last_raw_pcs.append(pc)

                if self._in_range(pc):
                    if prev_pc == 0xFFFFFFFF:
                        # 첫 번째 in-range PC: sentinel이므로 edge 생성하지 않음
                        prev_pc = pc
                        self.current_trace.add(pc)
                    else:
                        # Edge 생성 (prev_pc, cur_pc)
                        edge = (prev_pc, pc)
                        self.current_edges.add(edge)
                        self.current_edge_counts[edge] = self.current_edge_counts.get(edge, 0) + 1  # v4.5
                        self.current_trace.add(pc)
                        prev_pc = pc

                        # v4.2: 글로벌 기준으로 새로움 판단
                        if edge not in global_edges_ref:
                            self._last_new_at = sample_count
                            since_last_global_new = 0
                        else:
                            since_last_global_new += 1

                    # v4.2: idle PC 연속 카운터
                    if idle_pc is not None and pc == idle_pc:
                        consecutive_idle += 1
                    else:
                        consecutive_idle = 0
                else:
                    self._out_of_range_count += 1
                    # out-of-range도 idle 판정에 포함하지 않음
                    consecutive_idle = 0

                sample_count += 1
                self.total_samples += 1

                if sample_count in self._INTERVAL_CHECKPOINTS:
                    cur_unique_edges = len(self.current_edges)
                    self._unique_at_intervals[sample_count] = cur_unique_edges

                # v4.3: 조기 종료 조건 (OR) — 글로벌 임계값 설정 분리
                # 조건1: 연속 global_sat_limit회 글로벌 기준 새 edge 없음
                # 조건2: 연속 sat_limit회 idle PC에 머물러 있음
                if sat_limit > 0:
                    if global_sat_limit > 0 and since_last_global_new >= global_sat_limit:
                        self._stopped_reason = (
                            f"global_saturated (no global new edge for "
                            f"{since_last_global_new} consecutive samples, "
                            f"limit={global_sat_limit})"
                        )
                        break
                    if idle_pc is not None and consecutive_idle >= sat_limit:
                        self._stopped_reason = (
                            f"idle_saturated (idle PC {hex(idle_pc)} "
                            f"x{consecutive_idle} consecutive)"
                        )
                        break

            if interval > 0:
                time.sleep(interval)

        if not self._stopped_reason:
            if self.stop_event.is_set():
                self._stopped_reason = "stop_event"
            else:
                self._stopped_reason = f"max_samples ({self.config.max_samples_per_run})"

        # v4.3: prev_pc를 인스턴스에 저장하지 않음 (매 실행 독립)
        # 이전 v4.2에서는 self.prev_pc = prev_pc 로 캐리오버했으나,
        # 서로 다른 명령어 간의 가짜 edge를 방지하기 위해 제거

    def start_sampling(self):
        self.stop_event.clear()
        self.sample_thread = threading.Thread(target=self._sampling_worker, daemon=True)
        self.sample_thread.start()

    def stop_sampling(self) -> int:
        if self.sample_thread:
            self.stop_event.set()
            self.sample_thread.join(timeout=2.0)
        return len(self.current_edges)

    def evaluate_coverage(self) -> Tuple[bool, int]:
        """v4.5+: Edge Confirmation 기반 커버리지 평가.

        PC 샘플링 edge (prev_pc, cur_pc)는 타이밍 아티팩트를 포함한다.
        동일 코드경로를 실행해도 샘플링 타이밍에 따라 다른 쌍이 생성되어
        global_edges에 즉시 추가하면 corpus가 폭발적으로 증가한다.

        이를 방지하기 위해 2단계 승격 방식을 사용한다:
          1) 처음 관측 → global_edge_pending[edge] 증가
          2) pending 횟수 >= edge_confirm_threshold → global_edges 승격 (confirmed)

        1회성 타이밍 노이즈는 pending에서 소멸하고 corpus 추가를 유발하지 않는다.
        """
        confirm_threshold = self.config.edge_confirm_threshold

        # PC 커버리지(개별 주소)는 노이즈가 적으므로 그대로 합산
        self.global_coverage.update(self.current_trace)

        new_confirmed = 0
        for edge in self.current_edges:
            if edge in self.global_edges:
                continue  # 이미 확정된 edge — 건너뜀
            cnt = self.global_edge_pending.get(edge, 0) + 1
            if cnt >= confirm_threshold:
                # 임계값 도달 → global_edges로 승격
                self.global_edges.add(edge)
                self.global_edge_pending.pop(edge, None)
                new_confirmed += 1
            else:
                self.global_edge_pending[edge] = cnt

        # v4.5: Hit count bucket 변화 감지
        # v4.5+: 반드시 global_edges에 확정된 edge만 대상으로 한다.
        # 미확정(pending) edge의 hit count 변화는 타이밍 샘플링 노이즈이므로
        # corpus 추가 판단에 사용하면 is_interesting 오탐이 폭발적으로 증가한다.
        bucket_changes = 0
        for edge, count in self.current_edge_counts.items():
            old_total = self.global_edge_counts.get(edge, 0)
            new_total = old_total + count
            self.global_edge_counts[edge] = new_total

            # v4.5+: 확정된 edge만 bucket 변화 체크
            if edge not in self.global_edges:
                continue

            old_bucket = self.global_edge_buckets.get(edge, 0)
            new_bucket = _count_to_bucket(new_total)
            if new_bucket != old_bucket:
                self.global_edge_buckets[edge] = new_bucket
                # 새 edge가 아닌데 bucket이 바뀐 경우만 별도 카운트
                if old_total > 0:
                    bucket_changes += 1

        self._last_bucket_changes = bucket_changes  # 로그용

        # interesting = 새로 승격된 edge OR 확정된 edge의 bucket 변화
        is_interesting = (new_confirmed > 0) or (bucket_changes > 0)
        return is_interesting, new_confirmed + bucket_changes

    def load_coverage(self, filepath: str) -> int:
        """이전 세션의 커버리지 파일을 로드하여 global_coverage + global_edges에 합산"""
        loaded_pcs = 0
        loaded_edges = 0
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

        # edge 파일도 같이 로드 (coverage_edges.txt)
        edges_path = filepath.replace('coverage.txt', 'coverage_edges.txt')
        if os.path.exists(edges_path):
            with open(edges_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or ',' not in line:
                        continue
                    try:
                        parts = line.split(',')
                        prev_pc = int(parts[0], 16)
                        cur_pc = int(parts[1], 16)
                        self.global_edges.add((prev_pc, cur_pc))
                        loaded_edges += 1
                    except (ValueError, IndexError):
                        pass
            log.info(f"[Coverage] Loaded {loaded_edges} edges from {edges_path}")

        # v4.5: edge count 파일 로드 (coverage_edge_counts.txt)
        counts_path = filepath.replace('coverage.txt', 'coverage_edge_counts.txt')
        if os.path.exists(counts_path):
            loaded_counts = 0
            with open(counts_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or ',' not in line:
                        continue
                    try:
                        parts = line.split(',')
                        prev_pc = int(parts[0], 16)
                        cur_pc = int(parts[1], 16)
                        count = int(parts[2])
                        edge = (prev_pc, cur_pc)
                        self.global_edge_counts[edge] = count
                        self.global_edge_buckets[edge] = _count_to_bucket(count)
                        loaded_counts += 1
                    except (ValueError, IndexError):
                        pass
            log.info(f"[Coverage] Loaded {loaded_counts} edge counts from {counts_path}")

        log.info(f"[Coverage] Loaded {loaded_pcs} PCs from {filepath} "
                 f"(global: {len(self.global_coverage)} PCs, {len(self.global_edges)} edges)")
        return loaded_pcs

    def save_coverage(self, output_dir: str):
        """현재 global_coverage와 global_edges를 파일로 저장"""
        # PCs
        pc_path = os.path.join(output_dir, 'coverage.txt')
        with open(pc_path, 'w') as f:
            for pc in sorted(self.global_coverage):
                f.write(f"{hex(pc)}\n")

        # Edges
        edges_path = os.path.join(output_dir, 'coverage_edges.txt')
        with open(edges_path, 'w') as f:
            for prev_pc, cur_pc in sorted(self.global_edges):
                f.write(f"{hex(prev_pc)},{hex(cur_pc)}\n")

        # v4.5: Edge counts
        counts_path = os.path.join(output_dir, 'coverage_edge_counts.txt')
        with open(counts_path, 'w') as f:
            for (prev_pc, cur_pc), count in sorted(self.global_edge_counts.items()):
                f.write(f"{hex(prev_pc)},{hex(cur_pc)},{count}\n")

        log.info(f"[Coverage] Saved {len(self.global_coverage)} PCs → {pc_path}")
        log.info(f"[Coverage] Saved {len(self.global_edges)} edges → {edges_path}")
        log.info(f"[Coverage] Saved {len(self.global_edge_counts)} edge counts → {counts_path}")

    def close(self):
        self.stop_event.set()
        if self.sample_thread:
            self.sample_thread.join(timeout=1.0)
        if self.jlink:
            try:
                self.jlink.close()
            except Exception:
                pass


class NVMeFuzzer:
    """다중 Opcode 지원 NVMe 퍼저 (v4.3: subprocess nvme-cli + 글로벌 포화 설정 분리)"""

    VERSION = FUZZER_VERSION

    def __init__(self, config: FuzzConfig):
        self.config = config
        self.sampler = JLinkPCSampler(config)

        if config.enabled_commands:
            # --commands 지정 시: NVME_COMMANDS 전체에서 이름 매칭
            self.commands = [c for c in NVME_COMMANDS if c.name in config.enabled_commands]
        elif config.all_commands:
            # --all-commands: 위험 명령어 포함 전체
            self.commands = NVME_COMMANDS.copy()
        else:
            # 기본: 안전(비파괴) 명령어만
            self.commands = NVME_COMMANDS_DEFAULT.copy()

        log.info(f"[Fuzzer] Enabled commands: {[c.name for c in self.commands]}")

        # v4: Seed 리스트로 변경
        self.corpus: List[Seed] = []
        self.crash_inputs: List[Tuple[bytes, NVMeCommand]] = []

        self.output_dir = Path(config.output_dir)
        self.crashes_dir = self.output_dir / 'crashes'

        self.executions = 0
        self.start_time: Optional[datetime] = None

        self.cmd_stats: dict[str, dict] = defaultdict(lambda: {"exec": 0, "interesting": 0})
        for c in self.commands:
            self.cmd_stats[c.name] = {"exec": 0, "interesting": 0}
        self.rc_stats: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))

        # v4.3: 확장 mutation 통계 — 실제로 SSD에 전달된 내용을 추적
        self.mutation_stats = {
            "opcode_override": 0,     # opcode가 변형된 횟수
            "nsid_override": 0,       # nsid가 변형된 횟수
            "force_admin_swap": 0,    # Admin↔IO 교차 전송 횟수
            "data_len_override": 0,   # data_len 불일치 횟수
            "random_gen": 0,          # 완전 랜덤 생성 횟수
            "corpus_mutated": 0,      # corpus 기반 mutation 횟수
        }
        # 실제 전송된 opcode 분포 (원본과 다른 경우만)
        self.actual_opcode_dist: dict[int, int] = defaultdict(int)
        # 실제 전송된 passthru 타입 분포
        self.passthru_stats = {"admin-passthru": 0, "io-passthru": 0}

        # v4.3: timeout crash 발생 여부 — True면 finally에서 J-Link를 닫지 않음
        self._timeout_crash = False

        # v4.5: MOpt (mutation operator scheduling) 상태
        self.NUM_MUTATION_OPS = 16
        self.mopt_finds: List[int] = [0] * self.NUM_MUTATION_OPS   # operator별 새 coverage 발견 횟수
        self.mopt_uses: List[int] = [0] * self.NUM_MUTATION_OPS    # operator별 사용 횟수
        self._current_mutations: List[int] = []                     # 현재 실행에서 사용된 operator 목록
        self.mopt_mode: str = 'pilot'  # 'pilot' 또는 'core'
        self.mopt_weights: List[float] = [1.0 / self.NUM_MUTATION_OPS] * self.NUM_MUTATION_OPS
        self.mopt_pilot_rounds: int = 0

        # v4.5: Deterministic stage queue
        self._det_queue: deque = deque()  # (seed, generator) pairs

        # 명령어별 edge/PC 추적 (그래프 시각화용)
        # v4.3: defaultdict로 변경 — opcode_override 등 mutation별 키 자동 생성
        self.cmd_edges: dict[str, Set[Tuple[int, int]]] = defaultdict(set)
        self.cmd_pcs: dict[str, Set[int]] = defaultdict(set)
        # v4.3: deque로 교체 (pop(0) O(n) → popleft O(1))
        self.cmd_traces: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        # 기본 명령어 키 초기화
        for c in self.commands:
            self.cmd_edges[c.name] = set()
            self.cmd_pcs[c.name] = set()
            self.cmd_traces[c.name] = deque(maxlen=200)

        # v4.2: subprocess 입력 파일 경로 (재사용)
        self._nvme_input_path: Optional[str] = None

    @staticmethod
    def _tracking_label(cmd: 'NVMeCommand', seed: 'Seed') -> str:
        """v4.4: 실제 실행 내용 기준 추적 키 생성.
        opcode_override가 있으면:
          - NVMe 스펙에 일치하는 명령어가 있으면 해당 이름 사용
          - 없으면 원래 명령어명 없이 unknown_op0x{XX} 형태"""
        if seed.opcode_override is not None:
            # 실제 전송되는 passthru 타입 결정
            if seed.force_admin is not None:
                actual_type = "admin" if seed.force_admin else "io"
            else:
                actual_type = cmd.cmd_type.value
            spec_name = _OPCODE_TO_NAME.get((seed.opcode_override, actual_type))
            if spec_name is not None:
                return spec_name
            return f"unknown_op0x{seed.opcode_override:02X}"
        return cmd.name

    # =========================================================================
    # v4.5: Clone helper
    # =========================================================================

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

    # =========================================================================
    # v4.5: Calibration
    # =========================================================================

    def _calibrate_seed(self, seed: Seed) -> Seed:
        """시드를 N번 실행하여 edge 안정성 측정.
        안정한 edge(모든 실행에서 관측)만 global에 반영."""
        total_runs = self.config.calibration_runs
        if total_runs <= 0:
            seed.is_calibrated = True
            return seed

        edge_appearances: Dict[Tuple[int, int], int] = {}
        actual_runs = 0

        for run_i in range(total_runs):
            # _send_nvme_command() 내부에서 start_sampling()을 호출하므로
            # 여기서 별도로 start_sampling()을 호출하면 두 개의 sampling thread가
            # 동시에 실행되어 current_edges가 오염되고 zombie thread가 누적된다.
            rc = self._send_nvme_command(seed.data, seed)
            self.sampler.stop_sampling()
            self.executions += 1
            actual_runs += 1

            for edge in self.sampler.current_edges:
                edge_appearances[edge] = edge_appearances.get(edge, 0) + 1

            if rc in (self.RC_TIMEOUT, self.RC_ERROR):
                log.warning(f"[Calibration] {seed.cmd.name} rc={rc} at run {run_i+1} — stopping early")
                break

        # 안정성 계산
        # AFL++와 달리 PC Sampling은 확률적 샘플링이므로 실제로 실행된 코드도
        # 매 run마다 캡처되지 않을 수 있다. 따라서:
        #   - stable: 과반수(>50%) 이상 run에서 관측된 edge (seed 품질 메타데이터용)
        #   - global_edges 반영: all_seen(합집합) — 관측된 모든 edge를 커버리지로 인정
        # instrumentation 기반 AFL++처럼 cnt == actual_runs(100% 재현)를 쓰면
        # 거의 모든 edge가 unstable 처리되어 initial global coverage가 극도로 희박해지고
        # 퍼징 시작 후 대부분 입력이 "새 edge 발견"으로 오탐된다.
        all_seen = set(edge_appearances.keys())
        stable_threshold = actual_runs / 2.0  # 과반수 기준 (50% 초과)
        stable = {e for e, cnt in edge_appearances.items() if cnt > stable_threshold}
        stability = len(stable) / max(len(all_seen), 1)

        seed.is_calibrated = True
        seed.stability = stability
        seed.stable_edges = stable
        seed.covered_edges = all_seen

        # global_edges에 합집합(all_seen) 반영 — stable만 반영하면 initial coverage가
        # 너무 희박해져 퍼징 효율이 크게 저하된다.
        self.sampler.global_edges.update(all_seen)
        for edge in all_seen:
            self.sampler.global_edge_counts[edge] = \
                self.sampler.global_edge_counts.get(edge, 0) + edge_appearances[edge]
            self.sampler.global_edge_buckets[edge] = \
                _count_to_bucket(self.sampler.global_edge_counts[edge])
        self.sampler.global_coverage.update(self.sampler.current_trace)

        return seed

    # =========================================================================
    # v4.5: Deterministic Stage
    # =========================================================================

    def _deterministic_stage(self, seed: Seed):
        """CDW 필드에 대한 체계적 경계값 탐색 (제너레이터).
        대상: cdw10~cdw15 중 값이 0이 아닌 필드."""
        cdw_fields = ['cdw10', 'cdw11', 'cdw12', 'cdw13', 'cdw14', 'cdw15']
        arith_max = self.config.deterministic_arith_max

        for field_name in cdw_fields:
            original = getattr(seed, field_name)
            if original == 0:
                continue  # 미사용 가능성 높은 필드 건너뛰기

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

    # =========================================================================
    # v4.5: MOpt (Mutation Operator Scheduling)
    # =========================================================================

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
        if not self.config.mopt_enabled:
            return

        self.mopt_pilot_rounds += 1

        if self.mopt_mode == 'pilot':
            if self.mopt_pilot_rounds >= self.config.mopt_pilot_period:
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
            if self.mopt_pilot_rounds >= self.config.mopt_core_period:
                # Core → Pilot: 통계 리셋
                self.mopt_finds = [0] * self.NUM_MUTATION_OPS
                self.mopt_uses = [0] * self.NUM_MUTATION_OPS
                self.mopt_mode = 'pilot'
                self.mopt_pilot_rounds = 0
                log.info("[MOpt] Core→Pilot (reset)")

    def _log_smart(self):
        """v4.3: NVMe SMART / Health 로그를 읽어 INFO 레벨로 기록."""
        try:
            result = subprocess.run(
                ['nvme', 'smart-log', self.config.nvme_device],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                log.info("[SMART] === NVMe SMART / Health Log ===")
                for line in result.stdout.strip().splitlines():
                    log.info(f"[SMART] {line}")
            else:
                log.warning(f"[SMART] smart-log 실패 (rc={result.returncode}): "
                            f"{result.stderr.strip()}")
        except subprocess.TimeoutExpired:
            log.warning("[SMART] smart-log 타임아웃 (10s)")
        except FileNotFoundError:
            log.warning("[SMART] nvme-cli가 설치되지 않았습니다")
        except Exception as e:
            log.warning(f"[SMART] smart-log 실행 오류: {e}")

    def _setup_directories(self):
        self.crashes_dir.mkdir(parents=True, exist_ok=True)

    def _generate_default_seeds(self) -> List[Seed]:
        """각 Opcode별 NVMe 스펙 기반 정상 명령어를 초기 시드로 생성"""
        seeds: List[Seed] = []

        # 명령어별 정상 파라미터 템플릿: (cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, data, 설명)
        SEED_TEMPLATES: dict[str, list] = {
            "Identify": [
                # CDW10 = CNS (Controller or Namespace Structure)
                dict(cdw10=0x01, description="Identify Controller"),
                dict(cdw10=0x00, description="Identify Namespace"),
                dict(cdw10=0x02, description="Active NS ID list"),
                dict(cdw10=0x03, description="NS Identification Descriptor list"),
            ],
            "GetLogPage": [
                # CDW10[7:0]=LID, CDW10[26:16]=NUMDL (Number of Dwords Lower, 0-based)
                # NUMDL = (bytes / 4) - 1, data_len은 _send_nvme_command에서 NUMDL 기반으로 계산
                dict(cdw10=(0x0F << 16) | 0x01, description="Error Information Log (64B)"),
                dict(cdw10=(0x7F << 16) | 0x02, description="SMART / Health Log (512B)"),
                dict(cdw10=(0x7F << 16) | 0x03, description="Firmware Slot Info Log (512B)"),
                dict(cdw10=(0x1FF << 16) | 0x05, description="Commands Supported and Effects Log (2048B)"),
                dict(cdw10=(0x8C << 16) | 0x06, description="Device Self-test Log (564B)"),
            ],
            "GetFeatures": [
                # CDW10[7:0]=FID (Feature Identifier)
                dict(cdw10=0x01, description="Arbitration"),
                dict(cdw10=0x02, description="Power Management"),
                dict(cdw10=0x04, description="Temperature Threshold"),
                dict(cdw10=0x05, description="Error Recovery"),
                dict(cdw10=0x06, description="Volatile Write Cache"),
                dict(cdw10=0x07, description="Number of Queues"),
                dict(cdw10=0x08, description="Interrupt Coalescing"),
                dict(cdw10=0x09, description="Interrupt Vector Configuration"),
                dict(cdw10=0x0A, description="Write Atomicity Normal"),
                dict(cdw10=0x0B, description="Async Event Configuration"),
            ],
            "Read": [
                # CDW10=SLBA[31:0], CDW11=SLBA[63:32], CDW12[15:0]=NLB (0-based)
                dict(cdw10=0, cdw11=0, cdw12=0, description="Read LBA 0, 1 block"),
                dict(cdw10=1, cdw11=0, cdw12=0, description="Read LBA 1, 1 block"),
                dict(cdw10=0, cdw11=0, cdw12=7, description="Read LBA 0, 8 blocks"),
                dict(cdw10=1000, cdw11=0, cdw12=0, description="Read LBA 1000, 1 block"),
            ],
            "Write": [
                # CDW10=SLBA[31:0], CDW11=SLBA[63:32], CDW12[15:0]=NLB (0-based)
                dict(cdw10=0, cdw11=0, cdw12=0, data=b'\x00' * 512, description="Write LBA 0, 1 block zeros"),
                dict(cdw10=0, cdw11=0, cdw12=0, data=b'\xAA' * 512, description="Write LBA 0, 1 block pattern"),
                dict(cdw10=1000, cdw11=0, cdw12=0, data=b'\x00' * 512, description="Write LBA 1000, 1 block"),
            ],
            "SetFeatures": [
                # CDW10[7:0]=FID, CDW10[31]=SV(Save)
                dict(cdw10=0x07, cdw11=0x00010001, description="Set Number of Queues (1 SQ + 1 CQ)"),
            ],
            "FWDownload": [
                # CDW10=NUMD (0-based dwords), CDW11=OFST (dword offset)
                dict(cdw10=0xFF, cdw11=0, data=b'\x00' * 1024, description="FW Download offset=0, 1KB"),
            ],
            "FWCommit": [
                # CDW10[2:0]=CA(Commit Action), CDW10[5:3]=FS(Firmware Slot)
                dict(cdw10=0x01, description="Commit Action 1, Slot 0 (replace without activate)"),
                dict(cdw10=0x09, description="Commit Action 1, Slot 1"),
            ],
            "FormatNVM": [
                # CDW10[3:0]=LBAF, CDW10[11:9]=SES(Secure Erase)
                dict(cdw10=0x00, description="Format LBAF 0, no secure erase"),
            ],
            "Sanitize": [
                # CDW10[2:0]=SANACT(Sanitize Action), CDW10[3]=AUSE, CDW10[7:4]=OWPASS
                dict(cdw10=0x01, description="Block Erase"),
                dict(cdw10=0x02, description="Overwrite"),
                dict(cdw10=0x04, description="Crypto Erase"),
            ],
            "TelemetryHostInitiated": [
                # GetLogPage LID=0x07 + CDW10[8]=Create Telemetry
                dict(cdw10=(0x1FF << 16) | 0x07, description="Telemetry Host-Initiated Log"),
            ],
            "Flush": [
                dict(description="Flush (no parameters)"),
            ],
            "DatasetManagement": [
                # CDW10[7:0]=NR (Number of Ranges, 0-based), CDW11[2]=AD(Attribute Deallocate)
                dict(cdw10=0, cdw11=0x04, data=struct.pack('<IIIII', 0, 0, 0, 0, 8),
                     description="TRIM LBA 0, 8 blocks"),
            ],
        }

        for cmd in self.commands:
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
                        found_at=0,
                    )
                    seeds.append(seed)
                    log.info(f"[Seed] {cmd.name} (0x{cmd.opcode:02x}): {desc} "
                             f"CDW10=0x{seed.cdw10:08x}")
            else:
                # 알 수 없는 명령어는 기본 시드
                seeds.append(Seed(data=b'\x00' * 64, cmd=cmd, found_at=0))

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
                    for cmd in self.commands:
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

    def _calculate_energy(self, seed: Seed) -> float:
        """v4: AFLfast 'explore' 스케줄 - 적게 실행된 시드에 높은 에너지"""
        if seed.exec_count == 0:
            return self.config.max_energy  # 새 시드는 최대 에너지

        # factor = min(MAX_ENERGY, 2^(log2(total_execs / exec_count)))
        ratio = self.executions / seed.exec_count
        if ratio <= 1:
            return 1.0

        # bit_length()는 정수에만 사용 가능하므로 math.log2 사용
        try:
            power = int(math.log2(ratio))
            factor = min(self.config.max_energy, 2 ** power)
        except (ValueError, OverflowError):
            factor = 1.0

        return factor

    def _select_seed(self) -> Optional[Seed]:
        """v4: 에너지 기반 가중치 랜덤 선택"""
        if not self.corpus:
            return None

        # 에너지 계산
        for seed in self.corpus:
            seed.energy = self._calculate_energy(seed)

        # 가중치 랜덤 선택
        total_energy = sum(s.energy for s in self.corpus)
        if total_energy <= 0:
            return random.choice(self.corpus)

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

    def _cull_corpus(self):
        """v4.3: AFL++ 방식 corpus culling.
        각 edge에 대해 가장 작은 seed를 favored로 마킹하고,
        favored가 아닌 seed 중 기여도 없는 것을 제거한다."""
        if len(self.corpus) <= 10:
            return

        # 1) edge → best seed 매핑 (가장 작은 data 우선)
        edge_best: dict[tuple, Seed] = {}
        for seed in self.corpus:
            if not seed.covered_edges:
                continue
            for edge in seed.covered_edges:
                current = edge_best.get(edge)
                if current is None or len(seed.data) < len(current.data):
                    edge_best[edge] = seed

        # 2) favored 마킹
        favored_seeds = set()
        for seed in edge_best.values():
            favored_seeds.add(id(seed))
        for seed in self.corpus:
            seed.is_favored = id(seed) in favored_seeds

        # 3) 제거 대상: favored 아님 + exec_count >= 2 + 기본 시드 아님 (found_at > 0)
        # v4.5+: 임계값을 5→2로 낮춤. PC 샘플링 corpus는 false positive로 인해
        # 매우 빠르게 팽창하므로 unfavored seed를 더 공격적으로 제거한다.
        before = len(self.corpus)
        self.corpus = [
            s for s in self.corpus
            if s.is_favored or s.exec_count < 2 or s.found_at == 0
        ]
        removed = before - len(self.corpus)
        if removed > 0:
            log.info(f"[Cull] corpus {before} → {len(self.corpus)} "
                     f"(-{removed}, favored={sum(1 for s in self.corpus if s.is_favored)})")

        # 4) 하드 상한: 상한 초과 시 exec_count가 높은 비선호 seed부터 강제 제거
        hard_limit = self.config.max_corpus_hard_limit
        if hard_limit > 0 and len(self.corpus) > hard_limit:
            before_hard = len(self.corpus)
            # 기본 시드(found_at==0)와 선호 시드는 보호, 나머지를 exec_count 내림차순 정렬 후 삭제
            protected = [s for s in self.corpus if s.found_at == 0 or s.is_favored]
            evictable = sorted(
                [s for s in self.corpus if s.found_at > 0 and not s.is_favored],
                key=lambda s: s.exec_count, reverse=True
            )
            keep = max(0, hard_limit - len(protected))
            self.corpus = protected + evictable[:keep]
            log.info(f"[Cull] Hard limit {hard_limit}: corpus {before_hard} → {len(self.corpus)}")

    # =========================================================================
    # AFL++ Mutation Engine
    # =========================================================================

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
            # v4.5: MOpt — pilot/core 모드에 따른 operator 선택
            if self.config.mopt_enabled:
                mut = self._mopt_select_operator()
                self._current_mutations.append(mut)
            else:
                mut = random.randint(0, 15)

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
                if len(self.corpus) > 1:
                    other = random.choice(self.corpus)
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
        if len(self.corpus) < 2 or not seed.data:
            return seed

        other = random.choice(self.corpus)
        while other is seed and len(self.corpus) > 1:
            other = random.choice(self.corpus)

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
        if self.config.opcode_mut_prob > 0 and random.random() < self.config.opcode_mut_prob:
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
            # v4.3: 제외 opcode 필터링 — 제외 대상이면 override 취소
            if new_seed.opcode_override is not None and new_seed.opcode_override in excluded:
                new_seed.opcode_override = None

        # [2] nsid mutation — 잘못된 namespace로 에러 핸들링 코드 탐색
        if self.config.nsid_mut_prob > 0 and random.random() < self.config.nsid_mut_prob:
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

        # [4] data_len 의도적 불일치 — 커널은 통과, SSD DMA 엔진에 혼란
        if self.config.datalen_mut_prob > 0 and random.random() < self.config.datalen_mut_prob:
            new_seed.data_len_override = random.choice([
                0,                 # 빈 버퍼
                4,                 # 극소
                64,
                512,
                4096,
                8192,
                65536,             # 64KB
                random.randint(1, 2 * 1024 * 1024),  # 랜덤 (max 2MB)
            ])

        # [5] GetLogPage NUMDL 과대 요청 (GetLogPage일 때 15%)
        #     data_len을 NUMDL에 맞춰서 커널은 통과, SSD에 스펙 초과 크기 요청
        if seed.cmd.name == "GetLogPage" and random.random() < 0.15:
            lid = new_seed.cdw10 & 0xFF
            # NUMDL을 스펙보다 크게 설정
            oversized_numdl = random.choice([
                0x7FF,              # 11-bit 최대 (8192 bytes)
                0x3FF,              # 4096 bytes
                random.randint(0x100, 0x7FF),
            ])
            new_seed.cdw10 = (new_seed.cdw10 & 0xF800FFFF) | (oversized_numdl << 16)
            # data_len을 NUMDL에 맞춤 → 커널 통과 보장
            new_seed.data_len_override = (oversized_numdl + 1) * 4

        return new_seed

    # 반환값 상수: timeout/error를 구분
    RC_TIMEOUT   = -1001   # NVMe 타임아웃 (의미 있는 이벤트)
    RC_ERROR     = -1002   # subprocess 에러 (내부 문제)

    def _send_nvme_command(self, data: bytes, seed: Seed) -> int:
        """subprocess(nvme-cli) 기반 NVMe passthru 명령 전송.
        반환값:
          >= 0: nvme-cli returncode (0=성공, 양수=NVMe 에러)
          RC_TIMEOUT(-1001): NVMe 타임아웃
          RC_ERROR(-1002): 내부 에러
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

        # Admin 명령어별 고정 응답 크기
        ADMIN_FIXED_RESPONSE = {
            "Identify": 4096,
            "GetFeatures": 4096,
            "TelemetryHostInitiated": 4096,
        }

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
        elif cmd.cmd_type == NVMeCommandType.IO and cmd.name not in ("Flush", "DatasetManagement"):
            nlb = seed.cdw12 & 0xFFFF
            data_len = min(max(512, (nlb + 1) * 512), MAX_DATA_BUF)
        elif cmd.name == "GetLogPage":
            numdl = (seed.cdw10 >> 16) & 0x7FF
            data_len = min(max(4, (numdl + 1) * 4), MAX_DATA_BUF)
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
                    f.write(data)
            input_file = self._nvme_input_path

        # --- 타임아웃 ---
        timeout_ms = self.config.nvme_timeouts.get(
            cmd.timeout_group,
            self.config.nvme_timeouts.get('command', 8000)
        )

        # --- nvme CLI 명령 구성 ---
        nvme_cmd = [
            'nvme', passthru_type, self.config.nvme_device,
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
            f'--timeout={timeout_ms}',
        ]

        if data_len > 0:
            nvme_cmd.append(f'--data-len={data_len}')
            if input_file:
                nvme_cmd.extend([f'--input-file={input_file}', '-w'])
            else:
                nvme_cmd.append('-r')

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
                 f"nsid={actual_nsid} timeout={timeout_ms}ms({cmd.timeout_group}) "
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
            )

            # subprocess 타임아웃 = NVMe 타임아웃 + 여유 2초
            timeout_sec = timeout_ms / 1000.0 + 2.0
            try:
                stdout, stderr = process.communicate(timeout=timeout_sec)
            except subprocess.TimeoutExpired:
                process.kill()
                # v4.3: kill 후 communicate()에도 타임아웃 설정
                # nvme-cli가 커널 NVMe 에러 복구 중 D state (uninterruptible sleep)에
                # 빠지면 SIGKILL이 전달되지 않아 수십~수백 초 블로킹될 수 있음.
                # 원인: 커널 NVMe 드라이버가 command abort → controller reset →
                # PCIe FLR 순서로 에러 복구를 시도하며, 각 단계에 30~60초 소요.
                # 이 동안 ioctl() 시스템 콜이 반환되지 않아 프로세스가 D state에 머무름.
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    log.warning(
                        f"[NVMe TIMEOUT] {cmd.name} — nvme-cli가 D state "
                        f"(커널 NVMe 에러 복구 중). kill 후에도 프로세스 미종료. "
                        f"커널이 controller reset/PCIe FLR을 완료할 때까지 "
                        f"수십~수백 초 소요될 수 있음. 프로세스를 포기하고 진행합니다.")
                log.warning(f"[NVMe TIMEOUT] {cmd.name} (>{timeout_sec:.0f}s)")
                return self.RC_TIMEOUT

            rc = process.returncode

            # v4.3: 명령 완료 후 추가 샘플링 (post_cmd_delay_ms)
            # SSD 내부에서 명령 완료 후에도 후처리(캐시 플러시, 로그 기록 등)가
            # 진행될 수 있으므로, 해당 시간만큼 샘플링을 계속 유지
            if self.config.post_cmd_delay_ms > 0:
                time.sleep(self.config.post_cmd_delay_ms / 1000.0)

            log.info(f"[NVMe RET] rc={rc}")
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
                    stuck_pcs: Optional[List[int]] = None,
                    dmesg_snapshot: Optional[str] = None):
        input_hash = hashlib.md5(data).hexdigest()[:12]
        filename = f"crash_{seed.cmd.name}_{hex(seed.cmd.opcode)}_{input_hash}"
        filepath = self.crashes_dir / filename

        with open(filepath, 'wb') as f:
            f.write(data)

        meta = self._seed_meta(seed)
        meta["crash_reason"] = reason
        meta["timestamp"] = datetime.now().isoformat()

        # v4.3: timeout 시 SSD 펌웨어가 멈춘 PC 주소 기록
        if stuck_pcs:
            meta["stuck_pcs"] = [hex(pc) for pc in stuck_pcs]
            meta["stuck_pcs_unique"] = [hex(pc) for pc in sorted(set(stuck_pcs))]
            meta["stuck_pcs_count"] = len(stuck_pcs)
            # 가장 빈도 높은 PC = 가장 유력한 hang 지점
            from collections import Counter
            pc_counts = Counter(stuck_pcs)
            most_common = pc_counts.most_common(5)
            meta["stuck_pc_top5"] = [
                {"pc": hex(pc), "count": cnt, "ratio": f"{cnt/len(stuck_pcs):.0%}"}
                for pc, cnt in most_common
            ]

        # v4.4: dmesg 스냅샷 저장
        if dmesg_snapshot:
            meta["dmesg_snapshot"] = dmesg_snapshot
            # 별도 텍스트 파일로도 저장 (JSON에 넣기엔 길 수 있으므로)
            dmesg_file = str(filepath) + '.dmesg.txt'
            try:
                with open(dmesg_file, 'w') as f:
                    f.write(dmesg_snapshot)
            except Exception:
                pass

        with open(str(filepath) + '.json', 'w') as f:
            json.dump(meta, f, indent=2)

    def _save_per_command_data(self):
        """명령어별 edge/PC 데이터를 JSON 파일로 저장"""
        graph_dir = self.output_dir / 'graphs'
        graph_dir.mkdir(parents=True, exist_ok=True)

        for cmd_name in self.cmd_edges:
            edges = self.cmd_edges[cmd_name]
            pcs = self.cmd_pcs[cmd_name]
            traces = self.cmd_traces[cmd_name]

            if not edges and not pcs:
                continue

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
            log.info(f"[Graph] Saved {cmd_name}: {len(edges)} edges, "
                     f"{len(pcs)} PCs → {out_file}")

        # 전체 통합 edge 데이터도 저장
        all_data = {}
        for cmd_name in self.cmd_edges:
            if self.cmd_edges[cmd_name]:
                all_data[cmd_name] = {
                    "pcs": len(self.cmd_pcs[cmd_name]),
                    "edges": len(self.cmd_edges[cmd_name]),
                }
        with open(graph_dir / 'summary.json', 'w') as f:
            json.dump(all_data, f, indent=2)

    def _generate_graphs(self):
        """명령어별 PC flow 그래프를 DOT + PNG로 생성"""
        graph_dir = self.output_dir / 'graphs'
        graph_dir.mkdir(parents=True, exist_ok=True)

        has_graphviz = False
        try:
            subprocess.run(['dot', '-V'], capture_output=True, timeout=5)
            has_graphviz = True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            log.warning("[Graph] graphviz 'dot' not found — DOT 파일만 생성합니다. "
                        "PNG 렌더링은 'sudo apt install graphviz' 후 가능")

        for cmd_name, edges in self.cmd_edges.items():
            if not edges:
                continue

            pcs = self.cmd_pcs[cmd_name]

            # DOT 파일 생성
            dot_file = graph_dir / f"{cmd_name}_cfg.dot"
            png_file = graph_dir / f"{cmd_name}_cfg.png"

            # Edge별 가중치(빈도) 계산
            edge_counts: dict[Tuple[int, int], int] = defaultdict(int)
            for trace in self.cmd_traces[cmd_name]:
                for i in range(len(trace) - 1):
                    edge_counts[(trace[i], trace[i + 1])] += 1

            # 가중치 없는 edge는 1로 설정
            for e in edges:
                if e not in edge_counts:
                    edge_counts[e] = 1

            # 노드별 in/out degree 계산
            in_degree: dict[int, int] = defaultdict(int)
            out_degree: dict[int, int] = defaultdict(int)
            for (src, dst) in edges:
                out_degree[src] += 1
                in_degree[dst] += 1

            max_weight = max(edge_counts.values()) if edge_counts else 1

            lines = [
                f'digraph "{cmd_name}_CFG" {{',
                '  rankdir=TB;',
                f'  label="{cmd_name} (opcode) — {len(pcs)} PCs, {len(edges)} edges";',
                '  labelloc=t;',
                '  fontsize=14;',
                '  node [shape=box, style=filled, fontsize=9, fontname="Courier"];',
                '  edge [fontsize=8];',
                '',
            ]

            # 노드 (색상: entry=green, exit=red, 일반=lightblue)
            for pc in sorted(pcs):
                color = "lightblue"
                if in_degree[pc] == 0:
                    color = "palegreen"   # entry point (no incoming edge)
                elif out_degree[pc] == 0:
                    color = "lightsalmon"  # exit point (no outgoing edge)
                lines.append(f'  "0x{pc:08x}" [label="0x{pc:08x}", fillcolor={color}];')

            lines.append('')

            # Edge (굵기 = 가중치)
            for (src, dst), count in sorted(edge_counts.items()):
                penwidth = 1.0 + 3.0 * (count / max_weight)
                if count > 1:
                    lines.append(f'  "0x{src:08x}" -> "0x{dst:08x}" '
                                 f'[penwidth={penwidth:.1f}, label="{count}"];')
                else:
                    lines.append(f'  "0x{src:08x}" -> "0x{dst:08x}" '
                                 f'[penwidth={penwidth:.1f}];')

            lines.append('}')

            with open(dot_file, 'w') as f:
                f.write('\n'.join(lines))

            log.info(f"[Graph] {cmd_name}: DOT → {dot_file}")

            # PNG 렌더링
            if has_graphviz:
                try:
                    # edge 수가 많으면 sfdp (대규모 그래프용 레이아웃) 사용
                    layout = 'sfdp' if len(edges) > 500 else 'dot'
                    subprocess.run(
                        [layout, '-Tpng', '-Gdpi=150', str(dot_file), '-o', str(png_file)],
                        capture_output=True, timeout=120,
                    )
                    log.info(f"[Graph] {cmd_name}: PNG → {png_file}")
                except subprocess.TimeoutExpired:
                    log.warning(f"[Graph] {cmd_name}: PNG 렌더링 타임아웃 (edge가 너무 많음)")
                except Exception as e:
                    log.warning(f"[Graph] {cmd_name}: PNG 렌더링 실패: {e}")

        # 명령어 간 비교 차트 (matplotlib)
        self._generate_comparison_chart(graph_dir)

    def _generate_comparison_chart(self, graph_dir: Path):
        """명령어별 edge/PC 수를 비교하는 막대 차트 생성"""
        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt
        except ImportError:
            log.warning("[Graph] matplotlib 미설치 — 비교 차트 생략. "
                        "'pip install matplotlib' 로 설치 가능")
            return

        cmd_names = []
        edge_counts = []
        pc_counts = []
        trace_counts = []

        for cmd_name in sorted(self.cmd_edges.keys()):
            if self.cmd_edges[cmd_name] or self.cmd_pcs[cmd_name]:
                cmd_names.append(cmd_name)
                edge_counts.append(len(self.cmd_edges[cmd_name]))
                pc_counts.append(len(self.cmd_pcs[cmd_name]))
                trace_counts.append(len(self.cmd_traces[cmd_name]))

        if not cmd_names:
            return

        fig, axes = plt.subplots(1, 3, figsize=(15, 5))
        fig.suptitle('Coverage per NVMe Command', fontsize=14, fontweight='bold')

        # 1) Edge 수
        bars1 = axes[0].barh(cmd_names, edge_counts, color='steelblue')
        axes[0].set_xlabel('Unique Edges')
        axes[0].set_title('Edges per Command')
        for bar, val in zip(bars1, edge_counts):
            axes[0].text(bar.get_width() + 0.5, bar.get_y() + bar.get_height() / 2,
                         str(val), va='center', fontsize=9)

        # 2) PC 수
        bars2 = axes[1].barh(cmd_names, pc_counts, color='coral')
        axes[1].set_xlabel('Unique PCs')
        axes[1].set_title('PCs per Command')
        for bar, val in zip(bars2, pc_counts):
            axes[1].text(bar.get_width() + 0.5, bar.get_y() + bar.get_height() / 2,
                         str(val), va='center', fontsize=9)

        # 3) Trace 수 (실행 횟수)
        bars3 = axes[2].barh(cmd_names, trace_counts, color='mediumseagreen')
        axes[2].set_xlabel('Traces Recorded')
        axes[2].set_title('Executions per Command')
        for bar, val in zip(bars3, trace_counts):
            axes[2].text(bar.get_width() + 0.5, bar.get_y() + bar.get_height() / 2,
                         str(val), va='center', fontsize=9)

        plt.tight_layout()
        chart_file = graph_dir / 'command_comparison.png'
        plt.savefig(chart_file, dpi=150, bbox_inches='tight')
        plt.close()
        log.info(f"[Graph] 명령어 비교 차트 → {chart_file}")

    def _generate_heatmaps(self):
        """1D 주소 커버리지 히트맵 + 2D edge 히트맵 생성"""
        try:
            import matplotlib
            matplotlib.use('Agg')
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

        # 데이터가 있는 명령어만 수집
        active_cmds = [name for name in sorted(self.cmd_pcs.keys())
                       if self.cmd_pcs[name] or self.cmd_edges[name]]
        if not active_cmds:
            log.warning("[Heatmap] No coverage data to visualize")
            return

        # v4.4: 명령어 수 제한 — 너무 많으면 edge 수 기준 상위 MAX개만 표시
        MAX_HEATMAP_CMDS = 40
        if len(active_cmds) > MAX_HEATMAP_CMDS:
            log.info(f"[Heatmap] {len(active_cmds)} commands detected, "
                     f"limiting to top {MAX_HEATMAP_CMDS} by edge count")
            active_cmds.sort(key=lambda n: len(self.cmd_edges.get(n, set())),
                             reverse=True)
            active_cmds = sorted(active_cmds[:MAX_HEATMAP_CMDS])

        # Bin 크기 결정: 1D는 세밀하게, 2D는 조금 크게
        bin_size_1d = max(256, addr_range // 512)
        bin_size_2d = max(1024, addr_range // 256)
        n_bins_1d = (addr_range + bin_size_1d - 1) // bin_size_1d
        n_bins_2d = (addr_range + bin_size_2d - 1) // bin_size_2d

        # =================================================================
        # 1D Address Coverage Heatmap
        # =================================================================
        n_rows_1d = len(active_cmds) + 1  # +1 for global
        fig, axes = plt.subplots(n_rows_1d, 1,
                                 figsize=(18, 1.2 * n_rows_1d + 1.5),
                                 gridspec_kw={'hspace': 0.6})
        if n_rows_1d == 1:
            axes = [axes]

        fig.suptitle(f'Firmware Coverage Heatmap  (bin={bin_size_1d}B, '
                     f'range=0x{addr_start:X}–0x{addr_end:X})',
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
        ax = axes[0]
        im = ax.imshow(global_bins.reshape(1, -1), aspect='auto', cmap='YlOrRd',
                       extent=[addr_start, addr_end, 0, 1], interpolation='nearest')
        ax.set_yticks([])
        ax.set_title(f'ALL  —  {len(self.sampler.global_coverage)} PCs, '
                     f'{covered_bins}/{n_bins_1d} bins covered '
                     f'({100*covered_bins/n_bins_1d:.1f}%)',
                     fontsize=9, loc='left')
        ax.xaxis.set_major_formatter(plt.FuncFormatter(_hex_formatter))
        ax.tick_params(axis='x', labelsize=7)

        # Per-command
        for i, cmd_name in enumerate(active_cmds):
            cmd_bins = np.zeros(n_bins_1d)
            for pc in self.cmd_pcs[cmd_name]:
                if addr_start <= pc <= addr_end:
                    idx = (pc - addr_start) // bin_size_1d
                    if 0 <= idx < n_bins_1d:
                        cmd_bins[idx] += 1

            cmd_covered = int(np.count_nonzero(cmd_bins))
            ax = axes[i + 1]
            ax.imshow(cmd_bins.reshape(1, -1), aspect='auto', cmap='YlOrRd',
                      extent=[addr_start, addr_end, 0, 1], interpolation='nearest')
            ax.set_yticks([])
            ax.set_title(f'{cmd_name}  —  {len(self.cmd_pcs[cmd_name])} PCs, '
                         f'{len(self.cmd_edges[cmd_name])} edges, '
                         f'{cmd_covered}/{n_bins_1d} bins ({100*cmd_covered/n_bins_1d:.1f}%)',
                         fontsize=9, loc='left')
            ax.xaxis.set_major_formatter(plt.FuncFormatter(_hex_formatter))
            ax.tick_params(axis='x', labelsize=7)

        heatmap_file = graph_dir / 'coverage_heatmap_1d.png'
        # v4.4: 이미지 크기 제한 — matplotlib 최대 픽셀 제한(65536) 초과 방지
        fig_h_px = fig.get_size_inches()[1] * 150
        dpi_1d = min(150, int(65000 / max(fig.get_size_inches()[1], 1)))
        dpi_1d = max(dpi_1d, 50)  # 최소 DPI
        plt.savefig(heatmap_file, dpi=dpi_1d, bbox_inches='tight')
        plt.close()
        log.info(f"[Heatmap] 1D coverage heatmap → {heatmap_file} (dpi={dpi_1d})")

        # =================================================================
        # 2D Edge Heatmap (prev_pc × cur_pc 인접 행렬)
        # =================================================================
        n_cols = min(3, len(active_cmds))
        n_rows_2d = (len(active_cmds) + n_cols - 1) // n_cols

        fig, axes_2d = plt.subplots(n_rows_2d, n_cols,
                                    figsize=(6.5 * n_cols, 5.5 * n_rows_2d),
                                    squeeze=False)
        fig.suptitle(f'Edge Heatmap  prev_pc → cur_pc  (bin={bin_size_2d}B)',
                     fontsize=13, fontweight='bold')

        # 축 눈금 위치 (5개)
        tick_positions = np.linspace(0, n_bins_2d - 1, 6)
        tick_labels = [f'0x{int(addr_start + p * bin_size_2d):X}' for p in tick_positions]

        for idx, cmd_name in enumerate(active_cmds):
            row, col = divmod(idx, n_cols)
            ax = axes_2d[row][col]

            edges = self.cmd_edges[cmd_name]
            if not edges:
                ax.set_visible(False)
                continue

            # Edge 빈도 행렬 구성
            # unique edge = 1, trace에서 반복 출현 시 가산
            edge_matrix = np.zeros((n_bins_2d, n_bins_2d))

            # 1) unique edge로 기본 구조
            for prev_pc, cur_pc in edges:
                if addr_start <= prev_pc <= addr_end and addr_start <= cur_pc <= addr_end:
                    bx = (prev_pc - addr_start) // bin_size_2d
                    by = (cur_pc - addr_start) // bin_size_2d
                    if 0 <= bx < n_bins_2d and 0 <= by < n_bins_2d:
                        edge_matrix[by][bx] += 1

            # 2) trace에서 빈도 가산 (핫 edge 강조)
            for trace in self.cmd_traces[cmd_name]:
                for ti in range(len(trace) - 1):
                    p, c = trace[ti], trace[ti + 1]
                    if addr_start <= p <= addr_end and addr_start <= c <= addr_end:
                        bx = (p - addr_start) // bin_size_2d
                        by = (c - addr_start) // bin_size_2d
                        if 0 <= bx < n_bins_2d and 0 <= by < n_bins_2d:
                            edge_matrix[by][bx] += 1

            # log 스케일로 표시 (빈도 차이가 큼)
            edge_display = np.log1p(edge_matrix)

            im = ax.imshow(edge_display, aspect='equal', cmap='inferno',
                           origin='lower', interpolation='nearest')

            ax.set_xticks(tick_positions)
            ax.set_xticklabels(tick_labels, rotation=45, fontsize=6, ha='right')
            ax.set_yticks(tick_positions)
            ax.set_yticklabels(tick_labels, fontsize=6)
            ax.set_xlabel('prev_pc (from)', fontsize=8)
            ax.set_ylabel('cur_pc (to)', fontsize=8)

            # 대각선 참조선 (순차 실행 영역)
            ax.plot([0, n_bins_2d - 1], [0, n_bins_2d - 1],
                    'w--', alpha=0.3, linewidth=0.5)

            active_bins = int(np.count_nonzero(edge_matrix))
            ax.set_title(f'{cmd_name}  —  {len(edges)} edges, '
                         f'{active_bins} active bins',
                         fontsize=9)
            plt.colorbar(im, ax=ax, shrink=0.75, label='log(count+1)',
                         pad=0.02)

        # 빈 subplot 숨기기
        for idx in range(len(active_cmds), n_rows_2d * n_cols):
            row, col = divmod(idx, n_cols)
            axes_2d[row][col].set_visible(False)

        plt.tight_layout()
        edge_heatmap_file = graph_dir / 'edge_heatmap_2d.png'
        # v4.4: 이미지 크기 제한
        max_dim = max(fig.get_size_inches())
        dpi_2d = min(150, int(65000 / max(max_dim, 1)))
        dpi_2d = max(dpi_2d, 50)
        plt.savefig(edge_heatmap_file, dpi=dpi_2d, bbox_inches='tight')
        plt.close()
        log.info(f"[Heatmap] 2D edge heatmap → {edge_heatmap_file} (dpi={dpi_2d})")

    def _collect_stats(self) -> dict:
        elapsed = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        return {
            'version': self.VERSION,
            'executions': self.executions,
            'corpus_size': len(self.corpus),
            'crashes': len(self.crash_inputs),
            'coverage_unique_edges': len(self.sampler.global_edges),
            'coverage_pending_edges': len(self.sampler.global_edge_pending),
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

    def _print_status(self, stats: dict, last_samples: int = 0):
        log.warning(f"[Stats] exec: {stats['executions']:,} | "
                 f"corpus: {stats['corpus_size']} | "
                 f"crashes: {stats['crashes']} | "
                 f"edges: {stats['coverage_unique_edges']:,} "
                 f"(pending: {stats['coverage_pending_edges']:,}) | "
                 f"pcs: {stats['coverage_unique_pcs']:,} | "
                 f"samples: {stats['total_samples']:,} | "
                 f"last_run: {last_samples} | "
                 f"exec/s: {stats['exec_per_sec']:.1f}")

    def run(self):
        global log

        self._setup_directories()
        log, log_file = setup_logging(self.config.output_dir)
        log.warning(f"Log file: {log_file}")

        log.warning("=" * 60)
        log.warning(f" PC Sampling SSD Fuzzer v{self.VERSION}")
        log.warning("=" * 60)
        log.warning(f"NVMe device : {self.config.nvme_device}")
        log.warning(f"Commands    : {[c.name for c in self.commands]}")
        log.warning(f"J-Link      : {self.config.device_name} @ {self.config.jtag_speed}kHz")
        if self.config.addr_range_start is not None:
            log.warning(f"Addr filter : {hex(self.config.addr_range_start)}"
                     f" - {hex(self.config.addr_range_end)}")
        else:
            log.warning("Addr filter : NONE (all PCs collected - noisy!)")
        log.warning(f"Sampling    : interval={self.config.sample_interval_us}us, "
                 f"max={self.config.max_samples_per_run}/run, "
                 f"idle_sat={self.config.saturation_limit}, "
                 f"global_sat={self.config.global_saturation_limit}, "
                 f"post_cmd={self.config.post_cmd_delay_ms}ms")
        log.warning(f"Power Sched : max_energy={self.config.max_energy}")
        # v4.3: 로그 메시지 수정 — 실제 구현은 subprocess(nvme-cli) 방식
        log.warning(f"NVMe I/O    : subprocess (nvme-cli passthru)")
        log.warning(f"Random gen  : {self.config.random_gen_ratio:.0%}")
        timeout_str = ", ".join(f"{k}={v}ms" for k, v in self.config.nvme_timeouts.items())
        log.warning(f"Timeouts    : {timeout_str}")
        log.warning(f"Output      : {self.config.output_dir}")
        log.warning("=" * 60)

        # 이전 실행의 corpus/graphs 폴더 비우기
        for subdir in ('corpus', 'graphs'):
            target = self.output_dir / subdir
            if target.exists():
                shutil.rmtree(target)
                log.info(f"[Cleanup] {target} 삭제 완료")
            target.mkdir(parents=True, exist_ok=True)

        self._load_seeds()

        # v4.3: NVMe 디바이스 사전 검증
        nvme_dev = self.config.nvme_device
        if not os.path.exists(nvme_dev):
            log.error(f"[Pre-flight] NVMe 디바이스 {nvme_dev} 가 존재하지 않습니다.")
            log.error("  nvme list / ls /dev/nvme* 로 확인하세요.")
            return
        if not os.access(nvme_dev, os.R_OK | os.W_OK):
            log.error(f"[Pre-flight] NVMe 디바이스 {nvme_dev} 에 대한 읽기/쓰기 권한이 없습니다.")
            log.error("  sudo로 실행하거나 권한을 확인하세요.")
            return
        log.info(f"[Pre-flight] NVMe 디바이스 확인: {nvme_dev} ✓")

        # 이전 커버리지 로드 (resume)
        if self.config.resume_coverage:
            self.sampler.load_coverage(self.config.resume_coverage)

        if not self.sampler.connect():
            log.error("J-Link connection failed, aborting")
            return

        # J-Link PC 읽기 진단 + idle PC 감지
        if not self.sampler.diagnose():
            log.error("J-Link PC read diagnosis failed, aborting")
            return

        if self.sampler.idle_pc is not None:
            log.warning(f"Idle PC     : {hex(self.sampler.idle_pc)}")
        else:
            log.warning("Idle PC     : not detected (saturation = global edge only)")

        # v4.3: 퍼징 시작 전 SMART baseline 기록
        self._log_smart()

        # v4.5: 초기 시드 Calibration
        if self.config.calibration_runs > 0:
            total_seeds = len(self.corpus)
            log.warning(f"[Calibration] {total_seeds} seeds × "
                        f"{self.config.calibration_runs} runs each ...")
            calibrated_corpus = []
            cal_results = []  # (index, cmd_name, stability, stable_edges, all_edges)

            # J-Link DLL이 stderr로 직접 출력하는 "CPU is not halted" 등의
            # 타이밍 경고를 calibration 구간에서만 fd 수준으로 억제한다.
            devnull_fd = os.open(os.devnull, os.O_WRONLY)
            saved_stderr_fd = os.dup(2)
            os.dup2(devnull_fd, 2)
            os.close(devnull_fd)
            try:
                for i, seed in enumerate(self.corpus):
                    seed = self._calibrate_seed(seed)
                    calibrated_corpus.append(seed)
                    stable_cnt = len(seed.stable_edges) if seed.stable_edges else 0
                    all_cnt    = len(seed.covered_edges) if seed.covered_edges else 0
                    cal_results.append((i + 1, seed.cmd.name, seed.stability,
                                        stable_cnt, all_cnt))
                    if self._timeout_crash:
                        os.dup2(saved_stderr_fd, 2)
                        log.error("[Calibration] timeout during calibration — aborting")
                        return
            finally:
                os.dup2(saved_stderr_fd, 2)
                os.close(saved_stderr_fd)

            self.corpus = calibrated_corpus

            # ── Calibration 결과 요약 테이블 ──────────────────────────────
            W_IDX, W_CMD, W_STA, W_STB, W_ALL = 4, 20, 11, 12, 10
            sep = (f"{'─'*W_IDX}─{'─'*W_CMD}─{'─'*W_STA}─"
                   f"{'─'*W_STB}─{'─'*W_ALL}")
            hdr = (f"{'#':>{W_IDX}} {'Command':<{W_CMD}} {'Stability':>{W_STA}} "
                   f"{'StableEdges':>{W_STB}} {'AllEdges':>{W_ALL}}")
            log.warning("[Calibration] Results:")
            log.warning(sep)
            log.warning(hdr)
            log.warning(sep)
            for idx, cmd_name, stab, stable_cnt, all_cnt in cal_results:
                stab_str = f"{stab*100:.1f}%"
                log.warning(f"{idx:>{W_IDX}} {cmd_name:<{W_CMD}} "
                            f"{stab_str:>{W_STA}} "
                            f"{stable_cnt:>{W_STB}} {all_cnt:>{W_ALL}}")
            log.warning(sep)
            avg_stab = sum(r[2] for r in cal_results) / max(len(cal_results), 1)
            log.warning(f"  Seeds: {total_seeds}  |  "
                        f"Global stable edges: {len(self.sampler.global_edges)}  |  "
                        f"Avg stability: {avg_stab*100:.1f}%")
            log.warning(sep)

            # v4.5: Calibration 완료된 초기 시드에 대해 deterministic stage 등록
            if self.config.deterministic_enabled:
                for seed in self.corpus:
                    if not seed.det_done:
                        gen = self._deterministic_stage(seed)
                        self._det_queue.append((seed, gen))
                log.warning(f"[Det] Queued {len(self._det_queue)} seeds for deterministic stage")

            log.warning("[Calibration] Complete. Starting fuzzing...\n")
        else:
            log.info("[Calibration] Disabled (calibration_runs=0)")

        self.start_time = datetime.now()

        try:
            while True:
                elapsed = (datetime.now() - self.start_time).total_seconds()
                if elapsed >= self.config.total_runtime_sec:
                    log.info("Runtime limit reached")
                    break

                # v4.5: Deterministic stage 우선 소비
                is_det_stage = False
                if self._det_queue:
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
                    # v4: Power Schedule 기반 시드 선택 + CDW 변형
                    # v4.3: 완전 랜덤 비율을 설정값으로 분리
                    if self.corpus and random.random() >= self.config.random_gen_ratio:
                        base_seed = self._select_seed()
                        mutated_seed = self._mutate(base_seed)
                        fuzz_data = mutated_seed.data
                        cmd = mutated_seed.cmd
                        self.mutation_stats["corpus_mutated"] += 1
                    else:
                        cmd = random.choice(self.commands)
                        fuzz_data = os.urandom(random.randint(64, 512))
                        mutated_seed = Seed(data=fuzz_data, cmd=cmd)
                        self.mutation_stats["random_gen"] += 1

                # v4.5: MOpt — 현재 실행의 mutation 기록 리셋
                self._current_mutations = []

                # v4.3: 확장 mutation 통계 집계
                if mutated_seed.opcode_override is not None:
                    self.mutation_stats["opcode_override"] += 1
                    self.actual_opcode_dist[mutated_seed.opcode_override] += 1
                if mutated_seed.nsid_override is not None:
                    self.mutation_stats["nsid_override"] += 1
                if mutated_seed.force_admin is not None:
                    self.mutation_stats["force_admin_swap"] += 1
                if mutated_seed.data_len_override is not None:
                    self.mutation_stats["data_len_override"] += 1

                # passthru 타입 추적
                if mutated_seed.force_admin is not None:
                    pt = "admin-passthru" if mutated_seed.force_admin else "io-passthru"
                else:
                    pt = "admin-passthru" if cmd.cmd_type == NVMeCommandType.ADMIN else "io-passthru"
                self.passthru_stats[pt] += 1

                # NVMe 커맨드 전송
                rc = self._send_nvme_command(fuzz_data, mutated_seed)
                last_samples = self.sampler.stop_sampling()

                self.executions += 1
                track_key = self._tracking_label(cmd, mutated_seed)
                self.cmd_stats[track_key]["exec"] += 1

                # --- rc 분류 ---
                # RC_TIMEOUT: NVMe 타임아웃 (의미 있는 이벤트)
                # RC_ERROR: 내부 에러
                # >= 0: nvme-cli returncode (0=성공)

                if rc not in (self.RC_TIMEOUT, self.RC_ERROR):
                    self.rc_stats[track_key][rc] += 1

                # v4: Edge 기반 커버리지 평가
                is_interesting, new_edges = self.sampler.evaluate_coverage()

                # v4.3: 실제 실행 opcode 기준으로 분류하여 기록
                self.cmd_edges[track_key].update(self.sampler.current_edges)
                self.cmd_pcs[track_key].update(self.sampler.current_trace)
                # raw PC trace 저장 (deque maxlen=200 자동 관리)
                if self.sampler._last_raw_pcs:
                    raw_in_range = [pc for pc in self.sampler._last_raw_pcs
                                    if self.sampler._in_range(pc)]
                    if raw_in_range:
                        self.cmd_traces[track_key].append(raw_in_range)

                # 로그
                raw_count = len(self.sampler._last_raw_pcs)
                oor_count = self.sampler._out_of_range_count
                bucket_chg = getattr(self.sampler, '_last_bucket_changes', 0)
                det_tag = " [Det]" if is_det_stage else ""
                mopt_tag = f" mopt={self.mopt_mode}" if self.config.mopt_enabled else ""
                log.info(f"exec={self.executions}{det_tag} cmd={cmd.name} "
                          f"raw_samples={raw_count} edges={len(self.sampler.current_edges)} "
                          f"out_of_range={oor_count} new={new_edges} bucket_chg={bucket_chg} "
                          f"global_edges={len(self.sampler.global_edges)} "
                          f"pending_edges={len(self.sampler.global_edge_pending)} "
                          f"global_pcs={len(self.sampler.global_coverage)} "
                          f"last_new_at={self.sampler._last_new_at}{mopt_tag} "
                          f"stop={self.sampler._stopped_reason}")

                if self.sampler._unique_at_intervals:
                    log.debug(f"  saturation: {self.sampler._unique_at_intervals}")
                if self.sampler._last_raw_pcs:
                    all_pcs = [hex(pc) for pc in self.sampler._last_raw_pcs]
                    log.debug(f"  ALL raw PCs: {all_pcs}")
                if self.sampler.current_edges:
                    edges_str = [(hex(p), hex(c)) for p, c in sorted(self.sampler.current_edges)]
                    log.debug(f"  Edges: {edges_str[:20]}{'...' if len(edges_str) > 20 else ''}")

                # --- Timeout / Error 처리 ---
                if rc == self.RC_TIMEOUT:
                    # v4.3: timeout 시 SSD 불량 현상 유지 전략
                    # J-Link reconnect 하지 않음 — 펌웨어 상태를 있는 그대로 보존

                    # 1) J-Link로 SSD 펌웨어가 멈춘 PC를 읽기 (halt-read-go 반복)
                    log.warning("[TIMEOUT] SSD 펌웨어 hang 지점 확인을 위해 PC를 읽습니다...")
                    stuck_pcs = self.sampler.read_stuck_pcs(count=20)

                    actual_opcode = mutated_seed.opcode_override \
                        if mutated_seed.opcode_override is not None \
                        else cmd.opcode

                    if stuck_pcs:
                        from collections import Counter
                        pc_counts = Counter(stuck_pcs)
                        most_common_pc, most_common_count = pc_counts.most_common(1)[0]
                        unique_stuck = set(stuck_pcs)

                        log.error(
                            f"[TIMEOUT CRASH] {cmd.name} "
                            f"actual_opcode=0x{actual_opcode:02x} "
                            f"timeout_group={cmd.timeout_group}")
                        log.error(
                            f"  Stuck PCs ({len(stuck_pcs)} samples, "
                            f"{len(unique_stuck)} unique):")
                        for pc, cnt in pc_counts.most_common(5):
                            in_range = " [IN RANGE]" if self.sampler._in_range(pc) else " [OUT]"
                            log.error(
                                f"    {hex(pc)}: {cnt}/{len(stuck_pcs)} "
                                f"({100*cnt/len(stuck_pcs):.0f}%){in_range}")

                        if len(unique_stuck) == 1:
                            log.error(
                                f"  → 펌웨어가 {hex(most_common_pc)}에서 "
                                f"완전히 멈춤 (hang/deadlock)")
                        elif len(unique_stuck) <= 3:
                            log.error(
                                f"  → 펌웨어가 {len(unique_stuck)}개 주소에서 "
                                f"루프 중 (에러 핸들링 또는 busy-wait)")
                        else:
                            log.error(
                                f"  → 펌웨어가 {len(unique_stuck)}개 주소를 "
                                f"순회 중 (복구 루틴 진행 중일 수 있음)")
                    else:
                        log.error(
                            f"[TIMEOUT CRASH] {cmd.name} "
                            f"actual_opcode=0x{actual_opcode:02x} "
                            f"— J-Link PC 읽기 실패 (JTAG 연결 확인 필요)")

                    # 2) dmesg 캡처 (커널 NVMe 드라이버 동작 확인)
                    log.warning("[TIMEOUT] 커널 로그(dmesg)를 캡처합니다...")
                    dmesg_snapshot = self._capture_dmesg(lines=80)
                    # dmesg에서 NVMe 관련 라인만 요약 출력
                    nvme_lines = [l for l in dmesg_snapshot.splitlines()
                                  if 'nvme' in l.lower() or 'blk_update' in l.lower()
                                  or 'reset' in l.lower() or 'timeout' in l.lower()]
                    if nvme_lines:
                        log.error(f"  dmesg NVMe 관련 ({len(nvme_lines)}줄):")
                        for line in nvme_lines[-10:]:
                            log.error(f"    {line}")
                    else:
                        log.error("  dmesg에 NVMe 관련 메시지 없음")

                    # 3) crash 저장 (stuck PC + dmesg 포함)
                    self.crash_inputs.append((fuzz_data, cmd))
                    self._save_crash(fuzz_data, mutated_seed,
                                     reason="timeout", stuck_pcs=stuck_pcs,
                                     dmesg_snapshot=dmesg_snapshot)
                    log.error(f"  Crash 데이터 저장 완료 → {self.crashes_dir}/")

                    # 4) SSD 펌웨어를 resume 상태로 유지 (불량 현상 보존)
                    # halt하면 불량 현상이 멈추므로, 펌웨어가 돌고 있는
                    # 그대로 두어야 hang/loop 등의 현상을 외부에서 관찰 가능
                    log.error(
                        "  SSD 펌웨어를 resume 상태로 유지합니다. "
                        "(halt하지 않음 — 불량 현상 보존)")
                    log.error(
                        "  J-Link 디버거로 연결하여 현재 상태를 "
                        "관찰할 수 있습니다.")

                    # 5) NVMe 장치 상태 안내 (자동 복구 수행하지 않음)
                    log.error("")
                    log.error(
                        "  [NVMe 장치 안내] timeout 후 /dev/nvme* 가 "
                        "사라질 수 있습니다.")
                    log.error(
                        "  원인: 커널 NVMe 드라이버가 controller reset 후 "
                        "장치를 해제(unbind)함")
                    log.error(
                        "  확인: nvme list / ls /dev/nvme*")
                    log.error(
                        "  디버깅 완료 후 수동 복구:")
                    log.error(
                        "    echo 1 > /sys/bus/pci/devices/<BDF>/remove "
                        "&& echo 1 > /sys/bus/pci/rescan")
                    log.error(
                        "    또는 modprobe -r nvme && modprobe nvme")
                    log.error("")

                    # 6) 퍼징 중단 — reconnect/continue/rescan 하지 않음
                    self._timeout_crash = True
                    log.error(
                        "  퍼징을 중단합니다. SSD와 NVMe 장치 상태를 "
                        "그대로 유지합니다.")
                    break

                if rc == self.RC_ERROR:
                    log.warning(f"[ERROR] {cmd.name} subprocess internal error — skipping")
                    continue

                if is_interesting:
                    self.sampler.interesting_inputs += 1
                    self.cmd_stats[track_key]["interesting"] += 1

                    # v4: 새 Seed 추가 (CDW + 확장 mutation 필드 보존)
                    new_seed = Seed(
                        data=fuzz_data,
                        cmd=cmd,
                        cdw2=mutated_seed.cdw2, cdw3=mutated_seed.cdw3,
                        cdw10=mutated_seed.cdw10, cdw11=mutated_seed.cdw11,
                        cdw12=mutated_seed.cdw12, cdw13=mutated_seed.cdw13,
                        cdw14=mutated_seed.cdw14, cdw15=mutated_seed.cdw15,
                        opcode_override=mutated_seed.opcode_override,
                        nsid_override=mutated_seed.nsid_override,
                        force_admin=mutated_seed.force_admin,
                        data_len_override=mutated_seed.data_len_override,
                        found_at=self.executions,
                        new_edges=new_edges,
                        # v4.5+: 확정된 edge만 저장 (global_edges와 교집합)
                        # current_edges에는 미확정 noise edge도 포함되므로
                        # 전체를 저장하면 corpus culling의 favored 판정이 오염된다.
                        covered_edges=self.sampler.current_edges & self.sampler.global_edges,
                    )
                    self.corpus.append(new_seed)

                    # corpus 파일 저장 (CDW 메타데이터 포함)
                    input_hash = hashlib.md5(fuzz_data).hexdigest()[:12]
                    corpus_file = self.output_dir / 'corpus' / f"input_{cmd.name}_{hex(cmd.opcode)}_{input_hash}"
                    corpus_file.parent.mkdir(parents=True, exist_ok=True)
                    with open(corpus_file, 'wb') as f:
                        f.write(fuzz_data)
                    with open(str(corpus_file) + '.json', 'w') as f:
                        json.dump(self._seed_meta(new_seed), f)

                    log.info(f"[+] New coverage! cmd={cmd.name} "
                             f"CDW10=0x{mutated_seed.cdw10:08x} "
                             f"+{new_edges} edges (total: {len(self.sampler.global_edges)} edges, "
                             f"{len(self.sampler.global_coverage)} pcs)"
                             f" bucket_chg={getattr(self.sampler, '_last_bucket_changes', 0)}")

                    # v4.5: 새 seed에 대해 deterministic stage 등록
                    if self.config.deterministic_enabled and not new_seed.det_done:
                        gen = self._deterministic_stage(new_seed)
                        self._det_queue.append((new_seed, gen))
                        log.info(f"[Det] Queued {new_seed.cmd.name} "
                                 f"(queue size: {len(self._det_queue)})")

                # v4.5: MOpt — operator별 통계 업데이트
                if self.config.mopt_enabled and self._current_mutations:
                    if is_interesting:
                        for op in self._current_mutations:
                            self.mopt_finds[op] += 1
                    for op in self._current_mutations:
                        self.mopt_uses[op] += 1

                if self.executions % 100 == 0:
                    stats = self._collect_stats()
                    self._print_status(stats, last_samples)
                    # OS 버퍼까지 강제 flush (파일 핸들러만)
                    for h in log.handlers:
                        h.flush()
                        if isinstance(h, logging.FileHandler) and h.stream:
                            os.fsync(h.stream.fileno())

                # v4.3: 10000회마다 SMART 로그 기록
                if self.executions % 10000 == 0 and self.executions > 0:
                    self._log_smart()

                # v4.3: 1000회마다 corpus culling + J-Link heartbeat
                # v4.5: MOpt 모드 전환 체크
                if self.executions % 1000 == 0 and self.executions > 0:
                    self._cull_corpus()
                    self._mopt_update_phase()
                    # J-Link 연결 상태 확인
                    test_pc = self.sampler._read_pc()
                    if test_pc is None:
                        log.error("[J-Link] heartbeat 실패 — JTAG 연결이 끊어진 것 같습니다.")
                        log.error("  USB 케이블/J-Link 상태를 확인하세요.")
                        break

        except KeyboardInterrupt:
            log.warning("Interrupted by user")

        finally:
            # v4.3: 퍼징 종료 후 SMART 기록
            self._log_smart()

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
                    f"Coverage (edges) : {stats['coverage_unique_edges']:,}",
                    f"Coverage (PCs)   : {stats['coverage_unique_pcs']:,}",
                    "Per-command stats:",
                ]
                for cmd_name, cmd_stat in stats['command_stats'].items():
                    summary_lines.append(f"  {cmd_name}: exec={cmd_stat['exec']}, "
                                         f"interesting={cmd_stat['interesting']}")
                summary_lines.append("Return code distribution:")
                for cmd_name, rc_dist in self.rc_stats.items():
                    rc_summary = ", ".join(f"rc={rc}:{cnt}" for rc, cnt in sorted(rc_dist.items()))
                    summary_lines.append(f"  {cmd_name}: {rc_summary}")

                # v4.3: Mutation 통계
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

                # v4.5: Hit count bucketing 통계
                total_edges_with_counts = len(self.sampler.global_edge_counts)
                summary_lines.append(f"Hit count stats  : "
                                     f"edges_tracked={total_edges_with_counts}")

                # v4.5: MOpt 통계
                if self.config.mopt_enabled:
                    op_names = ['bitflip1', 'int8', 'int16', 'int32',
                                'arith8', 'arith16', 'arith32', 'randbyte',
                                'byteswap', 'delete', 'insert', 'overwrite',
                                'splice', 'shuffle', 'blockfill', 'asciiint']
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
                for h in log.handlers:
                    h.flush()
                    if isinstance(h, logging.FileHandler) and h.stream:
                        os.fsync(h.stream.fileno())
            except Exception:
                pass

            # v4.3: timeout crash 시 J-Link를 닫지 않음
            # SSD 펌웨어가 resume 상태로 계속 동작하도록 유지
            if self._timeout_crash:
                log.warning(
                    "[J-Link] timeout crash 상태이므로 J-Link 연결을 "
                    "유지합니다. SSD 펌웨어는 resume 상태로 동작 중입니다.")
            else:
                try:
                    self.sampler.close()
                except Exception:
                    pass


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=f'PC Sampling SSD Fuzzer v{FUZZER_VERSION}')
    parser.add_argument('--device', default=JLINK_DEVICE, help='J-Link target')
    parser.add_argument('--nvme', default=NVME_DEVICE, help='NVMe device')
    parser.add_argument('--namespace', type=int, default=NVME_NAMESPACE)
    parser.add_argument('--commands', nargs='+', default=[],
                        help='Commands to use (e.g., Read Write GetFeatures FormatNVM)')
    parser.add_argument('--all-commands', action='store_true', default=False,
                        help='Enable ALL commands including destructive ones '
                             '(FormatNVM, Sanitize, FWCommit, etc.)')
    parser.add_argument('--speed', type=int, default=JLINK_SPEED, help='JTAG speed (kHz)')
    parser.add_argument('--runtime', type=int, default=TOTAL_RUNTIME_SEC)
    parser.add_argument('--output', default=OUTPUT_DIR, help='Output dir')
    parser.add_argument('--seed-dir', default=SEED_DIR,
                        help='Seed directory path (load previous corpus as seeds)')
    parser.add_argument('--samples', type=int, default=MAX_SAMPLES_PER_RUN)
    parser.add_argument('--interval', type=int, default=SAMPLE_INTERVAL_US,
                        help='Sample interval (us)')
    parser.add_argument('--post-cmd-delay', type=int, default=POST_CMD_DELAY_MS,
                        help='Post-command sampling delay (ms)')
    parser.add_argument('--addr-start', type=lambda x: int(x, 0), default=FW_ADDR_START,
                        help='Firmware .text start (hex)')
    parser.add_argument('--addr-end', type=lambda x: int(x, 0), default=FW_ADDR_END,
                        help='Firmware .text end (hex)')
    parser.add_argument('--resume-coverage', default=RESUME_COVERAGE,
                        help='Path to previous coverage.txt')
    parser.add_argument('--saturation-limit', type=int, default=SATURATION_LIMIT,
                        help='Stop sampling after N consecutive idle PCs (0=disable)')
    parser.add_argument('--global-saturation-limit', type=int, default=GLOBAL_SATURATION_LIMIT,
                        help='Stop sampling after N consecutive non-new global edges (0=disable)')
    parser.add_argument('--max-energy', type=float, default=MAX_ENERGY,
                        help='Max energy for power schedule')
    parser.add_argument('--random-gen-ratio', type=float, default=RANDOM_GEN_RATIO,
                        help='Ratio of fully random inputs (0.0~1.0, default 0.2)')
    parser.add_argument('--exclude-opcodes', type=str, default='',
                        help='Comma-separated hex opcodes to exclude from fuzzing, '
                             'e.g. "0xC1,0xC0" or "C1,C0"')
    parser.add_argument('--opcode-mut-prob', type=float, default=OPCODE_MUT_PROB,
                        help='Opcode mutation probability (0.0=disable, default 0.10)')
    parser.add_argument('--nsid-mut-prob', type=float, default=NSID_MUT_PROB,
                        help='NSID mutation probability (0.0=disable, default 0.10)')
    parser.add_argument('--admin-swap-prob', type=float, default=ADMIN_SWAP_PROB,
                        help='Admin/IO swap probability (0.0=disable, default 0.05)')
    parser.add_argument('--datalen-mut-prob', type=float, default=DATALEN_MUT_PROB,
                        help='Data length mismatch probability (0.0=disable, default 0.08)')
    parser.add_argument('--timeout', nargs=2, action='append', metavar=('GROUP', 'MS'),
                        help='Set timeout per group, e.g. --timeout command 8000 '
                             '--timeout format 600000. '
                             f'Groups: {", ".join(NVME_TIMEOUTS.keys())}')

    # v4.5: 새 기능 CLI 옵션
    parser.add_argument('--calibration-runs', type=int, default=CALIBRATION_RUNS,
                        help='Calibration runs per initial seed (0=disable, default 3)')
    parser.add_argument('--no-deterministic', action='store_true', default=False,
                        help='Disable deterministic stage')
    parser.add_argument('--det-arith-max', type=int, default=DETERMINISTIC_ARITH_MAX,
                        help='Deterministic stage arithmetic max delta (default 10)')
    parser.add_argument('--no-mopt', action='store_true', default=False,
                        help='Disable MOpt mutation scheduling')
    parser.add_argument('--mopt-pilot-period', type=int, default=MOPT_PILOT_PERIOD,
                        help='MOpt pilot phase length in executions (default 5000)')
    parser.add_argument('--mopt-core-period', type=int, default=MOPT_CORE_PERIOD,
                        help='MOpt core phase length in executions (default 50000)')

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

    # CLI에서 지정한 타임아웃으로 오버라이드
    nvme_timeouts = NVME_TIMEOUTS.copy()
    if args.timeout:
        for group, ms in args.timeout:
            if group not in nvme_timeouts:
                parser.error(f"Unknown timeout group '{group}'. "
                             f"Valid: {', '.join(nvme_timeouts.keys())}")
            nvme_timeouts[group] = int(ms)

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
    print(f"\nv{FUZZER_VERSION} Features:")
    print("  - subprocess (nvme-cli) NVMe passthru")
    print("  - Global edge saturation (configurable) + idle PC detection")
    print("  - Per-execution prev_pc reset (no cross-execution false edges)")
    print("  - Post-command delay sampling")
    print("  - AFL++ havoc/splice mutation engine")
    print("  - Per-opcode NVMe spec seed templates")
    print("  - Per-command CFG graph generation")
    print(f"  - [v4.5] Hit count bucketing (AFL++ log buckets)")
    print(f"  - [v4.5] Calibration (runs={args.calibration_runs})")
    print(f"  - [v4.5] Deterministic stage (enabled={not args.no_deterministic}, "
          f"arith_max={args.det_arith_max})")
    print(f"  - [v4.5] MOpt mutation scheduling (enabled={not args.no_mopt}, "
          f"pilot={args.mopt_pilot_period}, core={args.mopt_core_period})")
    print()

    config = FuzzConfig(
        device_name=args.device,
        jtag_speed=args.speed,
        nvme_device=args.nvme,
        nvme_namespace=args.namespace,
        nvme_timeouts=nvme_timeouts,
        enabled_commands=args.commands,
        all_commands=args.all_commands,
        total_runtime_sec=args.runtime,
        output_dir=args.output,
        seed_dir=args.seed_dir,
        max_samples_per_run=args.samples,
        sample_interval_us=args.interval,
        post_cmd_delay_ms=args.post_cmd_delay,
        addr_range_start=args.addr_start,
        addr_range_end=args.addr_end,
        resume_coverage=args.resume_coverage,
        saturation_limit=args.saturation_limit,
        global_saturation_limit=args.global_saturation_limit,
        max_energy=args.max_energy,
        random_gen_ratio=args.random_gen_ratio,
        excluded_opcodes=excluded_opcodes,
        opcode_mut_prob=args.opcode_mut_prob,
        nsid_mut_prob=args.nsid_mut_prob,
        admin_swap_prob=args.admin_swap_prob,
        datalen_mut_prob=args.datalen_mut_prob,
        # v4.5
        calibration_runs=args.calibration_runs,
        deterministic_enabled=not args.no_deterministic,
        deterministic_arith_max=args.det_arith_max,
        mopt_enabled=not args.no_mopt,
        mopt_pilot_period=args.mopt_pilot_period,
        mopt_core_period=args.mopt_core_period,
    )

    fuzzer = NVMeFuzzer(config)
    fuzzer.run()
