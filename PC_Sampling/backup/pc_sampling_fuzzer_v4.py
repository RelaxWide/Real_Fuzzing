#!/usr/bin/env python3
"""
PC Sampling 기반 SSD 펌웨어 Coverage-Guided Fuzzer v4

J-Link V9 Halt-Sample-Resume 방식으로 커버리지를 수집하고,
NVMe CLI를 통해 SSD에 퍼징 입력을 전달합니다.

v4 변경사항:
- Sampled Edge 커버리지: (prev_pc, cur_pc) 튜플 기반
- Power Schedule: AFLfast explore 방식 에너지 기반 시드 선택
- Seed dataclass 도입
"""

from __future__ import annotations

import pylink
import time
import threading
import subprocess
import os
import json
import hashlib
import random
import logging
import math
from collections import defaultdict
from typing import Set, List, Optional, Tuple, Dict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from enum import Enum

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
NVME_TIMEOUT   = 8000         # ms

# PC 샘플링 설정
SAMPLE_INTERVAL_US    = 0     # 샘플 간격 (us), 0 = halt 직후 바로 다음 halt
MAX_SAMPLES_PER_RUN   = 500   # NVMe 커맨드 1회당 최대 샘플 수 (상한)
SATURATION_LIMIT      = 10    # 연속 N회 새 unique PC 없으면 조기 종료
POST_CMD_DELAY_MS     = 0     # 커맨드 완료 후 tail 샘플링 (ms)

# 퍼징 설정
MAX_INPUT_LEN     = 4096      # 최대 입력 바이트
TOTAL_RUNTIME_SEC = 3600      # 총 퍼징 시간 (초)
OUTPUT_DIR        = './output/pc_sampling_v4/'
SEED_DIR          = None      # 시드 폴더 경로 (없으면 None)
RESUME_COVERAGE   = None      # 이전 coverage.txt 경로 (없으면 None)

# Power Schedule 설정 (v4 추가)
MAX_ENERGY        = 16.0      # 최대 에너지 값

# =============================================================================


class NVMeCommandType(Enum):
    ADMIN = "admin-passthru"
    IO = "io-passthru"


@dataclass
class NVMeCommand:
    name: str
    opcode: int
    cmd_type: NVMeCommandType
    needs_namespace: bool = True
    needs_data: bool = True
    description: str = ""


NVME_COMMANDS = [
    # Admin Commands
    NVMeCommand("Identify", 0x06, NVMeCommandType.ADMIN, needs_data=False,
                description="장치/네임스페이스 정보 조회"),
    NVMeCommand("GetLogPage", 0x02, NVMeCommandType.ADMIN, needs_data=False,
                description="로그 페이지 조회"),
    NVMeCommand("GetFeatures", 0x0A, NVMeCommandType.ADMIN, needs_data=False,
                description="기능 조회"),
    # I/O Commands
    NVMeCommand("Read", 0x02, NVMeCommandType.IO, needs_data=False,
                description="데이터 읽기"),
    NVMeCommand("Write", 0x01, NVMeCommandType.IO,
                description="데이터 쓰기"),
]


@dataclass
class Seed:
    """v4: 시드 데이터 구조 (Power Schedule용)"""
    data: bytes
    cmd: NVMeCommand
    exec_count: int = 0          # 이 시드가 선택된 횟수
    found_at: int = 0            # 발견된 시점 (execution number)
    new_edges: int = 0           # 발견한 새 edge 수
    energy: float = 1.0          # 계산된 에너지


@dataclass
class FuzzConfig:
    device_name: str = JLINK_DEVICE
    interface: int = pylink.enums.JLinkInterfaces.JTAG
    jtag_speed: int = JLINK_SPEED

    nvme_device: str = NVME_DEVICE
    nvme_namespace: int = NVME_NAMESPACE
    nvme_timeout_ms: int = NVME_TIMEOUT

    enabled_commands: List[str] = field(default_factory=list)

    # 샘플링 설정
    sample_interval_us: int = SAMPLE_INTERVAL_US
    max_samples_per_run: int = MAX_SAMPLES_PER_RUN
    saturation_limit: int = SATURATION_LIMIT

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


class JLinkPCSampler:
    """J-Link Halt-Sample-Resume 기반 PC 수집기 (v4: Sampled Edge 지원)"""

    def __init__(self, config: FuzzConfig):
        self.config = config
        self.jlink: Optional[pylink.JLink] = None
        self._pc_reg_index: int = 9  # Cortex-R8: R15(PC)의 J-Link 레지스터 인덱스

        # v4: Edge 기반 커버리지
        self.global_edges: Set[Tuple[int, int]] = set()  # (prev_pc, cur_pc) 튜플
        self.current_edges: Set[Tuple[int, int]] = set()
        self.prev_pc: int = 0  # 이전 실행의 마지막 샘플 PC

        # 기존 PC 기반 커버리지 (비교용으로 유지)
        self.global_coverage: Set[int] = set()
        self.current_trace: Set[int] = set()

        self.stop_event = threading.Event()
        self.sample_thread: Optional[threading.Thread] = None
        self.total_samples = 0
        self.interesting_inputs = 0
        self._last_raw_pcs: List[int] = []
        self._out_of_range_count = 0

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

    def _resume(self):
        """halt 상태에서 실행을 재개한다 (CPU 리셋 없이)."""
        try:
            self._go_func()
        except Exception:
            self.jlink.restart()

    def reconnect(self, max_retries: int = 5) -> bool:
        for attempt in range(1, max_retries + 1):
            delay = min(2 ** attempt, 30)
            log.warning(f"[J-Link] Reconnect attempt {attempt}/{max_retries} (wait {delay}s)...")
            time.sleep(delay)
            if self.connect():
                return True
        log.error("[J-Link] All reconnection attempts failed")
        return False

    def diagnose(self, count: int = 20) -> bool:
        """시작 전 PC 읽기 진단 — J-Link 동작 검증"""
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
        if len(unique_pcs) <= 1:
            log.warning(f"[Diagnose] PC가 항상 같은 값입니다 ({hex(pcs[0])}). "
                        f"CPU가 멈춰있거나 idle loop에 있을 수 있습니다.")
        return True

    def _read_pc(self) -> Optional[int]:
        try:
            self._halt_func()
            pc = self._read_reg_func(self._pc_reg_index)
            self._go_func()
            return pc
        except Exception:
            return None

    def _in_range(self, pc: int) -> bool:
        """PC가 펌웨어 주소 범위 내인지 확인"""
        if self.config.addr_range_start is None or self.config.addr_range_end is None:
            return True
        return self.config.addr_range_start <= pc <= self.config.addr_range_end

    def _sampling_worker(self):
        # v4: Edge 수집
        self.current_edges = set()
        self.current_trace = set()
        self._last_raw_pcs = []
        self._out_of_range_count = 0
        self._last_new_at = 0
        self._unique_at_intervals = {}
        self._stopped_reason = ""

        sample_count = 0
        prev_unique_edges = 0
        since_last_new = 0
        interval = self.config.sample_interval_us / 1_000_000
        sat_limit = self.config.saturation_limit

        # v4: 이전 실행의 마지막 PC에서 시작 (연속성)
        prev_pc = self.prev_pc

        while not self.stop_event.is_set() and sample_count < self.config.max_samples_per_run:
            pc = self._read_pc()
            if pc is not None:
                self._last_raw_pcs.append(pc)

                if self._in_range(pc):
                    # v4: Edge 생성 (prev_pc, cur_pc)
                    edge = (prev_pc, pc)
                    self.current_edges.add(edge)
                    self.current_trace.add(pc)
                    prev_pc = pc
                else:
                    self._out_of_range_count += 1

                sample_count += 1
                self.total_samples += 1

                # v4: Edge 기준으로 새로움 판단
                cur_unique_edges = len(self.current_edges)
                if cur_unique_edges > prev_unique_edges:
                    self._last_new_at = sample_count
                    prev_unique_edges = cur_unique_edges
                    since_last_new = 0
                else:
                    since_last_new += 1

                if sample_count in (10, 25, 50, 100, 200, 500):
                    self._unique_at_intervals[sample_count] = cur_unique_edges

                # 조기 종료: 연속 N회 새 edge 없으면 포화 판정
                if sat_limit > 0 and since_last_new >= sat_limit:
                    self._stopped_reason = f"saturated (no new edge for {sat_limit} consecutive samples)"
                    break

            if interval > 0:
                time.sleep(interval)

        if not self._stopped_reason:
            if self.stop_event.is_set():
                self._stopped_reason = "stop_event"
            else:
                self._stopped_reason = f"max_samples ({self.config.max_samples_per_run})"

        # v4: 다음 실행을 위해 마지막 PC 저장
        self.prev_pc = prev_pc

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
        """v4: Edge 기반 커버리지 평가"""
        initial_edges = len(self.global_edges)
        initial_pcs = len(self.global_coverage)

        self.global_edges.update(self.current_edges)
        self.global_coverage.update(self.current_trace)

        new_edges = len(self.global_edges) - initial_edges
        new_pcs = len(self.global_coverage) - initial_pcs

        # Edge 기준으로 interesting 판단
        return new_edges > 0, new_edges

    def load_coverage(self, filepath: str) -> int:
        """이전 세션의 커버리지 파일을 로드하여 global_coverage에 합산"""
        loaded = 0
        if not os.path.exists(filepath):
            log.warning(f"[Coverage] File not found: {filepath}")
            return 0
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        self.global_coverage.add(int(line, 16))
                        loaded += 1
                    except ValueError:
                        pass
        log.info(f"[Coverage] Loaded {loaded} PCs from {filepath} "
                 f"(global coverage: {len(self.global_coverage)})")
        return loaded

    def save_coverage(self, filepath: str) -> int:
        """현재 global_coverage를 파일로 저장"""
        with open(filepath, 'w') as f:
            for pc in sorted(self.global_coverage):
                f.write(f"{hex(pc)}\n")
        return len(self.global_coverage)

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
    """다중 Opcode 지원 NVMe 퍼저 (v4: Power Schedule 지원)"""

    VERSION = "4.0"

    def __init__(self, config: FuzzConfig):
        self.config = config
        self.sampler = JLinkPCSampler(config)

        if config.enabled_commands:
            self.commands = [c for c in NVME_COMMANDS if c.name in config.enabled_commands]
        else:
            self.commands = NVME_COMMANDS.copy()

        log.info(f"[Fuzzer] Enabled commands: {[c.name for c in self.commands]}")

        # v4: Seed 리스트로 변경
        self.corpus: List[Seed] = []
        self.crash_inputs: List[Tuple[bytes, NVMeCommand]] = []

        self.output_dir = Path(config.output_dir)
        self.crashes_dir = self.output_dir / 'crashes'

        self.executions = 0
        self.start_time: Optional[datetime] = None

        self.cmd_stats = {c.name: {"exec": 0, "interesting": 0} for c in self.commands}
        self.rc_stats: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))

    def _setup_directories(self):
        self.crashes_dir.mkdir(parents=True, exist_ok=True)

    def _load_seeds(self):
        if self.config.seed_dir and os.path.isdir(self.config.seed_dir):
            for seed_file in Path(self.config.seed_dir).iterdir():
                if seed_file.is_file():
                    with open(seed_file, 'rb') as f:
                        data = f.read()
                        for cmd in self.commands:
                            seed = Seed(data=data, cmd=cmd, found_at=0)
                            self.corpus.append(seed)
            log.info(f"[Fuzzer] Loaded seeds for {len(self.commands)} commands")

        if not self.corpus:
            for cmd in self.commands:
                self.corpus.append(Seed(data=b'\x00' * 64, cmd=cmd, found_at=0))
                self.corpus.append(Seed(data=b'\xff' * 64, cmd=cmd, found_at=0))
                self.corpus.append(Seed(data=os.urandom(64), cmd=cmd, found_at=0))

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

    def _mutate(self, data: bytes) -> bytes:
        data = bytearray(data)
        mutation_type = random.randint(0, 5)

        if mutation_type == 0 and data:
            pos = random.randint(0, len(data) - 1)
            data[pos] = random.randint(0, 255)
        elif mutation_type == 1:
            pos = random.randint(0, len(data))
            data.insert(pos, random.randint(0, 255))
        elif mutation_type == 2 and len(data) > 1:
            del data[random.randint(0, len(data) - 1)]
        elif mutation_type == 3 and data:
            for _ in range(random.randint(1, min(10, len(data)))):
                data[random.randint(0, len(data) - 1)] = random.randint(0, 255)
        elif mutation_type == 4 and data:
            data[random.randint(0, len(data) - 1)] = random.choice([0x00, 0xff, 0x7f, 0x80])
        elif mutation_type == 5 and len(data) >= 4:
            src = random.randint(0, len(data) - 4)
            dst = random.randint(0, len(data) - 4)
            data[dst:dst+4] = data[src:src+4]

        return bytes(data[:self.config.max_input_len])

    def _build_nvme_cmd(self, data: bytes, cmd: NVMeCommand, input_file: str) -> List[str]:
        """NVMe CLI 커맨드 라인 구성"""
        nvme_cmd = [
            'nvme', cmd.cmd_type.value,
            self.config.nvme_device,
            f'--opcode={hex(cmd.opcode)}',
            f'--timeout={self.config.nvme_timeout_ms}',
        ]

        if cmd.needs_namespace:
            nvme_cmd.append(f'--namespace-id={self.config.nvme_namespace}')

        if cmd.needs_data and data:
            nvme_cmd.extend([
                f'--input-file={input_file}',
                f'--data-len={len(data)}',
            ])

        if cmd.name == "Read":
            nvme_cmd.append('-r')

        if cmd.cmd_type == NVMeCommandType.IO:
            lba = random.randint(0, 1000)
            nvme_cmd.append(f'--cdw10={lba & 0xFFFFFFFF}')
            nvme_cmd.append(f'--cdw11={(lba >> 32) & 0xFFFFFFFF}')
            nvme_cmd.append(f'--cdw12={0}')

        return nvme_cmd

    def _send_nvme_command(self, data: bytes, cmd: NVMeCommand) -> Optional[int]:
        """NVMe 커맨드 전송. 성공 시 rc(int), 실패/타임아웃 시 None 반환."""
        input_file = '/tmp/nvme_fuzz_input'

        try:
            with open(input_file, 'wb') as f:
                f.write(data)

            nvme_cmd = self._build_nvme_cmd(data, cmd, input_file)

            cmd_str = ' '.join(nvme_cmd)
            log.info(f"[NVMe] {cmd_str}  # data_len={len(data)} data={data[:16].hex()}{'...' if len(data) > 16 else ''}")

            # "덫 놓기" 전략: 명령 전에 샘플링 시작
            self.sampler.start_sampling()

            process = subprocess.Popen(
                nvme_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            timeout_sec = self.config.nvme_timeout_ms / 1000 + 5
            try:
                stdout, stderr = process.communicate(timeout=timeout_sec)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                self.sampler.stop_sampling()
                log.warning(f"[NVMe TIMEOUT] {cmd.name} (opcode={hex(cmd.opcode)})")
                log.debug(f"  stdout: {stdout.decode(errors='replace').strip()}")
                log.debug(f"  stderr: {stderr.decode(errors='replace').strip()}")
                return None

            self.sampler.stop_sampling()

            rc = process.returncode
            stdout_str = stdout.decode(errors='replace').strip()
            stderr_str = stderr.decode(errors='replace').strip()
            log.info(f"[NVMe RET] rc={rc}, stdout={stdout_str[:200]}")
            if stderr_str:
                log.info(f"[NVMe RET] stderr={stderr_str[:200]}")

            return rc

        except Exception as e:
            log.error(f"NVMe error ({cmd.name}): {e}")
            try:
                self.sampler.stop_sampling()
            except:
                pass
            return None

    def _save_crash(self, data: bytes, cmd: NVMeCommand):
        input_hash = hashlib.md5(data).hexdigest()[:12]
        filename = f"crash_{cmd.name}_{hex(cmd.opcode)}_{input_hash}"
        filepath = self.crashes_dir / filename

        with open(filepath, 'wb') as f:
            f.write(data)

        meta = {"command": cmd.name, "opcode": hex(cmd.opcode), "type": cmd.cmd_type.value}
        with open(str(filepath) + '.json', 'w') as f:
            json.dump(meta, f)

    def _collect_stats(self) -> dict:
        elapsed = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        return {
            'version': self.VERSION,
            'executions': self.executions,
            'corpus_size': len(self.corpus),
            'crashes': len(self.crash_inputs),
            'coverage_unique_edges': len(self.sampler.global_edges),
            'coverage_unique_pcs': len(self.sampler.global_coverage),
            'total_samples': self.sampler.total_samples,
            'interesting_inputs': self.sampler.interesting_inputs,
            'elapsed_seconds': elapsed,
            'exec_per_sec': self.executions / elapsed if elapsed > 0 else 0,
            'command_stats': self.cmd_stats,
            'rc_stats': {k: dict(v) for k, v in self.rc_stats.items()},
        }

    def _print_status(self, stats: dict, last_samples: int = 0):
        log.warning(f"[Stats] exec: {stats['executions']:,} | "
                 f"corpus: {stats['corpus_size']} | "
                 f"crashes: {stats['crashes']} | "
                 f"edges: {stats['coverage_unique_edges']:,} | "
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
                 f"saturation={self.config.saturation_limit}, "
                 f"post_cmd={self.config.post_cmd_delay_ms}ms")
        log.warning(f"Power Sched : max_energy={self.config.max_energy}")
        log.warning(f"Output      : {self.config.output_dir}")
        log.warning("=" * 60)

        self._load_seeds()

        # 이전 커버리지 로드 (resume)
        if self.config.resume_coverage:
            self.sampler.load_coverage(self.config.resume_coverage)

        if not self.sampler.connect():
            log.error("J-Link connection failed, aborting")
            return

        # J-Link PC 읽기 진단
        if not self.sampler.diagnose():
            log.error("J-Link PC read diagnosis failed, aborting")
            return

        self.start_time = datetime.now()

        try:
            while True:
                elapsed = (datetime.now() - self.start_time).total_seconds()
                if elapsed >= self.config.total_runtime_sec:
                    log.info("Runtime limit reached")
                    break

                # v4: Power Schedule 기반 시드 선택
                if self.corpus and random.random() < 0.8:
                    seed = self._select_seed()
                    fuzz_data = self._mutate(seed.data)
                    cmd = seed.cmd
                else:
                    cmd = random.choice(self.commands)
                    fuzz_data = os.urandom(random.randint(64, 512))
                    seed = None

                # NVMe 커맨드 전송
                rc = self._send_nvme_command(fuzz_data, cmd)
                last_samples = self.sampler.stop_sampling()

                self.executions += 1
                self.cmd_stats[cmd.name]["exec"] += 1

                if rc is not None:
                    self.rc_stats[cmd.name][rc] += 1

                # v4: Edge 기반 커버리지 평가
                is_interesting, new_edges = self.sampler.evaluate_coverage()

                # 로그
                raw_count = len(self.sampler._last_raw_pcs)
                oor_count = self.sampler._out_of_range_count
                log.info(f"exec={self.executions} cmd={cmd.name} "
                          f"raw_samples={raw_count} edges={len(self.sampler.current_edges)} "
                          f"out_of_range={oor_count} new_edges={new_edges} "
                          f"global_edges={len(self.sampler.global_edges)} "
                          f"global_pcs={len(self.sampler.global_coverage)} "
                          f"last_new_at={self.sampler._last_new_at} "
                          f"stop={self.sampler._stopped_reason}")

                if self.sampler._unique_at_intervals:
                    log.debug(f"  saturation: {self.sampler._unique_at_intervals}")
                if self.sampler._last_raw_pcs:
                    all_pcs = [hex(pc) for pc in self.sampler._last_raw_pcs]
                    log.debug(f"  ALL raw PCs: {all_pcs}")
                if self.sampler.current_edges:
                    edges_str = [(hex(p), hex(c)) for p, c in sorted(self.sampler.current_edges)]
                    log.debug(f"  Edges: {edges_str[:20]}{'...' if len(edges_str) > 20 else ''}")

                if rc is None:
                    self.crash_inputs.append((fuzz_data, cmd))
                    self._save_crash(fuzz_data, cmd)
                    log.error(f"Crash/Timeout with {cmd.name}!")
                    if not self.sampler.reconnect():
                        log.error("Cannot reconnect to J-Link, stopping")
                        break
                    time.sleep(1)
                    continue

                if is_interesting:
                    self.sampler.interesting_inputs += 1
                    self.cmd_stats[cmd.name]["interesting"] += 1

                    # v4: 새 Seed 추가
                    new_seed = Seed(
                        data=fuzz_data,
                        cmd=cmd,
                        found_at=self.executions,
                        new_edges=new_edges
                    )
                    self.corpus.append(new_seed)
                    log.info(f"[+] New coverage! cmd={cmd.name} "
                             f"+{new_edges} edges (total: {len(self.sampler.global_edges)} edges, "
                             f"{len(self.sampler.global_coverage)} pcs)")

                if self.executions % 100 == 0:
                    stats = self._collect_stats()
                    self._print_status(stats, last_samples)
                    # OS 버퍼까지 강제 flush (파일 핸들러만)
                    for h in log.handlers:
                        h.flush()
                        if isinstance(h, logging.FileHandler) and h.stream:
                            os.fsync(h.stream.fileno())

        except KeyboardInterrupt:
            log.warning("Interrupted by user")

        finally:
            stats = self._collect_stats()

            # Summary 출력 (콘솔 + 파일 모두)
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
            summary_lines.append("=" * 60)

            for line in summary_lines:
                print(line)
            for line in summary_lines:
                log.info(line)

            # 최종 flush (OS 버퍼까지, 파일 핸들러만)
            for h in log.handlers:
                h.flush()
                if isinstance(h, logging.FileHandler) and h.stream:
                    os.fsync(h.stream.fileno())

            self.sampler.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='PC Sampling SSD Fuzzer v4')
    parser.add_argument('--device', default=JLINK_DEVICE, help='J-Link target')
    parser.add_argument('--nvme', default=NVME_DEVICE, help='NVMe device')
    parser.add_argument('--namespace', type=int, default=NVME_NAMESPACE)
    parser.add_argument('--commands', nargs='+', default=[],
                        help='Commands to use (e.g., Read Write GetFeatures)')
    parser.add_argument('--speed', type=int, default=JLINK_SPEED, help='JTAG speed (kHz)')
    parser.add_argument('--runtime', type=int, default=TOTAL_RUNTIME_SEC)
    parser.add_argument('--output', default=OUTPUT_DIR, help='Output dir')
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
                        help='Stop sampling after N consecutive duplicate edges (0=disable)')
    parser.add_argument('--max-energy', type=float, default=MAX_ENERGY,
                        help='Max energy for power schedule')

    args = parser.parse_args()

    print("Available commands:")
    for cmd in NVME_COMMANDS:
        print(f"  {cmd.name}: opcode={hex(cmd.opcode)}, type={cmd.cmd_type.value}")
    print()
    print("v4 Features:")
    print("  - Sampled Edge coverage: (prev_pc, cur_pc) tuples")
    print("  - Power Schedule: AFLfast explore-style energy allocation")
    print()

    config = FuzzConfig(
        device_name=args.device,
        jtag_speed=args.speed,
        nvme_device=args.nvme,
        nvme_namespace=args.namespace,
        enabled_commands=args.commands,
        total_runtime_sec=args.runtime,
        output_dir=args.output,
        max_samples_per_run=args.samples,
        sample_interval_us=args.interval,
        post_cmd_delay_ms=args.post_cmd_delay,
        addr_range_start=args.addr_start,
        addr_range_end=args.addr_end,
        resume_coverage=args.resume_coverage,
        saturation_limit=args.saturation_limit,
        max_energy=args.max_energy,
    )

    fuzzer = NVMeFuzzer(config)
    fuzzer.run()
