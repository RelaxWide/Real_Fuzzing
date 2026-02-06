#!/usr/bin/env python3
"""
PC Sampling 기반 SSD 펌웨어 Coverage-Guided Fuzzer v2

J-Link V9 Halt-Sample-Resume 방식으로 커버리지를 수집하고,
NVMe CLI를 통해 SSD에 퍼징 입력을 전달합니다.

주의: J-Link V9는 완전한 Non-intrusive Trace를 지원하지 않습니다.
     이 코드는 ~10us halt로 PC를 읽는 방식을 사용합니다.
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
from collections import defaultdict
from typing import Set, List, Optional, Tuple
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
NVME_TIMEOUT   = 5000         # ms

# PC 샘플링 설정
SAMPLE_INTERVAL_US    = 0     # 샘플 간격 (us), 0 = halt 직후 바로 다음 halt
MAX_SAMPLES_PER_RUN   = 500   # NVMe 커맨드 1회당 최대 샘플 수 (상한)
SATURATION_LIMIT      = 10    # 연속 N회 새 unique PC 없으면 조기 종료
POST_CMD_DELAY_MS     = 0     # 커맨드 완료 후 tail 샘플링 (ms)

# 퍼징 설정
MAX_INPUT_LEN     = 4096      # 최대 입력 바이트
TOTAL_RUNTIME_SEC = 3600      # 총 퍼징 시간 (초)
OUTPUT_DIR        = './output/pc_sampling_v2/'
SEED_DIR          = None      # 시드 폴더 경로 (없으면 None)
RESUME_COVERAGE   = None      # 이전 coverage.txt 경로 (없으면 None)

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


def setup_logging(output_dir: str) -> logging.Logger:
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

    # 파일: DEBUG 이상 전부 기록
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    # 콘솔: INFO 이상만 출력
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    return logger


# 모듈 레벨 로거 (setup_logging 호출 전까지 콘솔만 사용)
log = logging.getLogger('pcfuzz')


class JLinkPCSampler:
    """J-Link Halt-Sample-Resume 기반 PC 수집기"""

    def __init__(self, config: FuzzConfig):
        self.config = config
        self.jlink: Optional[pylink.JLink] = None
        self._pc_reg_index: int = 9  # Cortex-R8: R15(PC)의 J-Link 레지스터 인덱스
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

            log.info(f"[J-Link] Connected: {self.config.device_name} @ {self.config.jtag_speed}kHz")

            # R15(PC)의 실제 레지스터 인덱스를 동적으로 탐색
            self._pc_reg_index = self._find_pc_register_index()
            log.info(f"[J-Link] PC register index: {self._pc_reg_index} "
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
        log.info(f"[Diagnose] PC를 {count}회 읽어서 J-Link 상태를 확인합니다...")
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
                log.info(f"  [{i+1:2d}] PC = {hex(pc)}{in_range}")
            else:
                failures += 1
                log.warning(f"  [{i+1:2d}] PC read FAILED")
            time.sleep(0.05)

        if not pcs:
            log.error("[Diagnose] PC를 한 번도 읽지 못했습니다. JTAG 연결을 확인하세요.")
            return False

        unique_pcs = set(pcs)
        log.info(f"[Diagnose] 결과: {len(pcs)}/{count} 성공, "
                 f"failures={failures}, unique PCs={len(unique_pcs)}")
        if len(unique_pcs) <= 1:
            log.warning(f"[Diagnose] PC가 항상 같은 값입니다 ({hex(pcs[0])}). "
                        f"CPU가 멈춰있거나 idle loop에 있을 수 있습니다.")
        return True

    def _read_pc(self) -> Optional[int]:
        """halt → register read → resume を1サイクル実行.
        DLL直接呼び出しでpylink wrapper overhead を回避."""
        try:
            self._halt_func()
            pc = self._read_reg_func(self._pc_reg_index)
            self._go_func()
            return pc
        except Exception:
            return None

    def _sampling_worker(self):
        self.current_trace = set()
        self._last_raw_pcs = []       # 이번 실행에서 수집한 모든 raw PC
        self._out_of_range_count = 0   # 범위 밖 PC 수
        self._last_new_at = 0          # 마지막으로 새 unique PC가 발견된 샘플 번호
        self._unique_at_intervals = {} # {샘플수: 그 시점의 unique PC 수}
        self._stopped_reason = ""      # 종료 사유
        sample_count = 0
        prev_unique = 0
        since_last_new = 0             # 마지막 새 PC 이후 연속 중복 횟수
        interval = self.config.sample_interval_us / 1_000_000
        sat_limit = self.config.saturation_limit

        while not self.stop_event.is_set() and sample_count < self.config.max_samples_per_run:
            pc = self._read_pc()
            if pc is not None:
                self._last_raw_pcs.append(pc)
                if self.config.addr_range_start is not None and self.config.addr_range_end is not None:
                    if self.config.addr_range_start <= pc <= self.config.addr_range_end:
                        self.current_trace.add(pc)
                    else:
                        self._out_of_range_count += 1
                else:
                    self.current_trace.add(pc)
                sample_count += 1
                self.total_samples += 1

                cur_unique = len(self.current_trace)
                if cur_unique > prev_unique:
                    self._last_new_at = sample_count
                    prev_unique = cur_unique
                    since_last_new = 0
                else:
                    since_last_new += 1

                if sample_count in (10, 25, 50, 100, 200, 500):
                    self._unique_at_intervals[sample_count] = cur_unique

                # 조기 종료: 연속 N회 새 PC 없으면 포화 판정
                if sat_limit > 0 and since_last_new >= sat_limit:
                    self._stopped_reason = f"saturated (no new PC for {sat_limit} consecutive samples)"
                    break
            if interval > 0:
                time.sleep(interval)

        if not self._stopped_reason:
            if self.stop_event.is_set():
                self._stopped_reason = "stop_event"
            else:
                self._stopped_reason = f"max_samples ({self.config.max_samples_per_run})"

    def start_sampling(self):
        self.stop_event.clear()
        self.sample_thread = threading.Thread(target=self._sampling_worker, daemon=True)
        self.sample_thread.start()

    def stop_sampling(self) -> int:
        if self.sample_thread:
            self.stop_event.set()
            self.sample_thread.join(timeout=2.0)
        return len(self.current_trace)

    def evaluate_coverage(self) -> Tuple[bool, int]:
        initial = len(self.global_coverage)
        self.global_coverage.update(self.current_trace)
        new_paths = len(self.global_coverage) - initial
        return new_paths > 0, new_paths

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
    """다중 Opcode 지원 NVMe 퍼저"""

    def __init__(self, config: FuzzConfig):
        self.config = config
        self.sampler = JLinkPCSampler(config)

        if config.enabled_commands:
            self.commands = [c for c in NVME_COMMANDS if c.name in config.enabled_commands]
        else:
            self.commands = NVME_COMMANDS.copy()

        log.info(f"[Fuzzer] Enabled commands: {[c.name for c in self.commands]}")

        self.corpus: List[Tuple[bytes, NVMeCommand]] = []
        self.crash_inputs: List[Tuple[bytes, NVMeCommand]] = []

        self.output_dir = Path(config.output_dir)
        self.crashes_dir = self.output_dir / 'crashes'

        self.executions = 0
        self.start_time: Optional[datetime] = None

        self.cmd_stats = {c.name: {"exec": 0, "interesting": 0} for c in self.commands}
        # {cmd_name: {rc: count}} — 커맨드별 리턴코드 분포
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
                            self.corpus.append((data, cmd))
            log.info(f"[Fuzzer] Loaded seeds for {len(self.commands)} commands")

        if not self.corpus:
            for cmd in self.commands:
                self.corpus.append((b'\x00' * 64, cmd))
                self.corpus.append((b'\xff' * 64, cmd))
                self.corpus.append((os.urandom(64), cmd))

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

            # 커맨드라인 로깅 (nvme CLI 형태로 한 줄)
            cmd_str = ' '.join(nvme_cmd)
            log.debug(f"[NVMe] {cmd_str}  # data_len={len(data)} data={data[:16].hex()}{'...' if len(data) > 16 else ''}")

            # =========================================================
            # [수정 1] "덫 놓기" 전략 적용
            # 명령을 보내기 전에 샘플링을 먼저 시작하여, 명령 처리 초반부(헤더 파싱 등)를 놓치지 않게 함
            # =========================================================
            self.sampler.start_sampling()

            process = subprocess.Popen(
                nvme_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            # =========================================================

            # 커맨드 완료 대기
            timeout_sec = self.config.nvme_timeout_ms / 1000 + 5
            try:
                stdout, stderr = process.communicate(timeout=timeout_sec)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                self.sampler.stop_sampling() # 타임아웃 시 샘플링 종료
                log.warning(f"[NVMe TIMEOUT] {cmd.name} (opcode={hex(cmd.opcode)})")
                log.debug(f"  stdout: {stdout.decode(errors='replace').strip()}")
                log.debug(f"  stderr: {stderr.decode(errors='replace').strip()}")
                return None

            # 프로세스가 정상 종료되면 샘플링 중단
            self.sampler.stop_sampling()

            # 리턴값, stdout, stderr 로깅
            rc = process.returncode
            stdout_str = stdout.decode(errors='replace').strip()
            stderr_str = stderr.decode(errors='replace').strip()
            log.debug(f"[NVMe RET] rc={rc}, stdout={stdout_str[:200]}")
            if stderr_str:
                log.debug(f"[NVMe RET] stderr={stderr_str[:200]}")
            if rc != 0:
                log.debug(f"[NVMe RET] {cmd.name} returned non-zero: rc={rc}")

            return rc

        except Exception as e:
            log.error(f"NVMe error ({cmd.name}): {e}")
            # 에러 발생 시에도 샘플링이 켜져있다면 꺼줘야 함
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
            'executions': self.executions,
            'corpus_size': len(self.corpus),
            'crashes': len(self.crash_inputs),
            'coverage_unique_pcs': len(self.sampler.global_coverage),
            'total_samples': self.sampler.total_samples,
            'interesting_inputs': self.sampler.interesting_inputs,
            'elapsed_seconds': elapsed,
            'exec_per_sec': self.executions / elapsed if elapsed > 0 else 0,
            'command_stats': self.cmd_stats,
        }

    def _print_status(self, stats: dict, last_samples: int = 0):
        log.info(f"[Stats] exec: {stats['executions']:,} | "
                 f"corpus: {stats['corpus_size']} | "
                 f"crashes: {stats['crashes']} | "
                 f"coverage: {stats['coverage_unique_pcs']:,} | "
                 f"samples: {stats['total_samples']:,} | "
                 f"last_run: {last_samples} | "
                 f"exec/s: {stats['exec_per_sec']:.1f}")

    def run(self):
        global log

        self._setup_directories()
        log = setup_logging(self.config.output_dir)
        log.info(f"Log file: {os.path.join(self.config.output_dir, 'fuzzer.log')}")

        log.info("=" * 60)
        log.info(" PC Sampling SSD Fuzzer v2")
        log.info("=" * 60)
        log.info(f"NVMe device : {self.config.nvme_device}")
        log.info(f"Commands    : {[c.name for c in self.commands]}")
        log.info(f"J-Link      : {self.config.device_name} @ {self.config.jtag_speed}kHz")
        if self.config.addr_range_start is not None:
            log.info(f"Addr filter : {hex(self.config.addr_range_start)}"
                     f" - {hex(self.config.addr_range_end)}")
        else:
            log.warning("Addr filter : NONE (all PCs collected - noisy!)")
        log.info(f"Sampling    : interval={self.config.sample_interval_us}us, "
                 f"max={self.config.max_samples_per_run}/run, "
                 f"saturation={self.config.saturation_limit}, "
                 f"post_cmd={self.config.post_cmd_delay_ms}ms")
        log.info(f"Output      : {self.config.output_dir}")
        log.info("=" * 60)

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

                # 코퍼스에서 선택 또는 새 커맨드 선택
                if self.corpus and random.random() < 0.8:
                    base_data, cmd = random.choice(self.corpus)
                    fuzz_data = self._mutate(base_data)
                else:
                    cmd = random.choice(self.commands)
                    fuzz_data = os.urandom(random.randint(64, 512))

                # NVMe 커맨드 전송 (내부에서 Popen 후 샘플링 시작)
                rc = self._send_nvme_command(fuzz_data, cmd)
                last_samples = self.sampler.stop_sampling()

                self.executions += 1
                self.cmd_stats[cmd.name]["exec"] += 1

                # rc 통계 (None = 타임아웃/에러)
                if rc is not None:
                    self.rc_stats[cmd.name][rc] += 1

                # 커버리지 평가
                is_interesting, new_paths = self.sampler.evaluate_coverage()

                # 매 실행마다 DEBUG 로그 (파일에만 기록)
                raw_count = len(self.sampler._last_raw_pcs)
                oor_count = self.sampler._out_of_range_count
                log.debug(f"exec={self.executions} cmd={cmd.name} "
                          f"raw_samples={raw_count} in_range={last_samples} "
                          f"out_of_range={oor_count} new_pcs={new_paths} "
                          f"global={len(self.sampler.global_coverage)} "
                          f"last_new_at={self.sampler._last_new_at} "
                          f"stop={self.sampler._stopped_reason}")
                if self.sampler._unique_at_intervals:
                    log.debug(f"  saturation: {self.sampler._unique_at_intervals}")
                if self.sampler._last_raw_pcs:
                    all_pcs = [hex(pc) for pc in self.sampler._last_raw_pcs]
                    log.debug(f"  ALL raw PCs: {all_pcs}")
                if self.sampler.current_trace:
                    in_range_pcs = sorted([hex(pc) for pc in self.sampler.current_trace])
                    log.debug(f"  In-range unique PCs: {in_range_pcs}")

                if rc is None:
                    self.crash_inputs.append((fuzz_data, cmd))
                    self._save_crash(fuzz_data, cmd)
                    log.warning(f"Crash/Timeout with {cmd.name}!")
                    if not self.sampler.reconnect():
                        log.error("Cannot reconnect to J-Link, stopping")
                        break
                    time.sleep(1)
                    continue

                if is_interesting:
                    self.sampler.interesting_inputs += 1
                    self.cmd_stats[cmd.name]["interesting"] += 1
                    self.corpus.append((fuzz_data, cmd))
                    log.info(f"[+] New coverage! cmd={cmd.name} "
                             f"+{new_paths} PCs (total: {len(self.sampler.global_coverage)})")

                if self.executions % 10 == 0:
                    stats = self._collect_stats()
                    self._print_status(stats, last_samples)
                    for h in log.handlers:
                        h.flush()

        except KeyboardInterrupt:
            log.info("Interrupted by user")

        finally:
            stats = self._collect_stats()

            log.info("=" * 60)
            log.info(" Fuzzing Complete")
            log.info("=" * 60)
            log.info(f"Total executions : {stats['executions']:,}")
            log.info(f"Elapsed          : {stats['elapsed_seconds']:.1f}s")
            log.info(f"Exec/s           : {stats['exec_per_sec']:.1f}")
            log.info(f"Corpus size      : {stats['corpus_size']}")
            log.info(f"Crashes          : {stats['crashes']}")
            log.info(f"Total samples    : {stats['total_samples']:,}")
            log.info(f"Interesting      : {stats['interesting_inputs']}")
            log.info(f"Coverage (unique PCs): {stats['coverage_unique_pcs']:,}")
            log.info("Per-command stats:")
            for cmd_name, cmd_stat in stats['command_stats'].items():
                log.info(f"  {cmd_name}: exec={cmd_stat['exec']}, "
                         f"interesting={cmd_stat['interesting']}")
            log.info("Return code distribution:")
            for cmd_name, rc_dist in self.rc_stats.items():
                rc_summary = ", ".join(f"rc={rc}:{cnt}" for rc, cnt in sorted(rc_dist.items()))
                log.info(f"  {cmd_name}: {rc_summary}")
            log.info("=" * 60)

            self.sampler.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='PC Sampling SSD Fuzzer v2')
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
                        help='Stop sampling after N consecutive duplicate PCs (0=disable, sample up to --samples)')

    args = parser.parse_args()

    print("Available commands:")
    for cmd in NVME_COMMANDS:
        print(f"  {cmd.name}: opcode={hex(cmd.opcode)}, type={cmd.cmd_type.value}")
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
    )

    fuzzer = NVMeFuzzer(config)
    fuzzer.run()
