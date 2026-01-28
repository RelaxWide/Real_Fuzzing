# PC Sampling 기반 SSD 펌웨어 퍼저 v2
# - 다중 NVMe Opcode 지원 (Admin + I/O)
# - 개선된 커버리지 추적

from __future__ import annotations

import pylink
import time
import threading
import subprocess
import os
import json
import hashlib
import random
from typing import Set, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from enum import Enum


class NVMeCommandType(Enum):
    ADMIN = "admin-passthru"
    IO = "io-passthru"


@dataclass
class NVMeCommand:
    """NVMe 커맨드 정의"""
    name: str
    opcode: int
    cmd_type: NVMeCommandType
    needs_namespace: bool = True
    needs_data: bool = True
    description: str = ""


# 지원하는 NVMe 커맨드 목록
NVME_COMMANDS = [
    # Admin Commands
    NVMeCommand("Identify", 0x06, NVMeCommandType.ADMIN, needs_data=False,
                description="장치/네임스페이스 정보 조회"),
    NVMeCommand("GetLogPage", 0x02, NVMeCommandType.ADMIN, needs_data=False,
                description="로그 페이지 조회"),
    NVMeCommand("SetFeatures", 0x09, NVMeCommandType.ADMIN,
                description="기능 설정"),
    NVMeCommand("GetFeatures", 0x0A, NVMeCommandType.ADMIN, needs_data=False,
                description="기능 조회"),
    NVMeCommand("VendorSpecific", 0xC0, NVMeCommandType.ADMIN,
                description="벤더 고유 명령"),

    # I/O Commands
    NVMeCommand("Read", 0x02, NVMeCommandType.IO, needs_data=False,
                description="데이터 읽기"),
    NVMeCommand("Write", 0x01, NVMeCommandType.IO,
                description="데이터 쓰기"),
]


@dataclass
class FuzzConfig:
    """퍼저 설정"""
    device_name: str = 'Cortex-R8'
    interface: int = pylink.enums.JLinkInterfaces.JTAG
    jtag_speed: int = 4000

    nvme_device: str = '/dev/nvme0'
    nvme_namespace: int = 1
    nvme_timeout_ms: int = 5000

    # 사용할 커맨드 이름 목록 (비어있으면 전체 사용)
    # 예: ["VendorSpecific", "Read", "Write"]
    enabled_commands: List[str] = field(default_factory=list)

    # 샘플링 설정
    sample_interval_us: int = 100
    max_samples_per_run: int = 500  # 기본값 줄임

    # 퍼징 설정
    max_input_len: int = 4096
    total_runtime_sec: int = 3600
    seed_dir: Optional[str] = None
    output_dir: str = './output/pc_sampling_v2/'

    # 주소 필터
    addr_range_start: Optional[int] = None
    addr_range_end: Optional[int] = None


class JLinkPCSampler:
    """J-Link PC 샘플러"""

    def __init__(self, config: FuzzConfig):
        self.config = config
        self.jlink: Optional[pylink.JLink] = None
        self.lock = threading.Lock()
        self.global_coverage: Set[int] = set()
        self.current_trace: Set[int] = set()
        self.stop_event = threading.Event()
        self.sample_thread: Optional[threading.Thread] = None
        self.total_samples = 0
        self.interesting_inputs = 0

    def connect(self) -> bool:
        try:
            if self.jlink and self.jlink.opened():
                self.jlink.close()

            self.jlink = pylink.JLink()
            self.jlink.open()
            self.jlink.set_tif(self.config.interface)
            self.jlink.connect(self.config.device_name, speed=self.config.jtag_speed)

            print(f"[J-Link] Connected: {self.config.device_name} @ {self.config.jtag_speed}kHz")

            # CPU 재시작
            try:
                self.jlink.restart()
            except:
                pass

            return True
        except Exception as e:
            print(f"[J-Link Error] {e}")
            return False

    def reconnect(self) -> bool:
        print("[J-Link] Reconnecting...")
        time.sleep(2)
        return self.connect()

    def _read_pc(self) -> Optional[int]:
        try:
            with self.lock:
                if not self.jlink or not self.jlink.connected():
                    return None
                self.jlink.halt()
                pc = self.jlink.register_read(15)
                self.jlink.restart()
                return pc
        except:
            return None

    def _sampling_worker(self):
        self.current_trace = set()
        sample_count = 0
        interval = self.config.sample_interval_us / 1_000_000

        while not self.stop_event.is_set() and sample_count < self.config.max_samples_per_run:
            pc = self._read_pc()
            if pc is not None:
                # 주소 필터링
                if self.config.addr_range_start and self.config.addr_range_end:
                    if self.config.addr_range_start <= pc <= self.config.addr_range_end:
                        self.current_trace.add(pc)
                else:
                    self.current_trace.add(pc)
                sample_count += 1
                self.total_samples += 1
            time.sleep(interval)

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

    def close(self):
        self.stop_event.set()
        if self.sample_thread:
            self.sample_thread.join(timeout=1.0)
        if self.jlink:
            try:
                self.jlink.close()
            except:
                pass


class NVMeFuzzer:
    """다중 Opcode 지원 NVMe 퍼저"""

    def __init__(self, config: FuzzConfig):
        self.config = config
        self.sampler = JLinkPCSampler(config)

        # 사용할 커맨드 필터링
        if config.enabled_commands:
            self.commands = [c for c in NVME_COMMANDS if c.name in config.enabled_commands]
        else:
            self.commands = NVME_COMMANDS.copy()

        print(f"[Fuzzer] Enabled commands: {[c.name for c in self.commands]}")

        self.corpus: List[Tuple[bytes, NVMeCommand]] = []  # (data, command) 쌍
        self.crash_inputs: List[Tuple[bytes, NVMeCommand]] = []

        self.output_dir = Path(config.output_dir)
        self.corpus_dir = self.output_dir / 'corpus'
        self.crashes_dir = self.output_dir / 'crashes'
        self.stats_file = self.output_dir / 'stats.json'
        self.coverage_file = self.output_dir / 'coverage.txt'

        self.executions = 0
        self.start_time: Optional[datetime] = None

        # 커맨드별 통계
        self.cmd_stats = {c.name: {"exec": 0, "interesting": 0} for c in self.commands}

    def _setup_directories(self):
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        self.crashes_dir.mkdir(parents=True, exist_ok=True)

    def _load_seeds(self):
        if self.config.seed_dir and os.path.isdir(self.config.seed_dir):
            for seed_file in Path(self.config.seed_dir).iterdir():
                if seed_file.is_file():
                    with open(seed_file, 'rb') as f:
                        data = f.read()
                        # 모든 커맨드에 대해 시드 추가
                        for cmd in self.commands:
                            self.corpus.append((data, cmd))
            print(f"[Fuzzer] Loaded seeds for {len(self.commands)} commands")

        if not self.corpus:
            # 기본 시드
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

    def _send_nvme_command(self, data: bytes, cmd: NVMeCommand) -> bool:
        """NVMe 커맨드 전송"""
        input_file = '/tmp/nvme_fuzz_input'

        try:
            # 입력 파일 작성
            with open(input_file, 'wb') as f:
                f.write(data)

            # 기본 명령어 구성
            nvme_cmd = [
                'nvme', cmd.cmd_type.value,
                self.config.nvme_device,
                f'--opcode={hex(cmd.opcode)}',
                f'--timeout={self.config.nvme_timeout_ms}',
            ]

            # 네임스페이스 추가 (I/O 커맨드에 필요)
            if cmd.needs_namespace:
                nvme_cmd.append(f'--namespace-id={self.config.nvme_namespace}')

            # 데이터가 필요한 커맨드
            if cmd.needs_data and data:
                nvme_cmd.extend([
                    f'--input-file={input_file}',
                    f'--data-len={len(data)}',
                ])

            # Read 커맨드는 출력 요청
            if cmd.name == "Read":
                nvme_cmd.append('-r')

            # I/O 커맨드는 추가 파라미터 필요
            if cmd.cmd_type == NVMeCommandType.IO:
                # LBA (Logical Block Address) - 랜덤 또는 고정
                lba = random.randint(0, 1000)
                nvme_cmd.append(f'--cdw10={lba & 0xFFFFFFFF}')  # LBA 하위
                nvme_cmd.append(f'--cdw11={(lba >> 32) & 0xFFFFFFFF}')  # LBA 상위
                # 블록 수 (cdw12)
                nvme_cmd.append(f'--cdw12={0}')  # 1 블록

            result = subprocess.run(
                nvme_cmd,
                capture_output=True,
                timeout=self.config.nvme_timeout_ms / 1000 + 5
            )

            return True

        except subprocess.TimeoutExpired:
            print(f"\n[!] Timeout: {cmd.name} (opcode={hex(cmd.opcode)})")
            return False
        except Exception as e:
            print(f"\n[!] Error ({cmd.name}): {e}")
            return False

    def _save_input(self, data: bytes, cmd: NVMeCommand, is_crash: bool = False):
        input_hash = hashlib.md5(data).hexdigest()[:12]
        filename = f"{cmd.name}_{hex(cmd.opcode)}_{input_hash}"

        if is_crash:
            filepath = self.crashes_dir / f'crash_{filename}'
        else:
            filepath = self.corpus_dir / f'input_{filename}'

        with open(filepath, 'wb') as f:
            f.write(data)

        # 메타데이터 저장
        meta = {"command": cmd.name, "opcode": hex(cmd.opcode), "type": cmd.cmd_type.value}
        with open(str(filepath) + '.json', 'w') as f:
            json.dump(meta, f)

    def _save_coverage(self):
        """커버리지를 파일로 저장"""
        with open(self.coverage_file, 'w') as f:
            for pc in sorted(self.sampler.global_coverage):
                f.write(f"{hex(pc)}\n")

    def _save_stats(self) -> dict:
        elapsed = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0

        stats = {
            'executions': self.executions,
            'corpus_size': len(self.corpus),
            'crashes': len(self.crash_inputs),
            'coverage_unique_pcs': len(self.sampler.global_coverage),
            'total_samples': self.sampler.total_samples,
            'interesting_inputs': self.sampler.interesting_inputs,
            'elapsed_seconds': elapsed,
            'exec_per_sec': self.executions / elapsed if elapsed > 0 else 0,
            'command_stats': self.cmd_stats,
            'timestamp': datetime.now().isoformat()
        }

        with open(self.stats_file, 'w') as f:
            json.dump(stats, f, indent=2)

        return stats

    def _print_status(self, stats: dict, last_samples: int = 0):
        # 줄바꿈으로 누적 출력
        print(f"[Stats] exec: {stats['executions']:,} | "
              f"corpus: {stats['corpus_size']} | "
              f"crashes: {stats['crashes']} | "
              f"coverage: {stats['coverage_unique_pcs']:,} | "
              f"samples: {stats['total_samples']:,} | "
              f"last_run: {last_samples} | "
              f"exec/s: {stats['exec_per_sec']:.1f}")

    def run(self):
        print("=" * 60)
        print(" PC Sampling SSD Fuzzer v2 - Multi-Opcode Support")
        print("=" * 60)
        print(f"Device: {self.config.nvme_device}")
        print(f"Commands: {[c.name for c in self.commands]}")
        print(f"J-Link: {self.config.device_name}")
        print("=" * 60)
        print()

        self._setup_directories()
        self._load_seeds()

        if not self.sampler.connect():
            print("[ERROR] J-Link connection failed")
            return

        self.start_time = datetime.now()

        try:
            while True:
                elapsed = (datetime.now() - self.start_time).total_seconds()
                if elapsed >= self.config.total_runtime_sec:
                    print("\n[Fuzzer] Runtime limit reached")
                    break

                # 코퍼스에서 선택 또는 새 커맨드 선택
                if self.corpus and random.random() < 0.8:
                    base_data, cmd = random.choice(self.corpus)
                    fuzz_data = self._mutate(base_data)
                else:
                    # 새로운 커맨드 시도
                    cmd = random.choice(self.commands)
                    fuzz_data = os.urandom(random.randint(64, 512))

                # 샘플링 & 실행
                self.sampler.start_sampling()
                time.sleep(0.01)  # 샘플링 시작 후 10ms 대기
                success = self._send_nvme_command(fuzz_data, cmd)
                time.sleep(0.05)  # 명령 후 50ms 더 샘플링
                last_samples = self.sampler.stop_sampling()

                self.executions += 1
                self.cmd_stats[cmd.name]["exec"] += 1

                # 커버리지 평가
                is_interesting, new_paths = self.sampler.evaluate_coverage()

                # 첫 몇 번은 상세 디버그 출력
                if self.executions <= 5:
                    print(f"[Debug] exec={self.executions} cmd={cmd.name} "
                          f"samples={last_samples} new_pcs={new_paths} "
                          f"current_trace={len(self.sampler.current_trace)} "
                          f"global={len(self.sampler.global_coverage)}")
                    # 수집된 PC 몇 개 출력
                    if self.sampler.current_trace:
                        sample_pcs = list(self.sampler.current_trace)[:5]
                        print(f"        PCs: {[hex(pc) for pc in sample_pcs]}")

                if not success:
                    self.crash_inputs.append((fuzz_data, cmd))
                    self._save_input(fuzz_data, cmd, is_crash=True)
                    print(f"[!] Crash/Timeout with {cmd.name}!")
                    self.sampler.reconnect()
                    time.sleep(1)
                    continue

                if is_interesting:
                    self.sampler.interesting_inputs += 1
                    self.cmd_stats[cmd.name]["interesting"] += 1
                    self.corpus.append((fuzz_data, cmd))
                    self._save_input(fuzz_data, cmd)
                    print(f"[+] New coverage! cmd={cmd.name} +{new_paths} PCs (total: {len(self.sampler.global_coverage)})")

                # 주기적 출력
                if self.executions % 10 == 0:
                    stats = self._save_stats()
                    self._print_status(stats, last_samples)

                # 커버리지 주기적 저장
                if self.executions % 100 == 0:
                    self._save_coverage()

        except KeyboardInterrupt:
            print("\n[Fuzzer] Interrupted")

        finally:
            print("\n" + "=" * 60)
            print(" Fuzzing Complete")
            print("=" * 60)
            stats = self._save_stats()
            self._save_coverage()

            print(f"Total executions: {stats['executions']:,}")
            print(f"Corpus size: {stats['corpus_size']}")
            print(f"Crashes: {stats['crashes']}")
            print(f"Coverage (unique PCs): {stats['coverage_unique_pcs']:,}")
            print(f"\nPer-command stats:")
            for cmd_name, cmd_stat in stats['command_stats'].items():
                print(f"  {cmd_name}: exec={cmd_stat['exec']}, interesting={cmd_stat['interesting']}")
            print(f"\nOutput: {self.output_dir}")
            print("=" * 60)

            self.sampler.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='PC Sampling SSD Fuzzer v2')
    parser.add_argument('--device', default='Cortex-R8', help='J-Link target')
    parser.add_argument('--nvme', default='/dev/nvme0', help='NVMe device')
    parser.add_argument('--namespace', type=int, default=1, help='NVMe namespace')
    parser.add_argument('--commands', nargs='+', default=[],
                        help='Commands to use (e.g., VendorSpecific Read Write)')
    parser.add_argument('--speed', type=int, default=4000, help='JTAG speed')
    parser.add_argument('--runtime', type=int, default=3600, help='Runtime (sec)')
    parser.add_argument('--output', default='./output/pc_sampling_v2/', help='Output dir')
    parser.add_argument('--samples', type=int, default=500, help='Max samples per run')
    parser.add_argument('--interval', type=int, default=100, help='Sample interval (us)')

    args = parser.parse_args()

    # 사용 가능한 커맨드 목록 출력
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
    )

    fuzzer = NVMeFuzzer(config)
    fuzzer.run()
