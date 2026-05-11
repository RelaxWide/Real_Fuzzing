# PC Sampling 기반 SSD 펌웨어 퍼저
# J-Link를 이용한 비침습적(최소 침습) 커버리지 퍼징
#
# 주의: J-Link V9는 완전한 Non-intrusive Trace를 지원하지 않습니다.
# 이 코드는 "Halt-Sample-Resume" 방식을 사용합니다.
# - 아주 짧게 CPU를 멈추고 (수 마이크로초)
# - PC 레지스터를 읽고
# - 바로 재개합니다.
#
# 완전한 Non-halt가 필요하면 J-Trace + ETM이 필요합니다.

from __future__ import annotations

import pylink
import time
import threading
import subprocess
import os
import json
import hashlib
from typing import Set, List, Optional
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass
class FuzzConfig:
    """퍼저 설정"""
    device_name: str = 'Cortex-R8'  # J-Link 타겟 디바이스
    interface: int = pylink.enums.JLinkInterfaces.JTAG
    jtag_speed: int = 4000  # kHz

    nvme_device: str = '/dev/nvme0'
    nvme_opcode: int = 0xC0  # Vendor Specific
    nvme_timeout_ms: int = 5000

    # 샘플링 설정
    sample_interval_us: int = 100  # 샘플 간격 (마이크로초)
    max_samples_per_run: int = 1000  # 한 실행당 최대 샘플 수

    # 퍼징 설정
    max_input_len: int = 4096
    total_runtime_sec: int = 3600
    seed_dir: Optional[str] = None
    output_dir: str = './output/pc_sampling/'

    # 주소 필터 (옵션)
    # 특정 범위만 커버리지로 인정 (펌웨어 코드 영역)
    addr_range_start: Optional[int] = None
    addr_range_end: Optional[int] = None


class JLinkPCSampler:
    """
    J-Link를 통한 PC 샘플링 클래스

    중요: pylink의 cpu_get_reg()는 CPU를 halt해야 동작합니다.
    이 클래스는 "빠른 Halt-Read-Resume" 방식을 사용합니다.

    완전한 Non-intrusive sampling은 J-Link V9에서 불가능합니다.
    (J-Trace + ETM 또는 SWO가 필요)
    """

    def __init__(self, config: FuzzConfig):
        self.config = config
        self.jlink: Optional[pylink.JLink] = None
        self.lock = threading.Lock()

        # 전체 세션의 글로벌 커버리지
        self.global_coverage: Set[int] = set()

        # 현재 실행의 트레이스
        self.current_trace: Set[int] = set()

        # 샘플링 스레드 제어
        self.is_sampling = False
        self.stop_event = threading.Event()
        self.sample_thread: Optional[threading.Thread] = None

        # 통계
        self.total_samples = 0
        self.total_executions = 0
        self.interesting_inputs = 0
        self.start_time: Optional[datetime] = None

    def connect(self) -> bool:
        """J-Link 연결"""
        try:
            if self.jlink and self.jlink.opened():
                self.jlink.close()

            self.jlink = pylink.JLink()
            self.jlink.open()
            self.jlink.set_tif(self.config.interface)
            self.jlink.connect(self.config.device_name, speed=self.config.jtag_speed)

            print(f"[J-Link] Connected: {self.config.device_name} @ {self.config.jtag_speed}kHz")

            # CPU가 멈춰있다면 재시작
            if self.jlink.halted():
                print("[J-Link] CPU was halted, restarting...")
                self.jlink.restart()
                time.sleep(0.1)

            return True

        except pylink.errors.JLinkException as e:
            print(f"[J-Link Error] Connection failed: {e}")
            return False

    def reconnect(self) -> bool:
        """재연결 (SSD 리셋 후 등)"""
        print("[J-Link] Attempting reconnection...")
        time.sleep(1)
        return self.connect()

    def _read_pc_halt_resume(self) -> Optional[int]:
        """
        PC 레지스터 읽기 (Halt-Read-Resume 방식)

        주의: 이 함수는 CPU를 아주 짧게 멈춥니다.
        완전한 non-intrusive가 아닙니다.
        """
        try:
            with self.lock:
                if not self.jlink or not self.jlink.connected():
                    return None

                # 1. Halt (CPU 멈춤)
                self.jlink.halt()

                # 2. PC 읽기 (ARM에서 R15 = PC)
                pc = self.jlink.register_read(15)

                # 3. Resume (CPU 재개)
                self.jlink.restart()

                return pc

        except pylink.errors.JLinkException as e:
            # JTAG 에러 (노이즈, 연결 불안정 등)
            return None
        except Exception as e:
            print(f"[Sampler Error] {e}")
            return None

    def _sampling_worker(self):
        """백그라운드 샘플링 워커"""
        self.current_trace = set()
        sample_count = 0
        interval_sec = self.config.sample_interval_us / 1_000_000

        while not self.stop_event.is_set():
            if sample_count >= self.config.max_samples_per_run:
                break

            pc = self._read_pc_halt_resume()

            if pc is not None:
                # 주소 범위 필터링 (설정된 경우)
                if self.config.addr_range_start and self.config.addr_range_end:
                    if self.config.addr_range_start <= pc <= self.config.addr_range_end:
                        self.current_trace.add(pc)
                else:
                    self.current_trace.add(pc)

                sample_count += 1
                self.total_samples += 1

            # 샘플 간격 대기
            time.sleep(interval_sec)

    def start_sampling(self):
        """샘플링 시작"""
        self.stop_event.clear()
        self.sample_thread = threading.Thread(target=self._sampling_worker, daemon=True)
        self.sample_thread.start()

    def stop_sampling(self) -> int:
        """샘플링 종료, 수집된 샘플 수 반환"""
        if self.sample_thread:
            self.stop_event.set()
            self.sample_thread.join(timeout=2.0)

        return len(self.current_trace)

    def evaluate_coverage(self) -> tuple[bool, int]:
        """
        커버리지 평가
        Returns: (is_interesting, new_paths_count)
        """
        initial_len = len(self.global_coverage)

        # 새로운 PC들을 글로벌 셋에 추가
        self.global_coverage.update(self.current_trace)

        final_len = len(self.global_coverage)
        new_paths = final_len - initial_len

        is_interesting = new_paths > 0

        return is_interesting, new_paths

    def close(self):
        """연결 종료"""
        if self.sample_thread:
            self.stop_event.set()
            self.sample_thread.join(timeout=1.0)

        if self.jlink:
            try:
                self.jlink.close()
            except:
                pass


class NVMeFuzzer:
    """NVMe 기반 퍼저"""

    def __init__(self, config: FuzzConfig):
        self.config = config
        self.sampler = JLinkPCSampler(config)

        # 코퍼스 관리
        self.corpus: List[bytes] = []
        self.crash_inputs: List[bytes] = []

        # 출력 디렉토리 설정
        self.output_dir = Path(config.output_dir)
        self.corpus_dir = self.output_dir / 'corpus'
        self.crashes_dir = self.output_dir / 'crashes'
        self.stats_file = self.output_dir / 'stats.json'

        # 통계
        self.executions = 0
        self.start_time: Optional[datetime] = None

    def _setup_directories(self):
        """출력 디렉토리 생성"""
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        self.crashes_dir.mkdir(parents=True, exist_ok=True)

    def _load_seeds(self):
        """시드 파일 로드"""
        if self.config.seed_dir and os.path.isdir(self.config.seed_dir):
            seed_path = Path(self.config.seed_dir)
            for seed_file in seed_path.iterdir():
                if seed_file.is_file():
                    with open(seed_file, 'rb') as f:
                        self.corpus.append(f.read())
            print(f"[Fuzzer] Loaded {len(self.corpus)} seeds")

        # 시드가 없으면 기본 시드 추가
        if not self.corpus:
            self.corpus.append(b'\x00' * 64)
            self.corpus.append(b'\xff' * 64)
            self.corpus.append(os.urandom(64))

    def _mutate(self, data: bytes) -> bytes:
        """입력 변형 (간단한 mutation)"""
        import random

        data = bytearray(data)

        # 여러 mutation 중 랜덤 선택
        mutation_type = random.randint(0, 5)

        if mutation_type == 0:
            # 랜덤 바이트 변경
            if data:
                pos = random.randint(0, len(data) - 1)
                data[pos] = random.randint(0, 255)

        elif mutation_type == 1:
            # 바이트 삽입
            pos = random.randint(0, len(data))
            data.insert(pos, random.randint(0, 255))

        elif mutation_type == 2:
            # 바이트 삭제
            if len(data) > 1:
                pos = random.randint(0, len(data) - 1)
                del data[pos]

        elif mutation_type == 3:
            # 여러 바이트 랜덤 변경
            if data:
                num_changes = random.randint(1, min(10, len(data)))
                for _ in range(num_changes):
                    pos = random.randint(0, len(data) - 1)
                    data[pos] = random.randint(0, 255)

        elif mutation_type == 4:
            # 특수 값 삽입 (boundary values)
            special_values = [0x00, 0xff, 0x7f, 0x80, 0x41]
            if data:
                pos = random.randint(0, len(data) - 1)
                data[pos] = random.choice(special_values)

        else:
            # 청크 복제
            if len(data) >= 4:
                src = random.randint(0, len(data) - 4)
                dst = random.randint(0, len(data) - 1)
                chunk = data[src:src+4]
                data[dst:dst+4] = chunk

        # 최대 길이 제한
        if len(data) > self.config.max_input_len:
            data = data[:self.config.max_input_len]

        return bytes(data)

    def _send_nvme_command(self, data: bytes) -> bool:
        """NVMe 커맨드 전송"""
        if not data:
            return True

        input_file = '/tmp/nvme_fuzz_input'

        try:
            # 입력 파일 작성
            with open(input_file, 'wb') as f:
                f.write(data)

            # NVMe admin-passthru 실행
            cmd = [
                'nvme', 'admin-passthru',
                self.config.nvme_device,
                f'--opcode={hex(self.config.nvme_opcode)}',
                f'--input-file={input_file}',
                f'--data-len={len(data)}',
                f'--timeout={self.config.nvme_timeout_ms}',
                '-r'
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.config.nvme_timeout_ms / 1000 + 5
            )

            return True

        except subprocess.TimeoutExpired:
            print("[NVMe] Command timeout - possible hang/crash")
            return False
        except FileNotFoundError:
            print("[NVMe] nvme-cli not found. Install with: sudo apt install nvme-cli")
            return False
        except Exception as e:
            print(f"[NVMe] Error: {e}")
            return False

    def _save_input(self, data: bytes, is_crash: bool = False):
        """입력 저장"""
        input_hash = hashlib.md5(data).hexdigest()[:16]

        if is_crash:
            filepath = self.crashes_dir / f'crash_{input_hash}'
        else:
            filepath = self.corpus_dir / f'input_{input_hash}'

        with open(filepath, 'wb') as f:
            f.write(data)

    def _save_stats(self):
        """통계 저장"""
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
            'timestamp': datetime.now().isoformat()
        }

        with open(self.stats_file, 'w') as f:
            json.dump(stats, f, indent=2)

        return stats

    def _print_status(self, stats: dict):
        """상태 출력"""
        print(f"\r[Stats] exec: {stats['executions']:,} | "
              f"corpus: {stats['corpus_size']} | "
              f"crashes: {stats['crashes']} | "
              f"coverage: {stats['coverage_unique_pcs']:,} | "
              f"exec/s: {stats['exec_per_sec']:.1f}", end='', flush=True)

    def run(self):
        """퍼징 메인 루프"""
        print("=" * 60)
        print(" PC Sampling 기반 SSD 퍼저")
        print("=" * 60)
        print(f"Target: {self.config.nvme_device}")
        print(f"Opcode: {hex(self.config.nvme_opcode)}")
        print(f"J-Link: {self.config.device_name}")
        print(f"Runtime: {self.config.total_runtime_sec}s")
        print("=" * 60)
        print()
        print("[!] 주의: J-Link V9는 완전한 Non-intrusive 모드를 지원하지 않습니다.")
        print("    이 퍼저는 Halt-Sample-Resume 방식을 사용합니다.")
        print("    SSD 타임아웃이 발생할 수 있습니다.")
        print()

        # 초기화
        self._setup_directories()
        self._load_seeds()

        # J-Link 연결
        if not self.sampler.connect():
            print("[ERROR] J-Link connection failed")
            return

        self.start_time = datetime.now()
        import random

        try:
            while True:
                # 런타임 체크
                elapsed = (datetime.now() - self.start_time).total_seconds()
                if elapsed >= self.config.total_runtime_sec:
                    print("\n[Fuzzer] Runtime limit reached")
                    break

                # 코퍼스에서 선택 및 변형
                base_input = random.choice(self.corpus)
                fuzz_input = self._mutate(base_input)

                # 1. 샘플링 시작
                self.sampler.start_sampling()

                # 2. NVMe 커맨드 전송
                success = self._send_nvme_command(fuzz_input)

                # 3. 샘플링 종료
                samples = self.sampler.stop_sampling()

                self.executions += 1

                # 4. 커버리지 평가
                is_interesting, new_paths = self.sampler.evaluate_coverage()

                if not success:
                    # 타임아웃/크래시
                    self.crash_inputs.append(fuzz_input)
                    self._save_input(fuzz_input, is_crash=True)
                    print(f"\n[!] Potential crash detected! Saved to crashes/")

                    # J-Link 재연결 시도
                    self.sampler.reconnect()
                    time.sleep(1)
                    continue

                if is_interesting:
                    # 새로운 경로 발견
                    self.sampler.interesting_inputs += 1
                    self.corpus.append(fuzz_input)
                    self._save_input(fuzz_input)

                # 주기적 상태 출력
                if self.executions % 10 == 0:
                    stats = self._save_stats()
                    self._print_status(stats)

        except KeyboardInterrupt:
            print("\n[Fuzzer] Interrupted by user")

        finally:
            # 최종 통계
            print("\n")
            print("=" * 60)
            print(" 퍼징 완료")
            print("=" * 60)
            stats = self._save_stats()
            print(f"총 실행: {stats['executions']:,}")
            print(f"코퍼스: {stats['corpus_size']}")
            print(f"크래시: {stats['crashes']}")
            print(f"커버리지 (unique PCs): {stats['coverage_unique_pcs']:,}")
            print(f"샘플 수: {stats['total_samples']:,}")
            print(f"유의미한 입력: {stats['interesting_inputs']}")
            print(f"실행 시간: {stats['elapsed_seconds']:.1f}s")
            print(f"출력 폴더: {self.output_dir}")
            print("=" * 60)

            self.sampler.close()


# ===========================================
# 대안 1: J-Link CLI를 이용한 샘플링
# pylink가 문제가 있을 경우 JLink.exe 명령줄 사용
# ===========================================
class JLinkCLISampler:
    """
    J-Link 명령줄 도구를 이용한 PC 샘플링

    JLink.exe 또는 JLinkExe를 subprocess로 호출합니다.
    pylink 라이브러리 문제가 있을 때 대안으로 사용하세요.
    """

    def __init__(self, config: FuzzConfig):
        self.config = config
        self.global_coverage: Set[int] = set()
        self.current_trace: Set[int] = set()
        self.script_file = '/tmp/jlink_read_pc.jlink'

    def _create_script(self):
        """J-Link 스크립트 파일 생성"""
        script = f"""
device {self.config.device_name}
si JTAG
speed {self.config.jtag_speed}
r
g
sleep 10
halt
regs
g
q
"""
        with open(self.script_file, 'w') as f:
            f.write(script)

    def sample_once(self) -> Optional[int]:
        """한 번 샘플링 (CLI 방식)"""
        self._create_script()

        try:
            result = subprocess.run(
                ['JLinkExe', '-CommandFile', self.script_file],
                capture_output=True,
                text=True,
                timeout=5
            )

            # 출력에서 PC 값 파싱
            # 예: "R15 (PC)   = 0x00012345"
            for line in result.stdout.split('\n'):
                if 'R15' in line or 'PC' in line:
                    parts = line.split('=')
                    if len(parts) >= 2:
                        pc_str = parts[1].strip().split()[0]
                        return int(pc_str, 16)

            return None

        except Exception as e:
            print(f"[JLink CLI Error] {e}")
            return None


# ===========================================
# 대안 2: GDB를 통한 PC 샘플링 (더 안정적)
# ===========================================
class GDBPCSampler:
    """
    GDB를 통한 PC 샘플링

    J-Link GDB Server + GDB를 사용합니다.
    pylink보다 더 안정적일 수 있습니다.
    """

    def __init__(self, config: FuzzConfig, gdb_port: int = 2331):
        self.config = config
        self.gdb_port = gdb_port
        self.global_coverage: Set[int] = set()
        self.current_trace: Set[int] = set()
        self.gdb_script = '/tmp/gdb_sample.py'

    def _create_gdb_script(self, num_samples: int = 100):
        """GDB Python 스크립트 생성"""
        script = f'''
import gdb
import time

pc_values = []

try:
    gdb.execute("target remote localhost:{self.gdb_port}", to_string=True)
    gdb.execute("continue &", to_string=True)

    for i in range({num_samples}):
        time.sleep(0.0001)  # 100us
        gdb.execute("interrupt", to_string=True)
        pc = gdb.parse_and_eval("$pc")
        pc_values.append(int(pc))
        gdb.execute("continue &", to_string=True)

    # 결과 출력
    print("PC_VALUES:" + ",".join(map(hex, pc_values)))

except Exception as e:
    print(f"ERROR:{{e}}")

gdb.execute("quit", to_string=True)
'''
        with open(self.gdb_script, 'w') as f:
            f.write(script)

    def sample(self, num_samples: int = 100) -> Set[int]:
        """여러 번 샘플링"""
        self._create_gdb_script(num_samples)

        try:
            result = subprocess.run(
                ['gdb-multiarch', '-x', self.gdb_script, '-batch'],
                capture_output=True,
                text=True,
                timeout=30
            )

            for line in result.stdout.split('\n'):
                if line.startswith('PC_VALUES:'):
                    values = line.replace('PC_VALUES:', '').split(',')
                    for v in values:
                        if v:
                            self.current_trace.add(int(v, 16))

            return self.current_trace

        except Exception as e:
            print(f"[GDB Sampler Error] {e}")
            return set()


# ===========================================
# 메인 실행
# ===========================================
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='PC Sampling SSD Fuzzer')
    parser.add_argument('--device', default='Cortex-R8', help='J-Link target device')
    parser.add_argument('--nvme', default='/dev/nvme0', help='NVMe device path')
    parser.add_argument('--opcode', type=lambda x: int(x, 0), default=0xC0, help='NVMe opcode')
    parser.add_argument('--speed', type=int, default=4000, help='JTAG speed (kHz)')
    parser.add_argument('--runtime', type=int, default=3600, help='Total runtime (seconds)')
    parser.add_argument('--output', default='./output/pc_sampling/', help='Output directory')
    parser.add_argument('--seeds', help='Seeds directory')
    parser.add_argument('--addr-start', type=lambda x: int(x, 0), help='Address range start (hex)')
    parser.add_argument('--addr-end', type=lambda x: int(x, 0), help='Address range end (hex)')

    args = parser.parse_args()

    config = FuzzConfig(
        device_name=args.device,
        jtag_speed=args.speed,
        nvme_device=args.nvme,
        nvme_opcode=args.opcode,
        total_runtime_sec=args.runtime,
        output_dir=args.output,
        seed_dir=args.seeds,
        addr_range_start=args.addr_start,
        addr_range_end=args.addr_end
    )

    fuzzer = NVMeFuzzer(config)
    fuzzer.run()
