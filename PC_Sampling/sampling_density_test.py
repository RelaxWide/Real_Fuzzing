#!/usr/bin/env python3
"""
샘플링 밀도 비교 테스트 스크립트

동일한 NVMe 커맨드를 두 가지 모드로 실행하여 PC 수집 결과를 비교:
1. Normal mode: SATURATION_LIMIT=10 (조기 종료)
2. Dense mode:  SATURATION_LIMIT=0, MAX_SAMPLES=500 (최대 샘플링)

Usage:
    sudo python3 sampling_density_test.py
    sudo python3 sampling_density_test.py --rounds 10
    sudo python3 sampling_density_test.py --commands Identify GetFeatures
"""

import pylink
import subprocess
import time
import os
import argparse
from dataclasses import dataclass
from typing import Optional, Set, List

# =============================================================================
# 설정
# =============================================================================
JLINK_DEVICE = 'Cortex-R8'
JLINK_SPEED = 12000
PC_REG_INDEX = 9

NVME_DEVICE = '/dev/nvme0'
NVME_TIMEOUT = 5000

FW_ADDR_START = 0x00000000
FW_ADDR_END = 0x00147FFF

# =============================================================================

@dataclass
class SamplingResult:
    raw_samples: int
    unique_pcs: int
    in_range_pcs: int
    out_of_range: int
    last_new_at: int
    pcs: Set[int]
    elapsed_ms: float


class JLinkSampler:
    def __init__(self):
        self.jlink: Optional[pylink.JLink] = None
        self._halt_func = None
        self._read_reg_func = None
        self._go_func = None

    def connect(self) -> bool:
        try:
            self.jlink = pylink.JLink()
            self.jlink.open()
            self.jlink.set_tif(pylink.enums.JLinkInterfaces.JTAG)
            self.jlink.connect(JLINK_DEVICE, speed=JLINK_SPEED)

            # DLL 함수 캐싱
            self._halt_func = self.jlink._dll.JLINKARM_Halt
            self._read_reg_func = self.jlink._dll.JLINKARM_ReadReg
            self._go_func = self.jlink._dll.JLINKARM_Go

            print(f"[J-Link] Connected: {JLINK_DEVICE} @ {JLINK_SPEED}kHz")
            return True
        except Exception as e:
            print(f"[J-Link Error] {e}")
            return False

    def _read_pc(self) -> Optional[int]:
        try:
            self._halt_func()
            pc = self._read_reg_func(PC_REG_INDEX)
            self._go_func()
            return pc
        except:
            return None

    def sample_during_command(self, nvme_cmd: List[str], max_samples: int,
                               saturation_limit: int) -> SamplingResult:
        """NVMe 커맨드 실행 중 PC 샘플링"""
        pcs: Set[int] = set()
        raw_pcs: List[int] = []
        out_of_range = 0
        last_new_at = 0
        since_last_new = 0

        start = time.perf_counter()

        # 샘플링 시작 후 커맨드 전송
        process = subprocess.Popen(
            nvme_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        sample_count = 0
        prev_unique = 0

        while sample_count < max_samples:
            # 프로세스 종료 체크
            if process.poll() is not None:
                break

            pc = self._read_pc()
            if pc is not None:
                raw_pcs.append(pc)
                sample_count += 1

                if FW_ADDR_START <= pc <= FW_ADDR_END:
                    pcs.add(pc)
                else:
                    out_of_range += 1

                cur_unique = len(pcs)
                if cur_unique > prev_unique:
                    last_new_at = sample_count
                    prev_unique = cur_unique
                    since_last_new = 0
                else:
                    since_last_new += 1

                # 조기 종료 (saturation_limit > 0일 때만)
                if saturation_limit > 0 and since_last_new >= saturation_limit:
                    break

        # 프로세스 완료 대기
        try:
            process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()

        elapsed = (time.perf_counter() - start) * 1000

        return SamplingResult(
            raw_samples=len(raw_pcs),
            unique_pcs=len(set(raw_pcs)),
            in_range_pcs=len(pcs),
            out_of_range=out_of_range,
            last_new_at=last_new_at,
            pcs=pcs,
            elapsed_ms=elapsed,
        )

    def close(self):
        if self.jlink:
            try:
                self.jlink.close()
            except:
                pass


def build_nvme_cmd(cmd_name: str) -> List[str]:
    """테스트용 NVMe 커맨드 빌드"""
    commands = {
        'Identify': ['nvme', 'admin-passthru', NVME_DEVICE,
                     '--opcode=0x06', f'--timeout={NVME_TIMEOUT}', '--namespace-id=1'],
        'GetFeatures': ['nvme', 'admin-passthru', NVME_DEVICE,
                        '--opcode=0x0a', f'--timeout={NVME_TIMEOUT}', '--namespace-id=1'],
        'GetLogPage': ['nvme', 'admin-passthru', NVME_DEVICE,
                       '--opcode=0x02', f'--timeout={NVME_TIMEOUT}', '--namespace-id=1'],
    }
    return commands.get(cmd_name, commands['Identify'])


def run_comparison(sampler: JLinkSampler, cmd_name: str, rounds: int):
    """Normal vs Dense 샘플링 비교"""
    print(f"\n{'='*60}")
    print(f" Command: {cmd_name} | Rounds: {rounds}")
    print(f"{'='*60}")

    nvme_cmd = build_nvme_cmd(cmd_name)
    print(f" NVMe: {' '.join(nvme_cmd)}")
    print()

    normal_results: List[SamplingResult] = []
    dense_results: List[SamplingResult] = []

    for i in range(rounds):
        # Normal mode (saturation=10)
        r_normal = sampler.sample_during_command(nvme_cmd, max_samples=500, saturation_limit=10)
        normal_results.append(r_normal)

        time.sleep(0.1)  # 커맨드 사이 간격

        # Dense mode (saturation=0, 전체 샘플링)
        r_dense = sampler.sample_during_command(nvme_cmd, max_samples=500, saturation_limit=0)
        dense_results.append(r_dense)

        print(f" Round {i+1:2d}: Normal(sat=10): samples={r_normal.raw_samples:3d}, "
              f"unique={r_normal.in_range_pcs:3d}, last_new={r_normal.last_new_at:3d}, "
              f"time={r_normal.elapsed_ms:.0f}ms")
        print(f"           Dense (sat=0):  samples={r_dense.raw_samples:3d}, "
              f"unique={r_dense.in_range_pcs:3d}, last_new={r_dense.last_new_at:3d}, "
              f"time={r_dense.elapsed_ms:.0f}ms")

        time.sleep(0.1)

    # 통계 요약
    print()
    print(f" {'─'*58}")
    print(f" Summary:")

    def avg(results, key):
        return sum(getattr(r, key) for r in results) / len(results)

    normal_avg_samples = avg(normal_results, 'raw_samples')
    normal_avg_unique = avg(normal_results, 'in_range_pcs')
    normal_avg_time = avg(normal_results, 'elapsed_ms')

    dense_avg_samples = avg(dense_results, 'raw_samples')
    dense_avg_unique = avg(dense_results, 'in_range_pcs')
    dense_avg_time = avg(dense_results, 'elapsed_ms')

    # 전체 누적 커버리지
    normal_total_pcs = set()
    dense_total_pcs = set()
    for r in normal_results:
        normal_total_pcs.update(r.pcs)
    for r in dense_results:
        dense_total_pcs.update(r.pcs)

    print(f"   Normal (sat=10): avg_samples={normal_avg_samples:.1f}, "
          f"avg_unique={normal_avg_unique:.1f}, avg_time={normal_avg_time:.0f}ms, "
          f"total_coverage={len(normal_total_pcs)}")
    print(f"   Dense  (sat=0):  avg_samples={dense_avg_samples:.1f}, "
          f"avg_unique={dense_avg_unique:.1f}, avg_time={dense_avg_time:.0f}ms, "
          f"total_coverage={len(dense_total_pcs)}")

    # 차이 분석
    only_in_dense = dense_total_pcs - normal_total_pcs
    only_in_normal = normal_total_pcs - dense_total_pcs

    print()
    print(f"   PCs only in Dense (missed by Normal): {len(only_in_dense)}")
    if only_in_dense and len(only_in_dense) <= 10:
        print(f"     {[hex(pc) for pc in sorted(only_in_dense)]}")
    print(f"   PCs only in Normal (luck-based):      {len(only_in_normal)}")

    speedup = dense_avg_time / normal_avg_time if normal_avg_time > 0 else 0
    print(f"   Time ratio (Dense/Normal): {speedup:.1f}x slower")
    print()


def main():
    parser = argparse.ArgumentParser(description='Sampling Density Comparison Test')
    parser.add_argument('--rounds', type=int, default=5, help='Number of rounds per command')
    parser.add_argument('--commands', nargs='+', default=['Identify', 'GetFeatures'],
                        help='Commands to test')
    args = parser.parse_args()

    print("="*60)
    print(" Sampling Density Comparison Test")
    print(" Normal (saturation=10) vs Dense (saturation=0)")
    print("="*60)

    sampler = JLinkSampler()
    if not sampler.connect():
        return

    try:
        for cmd_name in args.commands:
            run_comparison(sampler, cmd_name, args.rounds)
    except KeyboardInterrupt:
        print("\nInterrupted")
    finally:
        sampler.close()
        print("Done.")


if __name__ == "__main__":
    main()
