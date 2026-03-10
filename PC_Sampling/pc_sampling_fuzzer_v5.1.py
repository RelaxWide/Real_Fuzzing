#!/usr/bin/env python3
"""
PC Sampling 기반 SSD 펌웨어 Coverage-Guided Fuzzer v5.1

J-Link V9 Halt-Sample-Resume 방식으로 커버리지를 수집하고,
subprocess(nvme-cli)를 통해 SSD에 퍼징 입력을 전달합니다.

v5.1 변경사항:
- [Feature] PM Rotation: --pm 플래그로 매 PM_ROTATE_INTERVAL(기본 100)회 명령마다
    random.randint(0,4)로 PS0~PS4 중 랜덤 전환 (같은 PS 재진입 허용).
    _pm_set_state() → bool: SetFeatures(FID=0x02, CDW11=ps) 전송, rc·소요시간 로그 출력.
    [Stats] 출력과 동일 경계(executions % 100)에서 PS 전환.
    PS별 실행 횟수 / 진입 횟수 통계 — 종료 summary에 출력.
- [Feature] 정적 분석 커버리지 연동:
    퍼저 동일 디렉토리에 code_addrs.txt / functions.txt(Ghidra ghidra_export.py 생성) 두면
    자동 탐지 · 로드 (CLI 인자 불필요). 파일 없으면 기존 동작 유지.
    evaluate_coverage() 호출 후 신규 PC만 증분 처리 (bisect O(log N), 성능 영향 최소).
    [Stats] 출력 시 [StatCov] code: X.X% | funcs: N/M (Y.Y%) 행 추가.
    종료 summary에 Code Coverage / Func Coverage 섹션 추가.
- [Feature] 정적 분석 시각화 그래프 3종 (graphs/ 에 자동 생성):
    coverage_growth.png  : code_cov% / funcs_cov% 성장 곡선 (100회마다 스냅샷)
    firmware_map.png     : 펌웨어 함수 공간 전체 맵 (커버=초록 / 미커버=회색)
    uncovered_funcs.png  : 미커버 함수 Top-30 크기 내림차순 막대 차트
- [Tune] DIAGNOSE_STABILITY: 50 → 100, DIAGNOSE_MAX: 1000 → 5000
    idle PC 100개+ 환경(복잡한 RTOS, 주기 인터럽트)에서 최대 샘플 도달로
    idle 유니버스 수렴 미완료 발생 → 상한 확장으로 완전 수렴 보장.
    최대 소요 시간: 5000 × 50ms ≈ 4분 (퍼저 시작 시 1회).
- [BugFix] idle_pcs addr_range 필터 제거:
    RTOS/IRQ 핸들러(0x10000000+) 등 범위 밖 PC가 idle_pcs에서 빠지면
    consecutive_idle 카운터가 리셋되어 idle saturation이 동작하지 않는 문제 수정.
    idle_pcs는 전체 idle 유니버스를 포함, addr_range 필터는 coverage 추적에만 적용.
- [Feature] Crash 시 FAIL CMD 상세 출력:
    timeout crash 발생 시 dmesg 캡처 직후, 실패한 NVMe 명령의
    cmd/opcode/device/nsid/cdw2~15/data_len/data hex/mutations 전체를
    "!! FAIL CMD !!" 블록으로 강조 출력.
- [Feature] Crash 시 UFAS 펌웨어 덤프 자동 실행:
    fuzzer 동일 디렉토리의 ./ufas 파일이 있으면 crash 저장 직후 자동 실행.
    PCIe bus 번호는 /sys/class/nvme/<ctrl>/address sysfs 우선 탐지,
    실패 시 lspci fallback. 덤프 파일명: <YYYYMMDD>_UFAS_Dump.bin.
- [Feature] Crash 재현 TC replay .sh 자동 생성:
    _cmd_history(deque maxlen=100)에 NVMe 명령 + PM 동작을 순서대로 기록.
    crash 발생 시 crashes/replay_<tag>.sh 생성 — sudo bash replay_<tag>.sh 로 바로 실행.
    마지막 항목(CRASH CMD) 주석 표기, write 데이터는 replay_data_<tag>/data_NNN.bin 저장.
    --input-file 절대경로 저장 (실행 위치 무관), stdout > /dev/null 으로 response buffer 억제,
    명령어 CLI 전체 + rc=$? echo 출력, set +e 로 중간 실패 시에도 전체 시퀀스 실행.

v5.0 변경사항:
- [Feature] --interface auto/jtag/swd: J-Link 인터페이스 자동 탐지
    기본값 auto: JTAG 연결 시도 → 실패 시 SWD로 자동 전환.
    SWD 전용 SSD 제품에서도 별도 옵션 없이 자동 연결 가능.
    FuzzConfig.interface: int → Optional[int] (None=auto).
- [Feature] --pc-reg-index N: PC 레지스터 인덱스 수동 지정
    자동 탐지 실패 시 jlink_reg_diag.py로 인덱스 확인 후 강제 지정.
    _find_pc_register_index() 탐색 패턴 강화: R15/PC/EPC/MEPC/SEPC.
    Cortex-R8(=9), Cortex-M(=15), RISC-V 등 아키텍처별 대응.
- [Redesign] diagnose(): 수렴 기반 idle 유니버스 수집
    기존: 고정 횟수 샘플 후 빈도 임계값으로 idle PC 추정.
    문제: SWD에서 WFI wake로 20+개 PC 등장 → 단일 idle_pc 감지 불가.
    해결: 새 PC가 DIAGNOSE_STABILITY(기본 50)회 연속 나타나지 않을 때까지
          adaptive 샘플링 (최대 DIAGNOSE_MAX=1000회).
    수집된 모든 unique PC (범위 내) = "idle 유니버스":
      JTAG: WFI 고정 → 수십 샘플에 수렴, idle_pcs 1~2개.
      SWD:  주기적 인터럽트 핸들러까지 포함 → 더 많은 샘플 후 수렴, idle_pcs 20+개.
    --diagnose-stability, --diagnose-max CLI 옵션 추가.
- [BugFix] _sampling_worker(): idle 감지를 idle 유니버스 기반으로 교체
    기존 단일 idle_pc → SWD에서 None이 되어 idle saturation 완전 비작동.
    idle_pcs(유니버스) 내 PC가 sat_limit회 연속 → idle_saturated 조기종료.
    NVMe 커맨드 처리 코드는 idle 유니버스 밖에 있으므로 처리 중 오발동 없음:
      idle 유니버스 밖 PC 한 번이라도 나오면 consecutive_idle 리셋.

v4.7 변경사항:
- [BugFix] FUA 비트 위치 수정: CDW12[14] → CDW12[29] (NVMe spec 1.4 §6.3)
    기존 (1<<14)=0x4000은 NLB 필드 상위비트를 오염시켜 rc=2 발생.
    올바른 FUA 위치: CDW12[29] = Force Unit Access.
    Read LBA 0 FUA, Write LBA 0 FUA 시드 모두 수정.
- [BugFix] 컨트롤러 범위 명령의 NSID 수정: nsid_override=0 적용
    Identify Controller(CNS=0x01), GetLogPage LID=0x01/0x02,
    TelemetryHostInitiated는 네임스페이스 범위가 아닌 컨트롤러 범위.
    NVMe spec에서 해당 명령들의 NSID 필드는 Reserved → 0으로 전송.
    기존: cmd.namespace_id(=1) 사용 → rc=2 발생.
- [BugFix] Sanitize 초기 시드에서 제거
    Sanitize(Block Erase)는 rc=0 즉시 SSD 전체 데이터 소거 시작.
    퍼저 시작 시 자동 실행되어 데이터 파괴 위험 → 기본 시드에서 제거.
- [Feature] nsid_override 시드 템플릿 지원
    SEED_TEMPLATES dict에 nsid_override 키 추가,
    _generate_default_seeds() 루프에서 Seed 생성 시 반영.

v4.6 변경사항:
- [BugFix] io-passthru deprecated ioctl 경고 제거: nvme io-passthru를
    char device(/dev/nvme0) 대신 namespace block device(/dev/nvme0n1)로 전송.
    "using deprecated NVME_IOCTL_IO_CMD ioctl on the char device!" 경고 해결.
    admin-passthru는 char device 그대로 유지.
- [Feature] NVMe 명령 timeout / subprocess 감지 timeout 분리:
    기존에는 nvme-cli --timeout과 subprocess 감지 timeout이 동일한 값을 사용.
    nvme-cli --timeout(NVME_PASSTHRU_TIMEOUT_MS, 기본 30일)을 subprocess
    감지 timeout(nvme_timeouts, 기본 8~10초)과 분리하여 커널 NVMe 드라이버가
    timeout crash 후 controller reset을 수행하지 않도록 함.
    - subprocess 감지 timeout: 퍼저가 "crash 발생"을 인식하는 창 (빠름, 그대로)
    - nvme-cli --timeout: 커널이 NVMe 명령을 포기하는 시점 (길게 → reset 방지)
    정상 실행에서는 SSD가 ms~초 단위로 응답하므로 성능에 전혀 영향 없음.
- [Feature] Crash 시 NVMe PCIe 드라이버 즉시 unbind (SSD 상태 보존):
    문제: nvme-cli --timeout(30일)은 passthru 명령 자체에만 적용.
    Linux NVMe 드라이버는 내부 admin 명령(AER, keep-alive 등)에 ADMIN_TIMEOUT(60s)을
    사용하므로, 펌웨어 크래시 후 60초 뒤 nvme_reset_ctrl()이 발동하여 SSD 상태가
    덮어써진다.
    해결: timeout 감지 즉시 /sys/bus/pci/drivers/nvme/unbind로 드라이버 제거.
    드라이버가 사라지면 60초 타이머도 제거 → SSD 펌웨어 상태 장기 보존.
    /dev/nvme* 장치는 사라지지만 JTAG으로 펌웨어 접근 가능.
    분석 완료 후: echo '<BDF>' > /sys/bus/pci/drivers/nvme/bind
- [Feature] Crash 시 nvme-cli 프로세스 보존 (보조 수단):
    process.kill() 제거, start_new_session=True로 부모 종료 후에도 생존.
    unbind 후 nvme-cli는 ENODEV로 D-state에서 깨어나 자동 종료됨 (정상 동작).

v4.5 변경사항 (v4.5 이후 수정 포함):
- [Redesign] Primary coverage signal: (prev_pc, cur_pc) edge → unique PC 주소
    PC 샘플링 edge는 타이밍 아티팩트를 포함하여 결정론적이지 않다.
    동일 코드경로를 실행해도 샘플링 타이밍에 따라 다른 (prev_pc, cur_pc) 쌍이
    생성되어 corpus 추가 기준으로 사용하면 corpus가 폭발적으로 증가한다.
    개별 PC 주소는 코드가 실행되면 항상 생성되므로 결정론적이다.
    → is_interesting = 새 PC 주소 발견 여부 (new_pcs > 0)
    → Seed 필드: new_edges→new_pcs, covered_edges→covered_pcs, stable_edges→stable_pcs
    → corpus culling: edge→best_seed 매핑 → pc→best_seed 매핑
    → Calibration: PC 주소 안정성 측정
- [BugFix] covered_edges 노이즈: corpus 추가 시 noise edge를 포함하여 culling이
    무력화되던 문제 수정 (covered_pcs = current_trace로 교체)
- [Feature] Corpus 하드 상한: max_corpus_hard_limit (기본 0=비활성). culling 후에도
    초과 시 exec_count가 높은 비선호 seed부터 강제 제거하는 안전망.
- [BugFix] Corpus culling exec_count 임계값 5→2: unfavored seed를 더 빠르게 제거.
- [BugFix] _sampling_worker 포화 체크 PC 기반: global_coverage_ref(PC 주소) 기반.
    primary signal과 일치.
- [Feature] 로그 pcs_this_run 추가: per-exec 로그에 이번 실행 unique PC 수 추가.

v4.5 변경사항:
- [Feature] Calibration: 초기 시드를 N회(기본 3) 반복 실행하여 PC 주소 안정성 측정,
    global_coverage 초기화, 결과 요약 테이블(Stability / StablePCs / AllPCs) 출력
- [BugFix] Calibration DLL stderr 억제: os.dup2(devnull, 2)로 J-Link DLL 타이밍 경고 억제
- [BugFix] Calibration 이중 start_sampling 버그: _calibrate_seed() 내부의 명시적
    start_sampling() 호출 제거 (StablePCs 전부 0이 되던 문제 해결)
- [Feature] Deterministic stage: CDW10~CDW15 필드에 Walking bitflip / Arithmetic /
    Interesting 값 체계적 적용, 제너레이터 기반 + deque로 havoc보다 우선 소비
- [Feature] MOpt mutation scheduling: Pilot(5000회, 균등 사용 + 성공률 측정) /
    Core(50000회, 성공률 기반 가중치) 2단계 교대

v4.4 변경사항:
- [Feature] Tracking Label NVMe 스펙 매핑: _OPCODE_TO_NAME 역방향 테이블
- [Feature] Heatmap 이미지 크기 제한: MAX_HEATMAP_CMDS=40, DPI 동적 조정
- [Feature] Timeout dmesg 캡처: crash JSON + crash_*.dmesg.txt

v4.3 변경사항:
- [BugFix] 로그 메시지 불일치 수정: "ioctl direct" → "subprocess (nvme-cli)"
- [BugFix] 글로벌 포화 임계값 하드코딩 → global_saturation_limit 설정값 분리
- [BugFix] 실행 간 prev_pc 캐리오버 제거: 매 실행마다 sentinel(0xFFFFFFFF)으로 리셋
- [BugFix] post_cmd_delay_ms 미사용 수정: 명령 완료 후 추가 샘플링 대기 구현
- [Perf] cmd_traces를 collections.deque로 교체 (pop(0) O(n) → popleft O(1))
- [Perf] 샘플 간격 체크포인트를 frozenset으로 교체 (O(1) lookup 보장)
- [Feature] Corpus culling (_cull_corpus), J-Link heartbeat, NVMe 디바이스 사전 검증
- [Feature] Summary에 Mutation 통계 추가, 실제 opcode 기준 추적 (_tracking_label)
- [Feature] Timeout crash 시 불량 현상 보존: resume 없이 퍼징 중단, stuck PC 기록
- [BugFix] subprocess kill 후 D state 블로킹 방지: communicate()에 타임아웃 추가

v4.2 변경사항:
- subprocess + 샘플링 연동: idle/포화 감지 시 프로세스 kill → 즉시 다음 실행
- 글로벌 기준 포화 판정 (global_coverage 대비 새 PC 체크)
- idle PC 감지: diagnose에서 가장 빈도 높은 PC를 idle로 설정

v4.1 변경사항:
- Seed dataclass에 CDW2~CDW15 필드 추가
- Opcode별 NVMe 스펙 기반 정상 명령어를 초기 시드로 자동 생성
- AFL++ havoc/splice 기반 mutation 전략

v4 변경사항:
- Primary coverage signal: unique PC 주소 (global_coverage / current_trace)
- CFG 그래프/히트맵의 edge는 cmd_traces (ordered PC sequences)에서 도출
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
import sys
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
import bisect

# 버전
FUZZER_VERSION = "5.1"

# =============================================================================
# USER CONFIGURATION - 여기만 수정하세요
# =============================================================================

# Ghidra에서 확인한 펌웨어 코드(.text) 영역 주소
FW_ADDR_START = 0x00000000
FW_ADDR_END   = 0x00147FFF

# J-Link / JTAG 설정
JLINK_DEVICE  = 'Cortex-R8'
JLINK_SPEED   = 4000           # kHz

# NVMe 장치 설정
NVME_DEVICE    = '/dev/nvme0'
NVME_NAMESPACE = 1

# NVMe 명령어 그룹별 타임아웃 (ms)
# 그룹에 속하지 않는 명령어는 모두 'command'에 해당
NVME_TIMEOUTS = {
    'command':      18_000,    # 일반 명령어 (Identify, GetLogPage, GetFeatures, Read, Write 등)
    'format':       600_000,   # Format NVM — 전체 미디어 포맷, 수 분 소요 가능
    'sanitize':     600_000,   # Sanitize — 보안 삭제, 수 분~수십 분 소요
    'fw_commit':    120_000,   # Firmware Commit — 펌웨어 슬롯 활성화, 리셋 포함 가능
    'telemetry':    30_000,    # Telemetry Host/Controller — 대용량 로그 수집
    'dsm':          30_000,    # Dataset Management (TRIM/Deallocate)
    'flush':        30_000,    # Flush — 캐시 플러시, 미디어 기록 완료 대기
    'selftest':     30_000,    # Device Self-test START — 즉시 반환, 테스트는 백그라운드 실행
    'security':     30_000,    # Security Send/Receive — TCG/OPAL 프로토콜
}

# PC 샘플링 설정
SAMPLE_INTERVAL_US    = 0      # 샘플 간격 (us). 0 = halt-as-fast-as-possible (최대 밀도).
                               # 다른 제품(JTAG/정상 SWD)은 0으로도 안정적으로 동작한다.
                               # NVMe 안정성이 필요한 경우 아래 GO_SETTLE_MS 를 사용할 것.

# Go() 후 CPU 최소 실행 보장 시간 (ms)
# SAMPLE_INTERVAL_US 와 독립적인 하드웨어 안정성 파라미터.
# 기본값 0 = 비활성화 (JTAG / 정상 SWD 환경 — 하위 호환성 유지).
# SWD + 1.8V 레벨시프터 환경: NVMe DMA/클럭 게이팅으로 Go() 직후
#   halt 시 CPU 실행 시간이 너무 짧아 NVMe 커맨드 타임아웃 발생.
#   diagnose() 경험: 5ms 미만 → 불안정, 50ms → 안정.
#   이 값을 50 으로 설정하면 Go() 후 CPU에 최소 50ms 실행 시간 보장.
GO_SETTLE_MS          = 0      # ms. 0 = 비활성화 (기본값, JTAG/정상 SWD 환경).
                               # SWD + 1.8V 레벨시프터 등 불안정 환경에서 NVMe 타임아웃 발생 시
                               # --go-settle 50 등으로 올려서 시도.
MAX_SAMPLES_PER_RUN   = 500   # NVMe 커맨드 1회당 최대 샘플 수 (상한)
SATURATION_LIMIT      = 10    # idle 유니버스 연속 카운터: idle_pcs 내 PC가 N회 연속이면 조기 종료.
                               # diagnose()에서 수렴 수집한 idle 유니버스 기반 → JTAG/SWD 공통 동작.
GLOBAL_SATURATION_LIMIT = 20  # 연속 N회 새 global PC 없으면 조기 종료 (global_coverage 기준).
POST_CMD_DELAY_MS     = 0     # 커맨드 완료 후 tail 샘플링 (ms)

# v4.6: NVMe passthru 명령 자체의 timeout (nvme-cli --timeout 인자)
# subprocess 감지 timeout(NVME_TIMEOUTS)과 분리.
# 정상 실행에서는 SSD가 ms~초 단위로 응답하므로 이 값은 무관.
# crash 시: subprocess 감지 timeout(~10초)이 먼저 발동 → kill → D state.
#           이 값이 길면 커널이 NVMe 명령을 포기하지 않아 controller reset을 하지 않음.
#           → SSD 펌웨어 crash 상태 보존 (JTAG 분석 용이).
NVME_PASSTHRU_TIMEOUT_MS = 2_592_000_000  # 30일 (커널 reset 방지, u32 max ~49.7일)

# 퍼저 시작 시 nvme_core 모듈 파라미터로 설정할 타임아웃 (초)
# crash 발생 시 이 시간이 지나야 커널이 controller reset을 시작한다.
# 기본값: admin_timeout=60s, io_timeout=30s → 펌웨어 crash 후 ~60초면 reset됨.
# 이 값을 크게 설정하면 crash 상태가 장기간 보존되어 JTAG 분석 가능.
# 적용 대상: 설정 이후 새로 제출되는 NVMe 명령 (기존 in-flight AER 제외)
NVME_KERNEL_TIMEOUT_SEC = 2_592_000  # 30일 (30 * 24 * 3600)

# 퍼징 설정
MAX_INPUT_LEN     = 131072    # 최대 입력 바이트 (128KB = 256 blocks, Write 대용량 시드 지원)
TOTAL_RUNTIME_SEC = 604_800   # 총 퍼징 시간 (초) — 1주일
OUTPUT_DIR        = f'./output/pc_sampling_v{FUZZER_VERSION}/'
SEED_DIR          = None      # 시드 폴더 경로 (없으면 None)
RESUME_COVERAGE   = None      # 이전 coverage.txt 경로 (없으면 None)

# v5.0: 펌웨어 바이너리 파일명 (FWDownload 시드 생성용)
# .py 파일과 같은 디렉토리에 있는 파일명만 입력하세요.
# 예: FW_BIN_FILENAME = 'FW.bin'
# None 또는 파일이 없으면 더미 1KB zeros 시드로 대체됩니다.
FW_BIN_FILENAME   = None
_FW_BIN_PATH = (
    str(Path(__file__).parent / FW_BIN_FILENAME)
    if FW_BIN_FILENAME else None
)

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

# v5.1: PM 로테이션 설정 (--pm 플래그로 활성화)
PM_ROTATE_INTERVAL = 100   # 이 횟수마다 PS 상태 전환 (PS0→PS1→PS2→PS3→PS4→PS0...)
# PS별 subprocess 감지 timeout 배수 (PS1/PS2는 응답 지연 허용)
PS_TIMEOUT_MULT    = {0: 1, 1: 16, 2: 32, 3: 1, 4: 1}

# v4.7: Idle 유니버스 수집 (diagnose 수렴 설정)
# SWD에서 WFI wake로 주기적 인터럽트 핸들러까지 idle_pcs에 포함되도록
# 새 PC가 N회 연속 나오지 않을 때까지 충분히 샘플링한다.
DIAGNOSE_STABILITY = 100   # 새 idle PC 없이 연속 N회면 수렴으로 판정
DIAGNOSE_MAX       = 5000  # 수렴 전 최대 샘플 수 (상한)

# v4.5: Calibration 설정
CALIBRATION_RUNS  = 3      # 초기 시드당 calibration 실행 횟수 (0 = 비활성화)

# v4.5: Deterministic stage 설정
DETERMINISTIC_ENABLED = True
DETERMINISTIC_ARITH_MAX = 10  # 결정론적 단계 arithmetic 최대 delta

# v4.5: MOpt (mutation operator scheduling) 설정
MOPT_ENABLED      = True
MOPT_PILOT_PERIOD = 5000   # pilot 단계 실행 횟수
MOPT_CORE_PERIOD  = 50000  # core 단계 실행 횟수

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
    # ── v5.1: 즉시 추가 명령어 ──
    NVMeCommand("WriteZeroes", 0x08, NVMeCommandType.IO, needs_data=False,
                description="LBA 범위를 0으로 기록 (DMA 없음, DEAC 지원)"),
    NVMeCommand("Compare", 0x05, NVMeCommandType.IO,
                description="LBA 읽기 후 호스트 버퍼와 비교 (miscompare → error)"),
    NVMeCommand("WriteUncorrectable", 0x04, NVMeCommandType.IO, needs_data=False,
                description="LBA를 uncorrectable 상태로 마킹 (에러 주입)"),
    NVMeCommand("Verify", 0x0C, NVMeCommandType.IO, needs_data=False,
                description="LBA 읽기 후 CRC/PI 검증 (데이터 반환 없음)"),
    NVMeCommand("DeviceSelfTest", 0x14, NVMeCommandType.ADMIN, needs_data=False,
                needs_namespace=False, timeout_group="selftest",
                description="자가 진단 시작/중단 (백그라운드 실행, 즉시 반환)"),
    NVMeCommand("SecuritySend", 0x81, NVMeCommandType.ADMIN,
                needs_namespace=False, timeout_group="security",
                description="보안 프로토콜 전송 (TCG/OPAL/IEEE1667)"),
    NVMeCommand("SecurityReceive", 0x82, NVMeCommandType.ADMIN, needs_data=False,
                needs_namespace=False, timeout_group="security",
                description="보안 프로토콜 수신 (TCG/OPAL/IEEE1667)"),
    NVMeCommand("GetLBAStatus", 0x86, NVMeCommandType.ADMIN, needs_data=False,
                description="LBA 범위별 할당/미할당 상태 조회"),
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
    new_pcs: int = 0             # 발견한 새 unique PC 수 (primary coverage signal)
    energy: float = 1.0          # 계산된 에너지
    covered_pcs: Optional[set] = None   # 이 시드 실행 시 방문된 PC 주소 집합 (culling용)
    is_favored: bool = False     # v4.3: corpus culling에서 선정된 favored seed
    # v4.5: Calibration
    is_calibrated: bool = False  # calibration 완료 여부
    stability: float = 1.0      # 0.0~1.0, PC 안정성 비율
    stable_pcs: Optional[set] = None    # calibration에서 과반수 실행에 등장한 PC 주소
    # v4.5: Deterministic stage
    det_done: bool = False       # deterministic stage 완료 여부


@dataclass
class FuzzConfig:
    device_name: str = JLINK_DEVICE
    interface: Optional[int] = None  # None=auto(JTAG→SWD), 또는 JLinkInterfaces.JTAG/SWD
    jtag_speed: int = JLINK_SPEED
    pc_reg_index: Optional[int] = None  # None = auto-detect, 정수 = 강제 지정

    nvme_device: str = NVME_DEVICE
    nvme_namespace: int = NVME_NAMESPACE
    nvme_timeouts: dict = field(default_factory=lambda: NVME_TIMEOUTS.copy())

    enabled_commands: List[str] = field(default_factory=list)
    all_commands: bool = False   # True면 위험(파괴적) 명령어 포함 전체 활성화

    # 샘플링 설정
    sample_interval_us: int = SAMPLE_INTERVAL_US
    go_settle_ms: int = GO_SETTLE_MS  # Go() 후 CPU 최소 실행 보장 (ms). 0 = 비활성화
    max_samples_per_run: int = MAX_SAMPLES_PER_RUN
    saturation_limit: int = SATURATION_LIMIT

    # v4.3: 글로벌 포화 임계값 (이전 v4.2에서는 하드코딩 20)
    global_saturation_limit: int = GLOBAL_SATURATION_LIMIT

    # NVMe 커맨드 완료 후 추가 샘플링 시간 (ms)
    post_cmd_delay_ms: int = POST_CMD_DELAY_MS

    # v4.6: nvme-cli --timeout (커널 reset 방지용, subprocess 감지 timeout과 분리)
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

    # v4.7: Idle 유니버스 수렴 설정
    diagnose_stability: int = DIAGNOSE_STABILITY  # 새 idle PC 없이 연속 N회면 수렴
    diagnose_max: int = DIAGNOSE_MAX              # 수렴 전 최대 샘플 수

    # v4.5: Calibration
    calibration_runs: int = CALIBRATION_RUNS

    # v4.5: Deterministic stage
    deterministic_enabled: bool = DETERMINISTIC_ENABLED
    deterministic_arith_max: int = DETERMINISTIC_ARITH_MAX

    # v4.5: MOpt
    mopt_enabled: bool = MOPT_ENABLED
    mopt_pilot_period: int = MOPT_PILOT_PERIOD
    mopt_core_period: int = MOPT_CORE_PERIOD

    # v4.5+: Corpus 하드 상한 (0 = 무제한)
    max_corpus_hard_limit: int = MAX_CORPUS_HARD_LIMIT

    # v4.7: FWDownload 실제 펌웨어 시드 지원
    fw_bin: Optional[str] = None        # 펌웨어 바이너리 경로 (없으면 더미 시드)
    fw_xfer_size: int = 32768           # FWDownload 청크 크기(바이트), nvme fw-download -x 와 동일
    fw_slot: int = 1                    # FWCommit 슬롯 번호

    # v5.1: PM 로테이션 활성화 플래그 (0.0=비활성화, 1.0=활성화 — --pm 플래그로 설정)
    pm_inject_prob: float = 0.0


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
    """J-Link Halt-Sample-Resume 기반 PC 수집기"""

    # v4.3: 샘플 간격 체크포인트 (frozenset으로 O(1) lookup 보장)
    _INTERVAL_CHECKPOINTS = frozenset({10, 25, 50, 100, 200, 500})

    def __init__(self, config: FuzzConfig):
        self.config = config
        self.jlink: Optional[pylink.JLink] = None
        self._pc_reg_index: int = 9  # Cortex-R8: R15(PC)의 J-Link 레지스터 인덱스

        # sentinel: 유효 주소 범위 밖의 값으로 초기화하여 가짜 edge 방지
        self.prev_pc: int = 0xFFFFFFFF

        # Primary coverage signal: unique PC 주소 (v4.5+)
        self.global_coverage: Set[int] = set()   # 전체 세션에서 관측된 unique PC 주소
        self.current_trace: Set[int] = set()     # 이번 실행에서 관측된 unique PC 주소

        self.stop_event = threading.Event()
        self.sample_thread: Optional[threading.Thread] = None
        self.total_samples = 0
        self.interesting_inputs = 0
        self._last_raw_pcs: List[int] = []
        self._out_of_range_count = 0
        self._last_new_pcs: set = set()   # evaluate_coverage()에서 노출 — 정적 분석 연동용

        # v4.2: idle PC — diagnose()에서 가장 빈도 높은 PC로 설정
        self.idle_pc: Optional[int] = None
        # v4.7: idle PC 집합 — SWD에서 WFI wake로 여러 주소가 관찰될 때 대응
        self.idle_pcs: Set[int] = set()

    def connect(self) -> bool:
        try:
            if self.jlink and self.jlink.opened():
                self.jlink.close()

            self.jlink = pylink.JLink()
            self.jlink.open()

            # 인터페이스 결정: None=auto(JTAG 먼저 시도 → 실패 시 SWD fallback)
            _JTAG = pylink.enums.JLinkInterfaces.JTAG
            _SWD  = pylink.enums.JLinkInterfaces.SWD
            _jtag_pc_idx: Optional[int] = None  # auto JTAG 검증 중 탐지된 PC 인덱스 캐시
            if self.config.interface is not None:
                # 명시적 지정: 그대로 사용
                self.jlink.set_tif(self.config.interface)
                self.jlink.connect(self.config.device_name, speed=self.config.jtag_speed)
                iface_name = "JTAG" if self.config.interface == _JTAG else "SWD"
            else:
                # auto: JTAG 먼저 시도 + 실제 CPU 응답 검증 후 SWD fallback
                # register_list()/register_name()은 J-Link 내부 DB를 읽으므로
                # CPU 비응답 상태에서도 성공한다. 따라서 halt() 후 halted() 상태로
                # 실제 CPU 통신 여부를 판별한다.
                try:
                    self.jlink.set_tif(_JTAG)
                    self.jlink.connect(self.config.device_name, speed=self.config.jtag_speed)
                    # 실제 CPU halt 응답으로 JTAG 연결 검증
                    self.jlink.halt()
                    _jtag_halted = False
                    for _ in range(20):
                        if self.jlink.halted():
                            _jtag_halted = True
                            break
                        time.sleep(0.005)
                    if not _jtag_halted:
                        raise Exception("JTAG halt 미응답 (100ms 초과) — SWD 전용 타깃으로 판단")
                    _jtag_pc_idx = self._probe_pc_register_index()
                    # ★ JTAG 검증 완료 후 즉시 resume.
                    # halt() 상태로 반환하면 connect() 이후 _log_smart() 등 NVMe
                    # 명령이 펌웨어를 못 받아 10초 타임아웃이 바로 발생한다.
                    # JLINKARM_Go() — jlink_reg_diag.py에서 실증된 resume 방식.
                    # ctypes 호출이므로 Python 예외 없음, 실패 시 JLINKARM_IsHalted로 확인.
                    self.jlink._dll.JLINKARM_Go()
                    if bool(self.jlink._dll.JLINKARM_IsHalted()):
                        raise Exception(
                            "JLINKARM_Go() 호출 후 CPU 여전히 halt — "
                            "JTAG CPU resume 불가, SWD fallback 시도"
                        )
                    log.warning("[J-Link] JTAG 검증용 halt 해제 — CPU resumed (Go OK).")
                    iface_name = "JTAG (auto)"
                except Exception as jtag_err:
                    log.warning(f"[J-Link] JTAG 연결/검증 실패 ({jtag_err}), SWD로 재시도...")
                    self.jlink.close()
                    self.jlink = pylink.JLink()
                    self.jlink.open()
                    self.jlink.set_tif(_SWD)
                    self.jlink.connect(self.config.device_name, speed=self.config.jtag_speed)
                    iface_name = "SWD (auto-fallback)"

            log.warning(f"[J-Link] Connected: {self.config.device_name} @ {self.config.jtag_speed}kHz [{iface_name}]")

            # R15(PC)의 실제 레지스터 인덱스 결정
            if self.config.pc_reg_index is not None:
                # 사용자가 --pc-reg-index로 강제 지정
                self._pc_reg_index = self.config.pc_reg_index
                log.warning(f"[J-Link] PC register index: {self._pc_reg_index} (--pc-reg-index 강제 지정)")
            elif _jtag_pc_idx is not None:
                # auto JTAG 검증 중 이미 탐지됨 → 재호출 불필요
                self._pc_reg_index = _jtag_pc_idx
                log.warning(f"[J-Link] PC register index: {self._pc_reg_index} "
                         f"(name: {self.jlink.register_name(self._pc_reg_index)}, JTAG auto)")
            else:
                # SWD fallback 또는 explicit interface 경로 → 여기서 탐색
                self._pc_reg_index = self._find_pc_register_index()
                log.warning(f"[J-Link] PC register index: {self._pc_reg_index} "
                         f"(name: {self.jlink.register_name(self._pc_reg_index)})")

            # DLL 함수 참조 캐싱 (pylink wrapper 우회, 매 호출 attribute lookup 제거)
            # DLL 함수 참조 캐싱 (pylink wrapper 우회, 매 호출 attribute lookup 제거)
            self._halt_func = self.jlink._dll.JLINKARM_Halt
            self._read_reg_func = self.jlink._dll.JLINKARM_ReadReg
            self._go_func = self.jlink._dll.JLINKARM_Go

            return True
        except Exception as e:
            log.error(f"[J-Link Error] {e}")
            return False

    def _probe_pc_register_index(self) -> int:
        """JTAG 연결 검증 겸 PC 레지스터 인덱스 탐색 (예외를 그대로 raise).

        _find_pc_register_index()와 동일한 로직이지만 예외를 삼키지 않는다.
        auto-detect 시 JTAG try 블록 안에서 호출해 register_name() 실패까지
        SWD fallback 트리거로 사용한다.
        연결 유효하지만 PC 이름을 못 찾으면 15를 반환 (예외 없음).
        """
        _PC_NAMES = {'R15', 'PC', 'EPC', 'MEPC', 'SEPC'}
        all_regs = list(self.jlink.register_list())   # 실패 시 그대로 raise
        for idx in all_regs:
            name = self.jlink.register_name(idx).upper().strip()  # 실패 시 그대로 raise
            if name in _PC_NAMES:
                return idx
        for idx in all_regs:
            name = self.jlink.register_name(idx).upper().strip()
            if 'R15' in name:
                return idx
        return 15  # 연결은 유효하나 이름 매칭 실패 → fallback

    def _find_pc_register_index(self) -> int:
        """register_list()에서 PC 레지스터의 실제 인덱스를 찾는다.

        아키텍처별 PC 레지스터 이름:
          ARM Cortex-R/A : R15, r15
          ARM Cortex-M   : PC, R15
          RISC-V         : PC, mepc, pc
          MIPS           : PC, EPC
        자동 탐색 실패 시 --pc-reg-index N 으로 수동 지정 가능.
        """
        _PC_NAMES = {'R15', 'PC', 'EPC', 'MEPC', 'SEPC'}
        try:
            all_regs = list(self.jlink.register_list())
            # 1단계: 이름이 정확히 PC 계열인 것
            for idx in all_regs:
                name = self.jlink.register_name(idx).upper().strip()
                if name in _PC_NAMES:
                    return idx
            # 2단계: 이름에 R15 포함 (e.g. "R15_USR", "ARM_R15")
            for idx in all_regs:
                name = self.jlink.register_name(idx).upper().strip()
                if 'R15' in name:
                    return idx
        except Exception as e:
            log.warning(f"[J-Link] register_list() 탐색 실패: {e}")
        log.warning("[J-Link] PC 레지스터를 자동으로 찾지 못했습니다. fallback=15 사용.")
        log.warning("[J-Link] 올바른 인덱스를 jlink_reg_diag.py 로 확인 후 --pc-reg-index N 으로 지정하세요.")
        return 15

    def diagnose(self, count: int = 20) -> bool:
        """시작 전 PC 읽기 진단 — J-Link 동작 검증 + idle 유니버스 수집 (v4.7)

        idle_pcs 구성 전략 (JTAG/SWD 공통):
          새 PC가 DIAGNOSE_STABILITY회 연속 나타나지 않을 때까지 샘플링 (최대 DIAGNOSE_MAX회).
          JTAG: WFI 고정 → 수십 샘플에 수렴.
          SWD:  WFI wake로 주기적 인터럽트 핸들러까지 포함 → 더 많은 샘플 필요.
          수집된 idle_pcs = "idle 유니버스" — 퍼징 중 이 집합 밖 PC가 나오면 active 실행 중.
        """
        stability = self.config.diagnose_stability
        max_samples = self.config.diagnose_max

        log.warning(f"[Diagnose] idle 유니버스 수집 시작 "
                    f"(수렴 조건: 새 PC 없이 {stability}회 연속, 최대 {max_samples}회)...")

        # 1단계: 초기 20회 — 기본 동작 검증 및 로그 출력
        initial = min(count, 20)
        pcs_initial = []
        failures = 0
        for i in range(initial):
            pc = self._read_pc()
            if pc is not None:
                pcs_initial.append(pc)
                in_range = ""
                if self.config.addr_range_start is not None and self.config.addr_range_end is not None:
                    in_range = (" [IN RANGE]"
                                if self.config.addr_range_start <= pc <= self.config.addr_range_end
                                else " [OUT OF RANGE]")
                log.warning(f"  [{i+1:2d}] PC = {hex(pc)}{in_range}")
            else:
                failures += 1
                log.warning(f"  [{i+1:2d}] PC read FAILED")
            time.sleep(0.05)

        if not pcs_initial:
            log.error("[Diagnose] PC를 한 번도 읽지 못했습니다. JTAG 연결을 확인하세요.")
            return False

        # 2단계: 수렴 기반 adaptive 샘플링 — idle 유니버스 완성
        idle_universe: Set[int] = set(pcs_initial)
        consecutive_no_new = 0
        total = len(pcs_initial)

        log.warning(f"[Diagnose] 초기 {initial}회 완료, unique PCs={len(idle_universe)}. "
                    f"idle 유니버스 수렴 샘플링 시작...")

        consecutive_failures = 0
        while consecutive_no_new < stability and total < max_samples:
            pc = self._read_pc()
            total += 1
            if pc is not None and pc not in idle_universe:
                # 새 PC 발견 → 카운터 리셋
                idle_universe.add(pc)
                consecutive_no_new = 0
                consecutive_failures = 0
                log.warning(f"  [+{total:4d}] 새 idle PC: {hex(pc)} "
                            f"(누적 {len(idle_universe)}개)")
            else:
                # 기존 PC 재등장 또는 read 실패 → 수렴 카운터 증가
                consecutive_no_new += 1
                if pc is None:
                    consecutive_failures += 1
                    if consecutive_failures % 10 == 0:
                        log.warning(f"[Diagnose] J-Link read 연속 실패 {consecutive_failures}회 "
                                    f"— 연결 불안정 또는 CPU halt 방치 가능성")
                else:
                    consecutive_failures = 0
            # NVMe 보호: 5ms(이전)는 너무 짧아 펌웨어가 NVMe 큐 처리를 완료하기 전에
            # 다시 halt되어 컨트롤러가 불안정해진다.
            # 50ms: 펌웨어가 pending 인터럽트·AER·완료큐 처리 후 WFI로 돌아갈 시간 확보.
            # diagnose 총 시간: ~200샘플 × 50ms ≈ 10초 (허용 범위)
            time.sleep(0.05)

        if consecutive_no_new >= stability:
            log.warning(f"[Diagnose] idle 유니버스 수렴 완료: "
                        f"{len(idle_universe)}개 PC, {total}회 샘플 "
                        f"(새 PC 없이 {consecutive_no_new}회 연속)")
        else:
            log.warning(f"[Diagnose] 최대 샘플({max_samples}회) 도달. "
                        f"idle 유니버스 {len(idle_universe)}개 (수렴 미완료, 이대로 사용)")

        # idle_pcs = 수집된 전체 idle 유니버스 (범위 필터 없음)
        # addr_range 필터는 커버리지 추적(global_coverage, current_trace)에만 적용.
        # idle 감지용 idle_pcs는 out-of-range PC(RTOS 스케줄러, 인터럽트 핸들러 등)도
        # 포함해야 consecutive_idle 카운터가 리셋되지 않고 정상 동작함.
        self.idle_pcs = set(idle_universe)

        from collections import Counter
        pc_counts = Counter(pcs_initial)
        self.idle_pc = pc_counts.most_common(1)[0][0]  # 대표값 (로그/호환성)

        log.warning(f"[Diagnose] idle_pcs = {len(self.idle_pcs)}개 "
                    f"(범위 내), 대표 PC = {hex(self.idle_pc)}")

        # 샘플링 루프 종료 후 CPU가 running 상태임을 보장한다.
        self._ensure_running()
        return True

    def _ensure_running(self, settle_ms: int = 100) -> None:
        """샘플링 루프 후 CPU가 running 상태임을 보장한다."""
        ok = self._go_with_retry()
        if not ok:
            log.warning("[J-Link] _ensure_running: Go() 재시도 후에도 CPU halted 상태")

    def _go_with_retry(self, max_attempts: int = 5, retry_delay_s: float = 0.05) -> bool:
        """JLINKARM_Go() 재시도 래퍼.

        JLINKARM_Go()는 실패해도 Python exception을 발생시키지 않고 음수를 반환한다.
        "Could not start CPU core. (ErrorCode: -1)" 메시지는 J-Link DLL이 stderr에 직접
        출력하며, Python 레이어에서는 반환값을 확인해야만 감지 가능하다.

        NVMe DMA 처리 중 CPU 클럭 게이팅 등으로 Go()가 일시적으로 실패할 수 있으므로
        실패 시에만 짧은 대기 후 재시도한다. 성공 시 즉시 반환하여 오버헤드 최소화.
        """
        for attempt in range(max_attempts):
            ret = self._go_func()   # 0 = 성공, 음수 = 실패 (exception 없음)
            if ret == 0:
                return True         # 성공 시 즉시 반환 — sleep 없음
            # 실패 시에만 대기 후 재시도
            log.debug(f"[J-Link] Go() 재시도 {attempt + 1}/{max_attempts} (ret={ret})")
            time.sleep(retry_delay_s)
        log.warning(f"[J-Link] Go() {max_attempts}회 재시도 후에도 CPU halt 상태")
        return False

    def _read_pc(self) -> Optional[int]:
        try:
            self._halt_func()
            pc = self._read_reg_func(self._pc_reg_index)
            return pc
        except Exception:
            return None
        finally:
            self._go_with_retry()

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
        """PC 주소 기반 글로벌 포화 체크 + prev_pc 실행 간 리셋.

        global_coverage_ref(unique PC set) 기반 포화 판단:
        새 코드 경로를 실행해야만 새 PC가 나타나므로 올바른 포화 신호.
        primary coverage signal과 일치.
        """
        self.current_trace = set()
        self._last_raw_pcs = []
        self._out_of_range_count = 0
        self._last_new_at = 0
        self._unique_at_intervals = {}
        self._stopped_reason = ""

        sample_count = 0
        since_last_global_new = 0   # 연속 "이미 알려진 PC" 카운터 (global 기준)
        consecutive_idle = 0         # idle 유니버스 연속 카운터
        interval = self.config.sample_interval_us / 1_000_000
        # GO_SETTLE_MS: Go() 후 CPU에 최소 실행 시간 보장 (SWD+레벨시프터 NVMe 안정성).
        # SAMPLE_INTERVAL_US(샘플 밀도 제어)와 독립적. 둘 중 큰 값이 실제 sleep.
        settle_s  = self.config.go_settle_ms / 1_000.0
        effective_interval = max(interval, settle_s)
        sat_limit = self.config.saturation_limit
        global_sat_limit = self.config.global_saturation_limit  # v4.3: 설정값 사용
        idle_pcs = self.idle_pcs     # idle 유니버스 (diagnose에서 수렴 수집)

        # global_coverage(PC 주소 set) 참조 캐싱
        # CPython set.__contains__는 GIL 하에서 안전
        global_coverage_ref = self.global_coverage

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
                        self.current_trace.add(pc)
                        prev_pc = pc

                    # v4.5+: PC 기반 글로벌 포화 판단
                    if pc not in global_coverage_ref:
                        self._last_new_at = sample_count
                        since_last_global_new = 0
                    else:
                        since_last_global_new += 1

                    # v4.7: idle 유니버스 기반 연속 카운터
                    # diagnose()에서 수렴 수집한 idle_pcs = idle 상태에서 나올 수 있는 모든 PC.
                    # NVMe 커맨드 처리 코드는 idle 유니버스 밖 → 처리 중엔 consecutive_idle 리셋.
                    # idle 복귀 후 유니버스 내 PC만 연속 → sat_limit 도달 → 조기종료.
                    if idle_pcs and pc in idle_pcs:
                        consecutive_idle += 1
                    else:
                        consecutive_idle = 0
                else:
                    self._out_of_range_count += 1
                    consecutive_idle = 0  # out-of-range는 idle로 보지 않음

                sample_count += 1
                self.total_samples += 1

                if sample_count in self._INTERVAL_CHECKPOINTS:
                    # v4.5+: PC 기준으로 변경 (기존 edge 기준에서 전환)
                    self._unique_at_intervals[sample_count] = len(self.current_trace)

                # 조기 종료 조건 (OR)
                # 조건1: 연속 global_sat_limit회 이미 알려진 PC (새 코드 경로 없음, global 기준)
                # 조건2: 연속 sat_limit회 idle 유니버스 내 PC (idle 복귀 감지)
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

            if effective_interval > 0:
                time.sleep(effective_interval)

        if not self._stopped_reason:
            if self.stop_event.is_set():
                self._stopped_reason = "stop_event"
            else:
                self._stopped_reason = f"max_samples ({self.config.max_samples_per_run})"

        # v4.3: prev_pc를 인스턴스에 저장하지 않음 (매 실행 독립)
        # 이전 v4.2에서는 self.prev_pc = prev_pc 로 캐리오버했으나,
        # 서로 다른 명령어 간의 가짜 edge를 방지하기 위해 제거

    def start_sampling(self):
        # 이미 샘플링 중이면 스킵 (PM 구간에서 먼저 시작한 경우 중복 방지)
        if self.sample_thread and self.sample_thread.is_alive():
            return
        self.stop_event.clear()
        self.sample_thread = threading.Thread(target=self._sampling_worker, daemon=True)
        self.sample_thread.start()

    def stop_sampling(self) -> int:
        """샘플링 종료 후 이번 실행에서 관측된 unique PC 수를 반환 (primary signal).

        current_trace: unique PC 주소 set — 결정론적, primary coverage signal.
        last_run 로그값이 PC 수를 나타내므로 global_pcs와 직접 비교 가능.
        """
        if self.sample_thread:
            self.stop_event.set()
            self.sample_thread.join(timeout=2.0)
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
        pc_path = os.path.join(output_dir, 'coverage.txt')
        with open(pc_path, 'w') as f:
            for pc in sorted(self.global_coverage):
                f.write(f"{hex(pc)}\n")

        log.info(f"[Coverage] Saved {len(self.global_coverage)} PCs → {pc_path}")

    def close(self):
        self.stop_event.set()
        if self.sample_thread:
            self.sample_thread.join(timeout=1.0)
        if self.jlink:
            # 종료 전 CPU resume 보장 — halt 상태로 J-Link를 닫으면
            # SSD 펌웨어가 영구 정지 상태로 남는다.
            if self._go_func is not None:
                try:
                    self._go_with_retry(max_attempts=3, retry_delay_s=0.05)
                except Exception:
                    pass
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
        # v5.1: PM 로테이션 상태
        self._current_ps: int = 0                              # 현재 PS 상태
        # _ps_cmd_counter 제거 — PM 전환을 executions % 100 경계에서 처리
        # _ps_idx 제거 — 랜덤 전환으로 변경
        self.ps_exec_counts: dict[int, int] = {i: 0 for i in range(5)}  # PS별 실행 횟수
        self.ps_enter_counts: dict[int, int] = {i: 0 for i in range(5)} # PS별 진입 횟수

        # v5.1: 정적 분석 연동 (Ghidra export — code_addrs.txt / functions.txt)
        self._sa_loaded: bool = False
        self._sa_code_addrs: Optional[frozenset] = None
        self._sa_total_code: int = 0
        self._sa_func_entries: Optional[list] = None  # sorted by entry, bisect용
        self._sa_func_ends: Optional[list] = None
        self._sa_func_names: Optional[list] = None
        self._sa_total_funcs: int = 0
        self._sa_covered_addrs: int = 0       # 커버된 알려진 명령어 주소 수
        self._sa_entered_funcs: set = set()   # 진입한 함수 entry point 집합
        self._sa_thumb_mask: bool = False     # True면 PC & ~1 로 비교 (Thumb bit 자동 보정)
        self._sa_diag_done: bool = False      # 첫 update 진단 출력 완료 여부
        # 성장 곡선 이력: [(executions, elapsed_s, code_pct, funcs_pct), ...]
        self._sa_cov_history: list = []
        self._load_static_analysis()

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
        # v4.6: crash 시 보존된 nvme-cli PID (kill하지 않아 fd 유지 → SSD 상태 보존)
        self._crash_nvme_pid: Optional[int] = None
        # nvme_core 모듈 파라미터 원래 값 (종료 시 복원용)
        self._nvme_timeout_originals: dict = {}

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

        # 명령어별 PC/trace 추적 (그래프 시각화용)
        # v4.3: defaultdict로 변경 — opcode_override 등 mutation별 키 자동 생성
        self.cmd_pcs: dict[str, Set[int]] = defaultdict(set)
        # v4.3: deque로 교체 (pop(0) O(n) → popleft O(1))
        self.cmd_traces: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        # 기본 명령어 키 초기화
        for c in self.commands:
            self.cmd_pcs[c.name] = set()
            self.cmd_traces[c.name] = deque(maxlen=200)

        # v4.2: subprocess 입력 파일 경로 (재사용)
        self._nvme_input_path: Optional[str] = None

        # v5.1: 재현 TC용 명령 히스토리 (최근 100개, PM 포함)
        self._cmd_history: deque = deque(maxlen=100)

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

        for run_i in range(total_runs):
            # _send_nvme_command() 내부에서 start_sampling()을 호출하므로
            # 여기서 별도로 start_sampling()을 호출하면 두 개의 sampling thread가
            # 동시에 실행되어 zombie thread가 누적된다.
            rc = self._send_nvme_command(seed.data, seed)
            self.sampler.stop_sampling()
            self.executions += 1
            actual_runs += 1

            for pc in self.sampler.current_trace:
                pc_appearances[pc] = pc_appearances.get(pc, 0) + 1

            if rc == self.RC_TIMEOUT:
                log.error(f"[Calibration] {seed.cmd.name} timeout at run {run_i+1} — treating as crash")
                self._handle_timeout_crash(seed, seed.data)
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

    def _setup_directories(self):
        self.crashes_dir.mkdir(parents=True, exist_ok=True)

    def _generate_default_seeds(self) -> List[Seed]:
        """각 Opcode별 NVMe 스펙 기반 정상 명령어를 초기 시드로 생성"""
        seeds: List[Seed] = []

        # 명령어별 정상 파라미터 템플릿
        # CDW12 Protection/Access 비트 (NVMe 2.0 기준):
        #   [25]    DEAC  — WriteZeroes: deallocate after zeroing
        #   [26]    PRCHK[2] — Guard field check
        #   [27]    PRCHK[1] — Application Tag check
        #   [28]    PRCHK[0] — Reference Tag check
        #   [29]    PRACT  — Protection Info Action (insert/strip)
        #   [30]    LR     — Limited Retry
        #   [31]    FUA    — Force Unit Access
        # CDW13[15:0] = DSPEC — Directive Specific (Streams: Stream ID)
        # CDW14[31:0] = ILBRT — Initial Logical Block Reference Tag (E2E PI)
        # CDW15[15:0] = LBAT  — Logical Block Application Tag (E2E PI)
        # CDW15[31:16]= LBATM — LB Application Tag Mask (E2E PI)
        _FUA  = 1 << 31
        _LR   = 1 << 30
        _PRACT = 1 << 29
        _PRCHK_ALL = (1 << 26) | (1 << 27) | (1 << 28)  # 3-bit PRCHK 전체 set
        _PRINFO_ALL = _PRACT | _PRCHK_ALL                 # PRACT + PRCHK 전체
        _DEAC = 1 << 25                                   # WriteZeroes deallocate

        SEED_TEMPLATES: dict[str, list] = {
            # ================================================================
            # Identify — CDW10[7:0]=CNS, CDW10[31:16]=CNTID
            # ================================================================
            "Identify": [
                # CNS=0x01(Controller): NSID는 Reserved → nsid_override=0
                dict(cdw10=0x0001, nsid_override=0,           description="Identify Controller"),
                dict(cdw10=0x0000,                            description="Identify Namespace (NSID=1)"),
                dict(cdw10=0x0002, nsid_override=0,           description="Active NS ID list"),
                dict(cdw10=0x0003,                            description="NS Identification Descriptor list"),
                dict(cdw10=0x0004,                            description="Allocated NS ID List (incl. deleted)"),
                dict(cdw10=0x0005,                            description="I/O Command Set specific Identify NS"),
                dict(cdw10=0x0006, nsid_override=0,           description="Identify Primary Controller Capabilities"),
                dict(cdw10=0x0007, nsid_override=0,           description="Secondary Controller list"),
                dict(cdw10=0x0008, nsid_override=0,           description="Namespace Granularity List"),
                dict(cdw10=0x0009, nsid_override=0,           description="UUID List"),
                dict(cdw10=0x001C,                            description="I/O Cmd Set Allocated NS ID list"),
                dict(cdw10=0x001D,                            description="I/O Cmd Set Namespace ID Descriptor"),
                # CNTID 필드 포함 (CNS=0x06/0x07에서 특정 컨트롤러 조회)
                dict(cdw10=(0x0001 << 16) | 0x0006, nsid_override=0, description="Primary Ctrl Cap CNTID=1"),
                # 미지원 CNS — 에러 경로 탐색
                dict(cdw10=0x00FF, nsid_override=0,           description="CNS=0xFF (undefined, error path)"),
            ],

            # ================================================================
            # GetLogPage — CDW10[7:0]=LID, CDW10[26:16]=NUMDL, CDW10[15]=RAE
            #              CDW10[12:8]=LSP, CDW11[15:0]=NUMDH
            #              CDW12=LPOL (Log Page Offset Lower dword)
            #              CDW13=LPOU (Log Page Offset Upper dword)
            # ================================================================
            "GetLogPage": [
                # ── Mandatory (NVMe 2.0 §5.14) ──
                dict(cdw10=(0x0F << 16) | 0x01, nsid_override=0, description="Error Information Log (64B)"),
                dict(cdw10=(0x7F << 16) | 0x02, nsid_override=0, description="SMART / Health Log (512B)"),
                dict(cdw10=(0x0F << 16) | 0x03, nsid_override=0, description="Firmware Slot Information (64B)"),
                dict(cdw10=(0xFF << 16) | 0x04, nsid_override=0xFFFFFFFF, description="Changed NS List (4KB, NSID=broadcast)"),
                dict(cdw10=(0xFF << 16) | 0x05, nsid_override=0, description="Commands Supported and Effects (4KB)"),
                dict(cdw10=(0x8F << 16) | 0x06, nsid_override=0, description="Device Self-test Log (564B)"),
                dict(cdw10=(0x1FF << 16) | 0x07, nsid_override=0, description="Telemetry Host-Initiated (CDW10[8]=Create)"),
                dict(cdw10=(0x1FF << 16) | 0x08, nsid_override=0, description="Telemetry Controller-Initiated"),
                # ── Optional ──
                dict(cdw10=(0x7F << 16) | 0x09,                  description="Endurance Group Information (512B)"),
                dict(cdw10=(0x1FF << 16) | 0x0A, nsid_override=0, description="Predictive Failure Analysis"),
                dict(cdw10=(0x7F << 16) | 0x0B,                  description="Asymmetric Namespace Access (ANA)"),
                dict(cdw10=(0xFFF << 16) | 0x0C, nsid_override=0, description="Persistent Event Log (header 512B)"),
                dict(cdw10=(0xFF << 16) | 0x0D, nsid_override=0, description="Endurance Group Event Aggregate"),
                dict(cdw10=(0xFF << 16) | 0x0E, nsid_override=0, description="Media Unit Status"),
                dict(cdw10=(0xFF << 16) | 0x0F, nsid_override=0, description="Supported Capacity Config List"),
                dict(cdw10=(0xFF << 16) | 0x10, nsid_override=0, description="Feature Identifiers Supported & Effects (4KB)"),
                dict(cdw10=(0xFF << 16) | 0x11, nsid_override=0, description="NVMe-MI Commands Supported & Effects"),
                dict(cdw10=(0xFF << 16) | 0x12, nsid_override=0, description="Command and Feature Lockdown Log"),
                dict(cdw10=(0x1FF << 16) | 0x13, nsid_override=0, description="Boot Partition Log"),
                dict(cdw10=(0xFF << 16) | 0x70, nsid_override=0, description="Discovery Log (Fabrics, error path expected)"),
                dict(cdw10=(0xFF << 16) | 0x80,                  description="Reservation Notification Log"),
                dict(cdw10=(0xFF << 16) | 0x81, nsid_override=0, description="Sanitize Status Log"),
                # ── RAE=1 (Retain Async Event) 변형 ──
                dict(cdw10=(0x7F << 16) | (1 << 15) | 0x02, nsid_override=0,
                     description="SMART Log RAE=1 (CDW10[15]=1, retain async event)"),
                # ── LPOL 오프셋 (CDW12) ── 큰 로그의 중간부터 읽기
                dict(cdw10=(0x7F << 16) | 0x02, cdw12=0x200, nsid_override=0,
                     description="SMART Log LPOL=0x200 (middle offset)"),
                # ── NUMDH (CDW11[15:0]) — 4GB 초과 로그 ──
                dict(cdw10=(0xFFF << 16) | 0x0C, cdw11=0x0001, nsid_override=0,
                     description="Persistent Event Log NUMDH=1 (large request)"),
                # ── 미지원 LID — 에러 핸들러 경로 ──
                dict(cdw10=(0xFF << 16) | 0xFF, nsid_override=0, description="LID=0xFF (undefined, error path)"),
            ],

            # ================================================================
            # GetFeatures — CDW10[7:0]=FID, CDW10[9:8]=SEL (current/default/saved/supported)
            # ================================================================
            "GetFeatures": [
                dict(cdw10=0x01, description="Arbitration (burst size, priority weight)"),
                dict(cdw10=0x02, description="Power Management (power state)"),
                dict(cdw10=0x03, description="LBA Range Type"),
                dict(cdw10=0x04, description="Temperature Threshold (TMPTH, TMPSEL, THSEL)"),
                dict(cdw10=0x05, description="Error Recovery (DULBE, TLER)"),
                dict(cdw10=0x06, description="Volatile Write Cache"),
                dict(cdw10=0x07, description="Number of Queues"),
                dict(cdw10=0x08, description="Interrupt Coalescing"),
                dict(cdw10=0x09, description="Interrupt Vector Configuration"),
                dict(cdw10=0x0A, description="Write Atomicity Normal"),
                dict(cdw10=0x0B, description="Async Event Configuration"),
                dict(cdw10=0x0C, description="Autonomous Power State Transition"),
                dict(cdw10=0x0D, description="Host Memory Buffer"),
                dict(cdw10=0x0E, description="Timestamp"),
                dict(cdw10=0x0F, description="Keep Alive Timer"),
                dict(cdw10=0x10, description="Host Controlled Thermal Management"),
                dict(cdw10=0x11, description="Non-Operational Power State Config"),
                dict(cdw10=0x12, description="Read Recovery Level Config"),
                dict(cdw10=0x7E, description="Host Identifier (128-bit)"),
                dict(cdw10=0x7F, description="Reservation Notification Mask"),
                dict(cdw10=0x80, description="Reservation Persistence"),
                # SEL=1 (default value) 변형
                dict(cdw10=(1 << 8) | 0x06, description="Volatile Write Cache SEL=default"),
                dict(cdw10=(1 << 8) | 0x02, description="Power Management SEL=default"),
                # SEL=2 (saved) 변형
                dict(cdw10=(2 << 8) | 0x06, description="Volatile Write Cache SEL=saved"),
                # SEL=3 (supported capabilities) 변형
                dict(cdw10=(3 << 8) | 0x06, description="Volatile Write Cache SEL=capabilities"),
                # 미지원 FID — 에러 경로
                dict(cdw10=0xFF, description="FID=0xFF (undefined, error path)"),
            ],

            # ================================================================
            # SetFeatures — CDW10[7:0]=FID, CDW10[31]=SV (Save), CDW11=dword value
            # ================================================================
            "SetFeatures": [
                # FID=0x01: Arbitration — CDW11[2:0]=AB(High Priority Burst), [8:3]=HPW, [15:8]=MPW, [23:16]=LPW
                dict(cdw10=0x01, cdw11=0x00000003, description="Set Arbitration (burst=8, default priority)"),
                # FID=0x02: Power Management — CDW11[4:0]=PS (Power State)
                dict(cdw10=0x02, cdw11=0x00000000, description="Set Power State 0 (max performance)"),
                dict(cdw10=0x02, cdw11=0x00000004, description="Set Power State 4 (low power)"),
                # FID=0x04: Temperature Threshold — CDW11[15:0]=TMPTH(Kelvin), [19:16]=TMPSEL, [20]=THSEL
                dict(cdw10=0x04, cdw11=0x0000012C, description="Set Temp Threshold 300K composite (TMPSEL=0)"),
                dict(cdw10=0x04, cdw11=0x00010050, description="Set Temp Threshold 80K (unrealistically low, error path)"),
                dict(cdw10=0x04, cdw11=0x000107FF, description="Set Temp Threshold max (0x7FF K, TMPSEL=1 sensor1)"),
                # FID=0x05: Error Recovery — CDW11[15:0]=TLER(ms), CDW11[16]=DULBE
                dict(cdw10=0x05, cdw11=0x00000000, description="Set Error Recovery TLER=0 DULBE=0"),
                dict(cdw10=0x05, cdw11=0x00010064, description="Set Error Recovery TLER=100ms DULBE=1"),
                # FID=0x06: Volatile Write Cache — CDW11[0]=WCE (Write Cache Enable)
                dict(cdw10=0x06, cdw11=0x00000001, description="Set VWC=Enable"),
                dict(cdw10=0x06, cdw11=0x00000000, description="Set VWC=Disable"),
                # FID=0x07: Number of Queues (기존 유지)
                dict(cdw10=0x07, cdw11=0x00010001, description="Set Number of Queues (1 SQ + 1 CQ)"),
                # FID=0x08: Interrupt Coalescing — CDW11[7:0]=THR, CDW11[15:8]=TIME(100us)
                dict(cdw10=0x08, cdw11=0x00000000, description="Set Interrupt Coalescing disabled"),
                dict(cdw10=0x08, cdw11=0x00000A04, description="Set Interrupt Coalescing THR=4 TIME=10"),
                # FID=0x0B: Async Event Configuration — CDW11[0]=SMART Critical Warning
                dict(cdw10=0x0B, cdw11=0x00000000, description="Set AEC all disabled"),
                dict(cdw10=0x0B, cdw11=0x000000FF, description="Set AEC all enabled"),
                # FID=0x0E: Timestamp — CDW11+CDW12 = 48-bit timestamp (ms since epoch)
                dict(cdw10=0x0E, cdw11=0x00000000, description="Set Timestamp = 0 (reset)"),
                # FID=0x10: Host Controlled Thermal Management — CDW11[0]=TMT2EN, CDW11[1]=TMT1EN
                dict(cdw10=0x10, cdw11=0x00000003, description="Set HCTM both thresholds enabled"),
                # SV=1 변형 (설정값 저장)
                dict(cdw10=(1 << 31) | 0x06, cdw11=0x00000001, description="Set VWC=Enable + Save"),
            ],

            # ================================================================
            # Read — CDW10=SLBA[31:0], CDW11=SLBA[63:32], CDW12[15:0]=NLB
            #         CDW12[29]=PRACT, CDW12[30]=LR, CDW12[31]=FUA
            #         CDW13[15:0]=DSPEC (Streams ID), CDW14=ILBRT, CDW15=LBAT/LBATM
            # ================================================================
            "Read": [
                # ── 기본 LBA 범위 ──
                dict(cdw10=0,     cdw11=0, cdw12=0,      description="Read LBA 0, 1 block"),
                dict(cdw10=1,     cdw11=0, cdw12=0,      description="Read LBA 1, 1 block"),
                dict(cdw10=0,     cdw11=0, cdw12=7,      description="Read LBA 0, 8 blocks (4KB)"),
                dict(cdw10=0,     cdw11=0, cdw12=31,     description="Read LBA 0, 32 blocks (16KB)"),
                dict(cdw10=0,     cdw11=0, cdw12=127,    description="Read LBA 0, 128 blocks (64KB)"),
                dict(cdw10=0,     cdw11=0, cdw12=255,    description="Read LBA 0, 256 blocks (128KB)"),
                dict(cdw10=0,     cdw11=0, cdw12=0xFFFF, description="Read LBA 0, NLB max (65536 blocks)"),
                dict(cdw10=500,   cdw11=0, cdw12=0,      description="Read LBA 500"),
                dict(cdw10=1000,  cdw11=0, cdw12=0,      description="Read LBA 1000"),
                dict(cdw10=5000,  cdw11=0, cdw12=0,      description="Read LBA 5000"),
                dict(cdw10=10000, cdw11=0, cdw12=0,      description="Read LBA 10000"),
                # ── 64비트 LBA 경계 ──
                dict(cdw10=0x00000000, cdw11=0x00000001, cdw12=0,
                     description="Read LBA 4G (OOR error path)"),
                dict(cdw10=0xFFFF0000, cdw11=0xFFFFFFFF, cdw12=0,
                     description="Read SLBA near 64-bit max (OOR error path)"),
                # ── CDW12 상위 비트: Protection / Access ──
                dict(cdw10=0, cdw11=0, cdw12=_PRACT,
                     description="Read LBA 0, PRACT=1 (CDW12[29], PI action)"),
                dict(cdw10=0, cdw11=0, cdw12=_LR,
                     description="Read LBA 0, LR=1 (Limited Retry, CDW12[30])"),
                dict(cdw10=0, cdw11=0, cdw12=_FUA,
                     description="Read LBA 0, FUA=1 (Force Unit Access, CDW12[31])"),
                dict(cdw10=0, cdw11=0, cdw12=_PRINFO_ALL,
                     description="Read LBA 0, PRINFO=0xF (PRACT+PRCHK[2:0] all set)"),
                dict(cdw10=0, cdw11=0, cdw12=_FUA | _LR,
                     description="Read LBA 0, FUA+LR"),
                dict(cdw10=0, cdw11=0, cdw12=_PRCHK_ALL,
                     description="Read LBA 0, PRCHK=0x7 (guard+apptag+reftag check)"),
                # ── E2E Protection: CDW14=ILBRT, CDW15=LBAT/LBATM ──
                dict(cdw10=0, cdw11=0, cdw12=_PRINFO_ALL,
                     cdw14=0xDEADBEEF, cdw15=0xFFFF0000,
                     description="Read LBA 0, PI all + ILBRT=0xDEADBEEF LBATM=0xFFFF"),
                dict(cdw10=0, cdw11=0, cdw12=_PRACT,
                     cdw14=0x00000001, cdw15=0x00010001,
                     description="Read LBA 0, PRACT + ILBRT=1 LBATM=1 LBAT=1"),
                # ── Streams Directive (DTYPE=1) ──
                # CDW12[31:30]=0b01(DTYPE=1), CDW13[15:0]=Stream ID
                dict(cdw10=0, cdw11=0, cdw12=(1 << 30), cdw13=0x0001,
                     description="Read LBA 0, DTYPE=1 (Streams) DSPEC=1"),
                dict(cdw10=0, cdw11=0, cdw12=(1 << 30), cdw13=0x0002,
                     description="Read LBA 0, DTYPE=1 (Streams) DSPEC=2"),
            ],

            # ================================================================
            # Write — CDW10=SLBA[31:0], CDW11=SLBA[63:32], CDW12[15:0]=NLB
            #          CDW12[29]=PRACT, CDW12[30]=LR, CDW12[31]=FUA
            #          CDW13[15:0]=DSPEC, CDW14=ILBRT, CDW15=LBAT/LBATM
            # ================================================================
            "Write": [
                # ── 1 block ──
                dict(cdw10=0,     cdw11=0, cdw12=0, data=b'\x00' * 512,  description="Write LBA 0, 1 block zeros"),
                dict(cdw10=0,     cdw11=0, cdw12=0, data=b'\xAA' * 512,  description="Write LBA 0, 1 block 0xAA"),
                dict(cdw10=0,     cdw11=0, cdw12=0, data=b'\xFF' * 512,  description="Write LBA 0, 1 block 0xFF"),
                dict(cdw10=0,     cdw11=0, cdw12=0, data=bytes(range(256)) * 2,
                     description="Write LBA 0, sequential 0x00-0xFF"),
                # ── 다중 block ──
                dict(cdw10=0, cdw11=0, cdw12=7,   data=b'\x00' * (8   * 512), description="Write LBA 0, 8 blocks (4KB)"),
                dict(cdw10=0, cdw11=0, cdw12=31,  data=b'\x00' * (32  * 512), description="Write LBA 0, 32 blocks (16KB)"),
                dict(cdw10=0, cdw11=0, cdw12=127, data=b'\x00' * (128 * 512), description="Write LBA 0, 128 blocks (64KB)"),
                dict(cdw10=0, cdw11=0, cdw12=255, data=b'\x00' * (256 * 512), description="Write LBA 0, 256 blocks (128KB)"),
                # ── 다양한 SLBA ──
                dict(cdw10=500,   cdw11=0, cdw12=0, data=b'\x00' * 512, description="Write LBA 500"),
                dict(cdw10=1000,  cdw11=0, cdw12=0, data=b'\x00' * 512, description="Write LBA 1000"),
                dict(cdw10=5000,  cdw11=0, cdw12=0, data=b'\x00' * 512, description="Write LBA 5000"),
                dict(cdw10=10000, cdw11=0, cdw12=0, data=b'\x00' * 512, description="Write LBA 10000"),
                # ── 64비트 LBA 경계 ──
                dict(cdw10=0x00000000, cdw11=0x00000001, cdw12=0, data=b'\x00' * 512,
                     description="Write LBA 4G (OOR error path)"),
                dict(cdw10=0xFFFF0000, cdw11=0xFFFFFFFF, cdw12=0, data=b'\x00' * 512,
                     description="Write SLBA near 64-bit max (OOR error path)"),
                # ── CDW12 상위 비트 ──
                dict(cdw10=0, cdw11=0, cdw12=_PRACT, data=b'\x00' * 512,
                     description="Write LBA 0, PRACT=1 (PI action)"),
                dict(cdw10=0, cdw11=0, cdw12=_LR, data=b'\x00' * 512,
                     description="Write LBA 0, LR=1 (Limited Retry)"),
                dict(cdw10=0, cdw11=0, cdw12=_FUA, data=b'\x00' * 512,
                     description="Write LBA 0, FUA=1 (Force Unit Access)"),
                dict(cdw10=0, cdw11=0, cdw12=_PRINFO_ALL, data=b'\x00' * 512,
                     description="Write LBA 0, PRINFO=0xF (all PI bits)"),
                dict(cdw10=0, cdw11=0, cdw12=_FUA | _LR, data=b'\x00' * 512,
                     description="Write LBA 0, FUA+LR"),
                # ── E2E Protection: CDW14=ILBRT, CDW15=LBAT/LBATM ──
                dict(cdw10=0, cdw11=0, cdw12=_PRINFO_ALL,
                     cdw14=0xDEADBEEF, cdw15=0xFFFF0000,
                     data=b'\x00' * 512,
                     description="Write LBA 0, PI all + ILBRT=0xDEADBEEF LBATM=0xFFFF"),
                # ── Streams Directive (DTYPE=1) ──
                dict(cdw10=0, cdw11=0, cdw12=(1 << 30), cdw13=0x0001,
                     data=b'\x00' * 512,
                     description="Write LBA 0, DTYPE=1 (Streams) DSPEC=1"),
                # ── Dataset Management attributes (CDW13[3:0]=DSMA) ──
                dict(cdw10=0, cdw11=0, cdw12=0, cdw13=0x4,  # IDR (Random)
                     data=b'\x00' * 512, description="Write LBA 0, DSMA=IDR (Random access hint)"),
                dict(cdw10=0, cdw11=0, cdw12=0, cdw13=0x8,  # IDW (Incompressible)
                     data=b'\x00' * 512, description="Write LBA 0, DSMA=IDW (Incompressible hint)"),
            ],

            # ================================================================
            # WriteZeroes — CDW10=SLBA[31:0], CDW11=SLBA[63:32], CDW12[15:0]=NLB
            #                CDW12[25]=DEAC, CDW12[29]=PRACT, CDW12[30]=LR, CDW12[31]=FUA
            #                (데이터 전송 없음 — DMA 없이 펌웨어가 직접 0 기록)
            # ================================================================
            "WriteZeroes": [
                dict(cdw10=0,     cdw11=0, cdw12=0,                       description="WriteZeroes LBA 0, 1 block"),
                dict(cdw10=0,     cdw11=0, cdw12=7,                       description="WriteZeroes LBA 0, 8 blocks"),
                dict(cdw10=0,     cdw11=0, cdw12=255,                     description="WriteZeroes LBA 0, 256 blocks"),
                dict(cdw10=0,     cdw11=0, cdw12=0xFFFF,                  description="WriteZeroes LBA 0, NLB max"),
                dict(cdw10=0,     cdw11=0, cdw12=_DEAC,                   description="WriteZeroes LBA 0, DEAC=1 (deallocate)"),
                dict(cdw10=0,     cdw11=0, cdw12=_FUA,                    description="WriteZeroes LBA 0, FUA=1"),
                dict(cdw10=0,     cdw11=0, cdw12=_DEAC | _FUA,            description="WriteZeroes LBA 0, DEAC+FUA"),
                dict(cdw10=500,   cdw11=0, cdw12=0,                       description="WriteZeroes LBA 500"),
                dict(cdw10=5000,  cdw11=0, cdw12=0,                       description="WriteZeroes LBA 5000"),
                dict(cdw10=0x00000000, cdw11=0x00000001, cdw12=0,         description="WriteZeroes LBA 4G (OOR error path)"),
            ],

            # ================================================================
            # Compare — Read처럼 LBA에서 읽어 호스트 버퍼와 비교
            #            CDW10=SLBA[31:0], CDW11=SLBA[63:32], CDW12[15:0]=NLB
            # ================================================================
            "Compare": [
                dict(cdw10=0,     cdw11=0, cdw12=0, data=b'\x00' * 512,  description="Compare LBA 0, 1 block zeros"),
                dict(cdw10=0,     cdw11=0, cdw12=0, data=b'\xFF' * 512,  description="Compare LBA 0, 1 block 0xFF"),
                dict(cdw10=0,     cdw11=0, cdw12=0, data=b'\xAA' * 512,  description="Compare LBA 0, 1 block 0xAA"),
                dict(cdw10=0,     cdw11=0, cdw12=7, data=b'\x00' * (8 * 512), description="Compare LBA 0, 8 blocks"),
                dict(cdw10=500,   cdw11=0, cdw12=0, data=b'\x00' * 512,  description="Compare LBA 500"),
                dict(cdw10=0x00000000, cdw11=0x00000001, cdw12=0, data=b'\x00' * 512,
                     description="Compare LBA 4G (OOR error path)"),
            ],

            # ================================================================
            # WriteUncorrectable — LBA를 uncorrectable 상태로 마킹 (에러 주입)
            #                       CDW10=SLBA[31:0], CDW11=SLBA[63:32], CDW12[15:0]=NLB
            #                       데이터 전송 없음
            # ================================================================
            "WriteUncorrectable": [
                dict(cdw10=0,    cdw11=0, cdw12=0,      description="WriteUncorrectable LBA 0, 1 block"),
                dict(cdw10=0,    cdw11=0, cdw12=7,      description="WriteUncorrectable LBA 0, 8 blocks"),
                dict(cdw10=0,    cdw11=0, cdw12=0xFFFF, description="WriteUncorrectable LBA 0, NLB max"),
                dict(cdw10=500,  cdw11=0, cdw12=0,      description="WriteUncorrectable LBA 500"),
                dict(cdw10=5000, cdw11=0, cdw12=0,      description="WriteUncorrectable LBA 5000"),
                dict(cdw10=0x00000000, cdw11=0x00000001, cdw12=0,
                     description="WriteUncorrectable LBA 4G (OOR error path)"),
            ],

            # ================================================================
            # Verify — LBA 읽기 후 CRC/PI 검증 (데이터 호스트 반환 없음)
            #           CDW12[29]=PRACT, CDW12[28:26]=PRCHK, CDW12[30]=LR
            # ================================================================
            "Verify": [
                dict(cdw10=0,    cdw11=0, cdw12=0,         description="Verify LBA 0, 1 block"),
                dict(cdw10=0,    cdw11=0, cdw12=7,         description="Verify LBA 0, 8 blocks"),
                dict(cdw10=0,    cdw11=0, cdw12=255,       description="Verify LBA 0, 256 blocks"),
                dict(cdw10=0,    cdw11=0, cdw12=0xFFFF,    description="Verify LBA 0, NLB max"),
                dict(cdw10=0,    cdw11=0, cdw12=_PRINFO_ALL,
                     description="Verify LBA 0, PRINFO=0xF (all PI bits)"),
                dict(cdw10=0,    cdw11=0, cdw12=_LR,       description="Verify LBA 0, LR=1 (Limited Retry)"),
                dict(cdw10=0,    cdw11=0, cdw12=_PRCHK_ALL, description="Verify LBA 0, PRCHK=0x7 (all check bits)"),
                dict(cdw10=0,    cdw11=0, cdw12=_PRACT | _LR,
                     cdw14=0xDEADBEEF, description="Verify LBA 0, PRACT+LR+ILBRT=0xDEADBEEF"),
                dict(cdw10=500,  cdw11=0, cdw12=0,         description="Verify LBA 500"),
                dict(cdw10=0x00000000, cdw11=0x00000001, cdw12=0,
                     description="Verify LBA 4G (OOR error path)"),
            ],

            # ================================================================
            # DeviceSelfTest — CDW10[3:0]=STC (Self-test Code)
            #                   0x1=Short, 0x2=Extended, 0xE=Vendor, 0xF=Abort
            #                   명령은 즉시 반환, 테스트는 백그라운드 실행
            # ================================================================
            "DeviceSelfTest": [
                dict(cdw10=0x01, nsid_override=0, description="Short Self-test (background, ~2min max)"),
                dict(cdw10=0x02, nsid_override=0, description="Extended Self-test (background, duration varies)"),
                dict(cdw10=0x0E, nsid_override=0, description="Vendor specific self-test"),
                dict(cdw10=0x0F, nsid_override=0, description="Abort current self-test"),
                # NSID=1 (NS-scope self-test) — 일부 구현에서 NS별 테스트 지원
                dict(cdw10=0x01, description="Short Self-test (NS-scope, NSID=1)"),
                # 미지원 STC — 에러 경로
                dict(cdw10=0x03, nsid_override=0, description="STC=0x03 (undefined, error path)"),
            ],

            # ================================================================
            # SecuritySend — CDW10[31:24]=SECP, CDW10[23:8]=SPSP, CDW10[7:0]=NSSF
            #                 CDW11=TL (Transfer Length, bytes)
            #                 데이터: 호스트→SSD
            # ================================================================
            "SecuritySend": [
                # SECP=0x00: Security Protocol Information (Protocol List)
                dict(cdw10=(0x00 << 24), cdw11=512, data=b'\x00' * 512,
                     description="SecuritySend SECP=0x00 (Protocol List)"),
                # SECP=0x01: TCG (NVMe에서 가장 일반적)
                dict(cdw10=(0x01 << 24) | (0x0001 << 8), cdw11=512, data=b'\x00' * 512,
                     description="SecuritySend SECP=0x01 (TCG) SPSP=0x0001"),
                dict(cdw10=(0x01 << 24) | (0x0007 << 8), cdw11=512, data=b'\x00' * 512,
                     description="SecuritySend SECP=0x01 (TCG) SPSP=0x0007 (TCG SSC)"),
                # SECP=0x02: IEEE 1667 (USB-style storage authentication)
                dict(cdw10=(0x02 << 24), cdw11=512, data=b'\x00' * 512,
                     description="SecuritySend SECP=0x02 (IEEE 1667)"),
                # SECP=0xEA: NVMe-specific Security
                dict(cdw10=(0xEA << 24), cdw11=512, data=b'\x00' * 512,
                     description="SecuritySend SECP=0xEA (NVMe-specific)"),
                # SECP=0xEF: ATA Security (SATA 이식 제품 일부 구현)
                dict(cdw10=(0xEF << 24), cdw11=0, data=b'',
                     description="SecuritySend SECP=0xEF (ATA Security, TL=0)"),
                # 미지원 SECP — 에러 경로
                dict(cdw10=(0xFF << 24), cdw11=512, data=b'\x00' * 512,
                     description="SecuritySend SECP=0xFF (undefined, error path)"),
            ],

            # ================================================================
            # SecurityReceive — CDW10[31:24]=SECP, CDW10[23:8]=SPSP, CDW10[7:0]=NSSF
            #                    CDW11=AL (Allocation Length, bytes)
            #                    데이터: SSD→호스트 (data_len = CDW11 by _send_nvme_command)
            # ================================================================
            "SecurityReceive": [
                # SECP=0x00: Protocol list 조회 — 지원 프로토콜 목록
                dict(cdw10=(0x00 << 24), cdw11=512,
                     description="SecurityReceive SECP=0x00 (Protocol List), AL=512"),
                # SECP=0x01: TCG
                dict(cdw10=(0x01 << 24) | (0x0001 << 8), cdw11=512,
                     description="SecurityReceive SECP=0x01 (TCG) SPSP=0x0001, AL=512"),
                dict(cdw10=(0x01 << 24) | (0x0001 << 8), cdw11=4096,
                     description="SecurityReceive SECP=0x01 (TCG) SPSP=0x0001, AL=4KB"),
                # SECP=0x02: IEEE 1667
                dict(cdw10=(0x02 << 24), cdw11=512,
                     description="SecurityReceive SECP=0x02 (IEEE 1667), AL=512"),
                # SECP=0xEA: NVMe-specific
                dict(cdw10=(0xEA << 24), cdw11=512,
                     description="SecurityReceive SECP=0xEA (NVMe-specific), AL=512"),
                # AL=0 — 크기 0 조회 (지원 여부 확인용)
                dict(cdw10=(0x01 << 24), cdw11=0,
                     description="SecurityReceive SECP=0x01 AL=0 (capability probe)"),
                # 미지원 SECP
                dict(cdw10=(0xFF << 24), cdw11=512,
                     description="SecurityReceive SECP=0xFF (undefined, error path)"),
            ],

            # ================================================================
            # GetLBAStatus — CDW10=SLBA[31:0], CDW11=SLBA[63:32]
            #                 CDW12=MNDW (Max Number of Dwords, 0-based)
            #                 CDW13[15:0]=RL (Range Length), CDW13[31:16]=ATYPE
            #                   ATYPE=0: All LBAs, 1: Allocated, 2: Unallocated
            # ================================================================
            "GetLBAStatus": [
                dict(cdw10=0, cdw11=0, cdw12=0xFF, cdw13=(0x0000 << 16) | 0x0010,
                     description="GetLBAStatus LBA 0, ATYPE=0 (all), RL=16"),
                dict(cdw10=0, cdw11=0, cdw12=0xFF, cdw13=(0x0001 << 16) | 0x0010,
                     description="GetLBAStatus LBA 0, ATYPE=1 (allocated), RL=16"),
                dict(cdw10=0, cdw11=0, cdw12=0xFF, cdw13=(0x0002 << 16) | 0x0010,
                     description="GetLBAStatus LBA 0, ATYPE=2 (unallocated/deallocated), RL=16"),
                dict(cdw10=0, cdw11=0, cdw12=0xFF, cdw13=(0x0001 << 16) | 0xFFFF,
                     description="GetLBAStatus LBA 0, ATYPE=1 RL=max"),
                dict(cdw10=5000, cdw11=0, cdw12=0xFF, cdw13=(0x0001 << 16) | 0x0010,
                     description="GetLBAStatus LBA 5000, ATYPE=1, RL=16"),
                dict(cdw10=0x00000000, cdw11=0x00000001, cdw12=0xFF, cdw13=0x0010,
                     description="GetLBAStatus LBA 4G (OOR error path)"),
            ],

            # ================================================================
            # FWDownload — CDW10=NUMD (0-based dwords), CDW11=OFST (dword offset)
            # ================================================================
            "FWDownload": [
                dict(cdw10=0xFF, cdw11=0, data=b'\x00' * 1024, description="FW Download offset=0, 1KB"),
            ],

            # ================================================================
            # FWCommit — CDW10[2:0]=CA (Commit Action), CDW10[5:3]=FS (Firmware Slot)
            #             CA=0: replace, no activate
            #             CA=1: replace, activate on next reset
            #             CA=2: replace + activate on next reset (w/ reset)
            #             CA=3: activate without replace (existing slot)
            #             CA=5: replace + activate immediately (NVMe 1.3+)
            # ================================================================
            "FWCommit": [
                dict(cdw10=0x00, description="CA=0: replace image, no activate (Slot 0)"),
                dict(cdw10=0x01, description="CA=1: replace + activate on next reset (Slot 0)"),
                dict(cdw10=0x09, description="CA=1: replace + activate on next reset (Slot 1)"),
                dict(cdw10=0x02, description="CA=2: replace + activate on next reset (Slot 0)"),
                dict(cdw10=0x03, description="CA=3: activate without replace (Slot 0)"),
                dict(cdw10=0x05, description="CA=5: replace + activate immediately (Slot 0, NVMe 1.3+)"),
                dict(cdw10=0x0D, description="CA=5: replace + activate immediately (Slot 1, NVMe 1.3+)"),
            ],

            # ================================================================
            # FormatNVM — CDW10[3:0]=LBAF, CDW10[11:9]=SES (Secure Erase Settings)
            #              CDW10[8]=MSET, CDW10[12]=PI, CDW10[13]=PIL, CDW10[14]=METC
            #              SES=0: no erase, 1: user data erase, 2: cryptographic erase
            # ================================================================
            "FormatNVM": [
                dict(cdw10=0x0000, description="Format LBAF=0, SES=0 (no secure erase)"),
                dict(cdw10=0x0200, description="Format LBAF=0, SES=1 (user data erase)"),
                dict(cdw10=0x0400, description="Format LBAF=0, SES=2 (cryptographic erase)"),
                dict(cdw10=0x0001, description="Format LBAF=1, SES=0"),
                dict(cdw10=0x0002, description="Format LBAF=2, SES=0"),
                # PI 활성화 (메타데이터 + 보호정보)
                dict(cdw10=0x1000, description="Format LBAF=0, PI Type 0 (PI field disabled)"),
                dict(cdw10=0x1100, description="Format LBAF=0, PI=1 (Type 1 protection)"),
            ],

            # ================================================================
            # Sanitize — 기본 시드 없음 (rc=0이면 즉시 SSD 전체 소거 시작)
            # CDW10[2:0]=SANACT: 1=Block Erase, 2=Overwrite, 3=Crypto Erase, 4=Exit Failure
            # CDW10[4]=AUSE (Allow Unrestricted Sanitize Exit)
            # CDW10[5]=NODAS (No Deallocate After Sanitize)
            # 필요 시 --seed-dir로 직접 주입
            # ================================================================

            # ================================================================
            # TelemetryHostInitiated — GetLogPage LID=0x07
            # CDW10[8]=Create Telemetry (1=새 데이터 생성, 0=기존 반환)
            # ================================================================
            "TelemetryHostInitiated": [
                dict(cdw10=(0x1FF << 16) | 0x07, nsid_override=0,
                     description="Telemetry Host-Initiated, Create=0 (return existing)"),
                dict(cdw10=(0x1FF << 16) | (1 << 8) | 0x07, nsid_override=0,
                     description="Telemetry Host-Initiated, Create=1 (create new snapshot)"),
            ],

            # ================================================================
            # Flush — 파라미터 없음
            # ================================================================
            "Flush": [
                dict(description="Flush (no parameters)"),
            ],

            # ================================================================
            # DatasetManagement — CDW10[7:0]=NR (Number of Ranges, 0-based)
            #                      CDW11[2]=AD (Attribute Deallocate)
            #                      CDW11[0]=IDR, CDW11[1]=IDW (access hints)
            #                      data: 16B per range (Context Attrs + LBA Count + SLBA)
            # ================================================================
            "DatasetManagement": [
                # Range Entry 구조 (16B): [Context Attrs 4B][LBA Count 4B][SLBA 8B]
                # AD=1: TRIM (deallocate) — 가장 일반적인 용도
                dict(cdw10=0, cdw11=0x04,
                     data=struct.pack('<IIQ', 0, 8, 0),
                     description="TRIM LBA 0, 8 blocks (AD=1)"),
                dict(cdw10=0, cdw11=0x04,
                     data=struct.pack('<IIQ', 0, 256, 0),
                     description="TRIM LBA 0, 256 blocks (AD=1)"),
                dict(cdw10=0, cdw11=0x04,
                     data=struct.pack('<IIQ', 0, 8, 500),
                     description="TRIM LBA 500, 8 blocks (AD=1)"),
                # IDR=1: Sequential Read access hint
                dict(cdw10=0, cdw11=0x01,
                     data=struct.pack('<IIQ', 0, 8, 0),
                     description="DSM IDR=1 (Sequential Read hint), LBA 0, 8 blocks"),
                # IDW=1: Sequential Write access hint
                dict(cdw10=0, cdw11=0x02,
                     data=struct.pack('<IIQ', 0, 8, 0),
                     description="DSM IDW=1 (Sequential Write hint), LBA 0, 8 blocks"),
                # NR=1 (2 ranges): AD=1
                dict(cdw10=1, cdw11=0x04,
                     data=struct.pack('<IIQ', 0, 8, 0) + struct.pack('<IIQ', 0, 8, 100),
                     description="TRIM 2 ranges: LBA 0+8blk, LBA 100+8blk (NR=1, AD=1)"),
                # NR=max (256 ranges): AD=1 — 범위 최대치
                dict(cdw10=0xFF, cdw11=0x04,
                     data=struct.pack('<IIQ', 0, 1, 0) * 256,
                     description="TRIM 256 ranges (NR=0xFF, AD=1)"),
            ],
        }

        # v4.7: fw_bin이 제공된 경우 FWDownload/FWCommit 실제 시드 생성
        fw_bin  = self.config.fw_bin
        fw_xfer = self.config.fw_xfer_size
        fw_slot = self.config.fw_slot
        use_real_fw = bool(fw_bin and os.path.isfile(fw_bin))
        if use_real_fw:
            log.info(f"[Seed] fw_bin={fw_bin} (xfer={fw_xfer}B slot={fw_slot}) → 실제 FWDownload 시드 생성")
        else:
            log.info("[Seed] fw_bin 미지정 또는 파일 없음 → FWDownload 더미 시드 사용")

        for cmd in self.commands:
            # ── FWDownload: fw_bin 있으면 실제 청크 시드, 없으면 더미 ──
            if cmd.name == "FWDownload":
                if use_real_fw:
                    with open(fw_bin, "rb") as f:
                        fw_data = f.read()
                    offset = 0
                    chunk_idx = 0
                    while offset < len(fw_data):
                        chunk = fw_data[offset:offset + fw_xfer]
                        if len(chunk) % 4 != 0:
                            chunk = chunk + b'\x00' * (4 - len(chunk) % 4)
                        numd = (len(chunk) // 4) - 1  # CDW10: NUMD (0-based)
                        ofst = offset // 4             # CDW11: OFST (dword offset)
                        seed = Seed(data=chunk, cmd=cmd,
                                    cdw10=numd, cdw11=ofst, found_at=0)
                        seeds.append(seed)
                        log.info(f"[Seed] FWDownload chunk {chunk_idx} "
                                 f"offset={offset} ({len(chunk)}B) NUMD=0x{numd:x}")
                        offset += fw_xfer
                        chunk_idx += 1
                else:
                    # 더미: 1KB zeros (변이 시작점용)
                    seed = Seed(data=b'\x00' * 1024, cmd=cmd,
                                cdw10=0xFF, cdw11=0, found_at=0)
                    seeds.append(seed)
                    log.info("[Seed] FWDownload dummy 1KB (fw_bin 없음)")
                continue

            # ── FWCommit: fw_bin 있으면 올바른 슬롯으로, 없으면 기본 2개 ──
            if cmd.name == "FWCommit":
                if use_real_fw:
                    cdw10_commit = (fw_slot << 3) | 0x01  # CA=1: replace, activate on reset
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

            # ── 나머지 명령어: SEED_TEMPLATES 사용 ──
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
        """v4.3: AFL++ 방식 corpus culling (v4.5+: PC 주소 기반).
        각 PC에 대해 가장 작은 seed를 favored로 마킹하고,
        favored가 아닌 seed 중 기여도 없는 것을 제거한다."""
        if len(self.corpus) <= 10:
            return

        # 1) PC → best seed 매핑 (가장 작은 data 우선)
        pc_best: dict[int, Seed] = {}
        for seed in self.corpus:
            if not seed.covered_pcs:
                continue
            for pc in seed.covered_pcs:
                current = pc_best.get(pc)
                if current is None or len(seed.data) < len(current.data):
                    pc_best[pc] = seed

        # 2) favored 마킹
        favored_seeds = set()
        for seed in pc_best.values():
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

    def _load_static_analysis(self) -> None:
        """같은 디렉토리의 code_addrs.txt / functions.txt 자동 탐지 후 로드.

        파일이 없으면 아무것도 하지 않음 (기존 동작 유지).
        Ghidra의 ghidra_export.py 스크립트로 생성한 파일을 기대함.
        """
        script_dir = Path(__file__).parent.resolve()
        code_file = script_dir / 'code_addrs.txt'
        func_file  = script_dir / 'functions.txt'

        if not code_file.exists() and not func_file.exists():
            return  # 파일 없음 — 로그 없이 조용히 넘어감

        # --- code_addrs.txt ---
        if code_file.exists():
            addrs: set = set()
            with open(code_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            addrs.add(int(line, 16))
                        except ValueError:
                            pass
            self._sa_code_addrs = frozenset(addrs)
            self._sa_total_code = len(self._sa_code_addrs)
            # log은 run() 이후에야 설정되므로 print 사용
            print(f"[StaticAnalysis] code_addrs.txt: {self._sa_total_code:,}개 명령어 주소")

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
                print(f"[StaticAnalysis] functions.txt: {self._sa_total_funcs:,}개 함수")

        self._sa_loaded = self._sa_total_code > 0 or self._sa_total_funcs > 0

        # 로드된 주소 범위 출력 — J-Link 샘플 범위와 비교용
        if self._sa_code_addrs:
            _mn = min(self._sa_code_addrs)
            _mx = max(self._sa_code_addrs)
            print(f"[StaticAnalysis] code 주소 범위: 0x{_mn:08x} ~ 0x{_mx:08x}")
        if self._sa_func_entries:
            print(f"[StaticAnalysis] 함수 주소 범위: "
                  f"0x{self._sa_func_entries[0]:08x} ~ 0x{self._sa_func_entries[-1]:08x}")

        self._sa_diag_done = False   # 첫 update 시 1회만 진단 로그 출력

    def _update_static_coverage(self, new_pcs: set) -> None:
        """새로 발견된 PC 집합으로 정적 분석 커버리지를 증분 업데이트.

        O(new_pcs × log(funcs)) — Stats 출력마다 재계산하지 않음.
        """
        if not new_pcs:
            return

        # 첫 호출 시 1회 진단: 실제 PC 샘플과 static 주소의 매칭 여부 확인
        if not self._sa_diag_done:
            self._sa_diag_done = True
            sample = sorted(new_pcs)[:10]
            if self._sa_code_addrs:
                matched = [pc for pc in sample if pc in self._sa_code_addrs]
                # Thumb bit(bit0) 마스킹 시 매칭 여부도 확인
                matched_thumb = [pc for pc in sample if (pc & ~1) in self._sa_code_addrs]
                log.warning(
                    f"[StatDiag] 첫 new_pcs 샘플(최대10개): "
                    f"{[hex(p) for p in sample]}")
                log.warning(
                    f"[StatDiag] code_addrs 직접 매칭: {len(matched)}/{len(sample)}개  "
                    f"| Thumb bit(bit0) 마스킹 후 매칭: {len(matched_thumb)}/{len(sample)}개")
                if len(matched) == 0 and len(matched_thumb) > 0:
                    log.warning(
                        "[StatDiag] *** Thumb bit 불일치 감지! "
                        "J-Link PC의 bit0이 set된 것으로 보임 → 자동 마스킹 적용 ***")
                    self._sa_thumb_mask = True
                elif len(matched) == 0 and len(matched_thumb) == 0:
                    if self._sa_code_addrs:
                        _sa_min = min(self._sa_code_addrs)
                        _sa_max = max(self._sa_code_addrs)
                        _pc_min = min(new_pcs)
                        _pc_max = max(new_pcs)
                        log.warning(
                            f"[StatDiag] *** 주소 범위 불일치! "
                            f"PC 범위: 0x{_pc_min:08x}~0x{_pc_max:08x}  "
                            f"code_addrs 범위: 0x{_sa_min:08x}~0x{_sa_max:08x} ***")

        # 코드 주소 커버리지
        if self._sa_code_addrs is not None:
            for pc in new_pcs:
                pc_key = (pc & ~1) if getattr(self, '_sa_thumb_mask', False) else pc
                if pc_key in self._sa_code_addrs:
                    self._sa_covered_addrs += 1

        # 함수 커버리지 — bisect로 O(log N) 함수 탐색
        if self._sa_func_entries is not None:
            for pc in new_pcs:
                pc_key = (pc & ~1) if getattr(self, '_sa_thumb_mask', False) else pc
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

    def _send_nvme_command(self, data: bytes, seed: Seed, timeout_mult: int = 1) -> int:
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
            nlb = seed.cdw12 & 0xFFFF
            data_len = min(max(512, (nlb + 1) * 512), MAX_DATA_BUF)
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
                    f.write(data)
            input_file = self._nvme_input_path

        # --- 타임아웃 ---
        # subprocess 감지 timeout: 퍼저가 "이 명령은 crash"라고 판단하는 창
        timeout_ms = self.config.nvme_timeouts.get(
            cmd.timeout_group,
            self.config.nvme_timeouts.get('command', 8000)
        )
        if timeout_mult > 1:
            timeout_ms = int(timeout_ms * timeout_mult)
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
            target_device = f"{self.config.nvme_device}n{self.config.nvme_namespace}"
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
                start_new_session=True,  # v4.6: setsid() — 부모 종료/SIGHUP 후에도 생존
            )

            # subprocess 타임아웃 = NVMe 타임아웃 + 여유 2초
            timeout_sec = timeout_ms / 1000.0 + 2.0
            try:
                stdout, stderr = process.communicate(timeout=timeout_sec)
            except subprocess.TimeoutExpired:
                # v4.6: process.kill() 하지 않음.
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

    def _configure_nvme_timeouts(self) -> None:
        """퍼저 시작 시 nvme_core 모듈 타임아웃 파라미터를 늘린다.

        기본값: admin_timeout=60s, io_timeout=30s
        → 펌웨어 crash 후 ~60초면 커널이 controller reset을 시작해 crash 상태 소멸.

        이 값을 크게 설정하면 crash 발생 후에도 오랫동안 SSD 상태가 보존되어
        JTAG 분석이 가능해진다.

        제약: 설정 시점 이후 새로 제출되는 NVMe 명령에만 적용됨.
        현재 in-flight AER 명령의 deadline은 변경 불가.
        AER 이벤트가 발생해 재제출될 때부터 새 timeout이 적용된다.
        """
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
        """NVMe 장치의 PCIe bus 번호를 자동 탐지한다.

        1차: /sys/class/nvme/<ctrl>/address → "0000:01:00.0" → "01"
        2차 fallback: lspci | grep nvme
        반환값 예: "01" (hex 문자열), 탐지 실패 시 None.
        """
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
                    bus = parts[-2]  # "01"
                    log.warning(f"[UFAS] sysfs 탐지 성공: {addr} → bus={bus}")
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
                bus = nvme_lines[0].split(':')[0]
                log.warning(f"[UFAS] lspci 탐지 성공: bus={bus}")
                return bus
            else:
                log.warning("[UFAS] lspci에서 NVMe 장치를 찾지 못함")
        except Exception as e:
            log.warning(f"[UFAS] lspci 실행 실패: {e}")

        log.warning("[UFAS] PCIe bus 번호 자동 탐지 실패 — UFAS 덤프 건너뜀")
        return None

    def _run_ufas_dump(self) -> None:
        """crash 발생 시 UFAS 펌웨어 덤프를 실행한다.

        실행 파일: fuzzer 스크립트와 같은 디렉토리의 ./ufas
        명령: sudo ./ufas <pcie_bus> 1 <YYYYMMDD>_UFAS_Dump.bin --ini=./SnapShot/A815.ini
        Popen으로 PID 추적, timeout 후 D-state 대비 포기 처리.
        """
        TIMEOUT = 600   # 10분 — 펌웨어 덤프는 수 분 소요됨

        script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        ufas_path = os.path.join(script_dir, 'ufas')

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

        date_str = datetime.now().strftime('%Y%m%d')
        dump_filename = f"{date_str}_UFAS_Dump.bin"
        dump_path = os.path.join(script_dir, dump_filename)

        cmd = ['sudo', ufas_path, pcie_bus, '1', dump_path, '--ini=A815.ini']
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
        if out:
            log.warning(f"[UFAS] stdout:\n{out}")
        if err:
            log.warning(f"[UFAS] stderr:\n{err}")
        if rc == 0:
            log.warning(f"[UFAS] 덤프 완료 (rc=0) → {dump_path}")
        else:
            log.warning(f"[UFAS] 덤프 실패 (rc={rc})")

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
        # 절대경로로 변환 — 스크립트를 어느 디렉토리에서 실행해도 경로가 깨지지 않음
        data_dir_abs = data_dir.resolve()

        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
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
        ]

        for i, entry in enumerate(history, 1):
            label = entry['label']
            is_last = (i == len(history))
            marker = "  <- CRASH CMD" if is_last else ""
            step_str = f"[{i:03d}/{len(history)}] {label}{marker}"
            lines.append(f"# {step_str}")

            cmd_parts = [
                "nvme", entry['passthru_type'], entry['device'],
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
                "--timeout=30000",
            ]

            if entry['is_write'] and entry['data']:
                # 절대경로로 data bin 파일 저장 — 스크립트 실행 위치 무관
                data_file_abs = data_dir_abs / f"data_{i:03d}.bin"
                data_file_abs.write_bytes(entry['data'])
                cmd_parts += [f"--data-len={entry['data_len']}",
                               f"--input-file={data_file_abs}", "-w"]
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
        log.warning(f"[REPLAY] 재현 스크립트 → {sh_path}  ({len(history)}개 명령)")
        log.warning(f"[REPLAY] 실행: sudo bash {sh_path}")

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

    def _handle_timeout_crash(self, seed: Seed, fuzz_data: bytes) -> None:
        """RC_TIMEOUT 발생 시 공통 처리 (Calibration/Main loop 공용).

        stuck PC 분석 → dmesg 캡처 → crash 저장 → _timeout_crash 플래그 설정.
        호출 후 caller는 break로 현재 루프를 탈출해야 한다.
        """
        from collections import Counter

        cmd = seed.cmd
        actual_opcode = (seed.opcode_override if seed.opcode_override is not None
                         else cmd.opcode)

        # 1) stuck PC 읽기
        log.warning("[TIMEOUT] SSD 펌웨어 hang 지점 확인을 위해 PC를 읽습니다...")
        stuck_pcs = self.sampler.read_stuck_pcs(count=20)

        if stuck_pcs:
            pc_counts = Counter(stuck_pcs)
            most_common_pc, _ = pc_counts.most_common(1)[0]
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
        self._save_crash(fuzz_data, seed, reason="timeout",
                         stuck_pcs=stuck_pcs, dmesg_snapshot=dmesg_snapshot)
        log.error(f"  Crash 데이터 저장 완료 → {self.crashes_dir}/")

        # 3.5) 재현 TC replay 스크립트 생성
        _replay_tag = hashlib.md5(fuzz_data).hexdigest()[:8]
        log.warning("[TIMEOUT] 재현 TC 스크립트를 생성합니다...")
        self._generate_replay_sh(self.crashes_dir, _replay_tag)

        # 3.6) UFAS 펌웨어 덤프
        log.warning("[TIMEOUT] UFAS 펌웨어 덤프를 실행합니다...")
        try:
            self._run_ufas_dump()
        except Exception as _ufas_exc:
            log.warning(f"[UFAS] _run_ufas_dump 예기치 않은 예외: {_ufas_exc}")
        log.warning("[UFAS] _run_ufas_dump 반환")

        # 4) SSD 펌웨어를 resume 상태로 유지 (불량 현상 보존)
        log.error(
            "  SSD 펌웨어를 resume 상태로 유지합니다. "
            "(halt하지 않음 — 불량 현상 보존)")
        log.error(
            "  J-Link 디버거로 연결하여 현재 상태를 "
            "관찰할 수 있습니다.")

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

        # 6) 플래그 설정 — caller가 break로 루프 탈출
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

        for cmd_name in self.cmd_pcs:
            pcs = self.cmd_pcs[cmd_name]
            if not pcs:
                continue

            # Edge별 가중치(빈도) 계산 — traces에서 도출
            edge_counts: dict[Tuple[int, int], int] = defaultdict(int)
            for trace in self.cmd_traces[cmd_name]:
                for i in range(len(trace) - 1):
                    edge_counts[(trace[i], trace[i + 1])] += 1

            if not edge_counts:
                continue

            edges = set(edge_counts.keys())

            # DOT 파일 생성
            dot_file = graph_dir / f"{cmd_name}_cfg.dot"
            png_file = graph_dir / f"{cmd_name}_cfg.png"

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

        for cmd_name in sorted(self.cmd_pcs.keys()):
            if self.cmd_pcs[cmd_name] or self.cmd_traces[cmd_name]:
                cmd_names.append(cmd_name)
                # edges derived from traces
                derived_edges: Set[Tuple[int, int]] = set()
                for trace in self.cmd_traces[cmd_name]:
                    for i in range(len(trace) - 1):
                        derived_edges.add((trace[i], trace[i + 1]))
                edge_counts.append(len(derived_edges))
                pc_counts.append(len(self.cmd_pcs[cmd_name]))
                trace_counts.append(len(self.cmd_traces[cmd_name]))

        if not cmd_names:
            return

        fig, axes = plt.subplots(1, 3, figsize=(15, 5))
        fig.suptitle('Coverage per NVMe Command', fontsize=14, fontweight='bold')

        # 1) Edge 수 (traces에서 도출)
        bars1 = axes[0].barh(cmd_names, edge_counts, color='steelblue')
        axes[0].set_xlabel('Unique Edges (from traces)')
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

    def _generate_static_coverage_graphs(self):
        """정적 분석 커버리지 시각화 3종 생성 (파일 미로드 시 조용히 스킵).

        1. coverage_growth.png  — 성장 곡선 (code_cov% / funcs_cov% vs executions)
        2. firmware_map.png     — 펌웨어 주소 공간 커버리지 맵
        3. uncovered_funcs.png  — 미커버 함수 Top-30 (크기 순)
        """
        if not self._sa_loaded:
            return

        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt
            import matplotlib.patches as mpatches
        except ImportError:
            log.warning("[StatGraph] matplotlib 미설치 — 정적 분석 그래프 생략")
            return

        graph_dir = self.output_dir / 'graphs'
        graph_dir.mkdir(parents=True, exist_ok=True)

        # ------------------------------------------------------------------ #
        # 1. Coverage growth curve
        # ------------------------------------------------------------------ #
        if len(self._sa_cov_history) >= 2:
            execs  = [h[0] for h in self._sa_cov_history]
            c_pcts = [h[2] for h in self._sa_cov_history]
            f_pcts = [h[3] for h in self._sa_cov_history]

            fig, ax = plt.subplots(figsize=(10, 5))
            if self._sa_total_code > 0:
                ax.plot(execs, c_pcts, color='steelblue', linewidth=1.5,
                        label=f'Code ({self._sa_total_code:,} instrs)')
            if self._sa_total_funcs > 0:
                ax.plot(execs, f_pcts, color='coral', linewidth=1.5,
                        label=f'Functions ({self._sa_total_funcs:,})')

            ax.set_xlabel('Executions')
            ax.set_ylabel('Coverage (%)')
            ax.set_title('Coverage Growth — PC Sampling Fuzzer')
            ax.legend(loc='lower right')
            ax.set_ylim(0, max(max(c_pcts, default=0), max(f_pcts, default=0)) * 1.15 + 1)
            ax.grid(True, alpha=0.3)

            # 최종 값 annotation
            if c_pcts:
                ax.annotate(f'{c_pcts[-1]:.1f}%',
                            xy=(execs[-1], c_pcts[-1]),
                            xytext=(8, 4), textcoords='offset points',
                            color='steelblue', fontsize=9)
            if f_pcts:
                ax.annotate(f'{f_pcts[-1]:.1f}%',
                            xy=(execs[-1], f_pcts[-1]),
                            xytext=(8, -12), textcoords='offset points',
                            color='coral', fontsize=9)

            plt.tight_layout()
            growth_file = graph_dir / 'coverage_growth.png'
            plt.savefig(growth_file, dpi=150, bbox_inches='tight')
            plt.close()
            log.info(f"[StatGraph] 성장 곡선 → {growth_file}")

        # ------------------------------------------------------------------ #
        # 2. Firmware address-space map
        # ------------------------------------------------------------------ #
        if self._sa_func_entries and self._sa_total_funcs > 0:
            entries = self._sa_func_entries
            ends    = self._sa_func_ends
            entered = self._sa_entered_funcs

            # 함수를 entry 순으로 정렬 (이미 정렬됨)
            # 최대 400개까지만 표시 (너무 많으면 가독성 저하)
            MAX_FUNCS = 400
            step = max(1, len(entries) // MAX_FUNCS)
            sampled_idx = list(range(0, len(entries), step))

            n_show = len(sampled_idx)
            # 행 수: 20개씩 1행
            cols = 20
            rows = (n_show + cols - 1) // cols

            fig, ax = plt.subplots(figsize=(min(cols * 0.6, 14), max(rows * 0.4, 3)))
            ax.set_xlim(0, cols)
            ax.set_ylim(0, rows)
            ax.set_aspect('equal')
            ax.axis('off')

            fig.patch.set_facecolor('#1a1a2e')
            ax.set_facecolor('#1a1a2e')

            COLOR_COV   = '#00c875'   # 커버됨 (초록)
            COLOR_UNCOV = '#444466'   # 미커버 (어두운 보라)

            for plot_i, func_i in enumerate(sampled_idx):
                row = plot_i // cols
                col = plot_i % cols
                y   = rows - 1 - row  # 위에서 아래로

                # 크기에 비례한 너비 (시각적 강조)
                func_size = ends[func_i] - entries[func_i]
                w = 0.85
                h = min(0.85, 0.4 + func_size / 8000.0)
                h = min(h, 0.85)

                color = COLOR_COV if entries[func_i] in entered else COLOR_UNCOV
                rect = mpatches.FancyBboxPatch(
                    (col + 0.075, y + (0.85 - h) / 2), w, h,
                    boxstyle="round,pad=0.02",
                    facecolor=color, edgecolor='none', alpha=0.9)
                ax.add_patch(rect)

            n_cov   = len(entered)
            n_uncov = self._sa_total_funcs - n_cov
            cov_pct = 100.0 * n_cov / self._sa_total_funcs

            legend_patches = [
                mpatches.Patch(color=COLOR_COV,   label=f'Covered ({n_cov})'),
                mpatches.Patch(color=COLOR_UNCOV, label=f'Not covered ({n_uncov})'),
            ]
            ax.legend(handles=legend_patches, loc='upper right',
                      facecolor='#2a2a3e', edgecolor='gray',
                      labelcolor='white', fontsize=9)

            note = f'  (showing {n_show}/{self._sa_total_funcs} funcs)' \
                   if n_show < self._sa_total_funcs else ''
            ax.set_title(
                f'Firmware Function Map — {cov_pct:.1f}% covered{note}',
                color='white', fontsize=11, pad=8)

            map_file = graph_dir / 'firmware_map.png'
            plt.savefig(map_file, dpi=150, bbox_inches='tight',
                        facecolor=fig.get_facecolor())
            plt.close()
            log.info(f"[StatGraph] 펌웨어 맵 → {map_file}")

        # ------------------------------------------------------------------ #
        # 3. Top uncovered functions (by size)
        # ------------------------------------------------------------------ #
        if self._sa_func_entries and self._sa_total_funcs > 0:
            entered = self._sa_entered_funcs
            uncov = [
                (self._sa_func_names[i],
                 self._sa_func_ends[i] - self._sa_func_entries[i],
                 self._sa_func_entries[i])
                for i in range(len(self._sa_func_entries))
                if self._sa_func_entries[i] not in entered
            ]
            # 크기(bytes) 내림차순
            uncov.sort(key=lambda x: x[1], reverse=True)
            top = uncov[:30]

            if top:
                names_top  = [f"{n}  (0x{addr:08x})" for n, _, addr in top]
                sizes_top  = [sz for _, sz, _ in top]

                fig, ax = plt.subplots(figsize=(10, max(4, len(top) * 0.35)))
                bars = ax.barh(range(len(top)), sizes_top,
                               color='#e05a5a', edgecolor='none', height=0.7)
                ax.set_yticks(range(len(top)))
                ax.set_yticklabels(names_top, fontsize=8)
                ax.invert_yaxis()
                ax.set_xlabel('Function size (bytes)')
                ax.set_title(
                    f'Top {len(top)} Uncovered Functions (by size)\n'
                    f'Total uncovered: {len(uncov):,} / {self._sa_total_funcs:,}',
                    fontsize=11)
                ax.grid(True, axis='x', alpha=0.3)

                # 막대 끝에 크기 숫자
                for bar, sz in zip(bars, sizes_top):
                    ax.text(bar.get_width() + max(sizes_top) * 0.01,
                            bar.get_y() + bar.get_height() / 2,
                            str(sz), va='center', fontsize=7, color='#555')

                plt.tight_layout()
                uncov_file = graph_dir / 'uncovered_funcs.png'
                plt.savefig(uncov_file, dpi=150, bbox_inches='tight')
                plt.close()
                log.info(f"[StatGraph] 미커버 함수 Top-{len(top)} → {uncov_file}")

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
                       if self.cmd_pcs[name] or self.cmd_traces[name]]
        if not active_cmds:
            log.warning("[Heatmap] No coverage data to visualize")
            return

        # v4.4: 명령어 수 제한 — 너무 많으면 PC 수 기준 상위 MAX개만 표시
        MAX_HEATMAP_CMDS = 40
        if len(active_cmds) > MAX_HEATMAP_CMDS:
            log.info(f"[Heatmap] {len(active_cmds)} commands detected, "
                     f"limiting to top {MAX_HEATMAP_CMDS} by PC count")
            active_cmds.sort(key=lambda n: len(self.cmd_pcs.get(n, set())),
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

            # Edge 빈도 행렬 구성 — traces에서 도출
            edge_matrix = np.zeros((n_bins_2d, n_bins_2d))
            unique_edges: Set[Tuple[int, int]] = set()

            for trace in self.cmd_traces[cmd_name]:
                for ti in range(len(trace) - 1):
                    p, c = trace[ti], trace[ti + 1]
                    unique_edges.add((p, c))
                    if addr_start <= p <= addr_end and addr_start <= c <= addr_end:
                        bx = (p - addr_start) // bin_size_2d
                        by = (c - addr_start) // bin_size_2d
                        if 0 <= bx < n_bins_2d and 0 <= by < n_bins_2d:
                            edge_matrix[by][bx] += 1

            if not unique_edges:
                ax.set_visible(False)
                continue

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
            ax.set_title(f'{cmd_name}  —  {len(unique_edges)} edges, '
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
        ps_tag = (f" | PS{self._current_ps}"
                  f"(×{PS_TIMEOUT_MULT.get(self._current_ps, 1)}TO"
                  f"{',Admin' if self._current_ps in (3, 4) else ''})"
                  if self.config.pm_inject_prob > 0 else "")
        log.warning(f"[Stats] exec: {stats['executions']:,} | "
                 f"corpus: {stats['corpus_size']} | "
                 f"crashes: {stats['crashes']} | "
                 f"pcs: {stats['coverage_unique_pcs']:,} | "
                 f"samples: {stats['total_samples']:,} | "
                 f"last_run: {last_samples} | "
                 f"exec/s(avg): {stats['exec_per_sec']:.1f} | "
                 f"exec/s(win): {window_eps:.1f}"
                 f"{ps_tag}")
        if self._sa_loaded:
            sa_parts = []
            if self._sa_total_code > 0:
                pct = 100.0 * self._sa_covered_addrs / self._sa_total_code
                sa_parts.append(
                    f"code: {pct:.1f}% ({self._sa_covered_addrs:,}/{self._sa_total_code:,})")
            if self._sa_total_funcs > 0:
                n_f = len(self._sa_entered_funcs)
                fpct = 100.0 * n_f / self._sa_total_funcs
                sa_parts.append(f"funcs: {n_f}/{self._sa_total_funcs} ({fpct:.1f}%)")
            if sa_parts:
                log.warning(f"[StatCov] {' | '.join(sa_parts)}")

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
                 f"go_settle={self.config.go_settle_ms}ms, "
                 f"max={self.config.max_samples_per_run}/run, "
                 f"idle_sat={self.config.saturation_limit}, "
                 f"global_sat={self.config.global_saturation_limit}, "
                 f"post_cmd={self.config.post_cmd_delay_ms}ms")
        log.warning(f"Power Sched : max_energy={self.config.max_energy}")
        # v4.3: 로그 메시지 수정 — 실제 구현은 subprocess(nvme-cli) 방식
        log.warning(f"NVMe I/O    : subprocess (nvme-cli passthru)")
        if self.config.pm_inject_prob > 0:
            log.warning(f"PM Rotate   : interval={PM_ROTATE_INTERVAL}cmds, "
                        f"mode=random(PS0~PS4), "
                        f"timeout_mult=PS1×{PS_TIMEOUT_MULT[1]} PS2×{PS_TIMEOUT_MULT[2]}")
        if self._sa_loaded:
            sa_info = []
            if self._sa_total_code > 0:
                sa_info.append(f"code_addrs={self._sa_total_code:,}")
            if self._sa_total_funcs > 0:
                sa_info.append(f"funcs={self._sa_total_funcs:,}")
            log.warning(f"StaticAnalysis: {', '.join(sa_info)}")
        else:
            log.warning("StaticAnalysis: not loaded (code_addrs.txt / functions.txt 없음)")
        log.warning(f"Random gen  : {self.config.random_gen_ratio:.0%}")
        timeout_str = ", ".join(f"{k}={v}ms" for k, v in self.config.nvme_timeouts.items())
        log.warning(f"Timeouts    : subprocess={timeout_str}")
        passthru_days = self.config.nvme_passthru_timeout_ms / 86_400_000
        log.warning(f"Passthru TO : {self.config.nvme_passthru_timeout_ms}ms "
                    f"({passthru_days:.1f}일, nvme-cli --timeout)")
        log.warning(f"Kernel TO   : {self.config.nvme_kernel_timeout_sec}s "
                    f"(crash 후 커널 reset 유예, nvme_core admin/io_timeout)")
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

        if self.sampler.idle_pcs:
            pcs_str = ', '.join(hex(p) for p in sorted(self.sampler.idle_pcs))
            log.warning(f"Idle PCs    : {pcs_str} ({len(self.sampler.idle_pcs)} addrs)")
        else:
            log.warning("Idle PCs    : not detected (saturation = global PC only)")

        # nvme_core 모듈 타임아웃 파라미터 설정 (crash 상태 보존).
        # _log_smart() 이후에 설정: 이전에 실행하면 admin_timeout=30일 상태에서
        # smart-log ioctl이 제출되어, SSD 응답이 조금 느릴 때 커널이 계속 기다리고
        # Python 10초 timeout이 먼저 터지는 문제 방지.
        self._configure_nvme_timeouts()

        # v4.5: 초기 시드 Calibration
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
            os.close(devnull_fd)
            try:
                for i, seed in enumerate(self.corpus):
                    seed = self._calibrate_seed(seed)
                    calibrated_corpus.append(seed)
                    stable_cnt = len(seed.stable_pcs) if seed.stable_pcs else 0
                    all_cnt    = len(seed.covered_pcs) if seed.covered_pcs else 0
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
                   f"{'StablePCs':>{W_STB}} {'AllPCs':>{W_ALL}}")
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
                        f"Global PCs: {len(self.sampler.global_coverage)}  |  "
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
        self._window_t0 = self.start_time          # 구간별 exec/s 계산용
        self._window_exec0: int = 0

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
                        if base_seed is None:
                            cmd = random.choice(self.commands)
                            fuzz_data = os.urandom(random.randint(64, 512))
                            mutated_seed = Seed(data=fuzz_data, cmd=cmd)
                            self.mutation_stats["random_gen"] += 1
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

                # v5.1: 현재 PS 상태별 실행 카운트
                if self.config.pm_inject_prob > 0:
                    self.ps_exec_counts[self._current_ps] += 1

                # PS3/PS4: IO 명령 → Admin 명령으로 대체
                if self.config.pm_inject_prob > 0 and self._current_ps in (3, 4):
                    if cmd.cmd_type == NVMeCommandType.IO:
                        admin_cmds = [c for c in self.commands
                                      if c.cmd_type == NVMeCommandType.ADMIN]
                        if admin_cmds:
                            fallback_cmd = random.choice(admin_cmds)
                            fuzz_data = os.urandom(random.randint(64, 512))
                            mutated_seed = Seed(data=fuzz_data, cmd=fallback_cmd)
                            cmd = fallback_cmd
                            log.debug(f"[PM] PS{self._current_ps} IO→Admin 대체: {cmd.name}")

                # NVMe 커맨드 전송
                _timeout_mult = PS_TIMEOUT_MULT.get(self._current_ps, 1) \
                    if self.config.pm_inject_prob > 0 else 1
                rc = self._send_nvme_command(fuzz_data, mutated_seed,
                                             timeout_mult=_timeout_mult)
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

                # v4.5+: PC 기반 커버리지 평가 (primary signal)
                is_interesting, new_pcs = self.sampler.evaluate_coverage()

                # v5.1: 정적 분석 커버리지 증분 업데이트
                if self._sa_loaded and self.sampler._last_new_pcs:
                    self._update_static_coverage(self.sampler._last_new_pcs)

                # v4.3: 실제 실행 opcode 기준으로 분류하여 기록
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
                det_tag = " [Det]" if is_det_stage else ""
                mopt_tag = f" mopt={self.mopt_mode}" if self.config.mopt_enabled else ""
                log.info(f"exec={self.executions}{det_tag} cmd={cmd.name} "
                          f"raw_samples={raw_count} pcs_this_run={len(self.sampler.current_trace)} "
                          f"out_of_range={oor_count} new_pcs={new_pcs} "
                          f"global_pcs={len(self.sampler.global_coverage)} "
                          f"last_new_at={self.sampler._last_new_at}{mopt_tag} "
                          f"stop={self.sampler._stopped_reason}")

                if self.sampler._unique_at_intervals:
                    log.debug(f"  saturation: {self.sampler._unique_at_intervals}")
                if self.sampler._last_raw_pcs:
                    all_pcs = [hex(pc) for pc in self.sampler._last_raw_pcs]
                    log.debug(f"  ALL raw PCs: {all_pcs}")

                # --- Timeout / Error 처리 ---
                if rc == self.RC_TIMEOUT:
                    self._handle_timeout_crash(mutated_seed, fuzz_data)
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
                        new_pcs=new_pcs,
                        # 이 실행에서 방문한 PC 주소 집합 — culling의 favored 판정 기준
                        # PC 주소는 결정론적이므로 별도 필터링 불필요
                        covered_pcs=set(self.sampler.current_trace),
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
                             f"+{new_pcs} PCs (total: {len(self.sampler.global_coverage)} pcs)")

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
                    # exec/s(win) 계산을 PM 전환 전에 먼저 수행:
                    # PM 전환 시간(wake-up latency 등)이 직전 100개 명령의 속도를
                    # 왜곡하지 않도록, 명령 실행이 끝난 시점 기준으로 계산.
                    _now = datetime.now()
                    _wdt = (_now - self._window_t0).total_seconds()
                    _wexec = self.executions - self._window_exec0
                    _window_eps = _wexec / _wdt if _wdt > 0 else 0

                    # v5.1: PM 로테이션 — exec/s 계산 후 PS 전환
                    if self.config.pm_inject_prob > 0:
                        next_ps = random.randint(0, 4)
                        log.warning(
                            f"[PM] PS 상태 전환: PS{self._current_ps} → PS{next_ps}"
                            + (f" (timeout ×{PS_TIMEOUT_MULT[next_ps]})"
                               if PS_TIMEOUT_MULT[next_ps] > 1 else "")
                            + (" [Admin only]" if next_ps in (3, 4) else "")
                        )
                        self._pm_set_state(next_ps)
                        self._current_ps = next_ps
                        self.ps_enter_counts[next_ps] += 1

                    # 윈도우 리셋은 PM 전환 완료 후 — 전환 시간이 다음 윈도우에도 포함되지 않음
                    self._window_t0 = datetime.now()
                    self._window_exec0 = self.executions

                    # v5.1: 정적 분석 성장 곡선 스냅샷
                    if self._sa_loaded:
                        _elapsed_snap = (datetime.now() - self.start_time).total_seconds() \
                                        if self.start_time else 0
                        _cpct = (100.0 * self._sa_covered_addrs / self._sa_total_code
                                 if self._sa_total_code > 0 else 0.0)
                        _fpct = (100.0 * len(self._sa_entered_funcs) / self._sa_total_funcs
                                 if self._sa_total_funcs > 0 else 0.0)
                        self._sa_cov_history.append(
                            (self.executions, _elapsed_snap, _cpct, _fpct))

                    stats = self._collect_stats()
                    self._print_status(stats, last_samples,
                                       window_eps=_window_eps)
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

            # v4.3: 퍼징 종료 후 SMART 기록
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
                if self.config.pm_inject_prob > 0:
                    summary_lines.append(f"PM Rotate interval: {PM_ROTATE_INTERVAL}cmds (random PS0~PS4)")
                    for ps in range(5):
                        cnt = self.ps_exec_counts.get(ps, 0)
                        enters = self.ps_enter_counts.get(ps, 0)
                        if cnt > 0 or enters > 0:
                            pct = 100 * cnt / total
                            mult = PS_TIMEOUT_MULT.get(ps, 1)
                            note = f" [TO×{mult}]" if mult > 1 else \
                                   (" [Admin only]" if ps in (3, 4) else "")
                            summary_lines.append(
                                f"  PS{ps}: 실행 {cnt}회 ({pct:.1f}%), 진입 {enters}회{note}")

                # v5.1: 정적 분석 커버리지 요약
                if self._sa_loaded:
                    if self._sa_total_code > 0:
                        pct = 100.0 * self._sa_covered_addrs / self._sa_total_code
                        summary_lines.append(
                            f"Code Coverage    : {pct:.2f}%"
                            f" ({self._sa_covered_addrs:,} / {self._sa_total_code:,} instrs)")
                    if self._sa_total_funcs > 0:
                        n_f = len(self._sa_entered_funcs)
                        fpct = 100.0 * n_f / self._sa_total_funcs
                        summary_lines.append(
                            f"Func Coverage    : {fpct:.2f}%"
                            f" ({n_f} / {self._sa_total_funcs} functions)")

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
                self._generate_static_coverage_graphs()
            except Exception as e:
                log.error(f"Static coverage graph generation failed: {e}")

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
                # timeout crash가 아닌 정상 종료 시에만 타임아웃 복원
                self._restore_nvme_timeouts()

            # 정리 완료 — SIGINT 핸들러 복원
            if _old_sigint is not None:
                try:
                    _signal.signal(_signal.SIGINT, _old_sigint)
                except (OSError, ValueError):
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
    parser.add_argument('--interface', choices=['auto', 'jtag', 'swd'], default='auto',
                        help='J-Link 인터페이스 (default: auto). '
                             'auto=JTAG 먼저 시도 후 실패 시 SWD로 자동 전환. '
                             'jtag/swd=강제 지정')
    parser.add_argument('--pc-reg-index', type=int, default=None,
                        help='PC 레지스터 J-Link 인덱스 수동 지정. '
                             '자동 탐색 실패 시 jlink_reg_diag.py 로 확인 후 사용 '
                             '(Cortex-R8=9, Cortex-M=15, 아키텍처마다 다름)')
    parser.add_argument('--runtime', type=int, default=TOTAL_RUNTIME_SEC)
    parser.add_argument('--output', default=OUTPUT_DIR, help='Output dir')
    parser.add_argument('--seed-dir', default=SEED_DIR,
                        help='Seed directory path (load previous corpus as seeds)')
    parser.add_argument('--fw-bin', default=_FW_BIN_PATH,
                        help='[v4.7] 펌웨어 바이너리 경로 (FWDownload 실제 시드 생성, '
                             '없으면 더미 1KB 시드). 기본값: FW_BIN_FILENAME 설정')
    parser.add_argument('--fw-xfer', type=int, default=32768,
                        help='[v4.7] FWDownload 청크 크기(바이트), nvme fw-download -x 와 동일 '
                             '(default: 32768)')
    parser.add_argument('--fw-slot', type=int, default=1,
                        help='[v4.7] FWCommit 슬롯 번호 (default: 1)')
    parser.add_argument('--samples', type=int, default=MAX_SAMPLES_PER_RUN)
    parser.add_argument('--interval', type=int, default=SAMPLE_INTERVAL_US,
                        help='Sample interval (us). 0 = max density (기본값)')
    parser.add_argument('--go-settle', type=int, default=GO_SETTLE_MS,
                        help='Go() 후 CPU 최소 실행 보장 시간 (ms). '
                             '0=비활성화(JTAG/정상SWD). SWD+레벨시프터=50 권장. '
                             f'(default: {GO_SETTLE_MS})')
    parser.add_argument('--post-cmd-delay', type=int, default=POST_CMD_DELAY_MS,
                        help='Post-command sampling delay (ms)')
    parser.add_argument('--passthru-timeout', type=int, default=NVME_PASSTHRU_TIMEOUT_MS,
                        help='nvme-cli --timeout (ms). '
                             f'(default: {NVME_PASSTHRU_TIMEOUT_MS}ms = 30일)')
    parser.add_argument('--kernel-timeout', type=int, default=NVME_KERNEL_TIMEOUT_SEC,
                        help='nvme_core admin/io_timeout (초). crash 후 커널 reset 유예 시간. '
                             f'(default: {NVME_KERNEL_TIMEOUT_SEC}s = 24시간)')
    parser.add_argument('--addr-start', type=lambda x: int(x, 0), default=FW_ADDR_START,
                        help='Firmware .text start (hex)')
    parser.add_argument('--addr-end', type=lambda x: int(x, 0), default=FW_ADDR_END,
                        help='Firmware .text end (hex)')
    parser.add_argument('--resume-coverage', default=RESUME_COVERAGE,
                        help='Path to previous coverage.txt')
    parser.add_argument('--saturation-limit', type=int, default=SATURATION_LIMIT,
                        help='Stop sampling after N consecutive idle PCs (0=disable)')
    parser.add_argument('--global-saturation-limit', type=int, default=GLOBAL_SATURATION_LIMIT,
                        help='Stop sampling after N consecutive non-new global PCs (0=disable)')
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

    # v4.7: idle 유니버스 수렴 설정
    parser.add_argument('--diagnose-stability', type=int, default=DIAGNOSE_STABILITY,
                        help=f'idle 유니버스 수렴 조건: 새 PC 없이 연속 N회 (default: {DIAGNOSE_STABILITY}). '
                             'SWD에서 주기적 인터럽트를 모두 포함하려면 크게 설정')
    parser.add_argument('--diagnose-max', type=int, default=DIAGNOSE_MAX,
                        help=f'idle 유니버스 수집 최대 샘플 수 (default: {DIAGNOSE_MAX})')

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

    # v5.1: PM injection
    parser.add_argument('--pm', action='store_true', default=False,
                        help=f'PM 로테이션 활성화: {PM_ROTATE_INTERVAL}명령마다 PS0→PS1→PS2→PS3→PS4 순환. '
                             f'PS1 timeout×{PS_TIMEOUT_MULT[1]}, PS2 timeout×{PS_TIMEOUT_MULT[2]}, '
                             f'PS3/PS4 Admin 명령만 허용')

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
    print("  - Global PC saturation (configurable) + idle PC detection")
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
    print(f"  - [v4.6] io-passthru → namespace device (/dev/nvme0n1, deprecated ioctl 제거)")
    passthru_days = args.passthru_timeout / 86_400_000
    print(f"  - [v4.6] Passthru timeout={args.passthru_timeout}ms ({passthru_days:.1f}일, "
          f"커널 reset 방지, subprocess 감지={NVME_TIMEOUTS.get('command', 8000)}ms)")
    print(f"  - [v4.6] Crash 시 nvme-cli 프로세스 보존 (fd 유지 → SSD 상태 {passthru_days:.1f}일 보존)")
    print()

    config = FuzzConfig(
        device_name=args.device,
        interface={
            'auto': None,
            'jtag': pylink.enums.JLinkInterfaces.JTAG,
            'swd':  pylink.enums.JLinkInterfaces.SWD,
        }[args.interface],
        jtag_speed=args.speed,
        pc_reg_index=args.pc_reg_index,
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
        go_settle_ms=args.go_settle,
        post_cmd_delay_ms=args.post_cmd_delay,
        nvme_passthru_timeout_ms=args.passthru_timeout,
        nvme_kernel_timeout_sec=args.kernel_timeout,
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
        # v4.7
        diagnose_stability=args.diagnose_stability,
        diagnose_max=args.diagnose_max,
        # v4.5
        calibration_runs=args.calibration_runs,
        deterministic_enabled=not args.no_deterministic,
        deterministic_arith_max=args.det_arith_max,
        mopt_enabled=not args.no_mopt,
        mopt_pilot_period=args.mopt_pilot_period,
        mopt_core_period=args.mopt_core_period,
        # v4.7
        fw_bin=args.fw_bin,
        fw_xfer_size=args.fw_xfer,
        fw_slot=args.fw_slot,
        # v5.1
        pm_inject_prob=1.0 if args.pm else 0.0,
    )

    fuzzer = NVMeFuzzer(config)
    fuzzer.run()