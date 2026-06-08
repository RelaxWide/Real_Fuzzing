# P9 (Cortex-R5 / SWD) Bring-up

v8.0에서 P9는 **halt 기반 coverage 샘플러**(`sampler_type='halt'`)로 대응한다.
조사 결과 **P9는 DBGPCSR(비침습 PC 샘플)을 구현하지 않음**(DBGDIDR 0x77040013, 모든 PCSR
오프셋 0) — 그래서 메인 PCSR 방식 대신, 이 프로젝트의 원래 방식(v2~v5.6)인
**halt → reg pc → resume**를 OpenOCD telnet으로 되살려 쓴다. (ETM은 트레이스 핀 없어 불가.)

확정된 HW 구성 (J-Link connect로 검증):
- SW-DP 0x6BA02477, **AP[0]=APB-AP 단일**, ROMTbl 0x80020000→**0x80030000 Cortex-R5 (단일코어)**
- `targets r5 → halt → reg pc → PC 읽힘 ✓` (halt 방식 동작 확인됨)

---

## 바로 실행 가능 (추가 입력 없이)

```bash
sudo python3 pc_sampling_fuzzer_v8.0.py --product P9 --nvme /dev/nvme0n1
```
`--product P9` 만으로 자동 설정됨: **halt 샘플러**, swd, `r5_pcsr.cfg`, Cortex-R5,
UFAS·J-Link덤프 off, **go_settle=50ms**. (`--sampler`/`--go-settle` 등 추가 옵션 불필요.)

전제: `r5_pcsr.cfg`가 폴더에 있고, 그 안에 cortex_r 타깃이 `target create r5 cortex_r4 -dap r5.dap
-ap-num 0 -dbgbase 0x80030000` 로 정의돼 있을 것(이미 포함됨).

---

## 평가 환경에서 확인/튜닝할 것 (동작은 하되 품질 관련)

| 항목 | 의미 | 방법 | 상태 |
|------|------|------|------|
| **halt vs NVMe timeout** (핵심) | halt가 단일 컨트롤러 CPU를 멈춰 NVMe 명령을 굶기면 timeout(가성) | NVMe write 도중 샘플링하며 명령 정상완료 확인. timeout 나면 `--go-settle` ↑ | ⬜ |
| **`--go-settle <ms>`** | resume→다음 halt 최소 실행시간. 기본 50(v5.6 "50ms 안정") | 안정 최소값 탐색(불안정하면 ↑, coverage 밀도 원하면 ↓) | ⬜ |
| **fw_addr_start/end** | 펌웨어 .text(coverage 주소필터). 미지정(None)이면 **전체 PC 카운트 + 경고**(동작엔 무방) | Ghidra/map으로 .text 범위 확인 후 `PRODUCT_PROFILES['P9']` 에 입력 | ⬜ |
| resume 진행 확인 | resume 후 코어가 reset 없이 진행(PC가 매번 바뀜) | 부하 주며 reg pc 변화 관찰 | ⬜ |

> PCSR을 안 쓰므로 `pcsr_addrs`/`power_addr`/`power_mask`/DBGPCSR 주소는 **불필요**(profile에서 None 유지).

---

## 권장 순서
1. `--product P9 --no-jlink` 로 NVMe/PM 경로부터 확인(coverage 0, OpenOCD 불필요).
2. `--product P9` (기본 halt) 실행 → 로그 `[OpenOCD] 연결 성공 ... (1코어)` + diagnose가 idle PC 수집되나.
3. **halt vs NVMe**: 명령 timeout이 잦으면 `--go-settle 100`(또는 ↑)로 안정값 탐색.
4. coverage 누적 확인(`evaluate_coverage` new PC>0) 후, fw_addr .text 범위 입력해 필터 정밀화.

## 고정된 P9 설정 (변경 불필요)
- `sampler_type='halt'`, `go_settle_ms=50`, interface=swd, `r5_pcsr.cfg`, jlink_device='Cortex-R5',
  tcl_prefix='r5', `enable_ufas=False`, `enable_jlink_dump=False`.
