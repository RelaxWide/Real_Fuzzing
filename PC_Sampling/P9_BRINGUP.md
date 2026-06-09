# P9 (Cortex-R5 / SWD) Bring-up

**v8.1: P9는 J-Link(pylink) halt 샘플러**(`sampler_type='jlink_halt'`)로 대응한다.
조사 결과 **P9는 DBGPCSR(비침습 PC 샘플)을 구현하지 않음**(DBGDIDR 0x77040013, 모든 PCSR
오프셋 0) → halt→PC→resume 가 유일. (ETM은 트레이스 핀 없어 불가.)

v8.0 의 OpenOCD-telnet halt(`sampler_type='halt'`)는 소켓 read 타임아웃(2s) < OpenOCD halt-ack
지연 시 desync → resume 누락 → R5 컨트롤러가 halt 로 굳어 NVMe hang 하는 문제가 있었다. v8.1 은
**pylink 로 J-Link 를 직접 제어**(`halt → register_read(PC) → JLINKARM_Go()`, 블로킹 API)해
이 desync 를 없앤다. 상세: `pc_sampling_fuzzer_v8.1.md`.

확정된 HW 구성 (J-Link connect로 검증):
- SW-DP 0x6BA02477, **AP[0]=APB-AP 단일**, ROMTbl 0x80020000→**0x80030000 Cortex-R5 (단일코어)**
- pylink `halt → register_read(R15) → JLINKARM_Go()` 동작 확인됨 (`jlink_reg_diag.py`)

---

## 바로 실행 가능 (추가 입력 없이)

```bash
pip3 install pylink-square                                  # 최초 1회 (install_fuzzer_deps.sh 에 포함)
sudo python3 pc_sampling_fuzzer_v8.1.py --product P9 --nvme /dev/nvme0n1
```
`--product P9` 만으로 자동 설정됨: **J-Link halt 샘플러(pylink)**, swd, Cortex-R5,
jlink_speed=4000, ap_index=0, PC 레지스터 자동 탐지, UFAS·J-Link덤프 off, **go_settle=50ms**.

전제: `pylink-square` 설치 + J-Link 가 P9 에 물려 있을 것. OpenOCD/`r5_pcsr.cfg` 는 **불필요**
(v8.1 J-Link 샘플러는 pylink 가 USB 를 직접 점유 — OpenOCD 미사용).

---

## 평가 환경에서 확인/튜닝할 것 (동작은 하되 품질 관련)

| 항목 | 의미 | 방법 | 상태 |
|------|------|------|------|
| **PC 레지스터 인덱스** (핵심) | pylink `register_read(idx)` 의 PC(R15) 인덱스. connect 시 자동 탐지 | 로그 `[J-Link] 연결 성공 ... PC reg index=N (name=...)` 확인. name 이 R15/PC 아니면 `jlink_reg_diag.py` 로 올바른 index 찾아 `--pc-reg-index N` 지정 | ⬜ |
| **halt vs NVMe timeout** | halt가 단일 컨트롤러 CPU를 멈춰 NVMe 명령을 굶기면 timeout(가성) | NVMe write 도중 샘플링하며 명령 정상완료 확인. timeout 나면 `--go-settle` ↑ | ⬜ |
| **`--go-settle <ms>`** | resume→다음 halt 최소 실행시간. 기본 50 | 안정 최소값 탐색(불안정하면 ↑, coverage 밀도 원하면 ↓) | ⬜ |
| **`--pc-reg-index N`** | PC 레지스터 인덱스 강제(자동 탐지 실패/오탐 시) | 위 진단으로 확인된 값 지정 | ⬜ |
| **fw_addr_start/end** | 펌웨어 .text(coverage 주소필터) | ✅ **확정: 0x0 ~ 0x9cffff** (Ghidra) → profile 반영됨 | ✅ |
| **BB/func 파일 배치** | BB/func 커버리지 통계(firmware_map/coverage_growth)용 | Ghidra 산출 파일을 **`basic_blocks_P9.txt` / `functions_P9.txt`** 이름으로 fuzzer 폴더에 둘 것 (제품별 분리 — PM9M1과 안 섞임) | ⬜ |
| resume 진행 확인 | resume 후 코어가 reset 없이 진행(PC가 매번 바뀜) | 부하 주며 PC 변화 관찰 | ⬜ |

> J-Link 직접 제어라 `pcsr_addrs`/`power_addr`/`power_mask`/OpenOCD cfg 모두 **불필요**.
> resume 은 항상 `JLINKARM_Go()`(CPU 리셋 없음) — `restart()` 는 절대 안 씀.

---

## 권장 순서
1. `pip3 install pylink-square` (최초 1회). `--product P9 --no-jlink` 로 NVMe/PM 경로부터 확인(coverage 0).
2. `--product P9` 실행 → 로그 `[J-Link] 연결 성공 ... PC reg index=N` + diagnose 가 idle PC 수집되나.
   - PC reg index name 이 R15/PC 가 아니면 `python3 jlink_reg_diag.py --device Cortex-R5 --interface swd`
     로 올바른 index 확인 후 `--pc-reg-index N`.
3. **halt vs NVMe**: 명령 timeout 이 잦으면 `--go-settle 100`(또는 ↑)로 안정값 탐색.
4. coverage 누적 확인(`evaluate_coverage` new PC>0). BB/func 통계 원하면 `basic_blocks_P9.txt`/
   `functions_P9.txt` 배치.

## 고정된 P9 설정 (변경 불필요)
- `sampler_type='jlink_halt'`, `go_settle_ms=50`, interface=swd, jlink_device='Cortex-R5',
  `jlink_speed=4000`, `jlink_ap_index=0`, `pc_reg_index=None`(자동), `enable_ufas=False`, `enable_jlink_dump=False`.
