# P9 (Cortex-R5 / SWD) Bring-up — 사용자 입력 필요 항목

v8.0 에서 P9 제품 **골격(profile + r5 cfg + 코드 경로)** 은 구현 완료. 단, R5 는 현재
**J-Link 연결만** 확인된 상태라 OpenOCD PCSR 샘플링(coverage)에 필요한 **하드웨어 값들이
비어 있음(placeholder)**. 평가 환경에서 아래 값을 확보해 채우면 P9 가 정상 동작한다.

> 값을 채우기 전에도 **`--product P9 --no-jlink`** 로 NVMe/PM 경로(coverage 0)는 바로 테스트 가능.
> bring-up 값이 빈 채 `--product P9` (J-Link 사용)로 실행하면 명확한 에러로 중단된다.

---

## 채워야 할 위치 (딱 두 파일)

### A. `pc_sampling_fuzzer_v8.0.py` → `PRODUCT_PROFILES['P9']`

| 필드 | 의미 | R8 참고값 | P9 확보 방법 | 상태 |
|------|------|-----------|-------------|------|
| `pcsr_addrs` | per-core DBGPCSR(샘플 PC) 주소 **리스트** = `[CoreBase + offset, ...]`. **리스트 길이 = 코어 수.** | `[0x80030084, 0x80032084, 0x80034084]` (CoreBase+0x84) | ROM table 로 각 코어 debug base 확인 + R5 DBGPCSR offset(아래) 더하기 | ⬜ |
| `invalid_pc_vals` | PCSR 필터에서 제외할 R5 **SWD DPIDR** 값들 (tuple) | `(0x6ba02476, 0x6ba02477)` | OpenOCD 연결 로그의 DPIDR, 또는 `jlink_reg_diag.py` | ⬜ |
| `fw_addr_start` / `fw_addr_end` | 펌웨어 .text(coverage 필터) 주소 범위 | `0x0` / `0x3B7FFF` | Ghidra / map 파일 | ⬜ |
| `power_addr` | per-core debug power-up 레지스터 주소 (AXI write). **R5 에서 불필요하면 `None` 유지** | `0x30313f30` | 칩 디버그 문서 / R8 설정 참고. 불확실하면 우선 `None` 로 두고 PCSR 읽힘 확인 | ⬜ |
| `power_mask` | 위 레지스터의 코어별 enable 비트 | `0x00010101` (bit0/8/16) | 위와 동일 | ⬜ |

> `power_addr`/`power_mask` 가 `None` 이면 코드가 **power-up 단계를 자동 생략**한다.
> SWD 에서는 OpenOCD 가 CDBGPWRUPREQ 를 자동 처리하는 경우가 많으니, **먼저 `None` 으로 두고**
> PCSR 가 읽히는지 확인 → 안 읽히면 그때 값 입력.

### B. `r5_pcsr.cfg`

| 항목 | 의미 | R8 참고 | 상태 |
|------|------|---------|------|
| `swd newdap r5 cpu -expected-id 0x????????` | R5 SWD DPIDR. 모르면 줄 주석 처리 → 자동검출 → 로그값 고정 | — | ⬜ |
| `target create r5.abp ... -ap-num N` | DBGPCSR 읽는 **APB-AP** 번호 | R8=0 | ⬜ |
| `target create r5.axi ... -ap-num N` | power-up 쓰는 **AXI-AP** 번호 (power 안 쓰면 무시) | R8=1 | ⬜ |
| `adapter speed` | 안정 동작 속도 | 4000 | ⬜ (필요 시 조정) |

> cfg 의 target 이름 접두사(`r5`)는 profile 의 `tcl_prefix='r5'` 와 **반드시 일치**.

---

## 확정해야 할 사실 (HW/문서)

1. **코어 수** — R5 몇 코어를 샘플링? (`pcsr_addrs` 리스트 길이로 표현)
2. **각 코어 debug base 주소** + **R5 DBGPCSR offset** — ARMv7-R 디버그에서 DBGPCSR 은 보통
   `0x0A0`(또는 구현에 따라 `0x084`). R8 은 `+0x84` 였음. **이 offset 확인이 `pcsr_addrs` 의 핵심.**
3. **R5 SWD DPIDR** — cfg `-expected-id` + `invalid_pc_vals` 양쪽에 사용.
4. **DAP AP 레이아웃** — 어느 AP 가 APB(메모리/DBGPCSR), 어느 AP 가 AXI(power)인지.
5. **debug power-up 필요 여부** — R5 에서 per-core AXI power write 가 필요한지 (불필요하면 생략).
6. **펌웨어 .text 범위** — coverage 필터용.
7. **JLinkExe `-device` 문자열** — 현재 `'Cortex-R5'` 로 설정. 실제 장치명과 일치하는지 확인.

---

## 권장 bring-up 순서

1. **`--product P9 --no-jlink`** 로 NVMe/PM 경로부터 정상 확인 (coverage 0, OpenOCD 불필요).
2. `jlink_reg_diag.py --device Cortex-R5 --interface swd` 로 R5 SWD 연결 + DPIDR + PC reg 확인.
3. `r5_pcsr.cfg` 의 ap-num/DPIDR 채우고 `openocd -f r5_pcsr.cfg` 단독 실행 → telnet(4444) 에서
   `r5.abp read_memory 0x<DBGPCSR> 32 1` 로 **한 코어 PCSR 수동 읽기** 성공시키기.
   - 여기서 확정된 DBGPCSR 주소 = `pcsr_addrs` 항목.
4. 모든 코어 주소를 `PRODUCT_PROFILES['P9']['pcsr_addrs']` 에 입력, `fw_addr_*` / `invalid_pc_vals` 입력.
5. **`--product P9`** (J-Link) 실행 → 로그 `[OpenOCD] 연결 성공: PCSR read 검증 완료 (N코어)` 확인.
6. crash 시 UFAS/J-Link 덤프는 P9 에서 **영구 비활성**(profile) — stuck PC / dmesg / replay.sh 만 생성됨(정상).

---

## 현재 고정(변경 불필요)된 P9 설정

- `interface='swd'`, `openocd_config='r5_pcsr.cfg'`, `jlink_device='Cortex-R5'`, `tcl_prefix='r5'`
- `enable_ufas=False`, `enable_jlink_dump=False` (사용자: "UFAS·J-Link 덤프 둘 다 불가")
