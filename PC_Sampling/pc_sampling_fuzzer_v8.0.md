# PC Sampling SSD Firmware Fuzzer v8.0

OpenOCD PCSR 비침습 샘플링 + `nvme-cli` passthru 기반 Coverage-Guided + State-Aware Fuzzer.

**v8.0 핵심: 제품(Target) 일반화 + 신규 제품 P9(Cortex-R5·SWD)**
모든 target-specific 값을 제품별 **`PRODUCT_PROFILES`** 한 곳으로 모아 데이터 주도로 만들었다.
신규 제품 추가는 이 dict 에 레코드 하나만 추가하면 된다(코드 수정 없음).

v7.7 PM Robustness Perturbation(S1+S2), v7.6 시각화, v7.5 SequenceSeed corpus, v7.8
`--unsupported-skip`/`--no-jlink` 등 **기존 기능은 모두 그대로 유지**. 상세는
`pc_sampling_fuzzer_v7.8.md` 참조 — 이 문서는 v8.0 변경분만 다룬다.

---

## 지원 제품

| 제품 | interface | core | OpenOCD cfg | J-Link device | UFAS | J-Link dump | 상태 |
|------|-----------|------|-------------|---------------|------|-------------|------|
| **PM9M1** | SWD | 3 (R8) | `r8_pcsr.cfg` | Cortex-R8 | ✅ | ✅ | 정상 |
| **BM9H1** | JTAG | 2 (R8) | `r8_pcsr_jtag.cfg` | Cortex-R8 | ✅ | ✅ | 정상 |
| **P9** | SWD | R5 (TBD) | `r5_pcsr.cfg` | Cortex-R5 | ❌ | ❌ | **bring-up 필요** (`P9_BRINGUP.md`) |

```bash
sudo python3 pc_sampling_fuzzer_v8.0.py --product PM9M1 --nvme /dev/nvme0n1
sudo python3 pc_sampling_fuzzer_v8.0.py --product BM9H1 --nvme /dev/nvme0n1
# P9: bring-up 값 입력 전엔 --no-jlink 로 NVMe/PM 만 (coverage 0)
sudo python3 pc_sampling_fuzzer_v8.0.py --product P9 --nvme /dev/nvme0n1 --no-jlink
```

---

## v8.0 변경사항

### 1. Target Profile 일반화 (`PRODUCT_PROFILES`)

기존: `PRODUCT_CONFIGS` 는 `{interface, openocd_config}` 2필드뿐 → PCSR 주소/jlink device/덤프
정책 등은 코드에 하드코딩되거나 **interface(swd/jtag) 기준으로만** 갈렸다. 그래서 "SWD 인데 R8 과
다른 P9" 를 담을 수 없었다(예: PCSR 주소가 `interface=='jtag'?...:...` 로만 선택됨).

신규: 제품별 레코드에 **모든 target-specific 값**을 둔다.

| 필드 | 의미 |
|------|------|
| `interface` | `swd` / `jtag` |
| `openocd_config` | OpenOCD cfg 파일명 |
| `jlink_device` | JLinkExe `-device` 문자열 |
| `tcl_prefix` | OpenOCD cfg 가 만든 target object 접두사 (`r8`/`r5`). Python TCL(`<prefix>.dap/.abp/.axi`)이 이 값으로 보간됨 |
| `pcsr_addrs` | per-core DBGPCSR 주소 리스트 (**코어 수 = len**) |
| `power_addr` / `power_mask` | per-core debug power-up 레지스터. `None` 이면 power-up 단계 **생략** |
| `invalid_pc_vals` | PCSR 필터에서 제외할 DPIDR/IDCODE 값 |
| `fw_addr_start` / `fw_addr_end` | 펌웨어 .text(coverage 필터) 범위 |
| `enable_ufas` / `ufas_ini` | crash 시 UFAS 덤프 on/off + ini |
| `enable_jlink_dump` | crash 시 J-Link 메모리 덤프 on/off |

`--product` 선택지는 `PRODUCT_PROFILES.keys()` 에서 자동 생성. `--interface` 만 쓰는 **구식 호출도
그대로 동작**(R8 기본 profile 합성). PM9M1/BM9H1 의 resolved 값은 v7.7/v7.8 과 **byte-identical**.

### 2. 신규 제품 P9 (Cortex-R5, SWD)

- profile + `r5_pcsr.cfg` 템플릿 + 코드 경로 구현 완료.
- **UFAS·J-Link 메모리 덤프 둘 다 불가** → P9 profile 에서 영구 비활성. crash 시 stuck PC /
  dmesg / replay.sh 만 생성.
- coverage 는 OpenOCD PCSR 로 수집(bring-up 후). HW 값(코어 수/PCSR 주소/DPIDR/범위)은
  **placeholder** 상태 → **`P9_BRINGUP.md` 의 "사용자 입력 필요" 표대로 채우면 완료.**
- placeholder 가 빈 채 `--product P9`(J-Link 사용) 실행 시 **명확한 에러로 중단**.
  `--no-jlink` 면 NullSampler(coverage 0)라 통과 → NVMe/PM 만 검증 가능.

### 3. 가성 불량 방지 — 호스트 전송로 깨는 admin opcode 전송 차단

`nvme passthru`는 **kernel 소유 I/O 큐**를 쓰므로, 큐 관리 admin 명령을 보내면 firmware 결함이
아니라 호스트 전송로만 깨져 timeout(가성)이 난다. 예: opcode mutation + admin↔IO swap이 겹쳐
`nvme admin-passthru --opcode=0x00`(Delete I/O SQ)가 만들어지면 kernel I/O 큐가 삭제되고 이후
io-passthru가 무응답 → timeout → 불량 오판.

방지: **최종 해석된 명령이 `admin-passthru` 이고 opcode가 차단 세트면 전송 자체를 안 한다.**

- 차단 세트 `BLOCKED_ADMIN_OPCODES = {0x00,0x01,0x04,0x05,0x0C,0x7C}`
  (Create/Delete I/O SQ·CQ, AER, Doorbell Buffer Config) — 모두 가성/무한 block 유발.
- **admin-passthru 일 때만** 차단 → 같은 번호의 IO 명령(Flush/Write/WriteUncorrectable/Compare/
  Verify)은 정상 동작.
- 이중 방어: `_mutate`(예방, override/force_admin 되돌림) + `_send_nvme_command`(net, `RC_SKIP`
  반환 → 회계/커버리지/크래시 미반영). seed-from-disk·replay·sequence 등 모든 경로 커버.
- 종료 summary에 `Blocked admin opcode: N회` 출력.
- 범위 밖(이번 제외): Format 0x80/Sanitize 0x84 mutation(데이터 손실 — 별도), FWCommit 0x10(의도),
  vendor 0xC0~0xFF(의도, `--unsupported-skip`가 담당).

### 4. 코드 영향 범위 (v7.8 → v8.0)

| 사이트 | 변경 |
|--------|------|
| `PRODUCT_PROFILES`/`PRODUCT_CONFIGS` | 2필드 → full profile + 하위호환 뷰 |
| `FuzzConfig` | `tcl_prefix/pcsr_addrs/power_addr/power_mask/invalid_pc_vals/ufas_ini` 추가 |
| 샘플러 `__init__` | `_pcsr_addrs`/`_invalid_pc_mask` 를 profile 에서, `_tcl_prefix` 보관 |
| `_send_startup_tcl` | `r8.*` → `{tcl_prefix}.*`, power-up 은 `power_addr=None` 시 생략 |
| `_run_ufas_dump` | `--ini` 하드코딩 → `ufas_ini`(None 이면 생략) |
| `main()` 제품 해석 | full profile 주입 + bring-up placeholder 가드 + UFAS/JLink dump = profile ∧ CLI |
| `BLOCKED_ADMIN_OPCODES` / `RC_SKIP` | 신규 상수 (가성 방지 가드) |
| `_send_nvme_command` | admin-passthru + 차단 opcode → `RC_SKIP` 반환(전송 안 함) |
| `_mutate` | mutation 결과가 (admin+차단 opcode)면 override/force_admin 되돌림 |
| `_account_command` | `RC_SKIP` 조기 반환(회계 없이 continue) |

---

## 새 제품 추가 방법 (향후)

`PRODUCT_PROFILES` 에 레코드 1개 추가 + OpenOCD cfg 1개 작성이면 끝(코드 수정 불필요):

```python
'NEW': {
    'interface': 'swd', 'openocd_config': 'rX_pcsr.cfg',
    'jlink_device': 'Cortex-RX', 'tcl_prefix': 'rX',
    'pcsr_addrs': [0x..., ...], 'power_addr': 0x... or None, 'power_mask': 0x...,
    'invalid_pc_vals': (0x..., 0x...),
    'fw_addr_start': 0x0, 'fw_addr_end': 0x...,
    'enable_ufas': True/False, 'ufas_ini': '...' or None,
    'enable_jlink_dump': True/False,
},
```

---

## 검증 (구현 시 수행함)

- `python3 -c "import ast; ast.parse(...)"` 문법 OK.
- backward-compat: PM9M1/BM9H1 의 interface/cfg/jlink/pcsr_addrs/power/addr_range/invalid_pc_mask 가
  v7.8 상수와 동일함을 스크립트로 확인.
- `--help` 에 `--product {PM9M1,BM9H1,P9}` 노출 확인.
- `--product P9`(J-Link) → bring-up placeholder 가드 동작 확인.

남은 작업은 평가 환경에서의 **P9 HW bring-up** → `P9_BRINGUP.md` 참조.
