# pc_sampling_fuzzer v9.7

> per-version 규칙: `v9.7.py` = `v9.6.py` byte-copy + 아래 편집만. 베이스라인 v9.6 은 불변.

## 한 줄 요약

**명령이 커널에서 튕겨 펌웨어에 도달하지 못하던 문제**를 고쳤다. 근본 원인은 **시드 파일을 크기
제한 없이 읽던 `_load_seeds`**, 증폭 요인은 **실제 커널 한계(128KB)의 16배였던 고정 상한 2MB**다.
상한을 런타임 실측값(`_max_xfer_bytes()`)으로 통일하고, 그래도 커널이 거부한 명령은 **커버리지
귀속에서 제외**한다.

## 왜 (문제 정의)

replay 를 돌렸더니 `rc=22`(EINVAL)가 무더기로 올라온 데서 출발했다. 조사 결과 **replay 생성기
문제가 아니었다** — `_cmd_history.append()`(L10127)가 `Popen`(L10169)보다 먼저라서 **전송조차 못 한
명령도 히스토리에 남는다.** 즉 원본도 같은 rc=22 로 실패했고 replay 는 그 실패를 충실히 재현하고
있었다. 재현성이 깨진 게 아니라 **원본이 이미 실패였는데 그걸 성공으로 착각**하고 있었다.

### 왜 EINVAL 인가 — 커널이 SQE 조립 전에 거부한다

`nvme *-passthru --data-len=N` 은 ioctl → `nvme_map_user_request` → `blk_rq_map_user_iov` 를 타는데
거기에 다음이 있다:

```c
if (len > (queue_max_hw_sectors(q) << SECTOR_SHIFT))
    return -EINVAL;
```

**NVMe 명령이 조립되기도 전에** 걷어차인다. 도어벨은 울리지 않고 컨트롤러는 아무것도 못 본다.
→ 그 iteration 은 **펌웨어를 전혀 실행하지 않는다.**

### 진짜 원인: 상한값 자체가 틀렸다

`MAX_DATA_BUF = 2MB` 는 **클라이언트 제품의 실제 커널 한계보다 크다**(보통 128KB~1MB).
그래서 여섯 개 `data_len` 분기가 **전부** 합법적으로 EINVAL 을 낼 수 있었다. 빠진 클램프 하나가
아니라 **상한이 틀린 것**이 문제다.

### 그 큰 `data` 는 어디서 왔나 — 시드 파일 (근본 원인)

처음엔 "havoc/splice 가 `seed.data` 를 무한히 키웠다"고 봤는데 **틀렸다.**
`_mutate_bytes`(L7020)·`_splice`(L7474)·LLM `data_hex`(L5399)는 전부 `max_input_len`(=128KB)로
캡하고 있고, 이 캡은 v9.3 부터 있었으며 config 값도 이력상 불변이다.

진짜 출처는 **`_load_seeds`(L4818)** 였다 — `seed.data` 를 만드는 경로 중 **유일하게 상한이 없던 곳**:

```python
with open(seed_file, 'rb') as f:
    data = f.read()          # 크기 제한 없음
```

`--seed-dir` 의 파일을 통째로 읽어 `Seed.data` 로 쓴다. 그리고 그 아래 루프는 **모든 명령에 대해**
같은 바이트로 Seed 를 하나씩 만든다(`for cmd in self.commands`, break 없음). Write 는
`needs_data=True` 라 분기 2 로 들어가고, 클램프가 없으니 **파일 크기가 그대로 `--data-len`** 이 된다.

관측된 `2,621,454` 는 변이 결과가 아니라 **파일 하나의 바이트 수**다. 4096 의 배수가 아닌 것도
당연하다 — 그냥 파일 길이다.

**왜 계속 재발했나:** 이 시드는 `found_at=0` 이라 **epoch 리셋에서 항상 살아남는다.** 지우거나
잘리기 전까지 캠페인 내내 남아서 같은 EINVAL 을 반복 생산했다.

## 변경 상세 (`pc_sampling_fuzzer_v9.7.py`)

| 위치 | 내용 |
|---|---|
| **125** | `FUZZER_VERSION = "9.7.0"` |
| 초기화(`_mdts_cache` 옆) | `_max_xfer_cache`/`_at`, `_last_cmd_submitted` |
| **`_max_xfer_bytes()`** (신규, `_get_mdts` 뒤) | 전송 상한 **단일 출처**. `XFER_CACHE_TTL`(5000) 캐싱, `MAX_XFER_HARD_CAP`(2MB) 백스톱, 값 변경 시 경고, 재조회 실패 시 직전 값 유지 |
| **`_invalidate_device_caches()`** (신규) | POR rescan 성공 / **FWCommit 성공(rc=0, opcode 0x10)** 시 `nsze`+`mdts`+`전송상한` 캐시 즉시 만료 |
| `_send_nvme_command` | `MAX_DATA_BUF` 상수 → `self._max_xfer_bytes()` |
| `_send_nvme_command` data_len 분기 2 | `len(data)` → `min(len(data), MAX_DATA_BUF)` — **여섯 분기 중 유일하게 빠져 있던 클램프** |
| `_send_nvme_command` rc 처리부 | NVMe status 파싱 실패(=errno) 시 `_last_cmd_submitted = False` |
| **`_load_seeds`** | **근본 원인** — 시드 파일을 `min(전송상한, max_input_len)` 로 절단 + 경고 로그 |
| `_generate_state_replay_sh` | 같은 두 수정(사본이라 동일 버그였음) |
| `_io_workload_limits` | 자체 MDTS 계산 → 공유 헬퍼 |
| `_mutate` [4] data_len / [7] structured payload | 후보 생성 상한도 실측값으로 |
| `_account_command`(coverage 평가 뒤) | **③ 귀속 차단** — 미제출이면 `is_interesting=False, new_pcs=0` |
| 주기 요약 출력 | `Unsubmitted (errno)` 비율 + `Max xfer limit` |

### `_max_xfer_bytes()` 권위 순서

```
① /sys/block/<ns>/queue/max_hw_sectors_kb   ← 커널의 최종값
② (1 << MDTS) * PAGE_SIZE                    ← sysfs 노드가 없을 때
③ IO_WL_MDTS_FALLBACK (256KB)                ← 둘 다 없을 때
                          → clip(512, ..., 2MB)
```

**①이 MDTS 보다 우선인 이유:** 커널 한계는 MDTS 단독이 아니라 `max_segments`·페이지 제약까지
`min` 한 값이다. MDTS 로만 계산하면 그 차이만큼 계속 샌다. 기존 `_io_workload_limits`(v9.6)가
정확히 그 상태였다.

### 캐시 정책 — 매번 읽지 않는다, 그러나 바뀌면 따라간다

sysfs 를 명령마다 읽지 않는다. `XFER_CACHE_TTL = 5000` exec 캐싱으로,
기존 `_get_mdts`/`_get_nsze`(둘 다 5000)와 같은 주기다.

**그런데 이 값은 런 도중 바뀔 수 있다.** `max_hw_sectors` 는 큐 생성 시 컨트롤러 Identify(MDTS)
+ 드라이버 제약으로 정해지므로, 큐가 다시 만들어지면 달라질 수 있다. 이 퍼저는 그런 사건을
**스스로 일으킨다**:

| 사건 | 왜 바뀔 수 있나 |
|---|---|
| **POR 전원 사이클 + PCIe remove/rescan** | 타임아웃 복구마다 발생. 큐가 통째로 재생성된다 |
| **FWCommit(펌웨어 활성화)** | 새 펌웨어가 다른 MDTS 를 광고할 수 있다. 이 퍼저는 FWCommit 을 퍼징한다(`excluded_opcodes` 비어 있고 `FWDownload→FWCommit` 시퀀스가 config 에 있음) |
| 컨트롤러 리셋 | 커널 타임아웃 처리 경로 |

TTL 만 믿으면 그 직후 **최대 5000 명령**을 옛 값으로 보낸다. 상한이 실제보다 크면 그 구간
전체가 EINVAL(펌웨어 미도달)이고, 작으면 불필요한 절단이다. 그래서 `_invalidate_device_caches()`
로 **사건 시점에 명시적으로 버린다.**

> **주의 — 기존 `_fw_commit_reset_pending` 과 조건을 공유하면 안 된다.** 그 플래그는
> `isinstance(self.sampler, JLinkHaltSampler)` 로 게이트된 **J-Link 재연결 전용** 장치다
> (FW 활성화 → R5 코어 리셋 → 타겟 디버그 끊김 → halt 복구). MDTS 변화는 **device 쪽 사건**이라
> 샘플러와 무관하므로, 무효화는 `_send_nvme_command` 의 FWCommit 성공 지점에서
> **isinstance 검사 밖**에서 호출한다. 안쪽에 두면 PCSR 제품(PM9M1/BM9H1)에서 통째로 누락된다.

> **곁다리 수정:** `_nsze_cache`/`_mdts_cache` 도 v9.6 까지 **무효화 지점이 아예 없었다.**
> 같은 헬퍼로 함께 고쳤다.

**재조회 실패 시 폴백으로 퇴행하지 않는다.** `IO_WL_MDTS_FALLBACK`(256KB)은 이 장비의 실제
한계(128KB)보다 **크다.** 즉 "모르면 크게 잡는" 폴백은 이 방향으로 위험하다 — 한 번이라도
known-good 을 얻었으면 그것을 유지하고 경고만 남긴다.

### ③ 미제출 명령의 귀속 차단 — 무엇을 끊고 무엇을 남기나

**끊는 것:** `is_interesting`(corpus 편입) · `new_pcs`(소스별 edge 크레딧 → v9.6 LLM 부스트의 분자)
· staleness 리셋.

**남기는 것:** `global_coverage` / `_sa_covered_bbs` 갱신. 그 PC 는 펌웨어가 **실제로 실행한**
코드가 맞고(배경/idle 활동), 되돌리면 나중에 같은 PC 를 유령 재발견하는 톱니가 생긴다.
끊는 것은 "발견 사실"이 아니라 **"이 시드의 공로"** 다.

이게 왜 필요한가:
1. **corpus 자기증식 차단** — 실행조차 안 된 시드가 배경 PC 로 interesting 판정을 받아 편입되면,
   그 시드의 자식도 같은 이유로 전부 실패한다.
2. **v9.6 부스트 보호** — `_update_llm_boost` 는 arm 별 `gain/exec` 를 비교한다. 미제출은
   **분모는 늘리고 분자는 배경 노이즈**로 채우므로, EINVAL 비율이 arm 마다 다르면 부스트가
   측정 아티팩트를 학습한다.
3. **가시성** — 이번 건이 몇 달 안 잡힌 이유가 "안 나갔는데 나간 것처럼 보였다"는 것이다.
   `Unsubmitted (errno)` 카운터가 재발 시 즉시 드러낸다.

## 검증 상태

- `py_compile` OK
- **`_max_xfer_bytes` 6케이스**: sysfs 우선(MDTS 가 커도 sysfs 승) / sysfs 1MB / sysfs 없음→MDTS /
  MDTS=0→fallback / 8MB→HARD_CAP 클립 / sysfs=0→MDTS 폴백 — 전부 통과
- **캐시 TTL 2케이스**: TTL 내 유지 / TTL 초과 재조회 — 통과
- **클램프**: 여섯 분기 전부 상한 이하, 보고된 2,621,454 → 131,072 로 클램프 — 통과
- **시드 절단 5케이스**: 2,621,454B 파일→131,072 / 작은 시드 무변화 / 정확히 상한 / max_xfer 우세 /
  max_input_len 우세 — 전부 통과
- **캐시 거동 6케이스**(실제 메서드 소스를 추출해 가짜 sysfs 에 바인딩): 최초 조회 / TTL 내
  캐시 유지(sysfs 를 다시 안 읽음) / TTL 초과 재조회+변경 감지 경고 / 무효화 후 즉시 재조회 /
  sysfs 소실 시 직전 값 유지(폴백 퇴행 없음) / 최초부터 sysfs 없음→MDTS — 전부 통과
- **③ 귀속 게이트 4케이스**: 제출+새PC=크레딧 / errno+배경PC=차단 / errno+0 / 제출+0 — 통과
- **하드웨어 실측 미검증**

## 확인된 실측 (2026-08-04, 평가 환경)

| 항목 | 값 |
|---|---|
| `cat /sys/block/nvme0n1/queue/max_hw_sectors_kb` | **128** (= 131,072B) |
| 구 `MAX_DATA_BUF` | 2,097,152B — **실제 한계의 16배** |
| 로그에 2MB 초과 `data_len` | **있었음** — 근본 원인 확정의 결정적 단서 |

즉 여섯 분기 전부가 최대 2MB 를 내보낼 수 있었는데 커널은 128KB 에서 자른다. 시드 파일 경로는
그 2MB 천장마저 없었다.

### 배포 후 확인

```bash
# 1. 절단 경고 — 큰 시드 파일이 있었다면 시작 시 뜬다
grep "\[Seed\].*절단" fuzzer.log

# 2. 상한이 128KB 로 잡혔나
grep "XferLimit" fuzzer.log

# 3. 미제출 비율이 0 에 수렴하는가 (주기 요약)
grep "Unsubmitted (errno)" fuzzer.log | tail

# 4. 잔여 rc=22 가 있다면 전송 크기 외 다른 인자 문제
grep -B3 "NVMe RET] rc=22" fuzzer.log | grep -o 'data_len=[0-9]*' | sort -n | uniq -c | tail
```

3번이 0 으로 안 떨어지면 전송 크기 말고 다른 EINVAL 원인이 남아 있다는 뜻이다(nsid·metadata·
opcode 조합 등). 4번의 `data_len` 이 전부 상한 이하인데도 rc=22 라면 그쪽을 봐야 한다.

## 한계 (정직)

- **기존 시드 파일은 자동으로 안 고쳐진다.** v9.7 은 로드 시 절단하지만, 이미 corpus/`output/`
  에 저장된 큰 시드가 `--resume` 류로 되살아나면 그대로다. 시드 디렉터리를 한 번 점검할 것.
- **admin 큐 한계는 근사**다. sysfs 노드가 namespace 큐에만 있어 그 값을 admin 에도 쓴다.
  data 를 싣는 admin 명령은 대부분 작아서(SecuritySend/FWDownload) 실효 차이는 없을 것으로 본다.
- **LBA 정렬은 손대지 않았다.** 길이가 LBA 배수가 아니어도 블록 계층은 bounce buffer 로 처리하지
  EINVAL 을 내지 않는다. 그런 명령은 **펌웨어에 도달해서 NVMe status 를 받으므로 정상적인 퍼징
  신호**다 — 막을 이유가 없다.
- **MDTS 를 넘는 전송을 펌웨어가 어떻게 처리하는가**는 이 전송로로는 물을 수 없는 질문이다
  (커널이 먼저 거부). 그 질문을 던지는 레버는 **CDW12 의 NLB** 이고, 이건 SQE 안의 dword 라
  커널이 검사하지 않는다. v9.7 의 클램프는 NLB 을 건드리지 않으므로 그 경로는 그대로 살아 있다.
  오히려 지금까지는 data_len 이 커서 **아무것도 안 나갔는데**, 클램프 후에는 NLB 변이가
  실제로 발사된다 — **테스트가 줄어든 게 아니라 늘어난다.**

## 아직 안 한 것 / 다음 (v9.8+)

- v9.6 이 남긴 것: bandit 전환, `llm_cmd`/`llm_seq` arm 분리, `llm_score` 순환논리 제거.
- ROADMAP `Gate 0` 이후(dictionary / DSL / QD / state graph / call-graph)는 여전히 미착수.

## 파일

- `pc_sampling_fuzzer_v9.7.py` — v9.6 byte-copy + 위 편집
- `fuzzer_config.json` — **무변경**(신규 키 없음. 상한은 런타임 유도라 설정이 필요 없다)
