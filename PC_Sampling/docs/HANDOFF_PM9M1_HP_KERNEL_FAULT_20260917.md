# PM9M1_HP v10.2 — 커널 fault 조사 인계 (2026-09-17)

사내 Claude Code 등 후속 조사자가 대화 없이 이어받기 위한 기록이다.
대상은 소유·승인된 SSD의 안정성 시험이며, 원인 규명과 방어적 수정이 목적이다.

**현재 결론:** 퍼저 PID 5460이 ext4 파일을 여는 도중 `kmem_cache_alloc`에서
비정상 포인터를 역참조해 커널 general protection fault를 만났다.
APST 설정용 임시파일 생성 중 발견됐다는 가설이 강하지만 파일 경로는 미확정이다.
**최초 메모리 손상 주체·원인은 아직 확정하지 못했다.**

**중요한 운용 이력:** 사용자는 이전에 strict IOMMU 조건에서 더 빨리 freeze되어
현재 passthrough로 바꿨다고 밝혔다. 이를 모르고 strict 전환을 재실험으로 제안했다가
철회했다. 같은 전환을 새 해결책처럼 반복 제안하지 말 것. 당시 증상이 이번 커널
fault와 같은지는 아직 확인하지 못했다.

문서 작성 시 저장소 기준: `5dbb593` (main). 이 환경에서 실기 접근은 하지 않았다.
아래 관측값은 **사용자가 모니터·dmesg를 수동 전사한 내용**이며 원본 로그 파일은
아직 받지 못했다. 문장 부호·일부 철자·숫자에 전사 오류가 있을 수 있다.
코드 대조 결과와 실기 관측을 구분해서 읽어야 한다.

## 1. Critical issues — 확인된 장애와 증거

### 1.1 실행 환경과 증상

| 항목 | 확인 내용 |
|---|---|
| 제품 | PM9M1_HP |
| 실행 파일 | v10.2, v10.3이 아님 |
| 커널 | `6.8.12-060812-generic #202501300202` |
| 감시 | `env PCFUZZ_FREEZE_TRACE=47471`, 독립 `--freeze-watch` 창 |
| 실행 수 | 마지막 통계 이벤트 `exec=520900` |
| OS/임시파일 파일시스템 | `findmnt -T /tmp`: target `/`, source `/dev/sda2`, fstype `ext4` |
| 임시 경로 환경변수 | 사용자가 TMPDIR/TEMP/TMP를 별도로 지정하지 않았다고 확인 |
| 시험 NVMe | `nvme0`, PCI `0000:02:00.0` |
| PCI 경로 | `/sys/devices/pci0000:00/0000:00:01.1/0000:02:00.0` |
| IOMMU 도메인 | `/sys/bus/pci/devices/0000:02:00.0/iommu_group/type` = `identity` |
| 장애 후 상태 | watch_time 계속 갱신, SSH와 로컬 키보드 동작 |
| 사용자 조작 | 조사 당시 재부팅·종료 조작 없이 그대로 유지 중이라고 답변 |
| 퍼저 본창 끝 | `[PM] APST 자율 idle 진입 ...`, 별도 Python 오류 메시지는 보고되지 않음 |

이번 사건을 **OS 전체 프리즈로 부르지 않는다.** 커널 fault 후 퍼저 진행이 끊겼지만
감시 프로세스·SSH·키보드는 계속 동작했다. 과거 전체 프리즈 사례와 구분한다.

부팅 인자(사용자 전사; root UUID는 진단에 불필요하여 생략):

```text
BOOT_IMAGE=/boot/vmlinuz-6.8.12-060812-generic root=UUID=<생략> ro quiet splash iommu.passthrough=1 vt.handoff=7
```

### 1.2 FreezeWatch 마지막 관측

아래는 JSON 원본이 아니라 사용자가 전사한 필드를 정리한 것이다.

```text
watch_time = 2026-09-17T08:43:01
age_s      = 4832.363
received   = 7949025
missing    = 0
active     = {}
session    = 5460-16239606017012
pid        = 5460
```

마지막 이벤트 두 개:

```text
seq=7949024 mono=52070.330549717 tid=5460
phase=stats.fsync.exit stack=[] dropped=0 exec=520900
file=/home/ssd/pc_sample/output/pc_sampling_v10.2.0/llm/llm_20260916_212518.log

seq=7949025 mono=52070.330701962 tid=5460
phase=stats.sync.exit stack=[] dropped=0 exec=520900
```

별도 `last_nvme` 필드:

```text
seq=7949003 mono=52070.305770556 tid=5460
phase=nvme.before_popen stack=[send_nvme_command] dropped=0 exec=520899
argv=[nvme, io-passthru, /dev/nvme0n1,
      --opcode=0x1, --namespace-id=1,
      --cdw2=0x0, --cdw3=0x0, --cdw10=0x0, --cdw11=0x0,
      --cdw12=0x0, --cdw13=0x0, --cdw14=0x0, --cdw15=0x0,
      --timeout=2592000000, --data-len=158,
      --input-fie=output/pc_sampling_v10.2.0/.nvme_input.bin, -w]
```

`--input-fie`는 사용자 전사 그대로다. 실제 인자명은 원본과 대조할 것.
**last_nvme는 최신 이벤트 목록의 마지막 항목이 아니다.** 이 seq 뒤로 22개 이벤트가 진행했다.
`before_popen`은 실행 의도이며 FW 도달·완료 증거가 아니다.
여기에 나온 길이 158의 Write를 직접 원인으로 판단하지 않았다.

프로세스·메모리 관측:

```text
main: python3, State=Z (zombie), Threads=2, pid=5460, alive=true, wchan=0
threads:
  tid=5460 wchan=0
  tid=5467 wchan=futex_wait_queue
children:
  openocd pid=1121979 State=S (sleeping) Threads=2
    VmSize=18248 kB VmRSS=5376 kB alive=true wchan=do_select
  python3 pid=1122808 State=Z (zombie) Threads=1 alive=true wchan=0
memory:
  MemAvailable=30861204 kB
  SwapFree=0 kB
  Slab=59288 kB
  SUreclaim=249940 kB  [사용자 전사의 키]
  PageTables=17984 kB
```

메모리 항목은 원본 대조가 필요하다. 코드가 읽는 키는 `SUnreclaim`이며,
전사된 Slab과 해당 값의 크기 관계도 불일치한다. 확정값으로 사용하지 말 것.

해석:

- `alive=true`는 `/proc/<pid>/status`에서 Name을 읽었다는 구현상 판정이다.
  정상 실행 중이라는 뜻이 아니다. 메인 스레드 Z와 다른 스레드 잔류를 함께 관측했다.
- `futex_wait_queue`만으로 Python의 어떤 락인지, 원인인 교착 상태인지 알 수 없다.
- `stats.fsync.exit`와 `stats.sync.exit`가 있으므로 **해당 fsync 구간 안의 정지가 아니다.**
- `age_s`는 1시간 20분 32초다. 시계 변경·절전 등이 없었다면 마지막 이벤트는 대략
  2026-09-17 07:22:29다. 역산한 시각이므로 dmesg 원본과 대조해야 한다.
- 마지막 MemAvailable은 약 29.4 GiB다. 80분 전 메모리 상태나 OOM을 배제하는 값은 아니다.
- `missing=0` / `dropped=0`은 해당 관측의 누락 징후 없음이다. 전체 이력 보존은 아니며
  watcher의 `last_events`는 최대 12건이다. 마지막 출력 함수를 원인으로 단정하지 않는다.

### 1.3 커널 fault (원표기를 가능한 범위에서 보존)

```text
general protection fault, probably for non-canonical address 0x13a28e49732ef6c0:
0000 [#1] PREEMPT SMP NOPTI
CPU: 31 PID: 5460 Comm: python3 Not tainted 6.8.12-060812-generic #202501300202
RIP: 0010:kmem_cache_alloc+0xd3/0x350
Code: 87 89 10 00 48 8b 38 0f 84 27 02 00 00 48 85 ff 0f 84 1e 02 00 00
      41 8b 44 24 28 49 8b 9c 24 b8 00 00 00 49 8b 34 24 48 01 f8
      <48> 33 18 48 89 c1 48 89 f8 48 0f c9 48 31 cb 48 8d 8a 00 20 00 00
RAX: 13a28e49732ef6c0
RDI: 13a28e49732ef6a8
RBX: 0bc623af8ebf0957
R12: ffff91fdc2540100
```

Call Trace (사용자 전사의 `ext_inode`, `ext4*` 등은 아래에서 ext4로 정리했다.
정확한 심볼 이름은 원본 대조가 필요하다):

```text
<TASK>
 ? show_regs+0x6d/0x80
 ? die_addr+0x37/0xa0
 ? exc_general_protection+0x1db/0x480
 ? asm_exc_general_protection+0x27/0x30
 ? kmem_cache_alloc+0xd3/0x350
 ? ext4_inode_attach_jinode+0x53/0xd0
 ? __pfx_ext4_file_open+0x10/0x10
 ext4_inode_attach_jinode+0x53/0xd0
 ext4_file_open+0x6b/0xc0
 do_dentry_open+0x21d/0x570
 vfs_open+0x33/0x50
 do_open+0x2ed/0x470
 path_openat+0x135/0x2d0
 ? n_tty_write+0x206/0x3a0
 do_filp_open+0xaf/0x170
 do_sys_openat2+0xb3/0xe0
 __x64_sys_openat+0x55/0xa0
 x64_sys_call+0x1eb8/0x25c0
 do_syscall_64+0x7f/0x180
 ? irqentry_exit+0x43/0x50
 ? exc_page_fault+0x94/0x1b0
 entry_SYSCALL_64_after_hwframe+0x78/0x80
RIP: 0033:0x705db42c2fd4
... 사용자 공간 Code 등은 미수령 ...
end trace 0000000000000000
```

`Modules linked in` 전체도 미수령이다. `Not tainted`를 메모리 손상·드라이버 결함이
없다는 증명으로 사용하지 않는다. `?`가 붙은 프레임을 모두 확실한 호출 관계로 보지 않는다.

### 1.4 반복되던 NVMe/DMAR 기록

fault 약 4초 전에 다음 내용이 있었다. 사용자는 평소 퍼징 중에도 자주 출력된다고 설명했다.

```text
nvme0: nvme: nsid (10303) in cmd does not match nsid (1) of namespace
```

DMAR도 시나리오에 의해 이전부터 반복됐다고 한다:

```text
dmar_fault: 44 callbacks suppressed
DMAR: DRHD: handling fault status reg 3
DMAR: [DMA Read NO_PASID] Request device [02:00.0] fault addr 0x40000000000
      [fault reason 0x04] Access beyond MGAW
```

시험 SSD에서 나온 주소 폭 초과 DMA 요청의 기록이다. `DMA Read`는 장치가 호스트
메모리를 읽는 방향이며 NVMe Read 명령이라는 뜻이 아니다. 이 기록만으로
**SSD가 RAM을 덮어써서 SLUB 포인터를 망가뜨렸다**고 결론 내리면 안 된다.
`callbacks suppressed`는 출력 빈도 제한이며 정확한 DMA 실패 건수가 아니다.

`identity` 도메인이 확인됐으므로 일반적인 DMA 매핑 범위만으로 격리된 조건이라고도
볼 수 없다. 실패가 보고된 접근과 다른 주소 접근에 의한 메모리 손상 여부는 별개다.
반복되는 로그라는 이유만으로 무관하다고 단정하지 않는다.

## 2. Potential bugs — 가설과 코드 대조

### 2.1 가장 정합적인 발견 경로 (원인 확정 아님)

```text
stats.sync.exit
  → [PM] APST 자율 idle 진입 예정 로그
  → _apst_enable_short_itpt()
  → NamedTemporaryFile(suffix='.apst', delete=False)  [추정 open 대상]
  → /tmp의 ext4 파일 open
  → ext4_inode_attach_jinode / 저널 관련 객체 할당
  → kmem_cache_alloc에서 잘못된 포인터 접근
```

코드상 APST 로그는 **실제 APST 설정 완료 전**에 출력된다. 함수 안에서는 256B 테이블의
임시파일을 만든 뒤 `nvme set-feature -f 0x0C -v 1`을 호출한다.
따라서 이번 APST 설정을 SSD에 보내기 **전에** fault가 났을 가능성이 높다.
`sampler.start_sampling`은 설정 성공 뒤이므로 마지막 `active={}`와도 모순되지 않는다.

관련 위치 (행 번호는 이후 바뀔 수 있음):

- [v10.2 실행 파일](../pc_sampling_fuzzer_v10.2.py): `_apst_enable_short_itpt`, 약 11479행.
- 같은 파일 약 17659행: APST 로그 → 위 함수 → 성공 시 sampling 시작.
- 같은 파일 약 9015–9022행: 로그 handler flush/fsync와 freeze 이벤트.

열려고 했던 파일 이름 자체는 미확보다. `.apst`라고 단정하지 않는다.
임시파일을 옮기거나 없애고 APST를 꺼서 증상이 사라져도, 이미 존재하던 메모리 손상이
발견되지 않게 된 것일 수 있다.

### 2.2 레지스터와 명령 배열

```text
RDI 13a28e49732ef6a8 + 0x18 = RAX 13a28e49732ef6c0
fault instruction: 48 33 18  → xor rbx, QWORD PTR [rax]
```

v6.8.12 SLUB의 `get_freepointer()`는 `object + s->offset`에서 free pointer를 읽고,
freelist hardening 활성 시 XOR 등으로 복원한다. 보고된 명령 배열과 레지스터는 이
흐름과 정합하며 **바탕이 된 객체 포인터 자체가 잘못됐음**을 강하게 시사한다.
정확한 소스 행·필드 대응은 사용자의 **동일 빌드 vmlinux/config**로 역어셈블해 확정할 것.
상류 소스만으로 빌드 고유 offset까지 확정하지 않는다.

RBX는 hardening용 값일 수 있으므로 무작위처럼 보이는 것을 손상 증거로 삼지 않는다.
R12도 주소 모양만으로 정상임을 증명하지 못한다.
직접적인 실패는 단순 ENOMEM이 아니라 잘못된 접근이다. UAF/이중 해제/덮어쓰기,
잘못된 DMA, RAM 등 하드웨어 문제 중 무엇이 최초 원인인지는 미확정이다.

### 2.3 v9.8 비교

사용자 보고: v9.8은 같은 커널·OS 디스크에서 오래 동작했고, 적어도 이번처럼 하룻밤
안에 멈추지는 않았다. 엄밀히 같은 FW/설정/corpus/IOMMU 조건인지, 같은 DMAR 오류가
나왔는지는 미확인이다. 단발 비재현을 결함 없음의 증명으로 사용하지 않는다.

저장소의 v9.8과 v10.2에서 실제 수행한 코드 대조:

- `_apst_enable_short_itpt`는 AST 동일.
- 공통 `_send_nvme_command`의 전송 길이 계산·입력파일 준비는 차이 없음.
- 해당 함수의 주요 차이는 `_last_wire` 관측, freeze 이벤트, sampler capability에 의한
  분기다. 함수 전체가 동일하다는 뜻은 아니다.
- v10.2의 `LearningMixin._send_nvme_command`는 기본 발송 처리 전후를 계측한다.
- 입력 측에는 LLM `data_len` → `data_len_override` 반영, 길이를 포함한 중복 판정,
  JSON 생성 규칙, setup 보존 시퀀스 등이 추가됐다. 공통 발송 로직이 같아도 입력의
  분포·순서·타이밍은 달라진다. **이번 실행의 LLM 활성·채택 여부는 미답변이다.**

공유 자산은 `llm_learning.py`, `fuzzer_config.json`, `rag/` 등이다. 실행 PC 파일과
현재 저장소 버전이 동일한지는 아직 대조하지 못했다.

## 3. Reliability improvements — 인계 시 조사 원칙

- fault 발견 지점과 최초 메모리 손상 지점을 구분한다. ext4/APST/마지막 NVMe 명령을
  마지막으로 보였다는 이유만으로 근본 원인으로 지목하지 않는다.
- **strict에서 더 빨리 freeze했다는 기존 결과를 존중한다.** 그 freeze가 OS 전체 정지,
  NVMe 대기, 이번과 같은 oops 중 무엇이었는지 먼저 확인한다.
- 커널/드라이버 안전성과 SSD FW 동작을 나눠 조사한다. PRP를 Python에서 직접 만드는
  구조가 아니라 기존 nvme-cli/kernel passthru 경로라는 점을 전제로 한다.
- 실기 재현 전에 현재 dmesg·watcher·퍼저 로그와 실제 설정/코드 버전을 보존한다.
  이미 oops를 겪은 커널 상태를 다음 독립 비교의 시작 상태로 사용하지 않는다.
- 변경은 원인 가설에 대응하는 최소 차이로 한다. 무조건적인 길이 보정, APST 금지,
  커널 교체를 원인이 확정된 수정처럼 도입하지 않는다. 입력 범위를 제한하는 비교라면
  제한한 내용을 기록한다.
- 이 문서 작성까지 이번 장애를 수정하는 코드 변경이나 실기 설정 변경은 수행하지 않았다.

## 4. Suggested tests — 미답변 사항과 다음 작업

### 먼저 확인할 미답변 2건

1. 과거 strict freeze: SSH/로컬 입력도 정지했는가. 같은
   `general protection fault` / `kmem_cache_alloc`이 기록됐는가.
   기록이 있다면 당시 정확한 부팅 인자와 도메인 type도 확인한다.
2. 이번 v10.2: `--rag` / `--no-rag`, 실제 LLM 제안 채택 여부, `rag.learning` 설정.
   LLM 로그 파일이 있다는 이유만으로 제안 생성·채택이 있었다고 단정하지 않는다.

### 받을 최소 자료 (수동 전사 대신 파일 권장)

- 이번 dmesg 전체 (사용자 호스트에서 `sudo dmesg > ~/pm9m1_hp_kernel_fault.txt`).
- Windows에 보존한 FreezeWatch 로그. 최초 이벤트 정지·최초 Z 관측 주변.
- 퍼저 본로그와 LLM 로그, 실행 명령, 실제 config·버전/hash.
- 있다면 command history/ledger, `llm/learning_v10.2.json`.
- 같은 커널 빌드의 config와 vmlinux/debug symbols. 우선 입수 가능 여부 확인.

### 후속 조사 순서

1. 원본으로 시각·PID·최초 oops를 연결하고 수동 전사의 불일치를 해소한다.
2. 같은 빌드의 명령 배열로 fault 시 free object/cache/offset 대응을 확정한다.
   syscall trace만으로 open 대상 경로는 알 수 없으므로 임시파일 가설을 구분한다.
3. 실제 배포된 v9.8/v10.2와 공유 config를 대조해 입력 생성·복구 차이를 좁힌다.
4. LLM 활성·채택이 확인되면 새 입력 생성/길이 override/setup 보존의 영향을 독립 비교하는
   방안을 검토한다. 비활성이었다면 공통 실행·복구 차이를 먼저 조사한다.
5. 다음 실기 시험은 가설에 맞는 단일 조건 비교로 설계하고 FW·시작 corpus·경과 시간·
   실행 수·DMAR 방향/주소/사유·최초 oops를 보존한다. strict 재시험을 기본안으로 삼지 않는다.

### 관련 문서·1차 소스

- [기존 PM9M1_HP 조사와 FreezeWatch 명세](PM9M1_HP_FREEZE_V102.md)
- [v10.2 구현](pc_sampling_fuzzer_v10.2.md)
- [v10.2 LLM 구현](V10_2_LLM_IMPLEMENTATION.md)
- [과거 다른 제품/halt 조사](HANDOFF_osfreeze_investigation.md): P7 등의 결론을 PM9M1_HP에 그대로 적용하지 않는다.
- [Linux v6.8.12 SLUB](https://raw.githubusercontent.com/gregkh/linux/v6.8.12/mm/slub.c)
- [Linux v6.8.12 ext4 inode](https://raw.githubusercontent.com/gregkh/linux/v6.8.12/fs/ext4/inode.c)
- [Linux v6.8.12 JBD2](https://raw.githubusercontent.com/gregkh/linux/v6.8.12/fs/jbd2/journal.c)
- [DMAR fault 출력](https://raw.githubusercontent.com/gregkh/linux/v6.8.12/drivers/iommu/intel/dmar.c)
- [IOMMU 도메인 type](https://raw.githubusercontent.com/gregkh/linux/v6.8.12/Documentation/ABI/testing/sysfs-kernel-iommu_groups)
- [커널 인자](https://raw.githubusercontent.com/gregkh/linux/v6.8.12/Documentation/admin-guide/kernel-parameters.txt)

v10.3 백엔드 리뷰는 별건이며 앞선 리뷰에서 153개 테스트 통과까지 확인했다.
**그 통과가 이번 v10.2 실기 커널 장애의 수정·해결을 뜻하지는 않는다.**
