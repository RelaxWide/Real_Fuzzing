# HANDOFF — segfault / pagealloc memory corruption 조사 (해결)

> **결론 먼저:** "동작 중 비결정적 segfault + dmesg `pagealloc: memory corruption`"의 관측된
> 원인은 **퍼저도 장치도 아니라, 진단하려고 호스트 GRUB에 추가한 커널 debug 계측**이었다.
> 그걸 제거하니 **v9.3(in-process J-Link)이 J-Link 연결 + LLM 포함 16만+ 명령 안정 동작.**
> 즉 우리가 쫓던 "알 수 없는 segfault"의 대부분은 **진단 도구가 스스로 만든 것**(관측자 효과).

---

## 0. 최종 판정 — 크래시를 지배한 것

진단용으로 호스트 GRUB `GRUB_CMDLINE_LINUX_DEFAULT`에 넣었던 커널 debug 옵션:
`slub_debug=FZPU`, `debug_pagealloc=on`, `page_poison=1`, `softlockup_panic`,
`hardlockup_panic`, `nmi_watchdog`.

이것들이:
- **(a) `*_panic`** — 락업/멈춤을 경고가 아니라 **호스트 panic(크래시)** 으로 승격. 퍼저는
  crash 보존(JTAG)을 위해 **30일 nvme 커널 타임아웃**으로 명령을 D-state로 *의도적으로* 얼려두는데,
  그 멈춤이 lockup으로 잡히면 곧장 panic. (주범으로 추정)
- **(b) `debug_pagealloc`/`slub_debug`** — 큰 오버헤드 + free 페이지 unmap → 평소 조용히 넘어갈
  상황을 즉시 fault/crash로.

→ **관측자 효과(heisenbug): 프로브가 측정 대상보다 시스템을 더 크게 흔들었다.** debug 제거 후
같은 v9.3 코드가 disk-특이성 없이 안정. ("이 OS 디스크에서만" 크래시난 이유 = 그 디스크에만 이
옵션이 켜져 있었기 때문. 클론 디스크엔 없었음 → 그래서 클론은 멀쩡했던 것.)

## 1. 이건 faulthandler 재현이다

이 프로젝트에서 **두 번째** 같은 함정: 예전 `faulthandler`(진단 도구)가 스스로 크래시를
유발/오염시킨 것과 동일 패턴. **교훈:** 간헐적 메모리 손상엔
- 행동을 바꾸는 계측(panic / halt / heavy-debug)을 상시로 넣지 말 것,
- **비침습 관찰(core dump, dmesg, IOMMU DMAR fault)** 을 우선,
- 계측 전에 **계측 없는 baseline** 을 먼저 확보,
- **한 번에 한 변수**만 바꿀 것.

## 2. 배제된 것 (증거와 함께)

| 후보 | 배제 근거 |
|---|---|
| 퍼저 코드/버전 | v8.3·v8.8·v9.0·v9.3 전부 크래시했었음. 3개월 상수인 코드가 새 증상 원인일 수 없음 |
| LLM enabled-set 우회 (구 유력가설) | 버전·`--no-rag` 무관하게 재현 → 근본원인에서 강등 |
| J-Link native 콜백 | `--no-jlink`(NullSampler)에서도 크래시 → J-Link 무관. **v9.4 격리의 전제가 무효** |
| 물리 RAM | memtest 다중 패스 통과 |
| 호스트 하드웨어(PSU/열/보드) | **같은 HW·다른 OS 디스크(클론)에서 정상** → HW 아님 |
| config 파일 (30일 타임아웃 등) | 최신 config 그대로 다른 디스크에선 정상 → 단독 원인 아님 |
| OS 설치본 손상 | 클론이고, 재부팅으론 안 나았지만 **debug 옵션 제거로 해결** → 설치본 손상 아님 |

## 3. 미해결(정직) — 진짜 손상이 있었나?

`pagealloc: memory corruption`은 page_poison이 **실제 덮임을 탐지**했을 때만 뜬다. 그래서 계측이
잡은 게 **진짜 손상일 가능성**을 100% 배제하진 못한다. 두 경우가 남는다:
- **(A) 순수 계측 아티팩트** — debug 옵션이 만든 크래시. 제거로 진짜 종결.
- **(B) 계측이 실제 손상을 드러낸 것** — 지금은 탐지기를 껐으니 **조용히 진행 중**일 수 있음
  (유력 메커니즘: wedge된 컨트롤러의 late/stale DMA가 free/재사용 페이지 침).

**크래시 없이 확인하는 법:** debug 옵션은 뺀 채 `iommu.strict=1`만 켜고(아래) 원래 크래시
임계량을 넘겨 실행하며 카나리아로 관찰 —
```
dmesg | grep -iE "DMAR|pagealloc corruption"
```
- 깨끗 → (A). 순수 아티팩트. 종결.
- `DMAR fault` 또는 corruption **경고**(크래시 아님)가 뜸 → (B). 실제 장치 DMA 손상 잔존 →
  이제 오염 없이 그 신호로 정상 조사 가능.

## 4. 환경 권고 (JTAG crash 보존과 무충돌)

- **30일 nvme 커널 타임아웃 유지 가능** — 컨트롤러를 리셋하지 않아 펌웨어 crash 상태를 JTAG로
  분석할 수 있음. 단독으로는 위험 아님.
- **`iommu.strict=1`** (GRUB `GRUB_CMDLINE_LINUX_DEFAULT`에 추가 → `update-grub` → 재부팅):
  wedge된 컨트롤러의 late/stale DMA를 **컨트롤러 리셋 없이** 차단하고 `DMAR fault`로 기록.
  → host 보호 + 범인 명령 특정. (디스크마다 GRUB이 다르니 클론마다 각각 넣어야 함.)
- **debug 옵션은 상시 켜지 말 것.** 꼭 탐지가 필요하면 `page_poison=1` **하나만**(panic 없이)
  카나리아로.

## 5. 현재 상태 / 버전

- **현행 = v9.3** (in-process J-Link halt 샘플러). 16만+ 명령 · J-Link 연결 · LLM(RAG) 포함
  안정 실측.
- **v9.4** (J-Link 프로세스 격리 + mmap PC ring) = `backup/pc_sampling_fuzzer_v9.4_shelved.*` 로
  **접음(shelve).** 전제(J-Link native 크래시가 퍼저를 죽인다)가 무효로 판명되어 현재 불필요.
  향후 실운영에서 **계측 유발이 아닌 진짜 native SIGSEGV**를 재현하게 되면 재검토. (mmap
  coverage 동기화 등 내부는 하드웨어 없이 15/15 검증돼 있으니 그대로 재사용 가능.)
