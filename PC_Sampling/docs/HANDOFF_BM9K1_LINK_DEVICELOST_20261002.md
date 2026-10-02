# HANDOFF — BM9K1 SJTAG·PCSR 링크 불안정 / 장치 소실 (2026-10-02)

대상 실행 파일: `pc_sampling_fuzzer_v11.1.py` (v11 은 11.0.0 고정, v10.3 동결).
기준 커밋: origin/main `d8b98ad`. 실주소·키는 `risc-v/sjtag_addrs.json`(gitignore)에만 있다.

## 1. 한 줄 요약

BM9K1 에서 SJTAG 인증 실패 → PC 수집 0 → 장치 소실이 연달아 보였다. 원인은 셋이 겹쳐 있었다:
**(a) wine 의 USB 드라이버가 J-Link 를 잡음(해결)**, **(b) 펌웨어 부팅 후 디버그 링크가 수십 전송마다
끊김(미해결, 펌웨어 의심)**, **(c) 특정 Write 뒤 PCIe AER → 컨트롤러 리셋 → 장치 소실(불량 후보)**.
코드는 (a) 를 고치고, (b)·(c) 에서 퍼저가 조용히 헛돌지 않도록 방어를 넣었다.

## 2. 이번에 push 된 커밋

| 커밋 | 파일 | 내용 |
|---|---|---|
| `6be9f8a` | fuzzer v11.1 | BM9K1 시작 순서를 원래대로 되돌림: POR → SJTAG 인증 → boot sweep → rescan (부팅 대기 후 인증하던 7f68e71 revert) |
| `fa14ee0` | fuzzer v11.1 | FWCommit 재연결·샘플링 장애 재초기화 경로에서 **재인증 전 APST·keepalive 끄기**(`_prepare_sjtag_reauth`). `_apst_disable(force=True)` 는 원래 값이 0 이어도 다시 끈다 |
| `56e4341` | `risc-v/sjtag_unlock.py` | 서명 도구 대기 중 0.2s 마다 STATE 읽기(링크 유지 + 끊긴 시점 기록), APBAP3 쓰기 실패 메시지에 CTRL/STAT 표시 |
| `b389e28` | `risc-v/sjtag_unlock.py`, README | 서명 도구를 항상 `WINEDLLOVERRIDES=wineusb.sys=d` 로 실행 |
| `5d14977` | fuzzer v11.1 | 오버레이 bank 판별이 코어별 32회 연속 실패(스왑 제외)하면 그 코어 판별을 끄고 bank 0 으로 수집 |
| `d8b98ad` | fuzzer v11.1 | **장치 소실 감지 → 퍼징 중단 + 불량 캡처**(`crash_reason: device_lost`) |

테스트 626개 통과. 장치 경로 고정 시험 fixture 에 v11.1 `RiscvPcsrSampler`·`_send_nvme_command` 해시와
변경 사유(amendments)를 기록했다. **실기 검증은 아직 없음.**

실행 장비 반영(로컬 수정이 많아 pull 대신 파일 단위):
```
git fetch origin && git checkout origin/main -- \
  PC_Sampling/pc_sampling_fuzzer_v11.1.py PC_Sampling/risc-v/sjtag_unlock.py PC_Sampling/risc-v/README.md \
  PC_Sampling/tests/fixtures/v10_2_device_ast.json PC_Sampling/tests/test_v11_1_overlay_fallback.py \
  PC_Sampling/tests/test_v11_1_device_lost.py PC_Sampling/tests/test_v11_1_run_compare.py
```

## 3. 확인된 사실

### 3.1 wineusb 가 J-Link 를 잡는다 (해결)
- 증상: 서명 도구(`Clavis_Win.exe`) 실행 1~2초 뒤 DP 까지 응답 없음(CTRL/STAT 읽기 실패) → `REQUEST[n]: APBAP3 쓰기 3회 실패 (CSW 의심값 0x80000000)`.
- 근거: wine 출력 `fixme:wineusb:add_usb_device …`. 링크 유지 읽기 22회 중 +1.4s 이후 16회 실패.
- root(sudo) 로 뜬 wine 의 wineusb 가 호스트 USB 를 전부 등록하면서 pylink 가 쓰던 J-Link 를 잡음.
- 원래 구성은 apt `wine32` + `/root/.wine32` 였고, 현재는 포터블 `/home/ssd/wine-11.17-amd64-wow64` + `/root/.wine` — 이 차이로 발생했을 가능성이 큼.
- `wineusb.sys=d` 적용 확인: wine 로그 `ZwLoadDriver failed … wineusb: c0000142`, `Auto-start service "wineusb" failed to start: 1114`. 앞뒤 `winemenubuilder`·`parse_samba_dos`·`AppPolicyGetProcessTerminationMethod` 줄은 무해(stderr, 파싱 무관).

### 3.2 펌웨어 부팅 후 디버그 링크가 끊긴다 (미해결)
- APST 끄고 wine 없이도 `--read-burst` 약 70% 실패. 첫 드롭이 tx 33~61 근처에서 매번 다르고, **DPIDR 도 읽기 실패**(링크 전체 리셋).
- JLinkExe connect 초기 수십 단계는 매번 안정 → 핀·케이블 접촉 자체는 아니라고 사용자 판단. 디버거·케이블·샘플 동일.
- 링크 계층 코드(`sfe76_link.py`, `dap_access.py`, `sjtag_unlock.py` 의 read-burst 경로)는 9월 초 이후 변경 없음 → 코드는 원인에서 제외.
- 사용자 판단: **펌웨어에 따라 갈림**. 인증은 여러 번 하면 넘어감. POR 직후(펌웨어 부팅 전) 인증은 되고, 부팅 후엔 불안정.
- 퍼저 영향: connect 직후 pin 실패/검증 실패, diagnose `유효 0/0`(pin 단계부터 실패), 복구 후 수집 0.

### 3.3 PC 수집 0 의 직접 원인 = 오버레이 bank 판별 실패 (방어 완료)
- 복구 후 `cores=[0,1,2,3]` 정합성 100% 인데 `[StatCov] ⚠ ovl-drop 100.0% (266/266)`.
- H/F 의 버스트 앞뒤 bank 읽기(SBA)가 계속 실패해 버스트를 전부 버림(에러 로그 없음). 나머지 코어는 WFI 라 PC 거의 없음.
- `5d14977` 로 32회 연속 실패 시 판별 끔 → bank 0 수집. 로그: `[Overlay] coreN: bank 판별 32회 연속 실패(… 앞=… 뒤=…) — 이 코어 bank 판별 끔`. `앞/뒤=읽기 실패` 면 링크, 값이면 오버레이 맵-펌웨어 불일치.
- PCSR 주소 = `trace.te_base + core_stride*id + pcsr.offset` (TE 레지스터 블록, 하드웨어 주소). core0 통과 = te_base·offset 정상. 펌웨어가 주소를 옮길 수는 없다.

### 3.4 장치 소실 (방어 완료, 불량 후보)
- J-Link 사용 시: dmesg `AER: Multiple Correctable … 0000:00:01.1 [8086:a72d] Physical Layer RxErr` → `nvme0: resetting controller due to AER` → `Disabling device after reset failure: -19`.
- `--no-jlink` 에서도 발생: 명령 리턴이 `Interrupted system call` → `No such device` → `Resource temporarily unavailable` 반복. 따라서 J-Link 만의 문제는 아님(앞서의 'J-Link 가 PCIe 를 흔든다' 단정은 철회).
- 직전 명령(사용자 확인):
  ```
  nvme io-passthru /dev/nvme0n1 --opcode=0x1 --namespace-id=1 --cdw2=0x0 --cdw3=0xcd9c7fbb --cdw10=0x0 \
    --cdw11=0x0 --cdw12=0x49 --cdw13=0x8 --cdw14=0x0 --cdw15=0x0 --data-len=744 --input-file=data.bin -w
  ```
  Write, data-len 744(LBA 배수 아님), dmesg `resetting controller due to AER`. **재현 확인 필요**(crash 폴더 replay).
- `d8b98ad`: errno 실패(NVMe status 없음) 문구가 ENODEV/ENOENT/EAGAIN/EINTR/EIO 계열이면 `/sys/class/nvme/<ctrl>/state` 확인(최대 10초 live 대기). 없거나 dead 면 `[DEVICE LOST]` → `RC_TIMEOUT` → 기존 크래시 캡처(실패 명령·dmesg·replay·덤프) 후 중단. `ignore_opcodes`/`repro_opcodes` 설정 시에는 기존 규칙대로 POR 후 계속.

### 3.5 `/dev/nvme0n1` 만 사라지는 경우 (미대응)
- admin(`/dev/nvme0`) 은 rc=0, I/O 만 `No such file or directory`. `ls -l /dev/nvme0n1` 없음, `list-ns` 1, `id-ns` 정상(flbas 0, metasize 0), dmesg 특이사항 없음. **POR 하면 노드 복귀**.
- 해석: 리셋/상태 변화 때 커널이 namespace 를 지웠고, 장치는 회복했지만 Namespace Attribute Changed AEN 이 없어 커널이 다시 안 읽음(가설).
- 이 경우 컨트롤러가 live 라 `d8b98ad` 의 장치 소실 판정에 걸리지 않고 I/O 가 헛돈다.
- 재발 시 POR 전에: `nvme ns-rescan /dev/nvme0` → `ls -l /dev/nvme0n1`, `nvme id-ctrl /dev/nvme0 -H | grep -i -A3 oaes`. rescan 으로 돌아오면 AEN 누락(스펙 위반 후보), POR 로만 돌아오면 펌웨어 비정상 상태.

## 4. 남은 일 (우선순위)

1. **장치 소실 재현**: 3.4 의 Write 를 replay 로 재현 → 결정적이면 필드(data-len 744, cdw12/13) 축소. AER 줄 전체(type/status)로 링크 vs 펌웨어 판정.
2. **링크 불안정의 펌웨어 의존성 확정**: 이전 펌웨어로 `--read-burst 5` 비교. 펌웨어팀에 디버그/JTAG 관련 변경(전원·클럭 게이팅, 핀 mux, 워치독) 문의.
3. 선택 — 퍼저 보완(제안만, 미구현):
   - diagnose 전 링크 생존 확인 + `session.recover()` 1회, boot sweep 중 연속 전송 실패 시 복구.
   - pin 실패 사유(CSW/TAR/sbcs) 로깅 — 지금은 `0/0` 만 찍힘.
   - 재연결 시 원래 4코어 전체 재검증(현재는 그 시점 weights 기준이라 한 번 빠진 코어는 안 돌아옴).
   - I/O ENOENT + 컨트롤러 live 이면 `ns-rescan` 후 노드 확인, 안 돌아오면 불량 캡처.
   - 단독 `sjtag_unlock.py` 기본 `--power dbg-only` vs 퍼저 `power: both` 차이 — 맞출지 결정.
   - read-burst 판정 보강(드롭 직후 DPIDR 단발 → 여러 번 + 재활성화 후 재확인).
4. 메모리 `bm9k1_por_jtag_strap_blocker`: 09-28 커넥터 하드웨어 조치는 사용자 판단상 이번 원인 아님.

## 5. 자주 쓴 진단 명령

```
# APST 끄기 (APST 는 256B 테이블이 필요 — --data 없으면 stdin 대기)
sudo nvme set-feature /dev/nvme0 -f 0x0c -v 0 --data-len 256 --data /dev/zero
sudo nvme get-feature /dev/nvme0 -f 0x0c -H

# 링크 안정성 (읽기 전용, 인증 카운터 무소모)
sudo python3 risc-v/sjtag_unlock.py --read-burst 5 [--burst-delay 300] [--power both]

# 서명 도구 수동 확인 (wineusb 차단)
sudo env WINEDLLOVERRIDES=wineusb.sys=d /home/ssd/wine-11.17-amd64-wow64/bin/wine <Clavis_Win.exe> -s3 -f5

# 장치/namespace 상태
cat /sys/class/nvme/nvme0/state
sudo dmesg -w | grep -iE "aer|nvme"
```

## 6. 주의

- push 는 사용자가 명시할 때만.
- `sjtag_addrs.json`·실주소·서명 출력은 로그/문서에 남기지 않는다.
- 인증(`--execute`)은 카운터를 쓴다. 원인 조사는 `--read-burst`·`--diag` 같은 읽기 전용부터.
