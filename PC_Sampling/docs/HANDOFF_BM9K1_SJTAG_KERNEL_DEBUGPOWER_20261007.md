# HANDOFF — BM9K1 SJTAG 디버그 전원 드롭 / 커널 의존성 (2026-10-07)

[[HANDOFF_BM9K1_LINK_DEVICELOST_20261002.md]] 의 **3.2(디버그 링크 끊김, 펌웨어 의심)** 후속이다.
그 문서 이후 좁혀진 내용만 담는다. 대상은 소유·승인된 SSD 안정성 시험이며 원인 규명·방어가 목적이다.

기준: 실행 파일 `pc_sampling_fuzzer_v11.1.py`, origin/main `6470c37`.
아래 관측값은 **사용자가 수동 전사**한 것이고, 이 환경에서 실기 접근은 하지 않았다.
코드 대조와 실기 관측을 구분해서 읽어야 한다. 실주소·서명·`sjtag_addrs.json` 은 문서에 남기지 않는다.

## 1. 한 줄 요약

디버그 전원을 올린 상태에서 **최신 펌웨어 + 커널 6.8/7.0** 조합일 때만 수 초 안에
DAP 디버그 전원 영역이 내려가 SJTAG/PCSR 링크가 끊긴다. **커널 5.15 에서는 같은 하드웨어·
펌웨어로 끝까지 유지된다.** 지금까지 호스트 복구 리셋·런타임 PM·ASPM·IOMMU 를 하나씩
배제했고, 남은 틀은 **"커널이 장치에 보내는 nvme admin 명령 트래픽이 드롭을 유발한다"** 이다. 미확정.

## 2. 확정된 사실

### 2.1 펌웨어가 근본 (재확인)
- 공장초기화 → **과거 FW** 로 올려 정상화 → 그 상태에서 **최신 FW** 로 업데이트하면 unlock 이 잘 된다.
- 반면 최신 FW 를 바로 쓰면 아래 드롭·멈춤이 난다. 과거 FW 에는 증상 없음.
- 즉 "최신 FW 의 상태"가 방아쇠이고, 코드·설정·샘플·속도·wine·PMU 경로·젠더는 앞서 배제됨.

### 2.2 디버그 전원 드롭의 성격
- `ap_write_probe --watch` 로 보면 **6.8**: 처음 1초가량 전 AP 가 `O`·req/ack `1/1`·live 였다가
  수 초 내 `APBAP4` 부터 `E` 로, 이어서 전부 `E`. 이때 **CDBG req/ack 가 `0/0`, CSYS 가 `0/1`**.
- req 비트까지 0 → 호스트가 쓴 요청이 사라짐 = **칩 쪽에서 DP(디버그 전원 영역)가 리셋/다운**된 것.
  ack 만 떨어진 게 아니라 req 까지 0 인 점이 핵심.
- **5.15**: 같은 명령으로 전 AP `O`·`1/1`·live 가 수십 초 끝까지 유지. rev ff/unknown 없음.

### 2.3 디버그 전원 + admin 명령의 상호작용 (10-02 에서 이어짐)
- 커널 무관하게, `sjtag_unlock.py` 를 **한 번** 돌린 뒤 `nvme list`(Identify, opcode 0x6) 를 하면
  dmesg `I/O timeout, QID 0` → `resetting controller`. 실행 전에는 `nvme list` 가 여러 번 정상.
- 6.8/7.0 에서는 그 뒤 AER 이 따라붙음: `0000:00:01.1 [8086:a72d] ... Physical Layer RxErr` →
  컨트롤러 리셋 → 장치 소실. 5.15 에서는 이 AER/리셋 연쇄가 안 난다.
- Pre-flight 멈춤(최신 FW 에서 `LBA size 자동 감지 : 512B` 뒤 정지)도 같은 뿌리로 본다:
  디버그 전원이 올라간 상태에서 첫 장치 명령(id-ctrl)이 무응답 → D 상태. v11.1 에 선제 응답
  확인(`0d26edf`)으로 멈춤은 막았으나 **근본 원인은 아님**.

## 3. 세운 가설과 그 결과

| # | 가설 | 결과 | 근거 |
|---|---|---|---|
| H1 | 호스트(nvme/AER) 복구 리셋이 칩까지 전달 | **기각** | 드롭 순간 dmesg 에 reset/timeout/AER 없음 |
| H2 | 런타임 PM(자동 서스펜드)이 5.15↔6.8 다름 | **기각** | `power/control=on`, `runtime_status=active` 양쪽 동일 |
| H3 | ASPM policy 가 다름 | **기각(값)** | `policy` 선택값 양쪽 `[default]` 동일. 실제 L-state 는 미측정 |
| H4 | IOMMU 번역이 최신 FW 의 stray DMA 를 막아 멈춤 | **부분** | `strict=0`→`passthrough=1` 후 **도구 대기 읽기 실패는 사라짐**. 그러나 JTAG 드롭·간헐 validate 실패는 잔존 → NVMe/DMA 측엔 유효, 디버그 전원 드롭은 별개 |

### 3.1 IOMMU 운용 이력 (주의)
- 7/20 `iommu.strict=1` → 9/17 PM9M1_HP 조사에서 strict 가 더 빨리 freeze → `passthrough` 권고.
- 6.8 에는 한동안 `iommu.strict=0 slub_debug=U log_buf_len=8M vt.handoff=7` 로 두었고,
  이번에 `strict=0`→`passthrough=1` 로 영구 변경(`/etc/default/grub`, update-grub).
- **strict 를 새 해결책처럼 다시 제안하지 말 것.** passthrough 는 stray DMA 를 "막는" 게 아니라
  "통과"시키므로 호스트 메모리 손상 위험을 가린다 — 최신 FW 수정 전까지의 우회책으로만 본다.
- 5.15 cmdline 은 `vt.handoff=7` 뿐(IOMMU 옵션 없음 = 기본 off 로 추정).
- `slub_debug=U` 는 상시 금지 디버그 옵션. passthrough 시험 결론 확정 후 제거 예정(아직 남겨둠).

## 4. 현재 작업 틀: "커널이 장치를 얼마나 건드리나"

H2·H3 가 동일값으로 배제됐으므로, 커널 차이를 정적 전원 노브가 아니라 **동작**으로 본다.
nvme 드라이버는 백그라운드로 admin 명령(AEN·health 폴링 등)을 던지고, 그 주기·내용이
5.15↔6.8 에서 다를 수 있다. 2.3(디버그 전원 올라간 상태 + admin 명령 → FW 비정상)과 합치면:
5.15 는 장치를 덜 건드려 유지, 6.8 은 무언가를 던져 FW 가 그때마다 DP 를 내린다는 그림. 정상
명령이라 dmesg 에 에러로 안 남는 점과도 맞는다.

## 5. 다음 결정적 시험 (미실행)

**6.8 에서 nvme 드라이버 언바인드 후 `--watch`.** 커널이 그 장치에 NVMe 명령을 아예 안 보내게 한 뒤
디버그 전원이 유지되는지 본다. (읽기 전용, 인증 카운터 무소모)

```
lspci -nn | grep -i -e nvme -e "Non-Volatile"          # PCI 주소 확인
echo 0000:01:00.0 | sudo tee /sys/bus/pci/drivers/nvme/unbind   # 주소 교체
sudo python3 risc-v/ap_write_probe.py --watch 30 --interval 1
echo 0000:01:00.0 | sudo tee /sys/bus/pci/drivers/nvme/bind     # 되돌리기
```

- `O` 가 끝까지 유지 → **범인은 커널의 admin 명령 트래픽**. 다음은 5.15↔6.8 이 던지는 명령 차이
  좁히기(예: `nvme-cli`/udev/systemd 의 주기 조회, AEN 설정, health 폴링).
- 그래도 `E` 로 꺼짐 → nvme 명령이 아님 → PCIe 링크 레이어(ASPM 실제 L-state 등)로 이동.

병행: 5.15 와 6.8 에서 각각 디버그 전원 올린 뒤 어떤 admin 명령이 실제로 오가는지 비교
(`nvme`·udev 규칙·`nvme monitor`/`dmesg`), 그리고 펌웨어팀에 "디버그 전원 상태에서 admin
명령 수신 시 DP 를 내리거나 리셋하는 동작"이 최신 FW 에 들어갔는지 문의.

## 6. 운용 메모 (실기)

- **핀 삽입 순서가 변수**: pin 꽂은 **뒤** SSD 전원 투입 → 동작하는 경우가 생김. 전원 켜진 **상태에서**
  pin 삽입 → 장치가 날아감. 시험 간 이 순서를 고정해야 결과 비교가 성립.
- 드롭 뒤 상태: `nvme list` 에 FW 안 보이나 `/dev/nvme0` 는 존재, 명령은 `No such device`.
  POR 로 복귀. (10-02 문서 3.5 참조)
- `sjtag_unlock --execute` 는 인증 카운터 소모. 원인 조사는 `--read-burst`·`--diag`·`ap_write_probe --watch`
  같은 읽기 전용부터.

## 7. 상태 요약

- 코드 변경 없음(이번 턴은 조사·문서화). 방어 코드는 10-02 커밋들로 이미 반영됨.
- 미해결: 디버그 전원 드롭의 최신 FW×6.8/7.0 의존성. H1~H3 기각, H4 부분. 결정적 시험은 §5.
