# NVMe persistent-error 자동 리셋 정책 실험

## 판단

**상시 퍼징의 기본 해결책으로 리셋 억제를 권장하지 않는다.** 특정 SSD의 오류 뒤에도
동작이 계속 가능한지, 그리고 자동 리셋이 PC 관측 소실을 유발하는지를 구분하는
통제된 비교 실험용 패치다. 패치와 빌드 스크립트는 제공하지만 설치·실기 검증은 하지 않았다.

사용자가 보고한 커널은 `6.8.12-060812`다. upstream stable `v6.8.12`에서 persistent
internal error 이벤트 수신 시 `nvme_reset_ctrl()`를 호출하는 분기를 확인했다.
Ubuntu mainline 빌드의 정확한 소스/설정까지 대조한 것은 아니다.

NVMe Base 2.3 Figure 152는 persistent internal error(03h)를 지속적이며 특정 명령
집합으로 격리할 수 없는 실패로 정의하고 호스트 리셋을 권고한다(should).
Transient internal error(04h)는 리셋 없이 계속 동작할 수 있는 오류다.
따라서 03h를 무시해 계속 실행되는 것만으로 정상 상태나 스펙 준수를 입증할 수 없다.

관측 입력 `Write NLB=0x7f, LBA=512B, data_len=4096`은 요구 데이터 65536B보다
DMA 버퍼가 작다. 일반 FW 명령 변이 캠페인은 유효한 DMA 매핑을 유지하고,
이 불일치를 의도적으로 시험한다면 별도 전송 오류/복구 캠페인으로 결과를 기록한다.
FW의 개별 DMA 실패 격리 가능성, persistent 이벤트 보고 적절성, 리셋 복구 실패는
별도 검토 항목이며 호스트 로그만으로 어느 쪽의 결함인지 확정하지 않는다.

## 패치 동작

- 기본값: upstream 동작 유지.
- 시험 대상: 전체 PCI BDF가 정확히 일치하는 PCIe 컨트롤러 한 개.
- 해당 장치의 persistent internal error 이벤트에 한해서 자동 리셋 생략.
- 이벤트 trace와 결과 보존, rate-limited 경고, 다음 AER 요청 재제출 유지.
- 단순히 리셋 함수만 no-op으로 만드는 방식은 사용하지 않는다. 기존 호출자의
  `return`까지 남기면 다음 AER 요청이 제출되지 않아 이후 오류 관측이 끊긴다.
- IOMMU, PCIe AER, 타임아웃·CFS 처리 등 다른 리셋 경로는 그대로다. FW 자체가
  응답 불능이면 이 패치로 테스트 진행을 보장할 수 없다.

## 6.8.12-060812 장비에서 실행할 명령

Ubuntu/Debian의 해당 커널로 부팅한 장비에서 실행한다. 소스 다운로드와 전체 커널
빌드가 필요하므로 작업 디렉토리에 약 30GB 이상의 여유 공간을 확보한다.
스크립트는 upstream stable 6.8.12와 현재 `/boot/config-$(uname -r)`를 사용한다.
Ubuntu 패키지를 그대로 재빌드하는 것은 아니다. 인증서 경로를 비우고 디버그 정보
생성을 끄며, 추가 커널 `6.8.12-fwtest`를 만든다. 기존 커널은 삭제하지 않는다.

```bash
sudo apt update
sudo apt install -y git curl build-essential bc bison flex libssl-dev libelf-dev \
    libncurses-dev dwarves rsync cpio kmod python3 patch xz-utils zstd \
    dpkg-dev debhelper fakeroot

git clone https://github.com/RelaxWide/Real_Fuzzing.git "$HOME/Real_Fuzzing-fwtest"
bash "$HOME/Real_Fuzzing-fwtest/PC_Sampling/kernel/build_6_8_12_fwtest.sh"
```

빌드는 기본 2개 작업으로 수행한다. 늘리려면 실행 앞에 `FWTEST_JOBS=4` 등을 지정한다.
빌드 성공 후 출력되는 설치 스크립트를 실행한다. image와 headers만 설치한다.

```bash
bash "$HOME/nvme-fwtest-6.8.12/install-fwtest.sh"
sudo reboot
```

GRUB의 Advanced options에서 **6.8.12-fwtest** 항목을 선택하고 `e`를 누른다.
`linux`로 시작하는 줄 끝에 아래 파라미터를 추가한 뒤 `Ctrl+X` 또는 `F10`으로 부팅한다.
`0000:02:00.0`은 사용자가 보고한 장치의 예시이며 실제 시험 SSD의 전체 BDF와 대조한다.

```text
nvme_core.test_no_persistent_error_reset_bdf=0000:02:00.0
```

부팅 후 아래에서 `6.8.12-fwtest`와 지정한 BDF가 나오는지 확인하고, 기존 퍼저 명령을
실행한다. 파라미터는 이번 부팅에만 적용된다. 생성 커널은 서명되지 않으므로 Secure Boot가
이를 거부하는 환경에서는 별도의 신뢰된 커널 서명 절차가 필요하다.

```bash
uname -r
sudo cat /sys/module/nvme_core/parameters/test_no_persistent_error_reset_bdf
sudo journalctl -kf -o short-monotonic
```

해당 오류 수신 시 `FW TEST: persistent internal error ... skipping event-triggered reset,
rearming AER` 경고가 나오면 억제 분기가 실행된 것이다. 다른 원인의 리셋까지
차단하는 것은 아니다. 돌아가려면 재부팅하여 기존 6.8.12-060812 커널을 선택한다.

검증 범위: 빌드 스크립트의 shell 문법, 다운로드 URL, 패치 적용 및 아래 모의 C 테스트.
스크립트를 통한 전체 커널 빌드와 설치는 이 개발 환경에서 실행하지 않았다.

## 파일 및 검증

- `nvme-persistent-error-test-policy-v6.8.patch`: upstream v6.8용.
  stable v6.8.12에도 fuzz=0으로 적용되고 아래 8개 정책 테스트가 통과했다.
- `nvme-persistent-error-test-policy-v7.0.patch`: upstream v7.0용.
- `check_policy.py`: 소스를 임시 디렉토리에 복사하고 패치를 적용한 뒤, 실제 수정된
  C 함수들을 kernel API mock과 함께 컴파일·실행한다. 원본 소스와 장비는 변경하지 않는다.

```bash
python3 PC_Sampling/kernel/check_policy.py v6.8 /path/to/linux-6.8.12
```

검증 경우: 기본값, 빈 설정, 다른 BDF, 다른 transport, 일치 장치의 이벤트 보존과
재요청, 다른 오류, SMART 이벤트, 실패한 AER 완료. 각 기반 소스에서 8개 통과.
커널 전체 빌드·모듈 로드·실기 검증은 미실시다.

## 선택적 비교 실험

정확한 커널 소스에 패치를 적용해 빌드한 **시험 커널**에서만 다음 부팅 파라미터가
생긴다. 순정 커널에 넣어도 이 기능이 추가되지 않는다.

```text
nvme_core.test_no_persistent_error_reset_bdf=0000:02:00.0
```

이는 예시 BDF다. 먼저 실제 시험 SSD의 PCI 주소를 확인한다. 모듈로 배포한 경우에도
그 커널과 일치하는 빌드/서명/initramfs 처리가 필요하며, 실행 중 NVMe 모듈 강제 교체는
이 문서의 적용 방법이 아니다. 파라미터는 로드 시 설정하며 런타임 변경을 허용하지 않는다.
부팅 후 `/sys/module/nvme_core/parameters/test_no_persistent_error_reset_bdf`를 확인한다.
파라미터 없이 부팅하면 기존 자동 리셋 정책으로 돌아간다.

동일 FW/입력/초기 상태와 IOMMU 설정으로 비교한다. 이벤트 이후에는 시험을 무조건
계속하지 말고, 정상 명령 완료·기록된 데이터 정합성·PC 관측이 유지되는지 확인한다.
리셋 억제 시에도 지속 실패하면 중단하고 최초 오류의 로그와 덤프를 보존한다.
억제 상태에서만 계속 정상 동작한다면 FW의 오류 심각도 보고와 리셋 경로를 조사한다.
패치 사용 결과에는 호스트 리셋 정책을 바꾼 실험임을 명시한다.

## 근거

- NVMe Base 2.3, Figure 152, Asynchronous Event Information – Error Status.
- https://raw.githubusercontent.com/gregkh/linux/v6.8.12/drivers/nvme/host/core.c
- https://raw.githubusercontent.com/torvalds/linux/v7.0/drivers/nvme/host/core.c
- https://lists.infradead.org/pipermail/linux-nvme/2022-June/032604.html
- https://lists.infradead.org/pipermail/linux-nvme/2024-August/049566.html
