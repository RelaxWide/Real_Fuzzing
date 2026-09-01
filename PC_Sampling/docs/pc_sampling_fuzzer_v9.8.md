# pc_sampling_fuzzer v9.8

v9.8은 v9.7을 기준으로, FW의 비정상 NSID 처리 개선 전까지 `nsid_override`로 인한 불량 재발을 방지한다.

## 기본 동작

`fuzzer_config.json`의 다음 설정이 기본값이다.

```json
"nsid_override_policy": "active_only"
```

이 모드에서는 다음 규칙을 적용한다.

- 시작 시 `nvme list-ns`와 `/dev/nvmeXnY` 노드를 교차 확인해 현재 attach된 활성 NSID allowlist를 만든다.
- NSID mutation은 임의 32비트 값 대신 활성 allowlist 안에서 선택한다.
- namespace가 필요한 명령은 활성 NSID 중 하나만 발송한다.
- namespace가 필요 없는 명령은 NSID 0만 발송한다.
- LLM에는 활성 NSID 목록을 제공하며, 기존 seed/corpus, builtin·LLM sequence, state replay에서 비활성 override가 들어와도 최종 공통 발송 지점에서 allowlist 값으로 정규화한다.
- opcode/admin↔IO override가 발생하면 원본 명령이 아니라 최종 opcode와 실제 queue를 기준으로 NSID 규칙을 다시 계산한다. 미지 I/O opcode는 활성 namespace, 미지 admin opcode는 0을 사용한다.
- LLM이 활성 목록 밖의 NSID를 주면 corpus 저장 전에 제거한다. 목록 안의 NSID는 유지한다.
- I/O 명령의 NSID가 바뀌면 대상 block device도 `/dev/nvmeXn<actual_nsid>`로 함께 바꾼다.
- `--namespace`가 0 또는 broadcast 범위이면 pre-flight에서 실행을 중단한다.
- 정규화된 횟수는 종료 요약의 `NSID override policy`에 표시한다.
- 실제 발송 횟수는 `Actual NSID distribution`에 NSID별로 표시한다.
- crash replay history에는 원래 override가 아니라 실제 발송한 안전 NSID가 기록된다.

비활성 NSID는 명령을 버리지 않고 allowlist 값으로 바꾼다. 다만 실행 중 namespace가 사라져 대응 block device를 찾을 수 없으면 다른 namespace device로 잘못 보내지 않도록 해당 명령을 `RC_SKIP` 처리한다.

단일 namespace로 고정하려면 다음 정책을 사용한다.

```json
"nsid_override_policy": "configured_only"
```

## FW 개선 후 기존 탐색 복원

필터를 끄고 비정상 NSID까지 다시 검증하려면 아래처럼 변경한다.

```json
"nsid_override_policy": "fuzz"
```

이 모드에서는 mutation 또는 LLM/corpus/replay가 지정한 NSID를 그대로 발송한다. `0`, `0xffffffff`, 미존재 NSID 및 임의 32비트 값이 다시 FW에 전달될 수 있다.

## 실행

기존 v9.7 인자와 동일하다.

```bash
sudo python3 PC_Sampling/pc_sampling_fuzzer_v9.8.py \
  --product PM9M1_LNB \
  --nvme /dev/nvme0 \
  --namespace 1
```

시작 전 `fuzzer_config.json`에서 `nsid_override_policy`가 `active_only`인지 확인한다. 시작 로그의 `[NSID] active_only allowlist=[...]`가 기대한 namespace 목록과 일치해야 한다.
