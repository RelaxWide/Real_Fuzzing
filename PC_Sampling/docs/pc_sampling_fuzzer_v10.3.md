# pc_sampling_fuzzer v10.3

v10.3 은 v10.2 의 SSD FW 퍼징 기능을 그대로 두고, **LLM 백엔드를 사내 2노드 Samba
브리지에서 로컬 vLLM 으로 옮기는** 버전이다.

계획과 결정 근거는 [V10_3_LLM_BACKEND_PLAN.md](V10_3_LLM_BACKEND_PLAN.md) 를 따른다.

## 진행 상태

| 단계 | 내용 | 상태 |
|---|---|---|
| **P0** | 버전 생성 | **완료** |
| P1 | vLLM 생성 교체(검색 없음) | 미착수 |
| P2 | 로컬 RAG | 미착수 |
| P3 | 전환·측정 | 미착수 |

**P0 시점의 v10.3 은 v10.2 와 동작이 같다.** 버전 문자열·docstring·출력 디렉터리만
다르다. LLM 백엔드는 아직 기존 `rag.rag_bridge_client` 를 가리킨다.

## v10.2 대비 변경 (P0)

| 항목 | 내용 |
|---|---|
| `FUZZER_VERSION` | `10.2.0` → `10.3.0` |
| 출력 디렉터리 | `./output/pc_sampling_v10.3.0/` |
| docstring | LLM 항목을 "로컬 vLLM(OpenAI 호환)" 으로, 버전 요약에 v10.3 한 줄 추가 |
| 시험 대상 | `tests/test_v10_2_learning.py` 의 `FUZZER_FILE` 이 v10.3 을 가리킴 |

`llm_learning.py` · `riscv_cov.py` · `nvme_seeds.py` · `fuzzer_config.json` · `rag/` 는
버전 접미사가 없는 공유 자산이라 복사하지 않았다.

## 장치 경로 보호

`tests/fixtures/v10_2_device_ast.json` 의 고정 해시로 다음을 계속 검사한다.

```
RiscvPcsrSampler / JLinkHaltSampler / OpenOCDHaltSampler / OpenOCDPCSampler
_V101Fuzzer._send_nvme_command
```

**시험 대상은 활성 버전을 따라가지만 비교 기준은 검증된 v10.2 fixture 로 고정**한다
(`DEVICE_AST_FILES` 가 v10.2·v10.3 양쪽을 같은 기준선에 대조). 버전업이 기준선을 새로
만들면 의도치 않은 장치 경로 변경까지 승인하게 되므로, fixture 는 **자동 갱신하지 않는다.**
장치 경로를 의도적으로 바꿀 때만 리뷰 후 `hashes`/`source_commit`/`amendments` 를 함께 고친다.

## 실행

기존 v10.2 명령에서 파일명만 바꾸면 된다.

```bash
sudo python3 PC_Sampling/pc_sampling_fuzzer_v10.3.py \
  --product BM9K1 --nvme /dev/nvme0 --namespace 1 --rag
```

## 검증 (P0)

```bash
python3 -m unittest discover -s PC_Sampling/tests -p 'test_*.py'   # 92 tests, OK
python3 PC_Sampling/pc_sampling_fuzzer_v10.3.py --help
```

AST 보호가 실제로 v10.3 을 검사하는지는 **주입 시험으로 확인했다** — `RiscvPcsrSampler`
에 한 줄을 넣으면 `test_device_paths_match_frozen_v102_baseline` 이 실패하고, 되돌리면
통과한다.

실기 동작(실제 SSD·JTAG), DGX vLLM 서버, 추출된 JSONL 품질은 아직 검증하지 않았다.

## 알려진 정리 대상

- `llm_learning.py` 가 스냅샷 파일명을 `learning_v10.2.json` 으로 하드코딩한다. 공유
  모듈이라 v10.3 에서도 그 이름으로 쓴다(출력 디렉터리는 버전별로 갈리므로 충돌은 없다).
  P1 에서 이 모듈을 손댈 때 같이 정리한다.
- 시험 파일명이 `test_v10_2_*` 인 채로 v10.3 을 대상으로 한다. 파일명은 기능 단위라
  버전과 어긋나도 동작에는 문제가 없으나, 정리하려면 상호 import 를 함께 고쳐야 한다.
