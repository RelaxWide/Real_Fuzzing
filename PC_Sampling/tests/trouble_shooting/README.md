# trouble_shooting — 2026-09-29 BM9K1 정상 동작 시점 코드

BM9K1 인증·정합성이 정상 통과한 9/29 실행(`[CODE] sha=fd7927e8b51f`)의 코드를 그대로 옮긴 폴더.
현재 코드와 분리해서 같은 장비에서 그때 코드로 재현해 보기 위한 용도다.

## 출처
- 커밋 `d9cb5d1` (2026-09-29 17:00) 의 파일을 그대로 복사했다.
- `pc_sampling_fuzzer_v10.3.py` sha256[:12] = `fd7927e8b51f` — 9/29 로그와 일치.
- `fuzzer_config.json` 은 같은 커밋의 **저장소 버전**(sha `ad64bd3b6337`)이다.
  9/29 로그의 `cfg=33216362f83d` 는 실행 장비의 로컬 수정본이라 git 에 없다.
  그 로컬 값(예: PMU 인자·속도·전원요청)은 9/29 로그의 시작 줄을 보고 이 파일에 맞춰야 한다.

| 복사(d9cb5d1) | 링크(상위 `PC_Sampling/` 의 현재 파일) |
|---|---|
| `pc_sampling_fuzzer_v10.3.py`, `fuzzer_config.json`, `nvme_seeds.py`, `llm_learning.py`, `riscv_cov.py`, `risc-v/`, `rag/` | `products`, `dump`, `spec`, `pmu_4_1.py` |

링크 대상은 9/29 이후 저장소 변경이 없는 자산이거나 실행 장비에만 있는 파일이다
(`pmu_4_1.py` 는 저장소에 없으므로 `PC_Sampling/pmu_4_1.py` 가 있어야 한다).

## 실행
퍼저는 경로를 **스크립트 위치 기준**으로 푼다. 이 폴더의 파일을 직접 실행한다.
```
cd PC_Sampling/tests/trouble_shooting
sudo python3 pc_sampling_fuzzer_v10.3.py --product BM9K1 <9/29 과 같은 옵션>
```
시작 로그 `[CODE] sha=fd7927e8b51f` 를 확인한다. 산출물은 실행 위치의 `./output/` 에 생긴다.

단독 진단도 이 폴더의 9/29 버전으로 돌릴 수 있다:
```
sudo python3 risc-v/sjtag_unlock.py --diag
sudo python3 risc-v/sjtag_unlock.py --read-burst 5
```
