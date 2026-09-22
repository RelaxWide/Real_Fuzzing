# 기존 스펙 JSONL로 검색 품질 비교

`tools/rag_retrieval_eval.py`는 장치를 접근하거나 생성 모델을 호출하지 않는다.
스펙별 하위 폴더의 JSONL을 재귀 탐색하며 기존 검색 인덱스를 재사용한다.
소스 폴더(예: `/home/ssd/pc_sample/rag/jsonl`)와 검색 인덱스는 다르다.
현재 퍼저는 설정의 `rag.vllm.retrieval.index_dir` 아래 `current`가 가리키는
`chunks.jsonl`과 `vectors.f16.npy`를 읽는다. 원본이 추가 분할된 경우 정답 ID는
반드시 **검색 인덱스의 ID**로 지정한다. 원본만 있고 인덱스가 없으면 이 시험을
진행할 수 없다. 자동 재색인은 하지 않는다.

PC_Sampling 디렉터리에서 실행:

```bash
python3 tools/rag_retrieval_eval.py prepare \
  --source-dir /home/ssd/pc_sample/rag/jsonl \
  --output output/rag_eval_cases.json
```

설정의 인덱스 위치가 다르면 `--index-dir /실제/rag/index`를 추가한다.
다른 설정은 `--config /실제/fuzzer_config.json`으로 지정한다.
prepare는 임베딩 API를 호출하지 않는다. 원본 제목 추출 결과와 실제 인덱스의
15개 명령 후보 청크 본문을 출력한다. 후보가 없으면 실제 인덱스 본문에서
해당 명령의 표·절을 검색해 수동으로 정답을 추가한다. 제목 없는 후속 청크의
태그 상속은 아직 하지 않으며, 이 누락도 평가 대상이다.

## 정답표 확인

출력 JSON의 cases 항목을 편집한다:

- `relevant_doc_ids`: 실제 필드 정의를 확인한 정답 청크 ID 목록. 후보를 무조건 정답으로 삼지 않는다.
- `reviewed`: 확인 후 true.
- `baseline_query`: 기본값은 명령 하나의 간이 질의다. 운영 기준 비교에는 실제 질의로 교체한다.
- `enhanced_query`: 예: `NVMe Read Command Dword SLBA NLB LR FUA PRINFO`. 실제 스키마·스펙 필드만 쓴다.
- `split`: 가중치 조정용은 development, 최종 확인용은 validation. 확인용 결과로 반복 튜닝하지 않는다.
- 복수 명령 사례는 `commands: ["Read", "Write"]`를 추가하고 실제 복수 명령 질의를 입력한다.

모든 사례의 검토·질의·정답을 확인해야 평가가 진행된다. 기존 2/10을 재현하려면
당시 동일한 명령·질의·정답표를 사용해야 한다. 15개 기본 후보로 자동 재현되는 수치가 아니다.

```bash
python3 tools/rag_retrieval_eval.py evaluate \
  --cases output/rag_eval_cases.json \
  --bonus 0.1 --top-k 10 \
  --output output/rag_eval_report.json
```

A=기존 질의+임베딩, B=개선 질의+임베딩,
C=기존 질의+태그 가산점, D=개선 질의+태그 가산점.
최종 점수는 원본 유사도 + bonus × 명령 태그 일치 여부.
동일 실행의 동일 질의는 임베딩을 한 번만 요청하며, 각 질의는 전체 eligible 벡터와
비교한다. 운영 permission_groups를 적용한다. 모델/revision과 인덱스 본문 해시를
검사한다. 임베딩 길이 초과 시 질의를 몰래 바꾸지 않고 실패한다.

보고서는 split별 Hit@5/10, MRR(rr), 개선/악화/동률 명령과 명령별 순위·top 결과를 담는다.
Hit는 정답 중 하나 이상이 들어가는 비율이며, 모든 관련 청크의 recall은 아니다.
순위 개선만으로 생성 결과의 정확성 개선까지 입증한 것은 아니다.

파일은 덮어쓰지 않으므로 반복 시험에는 다른 output 이름을 쓴다.
태그·질의 변경은 **평가 도구 안에서만** 적용된다. 운영 검색, 원본 JSONL,
인덱스 벡터, llm_io 로그는 이 도구가 변경하지 않는다. 쿼리 스키마 자동 추출 및
운영 llm_io 로그 확장은 별도 변경이다. 실제 인덱스·API에서 결과를 확인한 뒤
운영 반영 여부를 결정한다.
