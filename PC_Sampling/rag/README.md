# RAG seed/sequence/classification — v9.0 (작업 중)

NVMe base / 고객·vendor / TCG·ATA 스펙의 산문 지식을 RAG/LLM 으로 활용해 ① spec-aware 시드 생성
② 기존 시드 유의미성 분류·필터링 ③ 시퀀스 skeleton ④ coverage plateau 시 보강을 제공하기 위한
**별도(2노드) 서브시스템**. fuzzer hot loop 밖에서 비동기 동작하며, fuzzer 와는 파일시스템 drop-box
로만 통신한다. (전체 설계는 세션 plan 참조.)

## 2노드 구성
- **Test PC**: NVMe + `pc_sampling_fuzzer_v9.0.py` 실행(stdlib-only, LLM 미설치).
- **Intranet PC**: RAG 서비스 + 사내 LLM(HTTP REST, OpenAI 호환) + 로컬 임베딩. 스펙 문서 로컬 read.
- **공유 FS(NFS/SMB)**: `rag/{requests,inbox,sequences,archive,rejects,status}` drop-box.

## 이 폴더의 현재 파일 (스키마 ground-truth 다리)

| 파일 | 실행 위치 | 역할 |
|------|-----------|------|
| `export_cmd_schemas.py` | **Test PC** | fuzzer 의 `CMD_SCHEMAS`/`NVME_COMMANDS`/위험명령 가드를 `cmd_schemas.json` 으로 추출 |
| `cmd_schemas.json` | (생성물) | 명령별 CDW 필드 정의 + 위험명령 가드. **Intranet PC 로 복사** |
| `rag_schema.py` | **Intranet PC** | `cmd_schemas.json` 만으로(fuzzer import 불필요) 프롬프트 렌더 + `validate_and_repair` + 위험명령 판정 |

### 사용
```bash
# 1) Test PC: 스키마 추출 (fuzzer 스키마가 바뀌면 재실행)
python3 export_cmd_schemas.py            # → cmd_schemas.json

# 2) cmd_schemas.json 을 Intranet PC 의 이 폴더로 복사

# 3) Intranet PC: 스키마 브리지 동작 확인
python3 rag_schema.py                     # 자가 테스트 출력
```
```python
from rag_schema import SchemaBridge
b = SchemaBridge("cmd_schemas.json")
prompt_block = b.schema_to_prompt("Identify")     # LLM 프롬프트에 주입(생성이 schema-valid 하도록)
cdw, repaired, ok = b.validate_and_repair("Read", {"cdw10":0,"cdw12":7})
danger, why = b.is_dangerous("Sanitize")          # 위험명령 → 생성 금지
```

`validate_and_repair` 는 fuzzer 와 **동일한 CMD_SCHEMAS** 기준(같은 JSON)이라, 여기서 통과한 시드는
fuzzer 흡수 시에도 schema-valid. 위험명령(파괴/큐/SECP 잠금/NS-delete)은 자동 거부.

## 다음 단계 (예정)
- `rag_seed_service.py`: ingest(PDF/헤더 청킹·태깅) → embed(로컬 sentence-transformers, 교체가능)
  → vectordb(FAISS) → retrieve → 프롬프트(여기 `schema_to_prompt`) → 사내 LLM(REST) →
  `validate_and_repair` → drop-box 에 시드/분류/skeleton emit. **mock LLM 포함**(모델 없이 테스트).
- fuzzer 측 흡수부(`RagBridge` + plateau 훅 + `Seed.seed_class`)는 서비스 출력 형식 확정 후 구현.

## 출력 계약 (서비스가 만들 파일 — fuzzer 가 흡수)
- **시드**: `<cmd>_<hash>.bin` + `<cmd>_<hash>.bin.json`({command, cdw2..cdw15, seed_class?, rag_meta?})
  — fuzzer 의 기존 외부시드 로더(`_load_seeds`) 포맷 재사용.
- **분류**: `classify_<id>.json` = `[{command, cdw*, seed_class, rationale}]`.
- **시퀀스**: `seq_<id>.json` = `[{name, commands:[cmd_name...], ctx_mode?}]`.
- 원자성: `*.tmp`→rename, `.bin.json` 은 `.bin` 뒤에 작성.
