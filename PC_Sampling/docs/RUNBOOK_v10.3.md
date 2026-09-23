# v10.3 운용 런북 — 로컬 vLLM + RAG

세팅부터 실행·진단·다음 작업까지. 설계 근거는 [V10_3_LLM_BACKEND_PLAN.md](V10_3_LLM_BACKEND_PLAN.md),
구현 현황 정본은 [pc_sampling_fuzzer_v10.3.md](pc_sampling_fuzzer_v10.3.md) 를 본다.
이 문서는 **실제로 돌리는 방법**과 **걸렸던 함정**을 모은 것이다.

작성 기준 2026-09-21. 시험 279개 통과, 인덱스 968청크 구축 완료.

---

## 1. 무엇이 바뀌었나

사내 2노드 Samba 브리지(오프라인 퍼징 PC → 드롭박스 → 온라인 LLM PC)를 버리고
**DGX Spark 의 로컬 vLLM** 으로 옮겼다. 공유 폴더도, 드롭박스 폴링도, 살았는지 감시할
브리지 서비스도 없다.

| 단계 | 내용 | 상태 |
|---|---|---|
| P0 | 버전 생성 | 완료 |
| P1 | vLLM 생성 교체 | 코드 완료 · **실서버 측정 안 함** |
| P2 | 로컬 RAG | 코드 완료 · 인덱스 968청크 구축 완료 |
| P3 | 전환·측정 | **미착수 — 여기가 다음 할 일** |

---

## 2. 물리 구성

```
┌─ DGX Spark  192.168.10.1 ─────┐        ┌─ 테스트 PC  192.168.10.2 ──┐
│  :8000  nemotron-3-super      │◄──HTTP─┤  pc_sampling_fuzzer_v10.3   │
│         생성, 컨텍스트 1M     │        │  rag/vllm_client.py          │
│  :8001  bge-m3                │◄──HTTP─┤  rag/index/  (968 청크)      │
│         임베딩, 입력 상한 8,192│        │  nvme-cli ─► SSD, JTAG/SWD  │
└───────────────────────────────┘        └──────────────────────────────┘
                        직결 링크
```

**생성과 임베딩은 별개 단계, 별개 상한, 별개 프로세스다.** 8,192 는 bge-m3 의 *임베딩*
입력 상한이고 1,000,000 은 nemotron 의 *생성* 컨텍스트다. 그래서 검색 질의는 프롬프트
전문이 아니라 짧은 질의를 따로 만들어 보낸다.

> ⚠ 설정에 한때 있던 `192.168.137.238` 은 **office PC 쪽 경로**다. 그 주소를 쓰면 직결
> 링크를 타지 않고 사무망으로 나갔다가 거부되어 `Errno 113` 이 난다.

DGX 에서 두 인스턴스를 띄운다. `--served-model-name` 이 설정의 `model`·`embed_model` 과
글자까지 같아야 한다.

```bash
vllm serve <nemotron-3-super> --port 8000 --host 0.0.0.0 --served-model-name nemotron-3-super
vllm serve BAAI/bge-m3       --port 8001 --host 0.0.0.0 --served-model-name bge-m3
```

`--host 0.0.0.0` 이 아니면 Spark 가 인터페이스를 둘 가지므로 직결 주소에서 안 들린다.
확인: `sudo ss -tlnp | grep -E '8000|8001'`

---

## 3. 파일 배치

**리포에 다 있다. 옮기거나 떼어낼 파일이 없다.**

```
PC_Sampling/
├── pc_sampling_fuzzer_v10.3.py     실행 파일
├── fuzzer_config.json              ← 여기만 편집
├── llm_learning.py, riscv_cov.py, nvme_seeds.py   (버전 접미사 없는 공유 자산)
├── rag/
│   ├── __init__.py
│   ├── vllm_client.py              module_path 가 가리키는 백엔드. 옮기지 말 것
│   ├── llm_schema.py               task별 json_schema
│   ├── rag_retrieval.py            질의 사다리 + numpy top-k
│   └── index/                      ← rag_ingest 가 만든다 (.gitignore)
├── tools/rag_ingest.py
└── products/<제품>/                커버리지 자산 (사내 관리, 리포에 없음)
```

직접 두는 것은 **JSONL 하나뿐**이고, 위치는 자유다.

```
~/rag_src/                  ← 리포 **밖**. PDF 별 하위 폴더 그대로 둬도 된다
├── NVMe_Base_2.3/part1.jsonl ...
└── PCIe_5.0/part1.jsonl ...
```

> ⚠ JSONL 을 리포 안에 두지 말 것. `.gitignore` 는 `rag/index/` 와 `rag/bridge/` 만
> 막는다. `PC_Sampling/` 아래 아무 데나 두면 **내부 스펙 원문이 커밋될 수 있다.**

JSONL 한 줄 = `{"doc_id", "title", "content", "permission_groups"}`.

---

## 4. 설정 — `fuzzer_config.json` 의 `rag`

```jsonc
"rag": {
  "module_path": "rag.vllm_client",          // 되돌리려면 rag.rag_bridge_client
  "pass_system_prompt": true,                // 되돌리려면 false
  "fail_limit": 10,                          // 연속 실패 상한 → RAG 비활성
  "request_interval_sec": 60,
  "vllm": {
    "base_url": "http://192.168.10.1:8000/v1",
    "model": "nemotron-3-super",
    "timeout_sec": 400.0,                    // 임베딩+생성+JSON교정 **전체** 예산
    "max_tokens": 16384,
    "temperature": 0.7,
    "chat_template_kwargs": {                // Nemotron 추론 제어 (null=서버 기본값)
      "enable_thinking": true,               //   추론 블록 생성 여부
      "low_effort": true                     //   추론을 짧게 → 생성 토큰↓ 응답↑
    },
    "structured_output": true,               // json_schema 강제
    "include_generators_in_schema": true,    // 중첩 anyOf 못 다루는 백엔드용 탈출구
    "freeform_retry": false,
    "retries": 1,
    "retrieval": {
      "enabled": false,                      // ← P2 를 켤 때 true
      "index_dir": "rag/index",
      "top_k": 5,
      "embed_base_url": "http://192.168.10.1:8001/v1",
      "embed_model": "bge-m3",
      "embed_model_revision": null,          // ← 채워 두길 권함 (§9)
      "query_max_chars": 8000,
      "context_max_chars": 60000
    }
  }
}
```

`--config PATH` 로 다른 파일을 쓸 수 있다. **퍼저가 검색할 때 쓰는 값과 인덱스를 만들 때
쓰는 값이 같아야 한다** — 다르면 벡터 공간이 달라져 조용히 엉뚱한 문서가 뽑힌다. 그래서
`rag_ingest` 도 같은 설정을 읽는다.

---

## 5. 도구 — `tools/rag_ingest.py`

JSONL → 임베딩 → 버전 인덱스. 인덱스를 만드는 **유일한 도구**이고, 스펙을 추가하거나
청크 크기·임베딩 모델을 바꿀 때마다 다시 쓴다(계획 목표 G3).

```
rag_ingest.py [--dry-run] [--index-dir DIR] [--config PATH]
              [--embed-base-url URL] [--embed-model NAME]
              [--embed-model-revision REV]
              [--max-chars N] [--batch N] [--timeout SEC]
              inputs [inputs ...]
```

입력은 **파일·디렉터리·글롭** 모두 받는다. 디렉터리는 하위까지 재귀로 `.jsonl` 만 찾으므로
**상위 폴더 하나만 넘기면 된다**. Windows 셸은 글롭을 펴 주지 않으므로(리터럴 `*` 를 열면
errno 22) 도구가 직접 편다.

### 5.1 점검 먼저 — `--dry-run`

```bash
python3 PC_Sampling/tools/rag_ingest.py ~/rag_src --dry-run
```

임베딩 서버·numpy·설정 **없이** 돈다. 인덱스도 안 만든다. JSONL 이 다른 망에만 있을 때
그쪽에서 확인하라고 만든 것이라, 리포만 있으면 그 자리에서 돌아간다.
종료코드 `0` = 진행 가능, `1` = 거부됨.

```
[점검] 파일 4개 · 레코드 8개
[점검] content 길이  최소 325,673  중앙 370,596  최대 394,163
[점검] 레코드/파일   2.0
[점검] --max-chars 6000 기준 → 청크 569개
[점검] doc_id 원본 고유값 8개
  ✓ doc_id 중복 없음
[점검] 그대로 색인 가능합니다.
```

| 줄 | 의미 |
|---|---|
| `doc_id 중복` | 게시 거부 사유. 한 PDF 를 쪽수로 쪼개면 흔하다 |
| `소스 식별자 중복` | `상위폴더/파일명` 이 겹침. 폴더 이름을 구분할 것 |
| `레코드/파일` 이 1~2 + content 수십만 자 | 레코드가 통짜라 기계 절단이 많다는 뜻 (§9) |
| `건너뜀` | content 가 비었거나 JSON 이 깨진 레코드 |

### 5.2 색인

```bash
python3 PC_Sampling/tools/rag_ingest.py ~/rag_src
```

sudo 불필요하다(NVMe·JTAG 를 안 건드린다). root 로 돌리면 인덱스 소유자가 root 가 돼
나중에 퍼저가 일반 사용자로 읽을 때 걸린다.

```
[ingest] 입력 32개
[ingest] 임베딩 서버: http://192.168.10.1:8001/v1  model=bge-m3  revision=(미지정)
[ingest] 소스 32개 → 청크 968개
[ingest] 새로 임베딩할 청크 968개
[ingest] 게시 완료: .../rag/index/v20260916_xxxxxx  (청크 968, 1024차원)
```

**`[ingest] 임베딩 서버:` 줄이 의도한 주소인지 먼저 확인할 것.** 여기가 틀리면 그 뒤는 전부
헛수고다.

### 5.3 인덱스 구조

```
rag/index/
├── current                        현재 버전 이름만 담은 포인터
└── v20260916_xxxxxx/
    ├── manifest.json              소스 sha256·모델·revision·차원·정규화·분할 설정
    ├── chunks.jsonl               doc_id/title/content/permission_groups/source_file
    └── vectors.f16.npy            float16, L2 정규화
```

새 버전을 완성·검증한 뒤 **포인터만 원자적으로 교체**한다. 이전 버전은 지우지 않는다 —
실행 중 캠페인이 쓰고 있을 수 있다. 캠페인은 시작 시점에 해석한 버전을 끝까지 쓰므로,
도는 중에 재색인해도 안전하다.

확인:

```bash
python3 -c "
import json, pathlib, numpy as np
i = pathlib.Path('PC_Sampling/rag/index'); v = (i/'current').read_text().strip()
m = json.loads((i/v/'manifest.json').read_text())
print(v, '|', m['chunks'], '청크 |', m['dim'], '차원 |', m['embed_model'], m['embed_model_revision'])
print('벡터', np.load(i/v/'vectors.f16.npy').shape)
print('소스', len(m['sources']), '개')
"
```

### 5.4 게시가 거부되는 조건

조용히 나쁜 인덱스를 만드는 것이 가장 나쁘므로, 아래는 **포인터를 바꾸지 않고 멈춘다.**

소스 식별자 중복 · `doc_id` 중복 · 본문↔벡터 개수 불일치 · 차원 이상 · NaN/Inf ·
영벡터 · 더 쪼갤 수 없는 청크. 동시 실행은 `.ingest.lock` 으로 막는다(중단된 작업이
락을 남겼으면 지우고 다시 실행하라고 알린다).

---

## 6. 퍼저 실행

```bash
sudo no_proxy=192.168.10.1 http_proxy= https_proxy= \
  python3 PC_Sampling/pc_sampling_fuzzer_v10.3.py \
  --product BM9K1 --nvme /dev/nvme0 --namespace 1 --rag
```

실행 디렉터리는 상관없다(`sys.path` 에 스크립트 디렉터리를 넣는다).
`--no-rag` 면 LLM 경로 없이 blind/mutation 퍼징만 한다.

> ⚠ **`sudo` 는 기본이 `env_reset` 이라 셸의 `no_proxy` 를 버린다.** 프록시가 잡힌
> 환경에서는 위처럼 명령줄에 함께 넘기지 않으면 LLM 호출이 프록시로 새어 나간다.

### 읽어야 할 로그

```
[LLM] 활성 — rag.vllm_client.generate_rag_response(system, user, meta) (interval=60s, ...)
[LLM/rag] 인덱스 v20260916_xxxxxx — 청크 968개, 1024차원, 모델 bge-m3     ← P2 켰을 때만
[LLM/funnel] 요청=270 → 통신ok=270 → JSONok=266 | 정상0건=61 연속실패=0/10
[LLM/task] eval 57→2274(39.9/40,캡98%) seed 41→103(2.5/8,캡17%) seq 141→841(6.0/6,캡92%,잘림38) wl 31→31(1.0) | gen버려짐=97
```

깔때기는 **기여가 낮을 때 어느 단계에서 줄었는지** 보라고 있는 것이다.

**채택 수를 합산하지 않는다.** 응답 1건당 상한이 task 마다 5배 넘게 다르다
(seeds 8 / seq 6 / eval 40) — 합계를 내면 corpus_eval 이 총합을 지배해서 정작
커버리지를 뚫는 시드 기여가 묻힌다. task 별 **요청 대비**로 본다.

| 표기 | 뜻 |
|---|---|
| `41→103` | 요청 41건 → 채택 103개 |
| `(2.5/8)` | 요청당 평균 2.5개, 상한 8 |
| `캡17%` | 응답의 17% 가 상한을 꽉 채움 → **높으면 상한이 기여를 자르고 있다** |
| `잘림38` | 상한 때문에 버려진 항목 수(절단 **전** 원본 기준) |
| `정상0건` | 응답은 정상인데 채택 0 — 중복이거나 대상이 컬링됨. **실패가 아니다** |
| `gen버려짐` | generator 변형이 seeds 예산에 밀려 버려진 수 |

### 상한이 의미 있는가

프롬프트가 요구하는 수(`emit up to N`)와 절단 값이 일치하므로 **몰래 더 자르지는 않는다.**
다만 둘이 걸린다.

- **generators 가 seeds 와 같은 예산을 나눠 쓴다.** `max_variants=16` 인데
  `max_seeds_per_round=8` 이라 생성 규칙 하나가 온전히 펼쳐질 수 없고, 평범한 시드가
  8칸을 채우면 변형이 **전부** 버려진다. `gen버려짐` 이 그 수다 — 예전엔 세기만 하고
  어디에도 보고하지 않았다.
- `corpus_eval` 표본 수는 하드코딩 40 이었다 → `corpus_eval_sample` 로 설정화.

`캡%` 가 90%대면 그 task 는 상한에 눌려 있다. 올릴지는 응답 지연(§6-3)과의 맞교환이다
— 항목이 늘면 생성 토큰도 늘어난다.

| 끊긴 지점 | 의심할 것 |
|---|---|
| `요청` → `통신ok` | 서버·네트워크. 메시지에 HTTP 상태와 오류 본문이 그대로 실린다 |
| `통신ok` → `JSONok` | 구조화 출력. 중첩 `anyOf`(generators) 미지원이면 `include_generators_in_schema=false`. `finish_reason=length` 면 `max_tokens` |
| `항목` → `채택` | 중복이거나 의미 검증 탈락. **실패가 아니다** |
| `정상0건` 이 큼 | LLM 이 답은 하는데 쓸모가 없음 — 프롬프트·검색 품질 |
| `연속실패=10/10` | 서킷브레이커 작동 → RAG 꺼짐. 퍼징 루프는 계속 돈다 |

### 실패로 세는 것 / 안 세는 것

통신 실패 · 잘림(최종 `finish_reason=length`) · 파싱 실패 · task 형식 오류만 실패다.
**정상 응답인데 중복으로 채택이 0개인 경우는 실패가 아니다** — 실패로 세면 정상 동작 중에
LLM 이 꺼진다.

### 되돌리기

| 상황 | 조치 |
|---|---|
| 검색이 의심스러움 | `retrieval.enabled=false` → P1 상태로 즉시 복귀 |
| LLM 경로 전체 문제 | `--no-rag` |
| vLLM 을 버리고 사내 브리지로 | `module_path=rag.rag_bridge_client`, `pass_system_prompt=false` |

---

## 6-1. 디버그 프로브가 안 붙을 때

퍼저의 복구 사다리는 이렇다. 위에서 실패하면 아래로 내려간다.

| 칸 | 하는 일 | 비용 |
|---|---|---|
| `_reinit_target()` | OpenOCD 유지 + 디버그 전원 재활성화 + proc 재정의 + telnet 재연결 | ~1초 |
| `_reconnect(3회)` | telnet `shutdown` 으로 J-Link USB 를 정상 해제한 뒤 OpenOCD 재시작 | 수초 |
| **`_probe_usb_recover()`** | **프로브 USB 강제 복구 — 최후 수단** | ~3초 |
| 종료 | | |

**최후 수단이 필요한 이유**: J-Link 는 자체 MCU·펌웨어를 갖고 있어 **호스트를 재부팅해도
리셋되지 않는다**(대부분의 보드가 S5 에서도 USB 에 +5V 를 유지한다). 프로브가 고착되면
사람이 케이블을 뽑는 것이 유일한 해제 수단이었고, 그 자리를 소프트웨어로 대신한다.

```jsonc
"probe_usb_reset": {
  "enabled": true,
  "vendor_ids": ["1366"],        // SEGGER. CMSIS-DAP 이면 "0d28" 등 추가
  "settle_sec": 3.0,
  "uhubctl_location": null,      // 설정해야만 uhubctl 을 쓴다
  "uhubctl_port": null
}
```

두 단계다.

1. **uhubctl** — VBUS 를 실제로 끊어 물리적 재삽입과 동등하다. 다만 **위치를 추측하지
   않는다.** 엉뚱한 포트를 끄면 DUT 전원이나 키보드가 날아가므로, `uhubctl_location`·
   `uhubctl_port` 를 명시했을 때만 쓴다.
2. **`USBDEVFS_RESET`** — 재열거만 시킨다. 더 약하지만 의존성이 없다. root 필요.

`vendor_ids` 에 일치하는 USB 장치만 만진다. **DUT 는 NVMe(PCIe)라 영향받지 않는다.**

> ⚠ **전기적으로 죽은 링크는 이걸로도 안 살아난다.** 고착만 푼다. 재부팅·재삽입에도
> 안 붙고 같은 DUT 가 다른 PC 에서 되면 프로브·USB·접지 쪽 고장이다 — §7 을 볼 것.

## 6-2. 샘플러 진단 계측

며칠씩 돌다 PCSR 이 죽는 원인을 사후에 가리기 위한 계측. **전부 읽기·기록뿐**이고
퍼징 경로를 바꾸지 않는다. 산출물은 `output/<버전>/sampler_diag/`.

| 파일 | 내용 |
|---|---|
| `openocd_<시각>.log` | OpenOCD 의 전체 출력(stdout+stderr) |
| `sampler_events.log` | 읽기 실패 시 DAP 상태, reinit/reconnect 이력, RSS/fd 추세 |

### OpenOCD 출력은 파이프가 아니라 파일로 받는다

**이건 계측이자 결함 수정이다.** OpenOCD 는 모든 로그를 stderr 로 쓰는데, 예전에는
`subprocess.PIPE` 로 받아 놓고 **정상 동작 중에는 아무도 읽지 않았다.** 리눅스 파이프
버퍼(기본 64 KiB)가 차는 순간 OpenOCD 는 다음 write 에서 **무기한 블록**된다. 읽기 실패
한 줄이 ~50B 라 며칠이면 조용히 임계에 닿고, 그때부터 telnet 응답이 끊겨 전면 PCSR
실패로 보인다. 파일은 블록되지 않는다.

### 읽기 실패 시 DAP 에게 직접 묻는다

실패 원인은 DP 의 `CTRL/STAT` 에 남는데, 예전에는 그걸 **읽지도 않고 다음 읽기의
sticky pre-clear 가 지워 버렸다.** 이제 지우기 **전에** 남긴다(읽기 1회, 스로틀됨).

| 관측 | 원인 |
|---|---|
| `STICKYERR` | AP 트랜잭션 fault — 타겟이 응답 거부. 링크는 살아 있음 |
| `STICKYORUN` | 오버런 — **속도 과다**. adapter speed 를 낮출 것 |
| `WDATAERR` | 쓰기 데이터 오류 — 신호 무결성 |
| `CDBGPWRUPACK` 꺼짐 | **디버그 전원 도메인이 내려감** |
| DPIDR/CTRL-STAT 을 아예 못 읽음 | SWD 링크 사망 — 물리·어댑터 |

### 누적 이력

`uptime / reads / reinit / reconnect / ok / fail` 을 실패·복구마다 남긴다.
치명적 실패 전에 `reinit` 이 수백 번 성공했다면 **점진 열화**, 첫 실패가 곧 치명이면
**급사**다. 이 구분이 없으면 원인 추정이 불가능하다.

### 재시작 사다리의 속도 변주

예전에는 **같은 설정으로 3번** 재시도했다 — 링크가 열화됐으면 3번 다 실패한다.
이제 회차마다 `adapter speed` 를 낮춘다(`reconnect_speeds_khz`, 기본 `[null, 1000, 500]`).
낮은 속도로라도 붙으면 캠페인이 안 죽는다.

### 리소스 추세

`resource_monitor` 가 5분마다 OpenOCD·퍼저의 RSS/fd/스레드 수를 남긴다. 단조 증가하면
호스트 누수다. **실패를 기다릴 필요 없이 몇 시간이면 추세가 보인다.**

```jsonc
"sampler_diag": { "resource_monitor": true, "resource_interval_sec": 300 },
"reconnect_speeds_khz": [null, 1000, 500]
```

> 계측은 **무슨 일이 있어도 읽기 경로에 예외를 올리지 않는다.** 이 프로젝트는 진단
> 도구가 스스로 버그가 된 사례를 두 번 겪었다(faulthandler, 커널 debug 옵션).

## 6-3. 프롬프트 크기 / 응답 지연

Nemotron 응답이 3분 넘게 걸릴 때 어디를 줄일지.

### 먼저 내역부터 본다

`rag.log_responses=true` 로 켜면 요청마다 `usage`(prompt/completion 토큰)·
`reasoning_chars`·`elapsed_sec` 가 `llm_io*.jsonl` 에 쌓인다. **생성 토큰 수가 곧
시간**이므로 여기부터 본다.

실측(2026-09): completion 4,914 / 7,708 / 8,187 / 8,834 / 12,122 토큰. 프롬프트
15K~19K 토큰. prompt throughput 이 generation 의 약 20배라 **prefill 은 병목이 아니다**
— 프롬프트 축소의 값어치는 prefill 시간이 아니라 **reasoning 길이를 줄이는 간접 효과**다.
그래서 확실한 이득이라고 단정하지 않는다.

### 추론 제어 — `chat_template_kwargs`

서버에 그대로 전달된다. 불리언만 받으며 클라이언트가 **보내기 전에** 타입을 검증한다.
`null` 이면 서버 기본값을 따라가므로, 무엇으로 돌고 있는지 알 수 없다 — 명시해 두는 편이
낫다. 어떤 값으로 부른 응답인지는 `diagnostics.requested_chat_template_kwargs` 에 남는다.

| 키 | 효과 |
|---|---|
| `enable_thinking` | 추론 블록 생성 여부. 끄면 짧고 빠르지만 형식 오류가 는다 |
| `low_effort` | 추론을 짧게. **생성이 병목이므로 여기가 가장 큰 지렛대다** |

> ⚠ `low_effort` 를 켜면 JSON 품질이 떨어져 교정 호출이 늘 수 있다. 최초 호출과 교정
> 호출이 **`timeout_sec` 하나를 나눠 쓰므로**(§P1) 예산 초과가 늘 수 있다. 실제로
> 추론을 낮췄을 때 예산 초과 20% 가 관측됐는데, **느려서가 아니라 재시도 때문일 수
> 있다.** `diagnostics.correction` 이 붙어 있는지 먼저 보고, 그렇다면 `json_retries`
> 를 줄이거나 `timeout_sec` 를 올리는 쪽이 답이다.

### 프롬프트의 숫자 표기 — 전부 10진수

시스템 프롬프트는 `All numeric fields ... are DECIMAL integers` 를 요구하는데, 스키마는
`valid=0x0,0x1` 처럼 **16진수로 보여주고 있었다.** 모델은 본 대로 따라 쓴다 — JSON 값에
`0x` 를 넣어 파싱이 깨진다(`_sanitize_json` 이 그걸 수습하려고 존재한다).

보여주는 형식과 요구하는 형식을 맞췄다.

| 대상 | 표기 | 이유 |
|---|---|---|
| `valid=` / `vendor=` / `reserved=` | **10진수** | 모델이 JSON 에 그대로 쓰는 필드 값 |
| 보정 노트(`cdw10: 31->6`) | **10진수** | `_llm_reject_block` 으로 **프롬프트에 되먹임된다** |
| `is_dangerous` 의 SECP | **10진수** | cdw10 에서 뽑은 필드 값 |
| `opcode=0x02` | **16진수 유지** | 규격 식별자. 모델은 `command` 를 **이름**으로 지정하지 숫자로 쓰지 않는다 |

되먹임 경로 둘(보정 노트·거절 사유)이 프롬프트로 들어가는 걸 놓치기 쉽다 — 스키마만
고치면 절반만 고친 것이다.

### 효과가 약한 것들 (실측으로 배제됨)

| 시도 | 왜 안 되나 |
|---|---|
| `max_tokens` 축소 | 생성이 실제로 5K~12K 토큰이라 자르면 `finish_reason=length` |
| 추론 레벨 낮추기 | 시간 예산 초과가 20% 발생 |
| `--max-model-len` 축소 | 프롬프트가 1M 의 2% 수준. hybrid SSM 이라 KV 계산도 다름 |
| `--enable-prefix-caching` | prefill 이 이미 20배 빠름 → 이득 작음 |

> 추론 레벨 실험에서 예산 초과가 잦다면 `diagnostics.correction` 을 확인할 것.
> 최초 호출과 JSON 교정 호출이 **하나의 예산**을 나눠 쓰므로(§P1), 응답 품질이 나빠져
> 교정이 늘면 같은 예산을 여러 번에 나눠 쓰다 초과한다. 그 경우 느려서가 아니라
> **재시도 때문**이고, `json_retries` 나 `timeout_sec` 쪽이 답이다.

### 실제로 줄인 것

| 항목 | 이전 | 이후 |
|---|---|---|
| 스키마 섹션(41개 명령) | 8,524자 | **2,926자** (cap 16 + 중복 제거) |
| — 중복 제거만 | 8,524자 | 7,043자 (−17%) |
| — cap 41→16 | — | 추가로 −4,117자 |
| favored 예시 6칸 | 중복이 칸을 채움 | 서로 다른 6개 |

**`schema_max` 가 48 이었다** — 구현 명령이 41개라 캡이 없는 것과 같았고, 관련도와
무관하게 매번 전 명령이 실렸다. 이제 16 이고, 호출부가 준 우선순위(never-sent →
low-yield) 앞쪽을 취한다. 정렬을 다시 하지 않는다.

**스키마 중복 제거**는 공통 필드(`SLBA_LO`/`NLB`/`PRINFO` …)를 용어집에 한 번만 쓰고
명령은 이름만 나열한다. 단 **같은 이름이 명령마다 다른 비트 위치를 갖는 경우**
(`SEL`/`STC`/`CA`/`NUMD` 등 15개)는 용어집에 올리지 않고 인라인한다 — 축약이 의미를
바꾸면 LLM 이 틀린 CDW 를 만든다.

> ⚠ `schema_max` 를 낮추면 **LLM 이 보는 명령 종류가 줄어든다.** 프롬프트만 주는 게
> 아니라 커버리지에 영향이 있을 수 있으니, `[LLM/funnel]` 채택률을 보며 조정할 것.

```jsonc
"schema_max": 16        // 0 이면 전부
```

## 6-4. BLAS 스레드 — 퍼저 hang 의 원인

**검색(P2)을 켜면 퍼저가 hang 처럼 보이는 현상이 있었다.** `sched_yield` busy-wait 로
관측됐고, 원인은 OpenBLAS 스레드풀이다.

`rag_retrieval.retrieve()` 의 top-k 행렬곱(`vectors @ vec`)이 OpenBLAS 를 부른다.
OpenBLAS 워커는 **연산이 끝난 뒤에도** 다음 작업을 기다리며 `sched_yield()` 로
busy-wait 한다(기본 spin 시간이 길다). 퍼저는 샘플러·LLM 워커·메인 루프가 함께 도는
멀티스레드 프로세스라, 코어 수만큼의 스핀 스레드가 CPU 를 태우고 다른 스레드를 굶긴다.

### 실측

| | OS 스레드 | 행렬곱 200회 | `sched_yield` |
|---|---|---|---|
| 제한 없음 | 4개 | 14.7 ms | **2,793회** |
| `*_NUM_THREADS=1` | 1개 | 23.8 ms | **0회** |

회당 0.073 → 0.119 ms. **60초에 한 번 도는 연산이라 무의미한 차이**이고, 스핀은 사라진다.

### 조치

`pc_sampling_fuzzer_v10.3.py` · `rag/rag_retrieval.py` · `tools/rag_ingest.py` 최상단에서
**numpy import 보다 먼저** 아래를 `setdefault` 한다(사용자 지정값은 존중).

```
OPENBLAS_NUM_THREADS · OMP_NUM_THREADS · MKL_NUM_THREADS
NUMEXPR_NUM_THREADS · VECLIB_MAXIMUM_THREADS = 1
```

> **순서가 전부다.** numpy 가 먼저 로드되면 환경변수는 무시된다. 이 코드베이스는 numpy
> 를 전부 함수 안에서 지연 import 하므로 최상단 설정이 확실히 먼저 잡힌다. 시험이
> 별도 프로세스를 띄워 "import 직후 값이 1이고 numpy 는 아직 미로드" 를 확인한다.

함께 고친 것 — `retrieve()` 가 질의마다 `vectors.astype(np.float32)` 로 **인덱스 전체를
복사**하고 있었다(10만 청크면 매 질의 400 MB). `_load()` 에서 한 번만 변환해 캐시한다.

### hang 이 다시 나면

```bash
PID=$(pgrep -f pc_sampling_fuzzer)
py-spy dump --pid $PID              # 모든 스레드의 파이썬 스택 — 이게 제일 빠르다
ps -o nlwp= -p $PID                 # 스레드 수가 코어 수만큼이면 네이티브 풀 의심
sudo strace -c -f -p $PID           # sched_yield 가 압도적이면 스핀
```

## 6-5. 종료 요약의 NSID 분포

`nsid` 는 퍼징 대상이라 값 종류가 계속 늘어난다. 전량 나열하면 긴 캠페인에서 이 한 줄이
요약을 통째로 덮는다(1,300종이면 **2.5만 자**). 횟수 상위만 보이고 꼬리는 접는다.

```
Actual NSID distribution (1,303종): nsid=1:120394회, nsid=0:512회, … , …그 외 1,295종 3,188회
```

- **값 순이 아니라 횟수 순**으로 자른다. 값 순으로 자르면 가장 많이 쓴 nsid 가 잘려 나간다
- 꼬리는 버리지 않고 **종수·합계**로 남긴다 — 개별 값보다 "얼마나 퍼졌나" 가 정보다
- 총 종수를 앞에 붙여 분포의 넓이를 한눈에 본다

```jsonc
"summary_nsid_top": 8      // 0 이면 전부 나열
```

## 6-6. LLM task 선택 — 초반 편중

기동 직후 첫 11회 요청이 `new_group_seeds` 8 / `sequences` 2 / `corpus_eval` 1 로 쏠리고
`io_patterns` 는 한 번도 안 나오는 현상이 있었다. 라운드로빈이 고장 난 게 아니다.

선택은 4단계고 **뒤가 앞을 덮는다**:

| 단계 | 위치 | 하는 일 |
|---|---|---|
| 1 | 기동부 | `seed_at_startup=true` 면 **회전판 0번**을 꺼내 1건 요청(순번도 소비) |
| 2 | `_llm_maybe_submit` | plateau 면 `sequences`/`new_group_seeds` 우선 (연속 `max_consec_task` 상한) |
| 3 | `_llm_maybe_submit` | 가중 라운드로빈 `_llm_rr_peek` — `rag.task_weights` |
| 4 | `LearningState.choose` | `adaptive_tasks=true` 면 3단계 결과를 **폴백으로만** 쓰고 보상 최고 task 를 고름 |

### 원인 ① — 기동 시딩이 회전판 밖에 있었다

예전 1단계는 `new_group_seeds` 를 하드코딩하고 회전 커서(`_llm_task_rr`)를 건드리지 않았다.
그래서 기동 직후 **1건째(시딩)와 2건째(회전판 0번)가 둘 다** `new_group_seeds` 로 나갔다.
`_learning_submitted` 가 `turn`/`explore_cursor` 는 올리는데 회전 커서만 빠져 있었다.

지금은 두 경로가 `_llm_rr_peek()` 하나를 공유한다. 기동 시딩도 회전판에서 꺼내고 순번을
소비하므로, 다음 요청은 그 다음 칸이다. `task_weights` 기본값 기준 회전판은 이렇게 돈다:

```
[new_group_seeds, sequences, sequences, corpus_eval, io_patterns, io_patterns]
   ↑ 기동 시딩      ↑ 2건째
```

기본값에선 1건째가 `new_group_seeds` 다 — 회전판 0번이 거기라서다. 이것만 다른 task 로
바꾸고 싶으면 `startup_task` 를 쓴다.

```jsonc
"startup_task": "off"      // 기본. 회전판이 정함(순번 0번)
"startup_task": "sequences" // 1건째만 고정. 순번은 그대로 소비 → 2건째는 회전판의 다음 칸
```

**고정해도 순번은 소비한다.** 안 그러면 1건째(고정)와 2건째(회전판 0번)가 겹치는 원래
버그로 돌아간다. 비활성이거나 모르는 이름이면 경고를 남기고 회전판을 따른다.

`seed_at_startup: false` 로 기동 요청 자체를 없앨 수도 있지만 순서는 안 바뀐다 — 그 칸이
비어 첫 요청이 늦어질 뿐이다.

### 원인 ② — 보상 표본 1건으로 탐욕 결정

편중의 원인은 4단계였다. 1단계가 `new_group_seeds` 를 제일 먼저 보내므로 그 task 가
완료 평가를 제일 먼저 채우고, **보상 표본이 있는 유일한 task** 가 되어 `max(ranked)` 를
계속 이긴다. 라운드로빈은 연속 상한과 탐색 턴(`turn % exploration_every == 0`)에서만 살아난다.
표본 1건은 추정치가 아닌데 그것으로 탐욕 결정을 내린 게 문제다.

```jsonc
"learning": {
  "min_reward_samples": 2     // 이 수만큼 완료 평가가 쌓여야 순위 경쟁에 참가. 1 = v10.2 동작
}
```

미달인 task 는 순위에서 빠지고 폴백(가중 라운드로빈)이 결정한다. 영구 배제가 아니라
**표본 대기**라서, 쌓이면 원래대로 보상 높은 task 를 고른다.

실제 `choose()` 를 11회 돌린 결과:

| `min_reward_samples` | seeds | seq | eval | io |
|---|---|---|---|---|
| 1 (수정 전) | **8** | 2 | 1 | 0 |
| 2 (기본) | 4 | 4 | 2 | 1 |
| 3 | 2 | 6 | 2 | 1 |

`new_group_seeds` 를 더 줄이고 싶으면 값을 올리기보다 `rag.task_weights.new_group_seeds`
를 내리는 쪽이 의도가 분명하다 — `min_reward_samples` 는 **초반 표본 부족**을 다루는 값이지
task 비중을 정하는 값이 아니다.

`new_group_seeds` 를 더 줄이고 싶으면 값을 올리기보다 `rag.task_weights.new_group_seeds`
를 내리는 쪽이 의도가 분명하다 — `min_reward_samples` 는 **초반 표본 부족**을 다루는 값이지
task 비중을 정하는 값이 아니다.

### 원인 ③ — 회전판이 고른 칸을 버리면서 순번만 소비 (io_patterns 기아의 진짜 원인)

①②를 고친 뒤에도 `io_patterns` 가 9건 동안 **한 번도** 안 나왔다. 남은 원인은 3단계와
4단계 사이에 있었다.

```python
task = self._llm_rr_next(active)        # 꺼내는 순간 순번을 올린다
task = self.learning.choose(...)        # 그 결과를 버릴 수 있다
```

`choose()` 는 회전판 결과를 **폴백으로만** 받는다. 탐색 턴이면 무시하고 `active[cursor]` 를,
보상이 쌓였으면 `max(ranked)` 를 돌려준다. 빌드 실패나 in-flight 거절로 아예 안 나가기도
한다. 그때마다 **버려진 칸이 소비**돼 그 자리는 다시 오지 않았다.

실측 30건에서 회전판이 `io_patterns` 를 10번 골랐는데 실제로 나간 건 5번뿐이다.
`task_weights.io_patterns = 2` 가 아무 효과가 없던 이유다.

```python
_rr_pick = self._llm_rr_peek(active)     # 소비하지 않고 본다
task = _cand if _cand is not None else _rr_pick
task = self.learning.choose(active, task, RAG_MAX_CONSEC_TASK)
...
if self.llm.submit(...):
    if task == _rr_pick:
        self._llm_rr_consume()           # 그 칸이 실제로 나갔을 때만
```

교체당하면 그 칸이 다음에 다시 온다. 기동 시딩도 같은 규칙을 따른다(①과 일관).

### 원인 ④ — cold start

보상이 없는 task 는 `ranked` 에 못 든다. 그래서 다른 task 에 보상이 붙는 순간 탐욕 분기가
비탐색 턴을 전부 가져가고 신참은 굶는다. `io_patterns` 는 `active` 의 **마지막**이라
탐색 턴으로도 4번째 탐색(=12번째 요청)에야 닿는다.

경쟁 task 에 `min_reward_samples` 만큼의 **시도**를 먼저 준다.

> ⚠ 게이트를 **보상 수**로 걸면 livelock 한다. 평가가 영영 완료되지 않는 task(소비되지 않는
> `io_workload` descriptor 등)가 영원히 cold 로 남아 매 턴 자기를 고른다 — 실제로 30건 중
> 18건을 먹었다. **요청 수**로 걸어야 `need × len(allowed)` 안에 끝난다.

동률은 회전판 선택이 이겨서 `task_weights` 가 warm-up 도 지배한다. `corpus_eval` 은
설계대로 탐색 슬롯 전용이라 제외한다.

### 효과

실제 `choose()` 를 구동한 결과:

| | 9건 | 30건 |
|---|---|---|
| 전 | seed 2, seq 4, eval 2, **io 1** | io 순번 10 / 실제 제출 5 |
| 후 | seed 2, seq 3, eval 2, **io 2** | seed 15, seq 4, eval 3, **io 8** |

`io_patterns` 가 보상을 영영 못 받는 최악 조건에서도 40건 중 6건 — 굶지도, 독점하지도
않는다.

**측정상 기아를 푼 것은 ③이다.** ④는 캠페인을 이어받아 보상이 남은 상황에서 한 번도 안 돈
task 가 밀리는 것을 막는 보조 장치다.

### 선택 결과를 로그에서 본다

`[LLM] 요청 제출` 에 회전판이 고른 것을 함께 남긴다. 교체가 일어났는지 바로 보인다.

```
[LLM] 요청 제출: task=sequences   (plateau=False, 회전판=io_patterns)   ← 교체됨
[LLM] 요청 제출: task=io_patterns (plateau=False, 회전판=io_patterns)
[LLM] io_patterns 요청 제출 — I/O 워크로드 descriptor 요청
```

시험: `tests/test_v10_3_task_selection.py` **35건** — 기동 블록과 `_llm_maybe_submit` 을
**소스 그대로 실행**해 확인한다. peek/consume 를 따로만 시험하면 호출부가 무조건 consume
해도 안 잡힌다(실제로 한 번 놓쳤다).

## 6-7. 명령 차단 — 두 층

### 6-7-1. 특정 (opcode, CDW 값) 조합 — `blocked_cdw_rules`

`opcode` 하나로는 못 막고 **특정 값**이 장치를 못 쓰게 만드는 경우가 있다.

> **vendor 0xC0 + CDW12=0x2 는 디버그 포트를 영구히 닫는다.** 전원 사이클로도 복구되지
> 않아(공장 초기화 필요) 그 샘플로 더는 PC 샘플링을 못 한다 — **OpenOCD 포트 4444 대기
> 타임아웃의 근본 원인**이다.

`0xC0` 은 이름 붙은 명령이 아니라 opcode 변이 `randint(0xC0, 0xFF)` 로만 나온다. 스키마도
`excluded_opcodes` 도 닿지 않고, 값을 볼 수 있는 곳은 발송 chokepoint 뿐이다.

```jsonc
"blocked_cdw_rules": [
  { "opcode": "0xC0", "cdw": 12, "value": "0x2", "scope": "any",
    "why": "디버그 포트 폐쇄" }
]
```

- **전 제품 공통**이다(제품 프로필이 아니라 `strategy` 에 두는 이유)
- `mask` 생략 = 전 비트 일치. 비트필드 일부만 볼 때 쓴다
- `scope` 는 `admin` / `io` / `any`(기본) — 같은 번호가 큐에 따라 다른 의미일 때
- 16진 문자열도 받는다. 잘못된 규칙은 기동 시 `sys.exit` 으로 즉시 죽는다(조용히 무시하면
  안 막힌 채로 돈다)

```
[GUARD] opcode 0xc0 + CDW12=0x00000002 전송 차단 — 디버그 포트 폐쇄 (cmd=Identify, admin-passthru)
```

차단은 `RC_SKIP` 을 돌려준다 — **§6-7-3** 참조.

v11(`pc_sampling_fuzzer_v11.py`)은 v10.3 을 `runpy` 로 실행하고 설정도 공유하므로 **자동
적용**된다. mixin 의 `_send_nvme_command` 도 마지막이 `super()` 위임이라 가드를 건너뛰지
않는다.

### 6-7-2. 영원히 거절되는 명령은 프롬프트 목표에서 뺀다

닫힌 되먹임 고리가 있었다.

```
가드 차단 → RC_SKIP → 회계 없이 continue → cmd_stats 에 안 남음
  → exercised 안 됨 → 'Never-sent command groups' 최상단 고정
  → LLM 이 매 라운드 그것만 제안 → 또 차단
```

걸려 있던 셋:

| 명령 | 사유 |
|---|---|
| `Lockdown` | `blocked_admin_opcodes` 의 0x24 |
| `FormatNVM` | `destructive` |
| `Sanitize` | `destructive` |

시퀀스에서는 더 나쁘다 — **멤버 하나가 막히면 체인 전체가 폐기된다**(부분 채택 금지).

판정은 목록을 새로 들지 않고 `is_dangerous()` 를 **cdw 없이** 부른다. 손으로 든 목록은
가드와 어긋난다. 값에 의존하는 가드(`SecuritySend` SECP, `NamespaceManagement` SEL,
`blocked_cdw_rules`)는 `cdw=0` 에서 통과하므로 **후보로 남는다** — 허용값으로는 실제로
나가고 스키마 `valid` 가 범위를 이미 강제한다.

```
[LLM] 영구 거절 명령을 프롬프트 후보에서 제외: ['FormatNVM', 'Lockdown', 'Sanitize']
```

**설정만 바꿔도 따라온다**(재시작 필요):

| 출처 | 자동 반영 |
|---|---|
| `fuzzing.excluded_opcodes` | ✅ |
| `strategy.blocked_admin_opcodes` | ✅ |
| `destructive` | ❌ — `pc_sampling_fuzzer_v10.3.py` 에 하드코딩 |

### 6-7-3. `RC_SKIP` 은 "실패" 가 아니다

| | `rc >= 0` | `RC_ERROR` | **`RC_SKIP`** |
|---|---|---|---|
| `executions` 증가 | ✅ | ✅ | ❌ |
| 커버리지 귀속 | ✅ | — | ❌ |
| crash/timeout 판정 | ✅ | — | ❌ |
| 실패 통계 | ✅ | ✅ | ❌ |

차단을 실패로 세면 **가짜 불량률**이 생기고, 실행으로 세면 **LLM vs mutation yield 의
분모가 오염**된다. 보내지도 않은 명령이 성과 지표를 망치는 것을 막는 장치다.

`_learning_observe` 는 부른다 — LLM 제안이 차단됐다는 사실은 학습에 남겨야 한다(보상은
안 붙는다).

## 6-8. 시퀀스 길이 — 상한이 아니라 프롬프트 문구가 병목이었다

`[LLM/task]` 가 `seq 3→7(2.3/6,캡0%)` 이면 **상한 6 에 평균 2.3, 한 번도 안 참** 이라
길이를 늘릴 여지가 있다는 뜻이다. 그런데 `max_seq_len` 만 올려도 모델은 그대로 3-6 개를
낸다 — 프롬프트가 그렇게 쓰여 있었기 때문이다.

```
"typically 3-6 commands"  →  "typically 6-10 commands"
max_seq_len: 16 → 24
```

리플레이 비용이 최악 1.5배가 되지만, 보상식이 `device_seconds` 로 나누므로 긴 체인은
스스로 페널티를 받는다.

`eval 2→80(40.0/40, 캡100%)` 의 캡 100% 는 **정상**이다 — `corpus_eval` 은 표본 40개를
전부 평가해 돌려줘야 하므로 항상 상한에 닿는다. 조치 대상이 아니다.

## 7. 트러블슈팅 — 실제로 걸렸던 것들

증상이 원인을 안 가리키는 것들만 모았다. **위에서부터** 의심한다.

| 증상 | 원인 | 조치 |
|---|---|---|
| `Errno 113 No route to host`, `nc` 는 성공 | **프록시.** `urllib` 은 프록시를 타고 `nc` 는 안 탄다 | `no_proxy` 설정. sudo 면 명령줄에 함께 |
| `Errno 113`, 직결인데 사무망 경로를 탐 | 설정 주소가 `192.168.137.238` | `192.168.10.1` 로 |
| `No module named 'rag.vllm_client'` | `rag_ingest.py` 가 `tools/` **밖**에 있음 | `ROOT=parent.parent` 이므로 `<base>/tools/` 아래 둘 것 |
| 설정이 멀쩡한데 "읽지 못했습니다" | 같은 원인(ROOT 가 한 단계 위) 또는 **UTF-8 BOM** 또는 JSON 문법 오류 | 메시지 **끝의 예외 문구**가 셋을 가른다 |
| `연결 실패 http://127.0.0.1:8001/...` | 설정을 못 읽어 내장 기본값으로 떨어짐 | `[ingest] 임베딩 서버:` 줄을 먼저 볼 것 |
| `Errno 22 Invalid argument` (`*.jsonl`) | Windows 셸이 글롭을 안 폄 | 지금은 도구가 직접 편다. 폴더를 넘겨도 된다 |
| `Errno 111 Connection refused` | 호스트는 닿는데 그 포트에 아무도 없음 | vLLM 기동·`--host 0.0.0.0` 확인 |
| `Errno 110 timed out` | 패킷이 조용히 버려짐(DROP) | 방화벽 |
| ping 은 되는데 TCP 만 113 | 방화벽이 ICMP 는 허용, TCP 는 REJECT | 8000/8001 열기 |
| `다른 색인 작업이 진행 중입니다` | 중단된 실행이 남긴 `.ingest.lock` | 파일 지우고 재실행 |
| 검색 켠 뒤 퍼저가 **hang**, `sched_yield` busy-wait | OpenBLAS 스레드풀 스핀 | `*_NUM_THREADS=1` (§6-4). numpy import 보다 먼저 |
| `swd: read data parity mismatch` + DPIDR 값이 매번 다름 | SWD 신호 무결성 | `adapter speed` 를 4000 → 1000 → 500 으로. 배선·GND 리턴 |
| 재부팅·재삽입에도 **영영** 안 붙고 같은 DUT 는 다른 PC 에서 됨 | 마진이 아니라 **고장**. 프로브·USB 포트·접지 | 프로브 USB 30초 분리 → `VTarget` 확인 → USB 포트 변경 → 프로브를 정상 PC 로 교차 확인 → 호스트·DUT 접지 통일. **속도 조절은 이 단계에서 무의미** |
| 수일 뒤 디버그 포트가 **영구히** 닫힘(전원 사이클 무효, 공장 초기화만 복구) | vendor `0xC0` + `CDW12=0x2` 가 나갔다 | `strategy.blocked_cdw_rules` 로 차단(§6-7-1). 이미 기본 규칙에 있다 |
| LLM 이 `Lockdown`/`Sanitize`/`FormatNVM` 만 반복 제안 | 차단된 명령이 `exercised` 가 안 돼 never-sent 에 고정 | §6-7-2 — 이미 후보에서 제외된다. 기동 로그 `[LLM] 영구 거절 명령을 프롬프트 후보에서 제외` 확인 |
| `io_patterns` 가 한 번도 요청 안 됨 | 회전판이 고른 칸을 `choose` 가 교체하며 순번만 소비 | §6-6 원인 ③. `[LLM] 요청 제출 ... 회전판=` 으로 교체 여부 확인 |
| `JLinkExe` 의 `VTarget = 0.000V` | VTref 배선 또는 프로브 입력 손상 | 커넥터 1번 핀 방향·핀 휨 확인. 프로브 교체 |

오류 번호가 층을 정확히 가리킨다 — **113=거부(REJECT), 111=포트 없음, 110=버려짐(DROP).**

---

## 8. 검증 현황 — 무엇을 믿어도 되나

### 시험으로 덮인 것 (385개, 전부 통과)

`tests/test_v10_3_backend.py` 90개가 **가짜 HTTP 서버로 DGX 없이** 돈다.
잘못되면 *인덱스가 조용히 망가지는* 것들이 여기 있다.

- 본문↔벡터 1:1 (상한 초과 청크를 잘라내지 않고 쪼개서 양쪽 다 임베딩)
- 벡터 재사용 키 = (소스, doc_id, **본문 sha256**) + 모델 + revision
- 게시 전 검증, 포인터 원자 교체, 사용 중 버전 미삭제, 단일 writer 락
- 스키마↔파서 대조(AST), 실패 분류, 진단 귀속, 시간 예산
- 입력 해석(글롭·디렉터리), 소스 식별, UTF-8 BOM
- LLM task 선택 — 회전판 순번 소비 조건, cold start, 기동 고정 (`test_v10_3_task_selection.py` 35)
- 명령 차단 — 실제 `_send_nvme_command` 로 값/마스크/scope (`test_v10_3_cmd_block.py` 15)
- 프롬프트 후보 필터 — 가드와 판정이 어긋나지 않는지 (`test_v10_3_prompt_targets.py` 7)

고친 것은 **되돌리면 해당 시험이 깨지는 것까지** 확인했다(주입 시험 21건).

### 아직 검증 안 된 것

- **계획 §6 "착수 전 통과 조건" 은 하나도 통과하지 못했다.** 실서버 구조화 출력(task별
  스키마, 중첩 `anyOf`, reasoning/content 분리, 출력 잘림), 백엔드 장애 시 퍼징 지속,
  Spark 동시 운용 메모리·지연·exec/s 영향.
- `rag_ingest._is_length_error` 는 vLLM 의 **오류 문구를 문자열로 맞춘다.** 청크가
  6,000자라 상한에 안 걸려 **쪼개기 재시도가 한 번도 발동한 적이 없다.** 실제 문구가
  다르면 그 경로는 발동하지 않고 그냥 예외로 죽는다.
- 실기(실제 SSD·JTAG) 동작, 추출된 JSONL 의 내용 품질.

2026-09-16 의 968청크 색인이 이 도구의 **첫 실서버 검증**이었다. 그 전까지는 전부
가짜 서버 상대였다.

---

## 9. 앞으로 할 일

장치 없이 먼저 확인하려면 [RAG 단독 테스트](RAG_SMOKE_TEST.md)를 따른다.
`python3 PC_Sampling/tools/rag_smoke_test.py`로 기존 인덱스 검색, 생성 OFF/ON을
검사하고 단계별 보고서를 저장한다.

### 0) 1분짜리 — revision 채우기

현재 인덱스의 `embed_model_revision` 이 비어 있다. 이름이 같은 채로 모델이 교체되면
탐지할 수단이 없고, 그러면 인덱스가 **조용히 틀린 채로** 돈다. 968청크라 재색인이 1분이다.

```bash
python3 PC_Sampling/tools/rag_ingest.py ~/rag_src --embed-model-revision bge-m3-20260916
```

### 1) 연기 시험 (30분) — 실서버가 스키마를 받는가

`retrieval.enabled=false` 인 채로 `--rag` 로 돌린다. P1 의 최대 미지수가 이것이다.
`통신ok` 는 오르는데 `JSONok` 이 안 오르면 중첩 `anyOf` 를 의심하고
`include_generators_in_schema=false` 로 비교한다.

### 2) 장애 주입 (5분) — 계획 §6 "백엔드 장애"

Spark 의 8000 을 내렸을 때 **LLM 요청이 끝나고 퍼징 루프가 계속 도는지** 본다.
연속 10회 실패로 서킷브레이커가 걸려 RAG 가 꺼지고 blind/mutation 으로 계속 도는 것이
정상이다. 캠페인 중에 알면 비싸고 지금은 5분이다.

### 3) **P1 기준선** (캠페인 시간) — 건너뛰면 안 된다

`retrieval.enabled=false`. 제품·FW·시작 corpus·시간 예산·샘플링 조건을 고정하고 돌린 뒤
`[LLM/funnel]` 마지막 줄을 기록한다. **이게 없으면 P2 가 나아졌는지 판단할 근거가 없다.**
단계를 쪼갠 이유가 이것이다.

### 4) P2 — 검색 켜고 같은 조건 반복

`retrieval.enabled=true`. 시작 로그에 `[LLM/rag] 인덱스 ...` 가 떠야 실제로 붙은 것이다.
P1↔P2 비교는 **독립 실행들의 분포**로 본다. 한 번의 실행에서 신규 코드 수가 많았다는
이유만으로 개선을 확정하지 않는다.

### 5) 결과가 시원찮으면 — 청크 품질부터

레코드 하나가 ~50쪽(24만~39만 자)이고 `--max-chars 6000` 으로 기계 절단된다. 6,000자를
넘는 긴 표 — NVMe 상태코드 표, CDW 비트 레이아웃 — 는 **반드시 쪼개진다.** 하필 이 퍼저에
제일 값어치 있는 것들이고, 검색은 여전히 뭔가를 뱉으니 증상이 안 보인다.

6,000자는 임베딩 상한(8,192 토큰) 대비 낮은 편이다(영문 기준 대략 1,500토큰 어림).
`--max-chars` 를 올려 재색인하고 비교하는 실험이 1분이니, 그때 해 보면 된다. 대신 청크를
키우면 벡터 하나가 너무 많은 내용을 대표해 검색 정밀도가 떨어지는 맞교환이 있다.

### 그다음 — 이 버전 범위 밖

- **v10.1 Spec outcome 분모** — 설계 완료·구현 0%. `V10_1_SPEC_OUTCOME_DENOMINATOR.md`.
  제품 비종속이라 적용 범위가 넓다.
- **BM9K1 실기 확인** — 코드 완료, 실측 미완. `SESSION_HANDOFF_v10.0_overlay.md` §4/§9.
  커버리지 자산은 사내 관리(`BM9K1_ASSETS.md` 규격, `tools/check_bm9k1_setup.py` 로 검증).
- `mutate_sequence()`(시퀀스 레벨 삽입/삭제/교환), `ScenarioSeed`, `--unsafe-cmds`.

---

## 10. 한눈에

```bash
# 점검 (서버 불필요)
python3 PC_Sampling/tools/rag_ingest.py ~/rag_src --dry-run

# 색인
python3 PC_Sampling/tools/rag_ingest.py ~/rag_src --embed-model-revision bge-m3-20260916

# 퍼징 (프록시 환경이면 no_proxy 를 sudo 에 함께)
sudo no_proxy=192.168.10.1 http_proxy= https_proxy= \
  python3 PC_Sampling/pc_sampling_fuzzer_v10.3.py \
  --product BM9K1 --nvme /dev/nvme0 --namespace 1 --rag

# 시험
python3 -m unittest discover -s PC_Sampling/tests -p 'test_*.py'   # 194 tests
```
