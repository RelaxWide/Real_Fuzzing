# T32 스크립트에서 찾을 것 — 우선순위대로

> VSCode 에서 **Ctrl+Shift+F** (폴더 전체 검색). `.cmm` 뿐 아니라 `.ts2` 도 포함.
> `attach.cmm` 은 전부 `INTERCOM.execute ...` 로 감싸여 있으므로
> **`SYStem.CONFIG.` 를 붙이지 말고 뒤쪽 키워드만** 검색해야 걸린다.

---

## ★★★ 1. `ACCESSPORT` — 어느 AP 인가

**검색어:** `ACCESSPORT`

찾는 것:
```
SYStem.CONFIG.APBACCESSPORT  <n>
SYStem.CONFIG.AHBACCESSPORT  <n>
SYStem.CONFIG.AXIACCESSPORT  <n>
SYStem.CONFIG.DEBUGACCESSPORT <n>
SYStem.CONFIG.MEMORYACCESSPORT <n>
```

**왜 결정적인가.** `&core_base = APB:0x81480000` 의 `APB:` 는 *어떤* APB-AP 인지
말해주지 않는다. APB-AP 가 **4개**(`APBAP1~4`)나 있는데 우리는 어느 것인지 모른다.
`APBACCESSPORT` 가 그걸 지정한다 → 그대로 `CORESIGHT_SetIndexAPBAPToUse` 값이 된다.

**없으면**: T32 기본값(보통 첫 번째로 선언된 APB-AP)이라는 뜻이므로 그것도 정보다.

## ★★★ 2. `AP:` / `DAP:` 접근 클래스로 쓴 주소

**검색어:** `AP:0x` 그리고 `DAP:0x`

찾는 것: `Data.Set AP:0x...`, `PER.Set DAP:0x...`, `Data.In AP:0x...` 같은 줄.

**왜 결정적인가.** T32 의 `AP:` 는 **AP 주소공간 그대로**다. 이게 하나라도 있으면
"APB 버스 주소 ↔ AP 주소공간 오프셋" 변환 관계를 **실측 예제로** 얻는다.
지금 막힌 질문(`SetCoreBaseAddr` 이 어느 쪽 주소인가)에 직접 답한다.

## ★★★ 3. `Data.LOAD` — 펌웨어 ELF 경로

**검색어:** `Data.LOAD`

찾는 것: `Data.LOAD.Elf "<경로>"`, `Data.LOAD.auto`, `sYmbol.` 관련 줄.

**왜 중요한가.** 심볼(ELF)은 **트레이스 디코더의 하드 의존성**이다.
지금 블로커와 별개로 어차피 필요하고, 이 줄이 **그 파일이 어디 있는지** 알려준다.
연결이 풀리는 즉시 다음 작업이 이걸로 시작된다.

## ★★ 4. `Trace.METHOD` / `COVerage` — 커버리지를 실제로 어떻게 만드나

**검색어:** `Trace.METHOD` , `COVerage`

찾는 것: `Trace.METHOD Onchip`(= ETB 사용 확정), `COVerage.ON`,
`COVerage.Add`, `COVerage.ListFunc`, `COVerage.EXPORT`.

**왜 중요한가.** 우리가 재현하려는 게 정확히 이 파이프라인이다.
`COVerage.EXPORT` 형식을 알면 **T32 결과를 정답지로 삼아** 디코더를 검증할 수 있다.

## ★★ 5. 트레이스 **켜는** 설정

**검색어:** `TECTRL` , `0xFD00` , `PER.Set`

`NexusTracedatadump.cmm` 에는 **끄는 것만** 있다:
```
PER.Set.simple &TECTRL %Long ^TECTRL_VAL   ; te disable (bit1 클리어)
```
**켜는 짝**이 다른 파일에 있어야 한다. 거기서 알아야 할 것:
- `TECTRL` 전체 비트 정의
- **BTM 인가 HTM 인가** (분기 메시지 방식)
- **주소 범위 필터** ← 32KB 버퍼엔 사실상 필수
- sync 주기

## ★ 6. 아직 못 본 `SYStem.CONFIG` 전부

**검색어:** `SYStem.CONFIG` (또는 `SYS.CONFIG`)

특히 `DMI`, `DEBUGMODULE`, `DMBASE`, `NEXUS`, `TRACE` 가 붙은 항목.
`COREDEBUG.Base` 말고 **DM 을 따로 지정하는 줄이 있으면 우리 CoreBase 가 틀린 것**이다.

## ★ 7. `SYStem.Option` 전부

**검색어:** `SYStem.Option` (또는 `SYS.OPTION`)

`DAPSYSPWRUPREQ` / `DAPDBGPWRUPREQ` 는 이미 봤다. 그 외 항목 중
`DAP`, `IMASKASM`, `RESetMode`, `AXIACEEnable` 같은 게 있으면 적어둘 것.

---

## 검색 결과를 어떻게 주면 되나

**줄 전체를 그대로** 주면 된다. 파일명도 같이. 양이 많으면
**1 → 2 → 3 순서로 하나씩**이 좋다 — 1번 하나만 나와도 스윕 범위가 확 줄어든다.

## 없을 때의 의미

| 못 찾음 | 해석 |
|---|---|
| `ACCESSPORT` 없음 | T32 가 기본 AP 를 쓴다 = 첫 번째 APB-AP(`APBAP1`, `DP:0x10000`) 유력 |
| `AP:0x` 없음 | T32 도 버스 주소로만 접근 → 변환 관계는 벤더에게 물어야 한다 (`ASK.md` §5) |
| `Data.LOAD` 없음 | 심볼을 T32 밖에서 로드한다는 뜻 → 빌드 산출물 경로를 따로 확보 |
| `Trace.METHOD` 없음 | 덤프 스크립트가 T32 트레이스 기능을 안 쓰고 **레지스터를 직접 두드린다**는 뜻 |
