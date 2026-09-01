# products/ — 제품별 자산

제품마다 필요한 파일을 `products/<제품명>/` 아래에 **고정된 이름**으로 둔다.
`fuzzer_config.json` 의 제품 레코드가 이 경로를 가리킨다.

## 파일 규약

| 파일 | config 키 | 생성 방법 | 없으면 |
|---|---|---|---|
| `basic_blocks.txt` | `bb_file` | `tools/ghidra_export.py` | BB 커버리지 없이 PC 단위로 동작 |
| `functions.txt` | `func_file` | `tools/ghidra_export.py` | 함수 커버리지 통계 없음 |
| `openocd.cfg` | `openocd_config` | 수동 작성 | OpenOCD 샘플러 기동 실패 |

형식: `basic_blocks.txt` = `0xSTART 0xEND`(END 미포함) / `functions.txt` = `0xENTRY <십진 size> <name>`

## 제품 현황

| 제품 | 샘플러 | openocd.cfg | BB/func | 비고 |
|---|---|---|---|---|
| `PM9M1` | pcsr (swd) | ❌ 배치 필요 | ❌ 배치 필요 | `PM9M1_LNB`/`PM9M1_HP` 가 **이 폴더를 공유** |
| `BM9H1` | pcsr (jtag) | ✅ | ❌ 배치 필요 | |
| `P7` | jlink_halt | 불필요 | ❌ 배치 필요 | OpenOCD 미사용 |
| `P9` | jlink_halt | ✅ (미참조) | ❌ 배치 필요 | `openocd.cfg` 는 `sampler_type='halt'` 시절 자산 — 되돌릴 때 사용 |

`PM9M1_LNB` / `PM9M1_HP` 는 펌웨어가 같아 별도 폴더를 두지 않고 config 에서
`products/PM9M1/...` 를 가리킨다.

## 퍼즈 호스트에서 배치할 것

리포에 없는 파일(바이너리·대용량 정적분석 산출물)은 호스트에서 이 구조로 옮긴다:

```
products/PM9M1/openocd.cfg          ← 기존 r8_pcsr.cfg
products/PM9M1/basic_blocks.txt     ← 기존 basic_blocks_PM9M1.txt
products/PM9M1/functions.txt        ← 기존 functions_PM9M1.txt
products/BM9H1/basic_blocks.txt     ← 기존 basic_blocks_BM9H1.txt
products/BM9H1/functions.txt        ← 기존 functions_BM9H1.txt
products/P7/{basic_blocks,functions}.txt
products/P9/{basic_blocks,functions}.txt
```

**아직 안 옮겨도 동작한다.** `resolve_asset()` 이 지정 경로에 파일이 없으면
**스크립트 루트의 같은 파일명으로 폴백**한다(구배치 호환). 이관이 끝나면 폴백은 그냥 안 쓰인다.
