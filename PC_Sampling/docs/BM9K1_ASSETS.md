# BM9K1 커버리지 자산 규격

> 진행 상황·설계 배경: `SESSION_HANDOFF_v10.0_overlay.md`


퍼저가 `products/BM9K1/` 에서 읽는 파일 전부. 추출 도구가 무엇이든(Ghidra/objdump/직접)
이 규격이면 동작한다. 검증: `python3 tools/check_bm9k1_setup.py`, `test_asset_contract.py`.

`<X>` = 코어 이름 **H / CM / F / Q** (숫자 아님).
`<N>` = 오버레이 순번 **0부터**, `.OVL_REGION_NN` 의 NN 과 같은 값.

## 1. 코어별 (모든 코어, 필수)

| 파일 | 형식 | 예 |
|---|---|---|
| `basic_blocks_core<X>.txt` | `<START> <END>` — END **exclusive** | `0x00010000 0x00010010` |
| `functions_core<X>.txt` | `<ENTRY> <size> <name>` — size는 **십진**, name에 공백 허용 | `0x00010000 32 nvme_admin_handler` |
| `callgraph_core<X>.txt` | `<CALLER> <CALLEE>` — 둘 다 함수 **entry** 주소 | `0x00010000 0x00010200` |

주소는 16진(`0x` 접두 있어도 없어도 됨, zero-pad 무관). `#` 주석·빈 줄 무시.
`END <= START` 인 BB, `size == 0` 인 함수는 **버려진다**(범위가 없어 조회 불가).

## 2. 오버레이 (H, F 만 — 오버레이 있는 코어)

| 파일 | 형식 | 비고 |
|---|---|---|
| `basic_blocks_core<X>_ovl<N>.txt` | 위와 동일 | 오버레이 **N 의 코드만** |
| `functions_core<X>_ovl<N>.txt` | 위와 동일 | 오버레이 **N 의 함수만** |

**H = `_ovl0` ~ `_ovl34` (35쌍 = 70개 파일), F = `_ovl0` ~ `_ovl3` (4쌍 = 8개).**

> ⚠ **끝 번호 주의** — H 는 `.OVL_REGION_00`(section 19) ~ `.OVL_REGION_34`(section **53**).
> 개수 35 로 `range(19, 19+34)` 를 쓰면 52 에서 끝나 **마지막 하나가 빠진다.**
> 상한은 `19 + 35 = 54`(배타) 또는 `<= 53`(포함).

### 반드시 지킬 것

1. **주소는 런타임 주소** — `0x00056000` 처럼 실제 실행 주소. Ghidra 오버레이
   주소공간의 오프셋이 아니다. `Address.getOffset()` 이 런타임 주소를 준다.
2. **오버레이별로 분리** — `_ovl3` 파일에는 3번 오버레이 것만. 섞이면 bank 귀속이
   전부 틀어진다. 35개 파일의 주소 범위가 서로 겹치는 것이 **정상**이다
   (같은 자리를 번갈아 쓰므로).
3. **번호 = `.OVL_REGION_NN` 의 NN** — 순서로 임의 부여하지 말 것. 런타임에 읽는
   헤더의 ID 와 이 번호가 같아야 한다.
4. **비오버레이 본체와 분리** — `basic_blocks_core<X>.txt`(접미사 없는 것)에는
   오버레이 창 주소가 들어가면 안 된다. 들어가면 본체가 오버레이 커버리지를 삼킨다.

## 3. 오버레이 레이아웃 맵 (오버레이 있으면 필수)

빌드 산출물을 **그대로** 두면 된다. 다음 이름 중 하나로 인식한다(우선순위 순):

```
overlay_core<X>.json
overlay_map_core<X>.json
FW_<X>Core_overlay_map.json      ← 현재 빌드가 내는 이름
<X>Core_overlay_map.json
FW_<X>Core.overlay_map.json
```

내용(빌드가 이미 내주는 형태):

```json
{ ".OVL_REGION_00": { "section_index": 19, "addr": 352256, "size": 3370 },
  ".OVL_REGION_01": { "section_index": 20, "addr": 352256, "size": 12896 } }
```

`addr` 은 모든 항목이 **동일**해야 한다(같은 자리를 공유하는 것이 오버레이의 정의).
퍼저는 여기서 base·창 크기·bank 수를 얻고, 런타임 판별은 헤더 규약
(`base+4` 의 워드 = `0x4F564C` `"OVL"` + 순번)으로 처리한다. **별도 판별표 불필요.**

> 규약(`base+4` 의 `"OVL"` 매직 + 순번)이 안 맞는 펌웨어가 나오면
> `overlay_probe_core<X>.json`(워드값 → bank 표)을 직접 두면 그쪽이 우선한다.
> 그 값은 ELF 오버레이 섹션의 바이트를 읽어야 나온다.

## 4. `symbols.json` (선택, 권장)

파일이 잘렸거나 표와 ELF 가 짝이 안 맞는 것을 잡는다. **counts 는 본체 기준**이고
오버레이는 별도 키다(총계와 섞으면 오버레이 코어마다 헛경고가 난다).

```json
{ "product": "BM9K1", "bb_end_convention": "exclusive",
  "cores": { "H": { "elf_sha256": "…",
                    "counts": { "basic_blocks": 12345, "functions": 678,
                                "overlay_banks": 35,
                                "overlay_basic_blocks": 4321,
                                "overlay_functions": 210 } } } }
```

`bb_end_convention` 이 `"exclusive"` 가 아니면 로드를 거부한다.

## 5. 필요 없는 것

| | |
|---|---|
| `filemap_core<X>.txt` | 현재 아무도 읽지 않음. 파일 단위 롤업 도입 시 사용 예정 |
| `callgraph_core<X>_ovl<N>.txt` | 아직 소비 코드 없음. 있으면 frontier 힌트가 오버레이까지 확장 가능 |

## 6. 배치 후 확인

```bash
python3 tools/check_bm9k1_setup.py       # ②-b 절이 전부 ✅ 여야 한다
```

퍼저 시작 로그에서 최종 확인:

```
[Overlay] H: 프로브 0x56004 OK (현재 bank=12, 오버레이 35개, bank 표 35개)
```

이 줄이 나오면 오버레이 구분이 실제로 동작 중이다.
`SBA 읽기 실패` 면 bank 0 으로 접혀 종전과 동일하게 동작하고(퍼징은 정상),
`매직과 불일치` 면 맵과 펌웨어가 다른 빌드다.
