# v11.5 — BM9K1 제품 파생형 (BM9K1_LENOVO / BM9K1_HP)

PM9M1(`PM9M1_LNB` / `PM9M1_HP`)처럼 `--product` 로 고른다.

```bash
sudo python3 pc_sampling_fuzzer_v11.5.py --product BM9K1_LENOVO ...
sudo python3 pc_sampling_fuzzer_v11.5.py --product BM9K1_HP ...
```

| 제품 | 설정 | 차이 |
|---|---|---|
| `BM9K1_LENOVO` | `BM9K1` 과 같은 프로필 | 없음(이름만) |
| `BM9K1_HP` | `BM9K1` 과 같은 프로필 + `state_exclude_lids: [223]` | state 관측에서 LID 0xDF snapshot 제외(PM9M1_HP 와 같은 규칙). 퍼징 명령으로 LID 0xDF 를 보내는 것은 막지 않는다 |
| `BM9K1` | 그대로 둔다 | v11.4 이하 실행 파일용 |

## 제품 계열 `family`
`fuzzer_config.json` `products.<제품>.family`(생략 시 제품명). v11.5 는 BM9K1 전용 동작을 제품명 대신 계열로 판정한다.

- 송신 timeout PS 배율(PS1·PS2 ×10, 마진 없음)
- PM SetFeatures 성공 시 추적 PS 갱신, forced_idle 분리 경로의 추적 PS 처리
- RISC-V 커버리지 자산 경로 `products/<family>/` — 파생형은 `products/BM9K1/` 를 같이 쓴다
- `rag.autoname_kw_off_products` 판정(제품명 또는 계열)

잘못된 `family`(빈 문자열·문자열 아님)는 시작 시 `[FATAL]`.

## 주의
- 파생형 프로필은 BM9K1 의 전체 복사다(PM9M1 파생형과 같은 방식 — 구버전 실행 파일이 import 때 모든 프로필의
  `interface` 를 읽으므로 상속 키로 줄이지 않았다). **BM9K1 설정을 바꾸면 세 프로필을 같이 바꾼다.**
  `tests/test_v11_5_product_variants.py` 가 세 프로필이 파생형 키 외에 같은지 검사한다.
- v11.4 이하로 `BM9K1_LENOVO`/`BM9K1_HP` 를 고르면 BM9K1 전용 동작이 꺼진다(제품명 판정). 파생형은 v11.5 이상에서 쓴다.
- `tools/check_bm9k1_setup.py` 는 `products.BM9K1` 을 본다(세 프로필이 같으므로 그대로 유효).
