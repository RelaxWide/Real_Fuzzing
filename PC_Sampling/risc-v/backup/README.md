# backup — 역할이 끝난 브링업 도구

각 파일이 **무엇을 밝혀냈고 왜 더는 안 쓰는지**를 남긴다.
얻은 사실은 상위 `README.md` / `BRINGUP_riscv_v10.md` / `sfe76_link.py` 에 흡수돼 있다.

| 파일 | 밝혀낸 것 | 종료 이유 |
|---|---|---|
| `probe_sfe76_pylink.py` | cJTAG **TIF=7** 확정, ARM **DP 통신** 성공(`0x6BA0009D`), **디버그 전원 ACK**(`0xF0000000`) 확인. AP 접근 실패 시 **STICKY 0/256** 이라는 결정적 단서 | DP/전원은 확정됐고, AP 는 `CORESIGHT_AddAP` 수동 선언으로 해결됨 |
| `connect_sfe76.py` | SEGGER hybrid-DAP 절차(`AddAP`+`SetIndexAPBAPToUse`+`SetCoreBaseAddr`)로 **첫 connect 성공**. AP/CoreBase 조합 스윕 | 설정이 확정돼 스윕이 불필요. 연결 로직은 `sfe76_link.py` 로 이관 |
| `connect_min.py` | **위치 vs 주소 교락 해소** — 같은 주소를 두 번 시도해 "0x81480000 이 안 되는 게 아니라 첫 시도가 안 되는 것" 을 증명 | 목적 달성 |
| `isolate_warmup.py` | **A/B/C 분리 실험.** A(connect 2회)만 성공 → setup 이중적용도, 대기도 아니고 **connect 시도 자체**가 필요함을 확정 | 목적 달성. 후속은 `diagnose_connect.py` |
| `SF_E76_cJTAG_probe.JLinkScript` | JLinkScript 에서 `JLINK_CORESIGHT_*` 가 전부 `0x80000000`(API 에러) 반환 | **JLinkScript 로는 CoreSight API 사용 불가** 확인 |
| `SF_E76_addap.JLinkScript` | `AddAP(Index,Type)` deprecated API 시도. 역시 CoreSight 호출 실패 | 위와 같음. 명령 문자열 방식으로 대체 |

## 여기서 배운 함정 (반복하지 말 것)

1. **한 handle 에 여러 설정을 섞지 말 것** — 핸들 재사용 시 한 번 붙으면
   이후가 전부 거짓 성공(24개 중 23개), 조합마다 close 하면 전부 실패.
2. **교락을 만들지 말 것** — `0x81480000` 을 항상 첫 자리에 두고 "이 주소는
   연결 실패" 라고 두 번 결론냈다. 순서를 통제하니 멀쩡했다.
3. **`connect()` 성공 = 코어 귀속 확정이 아니다** — 어느 코어에 붙었는지는
   halt/PC/hart 로 따로 확인해야 한다.
4. **JLinkScript 의 내장 함수는 DLL 익스포트가 아니다** — `nm -D` 에 안 나온다.
   `ctypes` 우회 불가.
