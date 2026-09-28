# dump/ — 크래시 덤프 도구 및 산출물

크래시 발생 시 펌웨어/메모리 덤프를 뜨는 **외부 도구**를 모아두는 곳.
경로는 `fuzzer_config.json` 의 `paths` 섹션에서 지정하며, 값은 **퍼저 스크립트
디렉토리 기준 상대경로**로 해석된다(`os.path.join(script_dir, ...)`).

## 여기에 두는 것

| 파일 | config 키 | 용도 |
|---|---|---|
| `ufas` | `paths.ufas_binary` | UFAS 펌웨어 덤프 (PM9M1 / BM9H1) |
| `Debug_Tool_v1.0.0.2` | `paths.debug_tool_binary` | RDDump (P9 / P7) |
| `run_smi_mem_dump_JLINK_USB.sh` | `paths.jlink_dump_script` | J-Link 메모리 덤프 |
| `DebugPackage/smi_mem_parsing/` | `paths.debug_package_dir` | 벤더 덤프 파서 (리포에 포함됨) |

`ufas` / `Debug_Tool` / `run_smi_mem_dump_*.sh` 는 **바이너리라 리포에 없다.**
퍼즈 호스트에서 이 폴더로 옮겨두어야 크래시 덤프가 동작한다.

## 아직 정리되지 않은 것

- **`ufas_ini`** (`PM9M1_A815.ini`): UFAS 는 `cwd=script_dir` 로 실행되고 `--ini=<값>` 이
  그대로 전달된다. config 값을 `dump/PM9M1_A815.ini` 로 지정해 두었으니 **이 폴더에**
  두면 된다(PM9M1 계열과 BM9H1 이 공유하므로 제품 폴더가 아니라 도구 옆에 둔다).
- ~~덤프 산출물이 스크립트 루트에 쌓인다~~ → **해결(v10.3).** 도구는 산출물을 이 폴더에
  쓰고, 퍼저가 덤프 전후 스냅샷 차이로 새 파일을 `crashes/crash_<ts>/` 에 **복사**한다
  (원본은 여기 남는다 — 디스크가 차면 주기적으로 비울 것). 도구 stdout 로그도 crash
  폴더에 쓴다. `_find_latest_jlink_dump()` 도 이 폴더를 본다. 런북 §6-10.
- `paths.pmu_script`(`pmu_4_1.py`)는 전원 제어 도구라 덤프가 아니어서 옮기지 않았다.
