# SF-E76 Secure JTAG unlock

SiFive **E76** 기반 SSD 컨트롤러의 **secure JTAG(PKC/ECDSA challenge-response)** 인증을
J-Link(pylink)로 수행해 디버그(DM) 게이트를 여는 도구.

T32 `clavis.cmm`의 인증 상태머신을 포팅했다. 인증 자체(state machine·폴링·34워드 전송·
challenge 조합)는 코드에 있고, **사용자가 넣는 것은 두 가지뿐**이다:

1. `SJTAG_BASE` (`--base 0x....`) — SJTAG 레지스터 블록 주소
2. 서명 도구 (`--tool <path>`) — challenge에 P-521 서명하는 외부 실행파일(개인키 보유)

## 파일

| 파일 | 역할 |
|---|---|
| `sjtag_unlock.py` | 메인 — secure JTAG 인증 + probe/scan |
| `sfe76_link.py` | J-Link 연결 계층 |
| `dap_access.py` | ADIv6 DP/AP 원시 접근(MEM-AP read/write) |
| `analyze_clavis.py` | `clavis.cmm` 정적 구조 분석기(자립, 비밀값 마스킹) |
| `sjtag_addrs.json` | 실제 주소/레지스터 맵 (코드엔 주소 없음 — 여기서 로드) |
| `sjtag_addrs.example.json` | 주소/레지스터 맵 **템플릿**(placeholder) |
| `test_*.py` | 단위 테스트(하드웨어 불필요) |

## 설정 — 주소 맵

AP 맵·CoreBase·SJTAG 레지스터 오프셋 등 주소는 **코드(.py)에 없고** JSON에서 로드한다.
`sjtag_unlock.py`/`sfe76_link.py`는 `sjtag_addrs.json`(없으면 `.example.json`)을 읽는다.

이 구조의 목적은 **주소를 코드에서 분리**하는 것이다. git 노출은 허용하되(레포엔 실제
`sjtag_addrs.json`이 올라가 있음), 코드만 읽는 사내 LLM 컨텍스트에서는 이 JSON 한 파일만
제외하면 주소가 노출되지 않는다.

- 실기: `sjtag_addrs.json`(실제 값)으로 동작.
- example만 있는 환경: placeholder라 실기 쓰기가 거부되고 단위 테스트만 통과.

## 현재 진단 — ① 콜드 DP warmup (해결됨) / ② 유지 드롭 (측정 중)

**① 콜드 전원요청 실패 = DP warmup 문제 (실측으로 확정, 수정됨)**
실측: cJTAG 활성화 **직후**엔 DP 가 아직 동기 전이라 **첫 트랜잭션(전원요청 write)이 통째로
안 먹는다** — `CTRL/STAT=0x00000000`, CDBG req 리드백 0. 그래서 초기 폴링이 ACK 를 못 받고
"DAP 전원 ACK 실패". 그런데 `--diag` 의 AP IDR 스윕(DP SELECT 바꿔가며 다수 read)이 **DP 를
깨우면** 그 도중 전원이 latch되고, 한 번 뜨면 close/reopen 후에도 남아 다음 실행은 바로 붙었다.
→ **원인은 "전원 못 세움/KEEPER"가 아니라 콜드 DP warmup.** `prepare_session` 이 이제
DP SELECT/DPIDR priming + ABORT·req **주기적 재기입** + 긴 폴링으로 warmup 을 내장 —
`--diag` 를 먼저 안 돌려도 콜드에서 전원이 latch된다.

**② 전원 확보 후 40~180 tx 뒤 드롭 (별개 현상, 측정 중)**
전원이 `0xF0000000` 로 뜬 뒤에도 read/write **40~180 tx(가변)** 후 `→ 0x80000000` 로
드롭(CDBG req 까지 빠짐), 복구는 fresh 필요. 링크/시스템 전원은 정상, 디버그 도메인만 회수.
전체 인증(pubkey 34+sig 34+폴링)은 180 tx 를 넘기므로 **이 유지 문제 해결이 인증의 선결 조건.**
- 후보: cJTAG KEEPER escape(RISC-V 흔함, TMSC floating→오검출→escape 리셋) vs 벤더 PMU
  도메인 회수. 단 J-Link HW V13.00 은 no-KEEPER 워크어라운드 세대·cJTAG init 모드도 올바름
  (`SetcJTAGInitMode=1`=SiFive용) → 문서만으론 미확정.
- **결정 측정**: `--read-burst` 가 드롭 순간 **DPIDR·CTRL/STAT 캡처** — DPIDR 깨짐=링크/DP
  리셋(KEEPER escape), DPIDR 정상+CDBG=0=전원 도메인만 회수. `--burst-delay` 로 시간/tx 기반.
- T32(clavis)가 유지되는 이유: `CJTAGFLAGS NOKEEPER USEOAC` + 상시 AUX 세션
  (`INTERCOM.execute Localhost:&AUXport`)이 DAP 를 붙잡음. 우리는 connectionless one-shot.

## 실행

```bash
# 0) diag — CDBG 요청 latch 여부 + 6개 AP IDR 스윕 + sticky
sudo python3 sjtag_unlock.py --base 0x<BASE> --power both --diag

# 0b) ★ 전원창 드롭 원인 판별 (read-only, 카운터 무소모) — 현재 핵심 단계
sudo python3 sjtag_unlock.py --base 0x<BASE> --power both --read-burst 30
sudo python3 sjtag_unlock.py --base 0x<BASE> --power both --read-burst 30 --burst-delay 50

# 1) probe (read-only, 서명 도구 불필요) — base 뒤 SJTAG 블록 검증
sudo python3 sjtag_unlock.py --base 0x<BASE> --power both

# 2) scan — base 가 진짜 SJTAG 블록인지/어디인지 실측(default-slave vs live)
sudo python3 sjtag_unlock.py --base 0x<BASE> --power sys-only --scan
sudo python3 sjtag_unlock.py --base 0x<BASE> --power sys-only --scan --scan-window 0x100000

# 3) 전체 인증 (쓰기) — 서명 도구 + 워드 순서 필요.
#    인증 직후 **같은 세션에서** dm_scan 이 이어서 돌아 DM 열림을 실측한다.
sudo python3 sjtag_unlock.py --base 0x<BASE> \
    --tool /path/signer.exe --tool-prefix wine \
    --power both --execute --word-order t32-negative

# 4) DM 기동+확인 — dmcontrol.dmactive=1 써서 DM 리셋해제 후 dmstatus 확인
#    (auth 잔존 시 단독 사용 가능. dmactive 는 코어 안 멈추는 표준 write, 인증 무관)
sudo python3 sjtag_unlock.py --base 0x<BASE> --power both --dm-activate
# (읽기만 하려면 --dm-scan — 단 dmactive=0 이면 DM 이 0 으로 읽혀 안 잡힘)
```

- **드롭 판별(0b)** — `[drop]` 줄로 두 원인 가르기(현재 핵심):

  | DPIDR at drop | `--burst-delay` 넣으니 | 결론 | 다음 |
  |---|---|---|---|
  | **깨짐**(0x8..0/None) | tx 무관 같은 tx | cJTAG KEEPER escape | TMSC pull / JLinkScript cJTAG / SEGGER 문의 |
  | **정상**(0x6BA0…)+CDBG=0 | 더 빨리 죽음 | 전원 도메인 타이머 회수 | 전원 keepalive 재검토 |
  | **정상**+CDBG=0 | tx 무관 | 전원 도메인 활동 회수 | 전원·링크 상호작용 조사 |

- **인증 성공 후(실측)**: STATE=`0x110`(AUTH_PASS 0x100 + SOFT_LOCK 0x10) → **AUTH_PASS 지속됨**
  (별도 세션/JLinkExe connect 후에도 남음). 즉 인증은 세션이 날리지 않는다. 다만 **AUTH_PASS ≠
  DM 접근** — DM 은 별도 AP(APBAP1 의 COREDEBUG.Base)라, ①JLinkExe 가 그 DM 위치를 모르거나
  (JLinkScript/설정 필요) ②AUTH_PASS 외 추가 게이트가 있을 수 있다.
- **DM 은 dmactive=1 로 깨워야 함(실측)**: DM AP(APBAP1)@COREDEBUG.Base 를 그냥 읽으면
  `0x00000000`(dmstatus version=0) — DM 이 리셋상태라서다. `--dm-activate`(또는 execute 가
  auth 직후 자동)로 `dmcontrol.dmactive=1` 을 쓴 뒤 dmstatus 가 version 2/3 으로 살면 → **auth
  가 DM 열음 확정**(JLinkExe 엔 DM base/AP 만 지정). dmcontrol write 가 안 먹으면(리드백 0) →
  DM 이 이 AP/주소로 안 열림 = 추가 게이트/재확인.
- **diag(0)** AP 스윕: **APBAP3만 실패·AXI/AHB LIVE** 면 SJTAG 경로가 시스템 도메인일 가능성.
- **인증(3)** 은 `--execute`가 있어야만 쓰기를 한다. 그 전엔 read-only.
- **`--power sys-only`**: CDBG ACK 없이도 진행. 봐야 할 로그는 `[power A/B] … CDBGPWRUPACK 0→1`
  과 `★★★ … 직접 증명`. (dmstatus stride 추정보다 강한 전원영역 신호)
- **서명 도구가 Windows .exe**: 리눅스에서 돌리면 `--tool-prefix wine`로 감싼다.
  (`sudo`로 실행하므로 wineprefix도 root 기준으로 준비 — 상세는 아래 "서명 도구" 참고)
- **워드 순서**: 실기에서 도구가 stdout을 역순으로 낸다고 확인됨 → `--word-order t32-negative`
  (도구 출력을 되뒤집어 주소 증가순으로 주입). `[4] pubkey`에서 `INVALID_PUBLIC_KEY`면
  `--word-order stdout`으로 재시도.

## 인증 시도 아끼기 — 사전 절차 (전부 카운터 무소모)

인증 횟수 제한이 있을 수 있어, **실제 인증(4)은 마지막 1회**로 미루고 그 전까지는
시도를 소모하지 않는 단계만 수행한다. 관측: pubkey 주입 중 word~21 에서 AP 에러
(0x80000000 = STICKYERR 후 접근 실패)로 중단 — 순수 transport 문제.

1. **write 견고성(코드)**: 워드 쓰기 실패 시 sticky 클리어 + 재시도로 자가복구 →
   34워드 완주. (`w()` 재시도 + `mem_write32` 진입부 self-heal)
2. **transport 검증(read-only, 카운터 0)**:
   ```bash
   sudo python3 sjtag_unlock.py --base 0x<BASE> --power both --read-burst 20
   ```
   REQUEST 34워드를 20회 연속 읽어(=write와 동일 재시도) 긴 시퀀스를 안 끊고 견디는지
   실증. `최종실패 0` 이면 완주 확신. (reads 는 상태머신 무관 → 인증 무소모)
3. **credential 사전 확정(오프라인, HW 불필요)**:
   ```bash
   python3 sjtag_unlock.py --analyze-pubkey --tool /path/signer.exe --tool-prefix wine
   ```
   `-s3` 2회 실행 → 정적키 동일성 + P-521 좌표구조(각 17워드, 최상위워드<0x200)로
   word-order 후보를 2개로 좁힘. grant(`0xFFFFFFFF`)·challenge 배열은 clavis 대조로 확정됨.
4. **그 다음에야** 실제 인증 1회(`--execute`). 직전 STATE 읽어 락아웃 여부 확인.

## 서명 도구 (.exe) 실행

`.exe`는 `-s3 -f5`로 공개키 Qx,Qy(34워드, **정적**)를, `-s1 -f5 <challenge>`로 서명
r,s(34워드, **세션마다 다름**)를 stdout에 줄당 1개 hex로 낸다. 서명은 device의 nonce가
들어간 live challenge를 그 자리에서 서명해야 하므로 **미리 뽑아 저장 불가**(공개키는 정적이라 가능).

- 출력은 bytes로 받아 인코딩(UTF-8/UTF-16/BOM) 자동 판별, 서명값은 로그에 남기지 않는다(해시만).
- 리눅스 실행 시: `sudo apt install --no-install-recommends wine32 wine64`(PE32면 i386 필요),
  root용 win32 prefix 생성 후 `--tool-prefix wine`. 단독 확인:
  `wine /path/signer.exe -s3 -f5` → 34줄.

## 테스트

```bash
python3 -m unittest -v test_sjtag_unlock.py
python3 -m unittest -v test_analyze_clavis.py
```
