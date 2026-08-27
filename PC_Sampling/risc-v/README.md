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

## 현재 진단 — 디버그 전원을 못 세우는 것이 블로커

실기 관측: `DPIDR=0x6BA0…`(마스킹, DP/cJTAG 링크 정상), `CTRL/STAT=0x80000000` →
**CSYSPWRUPACK(bit31)=1**(시스템 전원 확보), **CDBGPWRUPACK(bit29)=0**(디버그 전원 미확보).
`--power sys-only` probe 에서 APBAP3 IDR 읽기 실패(SUSPECT 값).

clavis 는 **디버그 전원을 켠 채로** APBAP3(=`APB3:`)에서 인증한다. 즉 디버그 전원은
**인증 전에 이미 필요**하고(인증이 여는 것은 전원이 아니라 그 뒤의 DM/코어 접근),
우리도 과거 APBAP3 IDR 을 읽은 적이 있다. → 진짜 문제는 "인증해야 전원이 열린다"가
아니라 **지금 connectionless 셋업이 디버그 전원을 못 세우는 것**이다.

의심: 우리가 쓴 CDBG 전원요청이 CTRL/STAT 리드백에 안 서는 정황(req 비트=0) →
**전원요청 write 자체가 안 먹을 수 있음.**

→ `--diag` 로 (1) CDBG 요청이 latch 되는지, (2) 6개 AP 중 어디에 닿는지, (3) sticky 를
실측해 **"전원요청 문제 / 도메인 문제 / 이미 확보"** 중 무엇인지 가른다.

## 실행

```bash
# 0) diag (원인 판별의 출발점) — CDBG 요청 latch 여부 + 6개 AP IDR 스윕 + sticky
sudo python3 sjtag_unlock.py --base 0x<BASE> --power both --diag

# 1) probe (read-only, 서명 도구 불필요) — base 뒤 SJTAG 블록 검증
sudo python3 sjtag_unlock.py --base 0x<BASE> --power sys-only

# 2) scan — base 가 진짜 SJTAG 블록인지/어디인지 실측(default-slave vs live)
sudo python3 sjtag_unlock.py --base 0x<BASE> --power sys-only --scan
sudo python3 sjtag_unlock.py --base 0x<BASE> --power sys-only --scan --scan-window 0x100000

# 3) 전체 인증 (쓰기) — 서명 도구 + 워드 순서 필요. 인증 후 CDBGPWRUPACK 전이 관찰
sudo python3 sjtag_unlock.py --base 0x<BASE> \
    --tool /path/signer.exe --tool-prefix wine \
    --power sys-only --execute --word-order t32-negative
```

- **diag(0)** 판정:
  - `[prepare] … CDBG req/ack=0/0` + `⚠ CDBG req 안 섬` → **전원요청 write 문제**(진짜 원인 후보).
  - AP 스윕에서 **APBAP3만 실패, AXI/AHB LIVE** → SJTAG 경로가 시스템 도메인일 가능성.
  - **전부 LIVE** → 디버그 전원 이미 확보 → 인증(3) 진행.
- **인증(3)** 은 `--execute`가 있어야만 쓰기를 한다. 그 전엔 read-only.
- **`--power sys-only`**: CDBG ACK 없이도 진행. 봐야 할 로그는 `[power A/B] … CDBGPWRUPACK 0→1`
  과 `★★★ … 직접 증명`. (dmstatus stride 추정보다 강한 전원영역 신호)
- **서명 도구가 Windows .exe**: 리눅스에서 돌리면 `--tool-prefix wine`로 감싼다.
  (`sudo`로 실행하므로 wineprefix도 root 기준으로 준비 — 상세는 아래 "서명 도구" 참고)
- **워드 순서**: 실기에서 도구가 stdout을 역순으로 낸다고 확인됨 → `--word-order t32-negative`
  (도구 출력을 되뒤집어 주소 증가순으로 주입). `[4] pubkey`에서 `INVALID_PUBLIC_KEY`면
  `--word-order stdout`으로 재시도.

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
