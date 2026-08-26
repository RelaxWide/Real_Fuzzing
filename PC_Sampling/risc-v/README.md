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
| `sjtag_addrs.example.json` | ★ 주소/레지스터 맵 **템플릿** |
| `test_*.py` | 단위 테스트(하드웨어 불필요) |

## 설정 — 주소 맵 (필수)

AP 맵·CoreBase·SJTAG 레지스터 오프셋 등 기밀 주소는 코드에 없고 로컬 JSON에서 로드한다.

```bash
cp sjtag_addrs.example.json sjtag_addrs.json   # 이 파일은 .gitignore 됨
# sjtag_addrs.json 을 T32/clavis 의 실제 값으로 채운다
```

`sjtag_addrs.json`은 **커밋되지 않는다**(`.gitignore`). 커밋본 example은 placeholder라
실기 실행이 거부되고 단위 테스트만 통과한다.

## 실행

```bash
# 1) probe (read-only, 서명 도구 불필요) — 게이트 존재·도달 확인
sudo python3 sjtag_unlock.py --base 0x<BASE>

# 2) scan — base 가 진짜 SJTAG 블록인지/어디인지 실측(default-slave vs live)
sudo python3 sjtag_unlock.py --base 0x<BASE> --scan
sudo python3 sjtag_unlock.py --base 0x<BASE> --scan --scan-window 0x100000

# 3) 전체 인증 (쓰기) — 서명 도구 + 워드 순서 필요
sudo python3 sjtag_unlock.py --base 0x<BASE> --tool <signer> \
    --execute --word-order t32-negative
```

- 인증(3)은 `--execute`가 있어야만 쓰기를 한다. 그 전엔 read-only.
- 워드 순서가 미확정이라 필수 인자. `[4] pubkey`에서 `INVALID_PUBLIC_KEY`면 `--word-order stdout`으로 재시도.
- 도구는 인증 전/후 dmstatus를 A/B로 읽어 "인증이 DM 게이트를 여는지" 판정한다.

## 테스트

```bash
python3 -m unittest -v test_sjtag_unlock.py
python3 -m unittest -v test_analyze_clavis.py
```
