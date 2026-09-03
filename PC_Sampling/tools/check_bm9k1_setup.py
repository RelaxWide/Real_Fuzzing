#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BM9K1 실행 준비 점검 — 뭐가 빠졌는지 알려준다.

사용:  sudo python3 tools/check_bm9k1_setup.py
       (sjtag_addrs.json 이 root-lock 이라 sudo 필요)

★ 값은 찍지 않는다 — '채워짐/비어있음'과 개수만. 결과를 그대로 공유해도 안전하다.
"""
import json
import os
import sys
from pathlib import Path

# 실기 기본 설치 위치. 다른 곳이면 PCSAMPLE_ROOT 환경변수나 --root 로 덮는다.
DEFAULT_ROOT = "/home/ssd/pc_sample"


def _find_root():
    """퍼저 루트(= fuzzer_config.json / pc_sampling_fuzzer_v*.py 가 있는 곳)를 찾는다.
    스크립트를 어디서 실행하든, 어디에 복사했든 동작하게 — 위치 추정에 의존하지 않는다.
    --root 로 명시할 수도 있다."""
    for i, a in enumerate(sys.argv):
        if a == "--root" and i + 1 < len(sys.argv):
            return Path(sys.argv[i + 1]).resolve()
    env = os.environ.get("PCSAMPLE_ROOT")
    if env:
        return Path(env).resolve()
    here = Path(__file__).resolve()
    cands = [
        Path(DEFAULT_ROOT),          # 실기 기본 설치 위치
        here.parent.parent,          # tools/ 안에 있을 때
        here.parent,                 # 퍼저 루트에 바로 있을 때
        Path.cwd(), Path.cwd().parent,
    ]
    # 위쪽으로도 몇 단계 훑는다
    for base in (here.parent, Path.cwd()):
        p = base
        for _ in range(4):
            p = p.parent
            cands.append(p)
    seen = set()
    for c in cands:
        if c in seen:
            continue
        seen.add(c)
        if (c / "fuzzer_config.json").exists() or list(c.glob("pc_sampling_fuzzer_v*.py")):
            return c
    return None


ROOT = _find_root()
if ROOT is None:
    print("❌ 퍼저 루트를 못 찾았다 (fuzzer_config.json / pc_sampling_fuzzer_v*.py 기준).")
    print(f"   기본값 {DEFAULT_ROOT} 에도 없다. --root <퍼저디렉토리> 또는")
    print("   PCSAMPLE_ROOT 환경변수로 지정하라.")
    print(f"   참고: 스크립트={Path(__file__).resolve()}  cwd={Path.cwd()}")
    sys.exit(2)
print(f"퍼저 루트: {ROOT}\n")
RV = ROOT / "risc-v"
PROD = ROOT / "products" / "BM9K1"
CORES = ("H", "CM", "F", "Q")

ok = ng = 0


def good(k, v):
    global ok
    print(f"  {k:34} ✅ {v}"); ok += 1


def bad(k, v):
    global ng
    print(f"  {k:34} ❌ {v}"); ng += 1


print("=== ① 기밀 설정 (risc-v/sjtag_addrs.json) ===")
p = RV / "sjtag_addrs.json"
j = None
if not p.exists():
    bad("파일", f"없음: {p}")
else:
    try:
        j = json.loads(p.read_text())
        good("JSON 파싱", "OK")
    except Exception as e:
        bad("JSON 파싱", f"실패 → {e}")
        print("     ★ 이러면 sjtag_addrs.example.json(placeholder)로 **조용히 fallback** 되어")
        print("       'sjtag_base 미설정' 으로 보인다. 쉼표/괄호를 확인하라.")

if j:
    rt, pc = j.get("runtime") or {}, j.get("pcsr") or {}
    base = str(rt.get("sjtag_base", "")).strip()
    (good if base and base not in ("0x0", "0", "") else bad)(
        "runtime.sjtag_base", "채워짐" if base and base not in ("0x0", "0") else "비어있음/0")
    tool = str(rt.get("sign_tool", "")).strip()
    if tool and tool != "/path/to/signer.exe":
        (good if os.path.exists(tool) else bad)(
            "runtime.sign_tool", "존재" if os.path.exists(tool) else f"경로 없음")
    else:
        bad("runtime.sign_tool", "비어있음/placeholder")
    good("runtime.tool_prefix", rt.get("tool_prefix") or "(비어있음 — wine 이면 채울 것)")

    (good if str(pc.get("offset", "")).strip() else bad)(
        "pcsr.offset", "채워짐" if str(pc.get("offset", "")).strip() else "없음")
    (good if str(pc.get("core_stride", "")).strip() else bad)(
        "pcsr.core_stride", "채워짐" if str(pc.get("core_stride", "")).strip() else "없음")
    cs = pc.get("cores") or []
    (good if len(cs) == 4 else bad)("pcsr.cores", f"{len(cs)}개 (4개 필요)")
    seen = {}
    for c in cs:
        cid, nm, elf = c.get("id"), c.get("name"), c.get("elf", "")
        seen[nm] = cid
        (good if os.path.exists(elf) else bad)(
            f"  core {nm}(id={cid}) ELF", "존재" if os.path.exists(elf) else "경로 없음")
    want = {"H": 0, "CM": 1, "F": 2, "Q": 3}
    if cs and seen != want:
        bad("코어 id 매핑", f"{seen} — 기대 {want} (id 는 커버리지 키에 박히므로 고정)")
    elif cs:
        good("코어 id 매핑", "H=0 CM=1 F=2 Q=3")

    tb = str((j.get("trace") or {}).get("te_base", "")).strip()
    (good if tb else bad)("trace.te_base", "채워짐" if tb else "없음 (PCSR 주소 유도에 필요)")

print("\n=== ② 정적 분석 산출물 (products/BM9K1/) ===")
if not PROD.is_dir():
    bad("디렉토리", f"없음: {PROD}")
else:
    miss = []
    for c in CORES:
        for kind in ("basic_blocks", "functions", "callgraph"):
            f = PROD / f"{kind}_core{c}.txt"
            if not f.exists():
                miss.append(f.name)
    (good if not miss else bad)("코어별 표 12개",
                                "전부 있음" if not miss else f"누락 {len(miss)}: {miss[:4]}…")
    sj = PROD / "symbols.json"
    if sj.exists():
        try:
            sm = json.loads(sj.read_text())
            conv = sm.get("bb_end_convention")
            (good if conv == "exclusive" else bad)(
                "symbols.json bb_end_convention", conv or "없음")
        except Exception as e:
            bad("symbols.json", f"파싱 실패 {e}")
    else:
        bad("symbols.json", "없음")

print("\n=== ③ 실행 의존성 ===")
try:
    import pylink  # noqa
    good("pylink", "import OK")
except Exception as e:
    bad("pylink", f"import 실패 {e}")
for name, path in (("fuzzer_config.json", ROOT / "fuzzer_config.json"),
                   ("riscv_cov.py", ROOT / "riscv_cov.py"),
                   ("elf_map.py", RV / "elf_map.py")):
    (good if path.exists() else bad)(name, "있음" if path.exists() else "없음")
try:
    cfg = json.loads((ROOT / "fuzzer_config.json").read_text())
    p9 = cfg["products"]["BM9K1"]
    good("products.BM9K1", f"sampler={p9['sampler_type']} interface={p9['interface']}")
except Exception as e:
    bad("products.BM9K1", f"{e}")

print(f"\n=== 결과: 통과 {ok} / 실패 {ng} ===")
print("  → 준비 완료. sudo python3 pc_sampling_fuzzer_v10.0.py --product BM9K1" if ng == 0
      else "  → 위 ❌ 를 채워야 한다.")
sys.exit(1 if ng else 0)
