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
    """퍼저 루트를 정한다.

    ★ 명시 경로(--root / PCSAMPLE_ROOT / DEFAULT_ROOT)는 **디렉토리이기만 하면 그대로 쓴다.**
      내용물(fuzzer_config.json 등)로 검증하면 안 된다 — 그 파일이 없는 걸 **찾아내는 게
      이 도구의 일**이라, 검증에 실패해 엉뚱한 상위 디렉토리로 떨어지면 전부 '없음'이 된다.
      (실기서 /home/ssd 를 루트로 잡아 모든 항목이 없다고 나온 원인)
    자동 탐색으로 내려갈 때만 내용물로 검증한다."""
    for i, a in enumerate(sys.argv):
        if a == "--root" and i + 1 < len(sys.argv):
            return Path(sys.argv[i + 1]).resolve(), "--root"
    env = os.environ.get("PCSAMPLE_ROOT")
    if env:
        return Path(env).resolve(), "PCSAMPLE_ROOT"
    d = Path(DEFAULT_ROOT)
    if d.is_dir():
        return d.resolve(), "기본 설치 경로"

    here = Path(__file__).resolve()
    cands = [here.parent.parent, here.parent, Path.cwd(), Path.cwd().parent]
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
            return c, "자동 탐색"
    print(f"❌ 퍼저 루트를 못 찾았다. 기본값 {DEFAULT_ROOT} 도 없다.")
    print("   --root <퍼저디렉토리> 또는 PCSAMPLE_ROOT 환경변수로 지정하라.")
    print(f"   시도한 후보: {[str(c) for c in list(seen)[:6]]}")
    sys.exit(2)


ROOT, _why = _find_root()
print(f"퍼저 루트: {ROOT}   (출처: {_why})")
if not (ROOT / "fuzzer_config.json").exists():
    print(f"  ⚠ 이 경로에 fuzzer_config.json 이 없다 — 루트가 맞는지 확인하라"
          f" (--root / PCSAMPLE_ROOT 로 지정 가능)")
print()
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
    # ★ '미설정'과 '값이 0'은 다르다. 0 도 유효 주소일 수 있으므로 있는 그대로 보고하되,
    #   example placeholder 와 같은 값이면 주의만 준다(단정하지 않는다).
    raw_base = rt.get("sjtag_base", None)
    base = str(raw_base).strip() if raw_base is not None else ""
    if base == "":
        bad("runtime.sjtag_base", "비어있음(키 없음/빈 문자열)")
    elif base in ("0", "0x0"):
        good("runtime.sjtag_base", "0 — 유효 주소로 취급함. "
                                   "단 example placeholder 도 0x0 이니 실제 값인지 확인")
    else:
        good("runtime.sjtag_base", "채워짐")
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

print("\n=== ②-b 코드 오버레이 자산 ===")
try:
    sys.path.insert(0, str(ROOT))
    import riscv_cov as _rc
except Exception as _e:
    _rc = None
    bad("riscv_cov import", f"{_e}")
# 오래된 사본을 물면 여기서 AttributeError 로 죽는 대신 이유를 말한다.
# (실제로 겪음: 호스트가 pull 전이라 함수가 없어 체커가 터졌다)
if _rc is not None and not hasattr(_rc, "overlay_layout_candidates"):
    bad("riscv_cov 버전",
        f"오버레이 지원 없는 옛 사본이다 — git pull 필요. "
        f"로드된 파일: {getattr(_rc, '__file__', '?')}")
    _rc = None
if not PROD.is_dir():
    bad("오버레이", "products 디렉토리 없음")
else:
    _any_ovl = False
    for c in CORES:
        omap = PROD / f"overlay_probe_core{c}.json"      # 실측 판별표(수동, 선택)
        olay = None                                       # 빌드 레이아웃 맵
        if _rc is not None:
            for _cand in _rc.overlay_layout_candidates(c):
                if (PROD / _cand).exists():
                    olay = PROD / _cand
                    break
        # 파일명 오타를 잡는다 — 단수형(basic_block_)이면 로더가 조용히 무시한다
        wrong = sorted(PROD.glob(f"basic_block_core{c}_ovl*.txt"))
        if wrong:
            bad(f"core{c} 파일명",
                f"단수형 {len(wrong)}개 발견 — 'basic_blocks_'(복수)여야 로드된다"
                f" 예: {wrong[0].name}")
        # ★ 0바이트 파일은 '있는 표' 가 아니다. 추출기가 내용 없는 파일을 남기면
        #   오버레이 없는 코어가 오버레이 있는 것처럼 보이고, 런타임에는 그 bank 의
        #   샘플이 BB 를 못 찾아 조용히 버려진다. (실제로 겪음)
        _empty = sorted(f.name for f in
                        list(PROD.glob(f"basic_blocks_core{c}_ovl*.txt"))
                        + list(PROD.glob(f"functions_core{c}_ovl*.txt"))
                        if f.stat().st_size == 0)
        if _empty:
            bad(f"core{c} 빈 표 파일",
                f"{len(_empty)}개가 0바이트 — 추출 실패다. 지우거나 다시 뽑아라: "
                f"{_empty[:4]}{'…' if len(_empty) > 4 else ''}")
        bbs = sorted(f for f in PROD.glob(f"basic_blocks_core{c}_ovl*.txt")
                     if f.stat().st_size > 0)
        fns = sorted(f for f in PROD.glob(f"functions_core{c}_ovl*.txt")
                     if f.stat().st_size > 0)
        if not (bbs or fns or omap.exists() or olay):
            # 아무 줄도 안 찍으면 "왜 이 코어는 없지?" 로 오해한다 — 정상임을 명시.
            good(f"core{c} 오버레이", "없음 (이 코어는 오버레이 미사용 — 정상)")
            continue
        _any_ovl = True
        if not (omap.exists() or olay):
            _cands = _rc.overlay_layout_candidates(c)[:3] if _rc else []
            # ★ 무슨 파일 때문에 이 코어를 오버레이로 판단했는지 보여준다.
            #   "이 코어는 오버레이 없는데?" 일 때 그 파일들이 잘못 생긴 것이다.
            _found = sorted(f.name for f in (bbs + fns))
            bad(f"core{c} 오버레이 설정",
                f"오버레이 표 {len(_found)}개가 있는데 레이아웃 맵이 없다. "
                f"발견: {_found[:4]}{'…' if len(_found) > 4 else ''} | "
                f"찾는 맵 이름: {_cands}")
            continue
        try:
            if omap.exists():
                om = json.loads(omap.read_text())
                n_map = len(om.get("bank_sizes") or {})
                src = "실측 판별표"
            else:
                _lay = json.loads(olay.read_text())
                om = _rc.overlay_from_layout(_lay) or {}
                if not om:
                    bad(f"core{c} 레이아웃 맵",
                        ".OVL_REGION_NN: section_index/addr/size 스키마가 아니거나"
                        " 주소가 제각각이다(진짜 오버레이가 아님)")
                    continue
                n_map = len(om.get("bank_sizes") or {})
                om = {"base": om["base"], "probe_offsets": om["probe_offsets"],
                      "header": {"magic": hex(om["magic"])}}
                src = f"{olay.name} (규약 유도)"
        except Exception as e:
            bad(f"core{c} 오버레이 설정", f"파싱 실패 {e}")
            continue
        good(f"core{c} 오버레이 설정", "%s, bank %d개" % (src, n_map))
        idx_bb = {int(f.stem.rsplit("_ovl", 1)[1]) for f in bbs}
        idx_fn = {int(f.stem.rsplit("_ovl", 1)[1]) for f in fns}
        want = set(range(n_map))
        probe = om.get("probe_offsets") or []
        hdr = om.get("header") or {}
        if not probe:
            bad(f"core{c} probe", "판별 오프셋 없음 — 레이아웃 맵의 addr/size 를 확인하라")
        else:
            good(f"core{c} probe",
                 f"0x{int(om['base']) + probe[0]:X} 읽기 1워드"
                 + (f", 매직 {hdr.get('magic')}" if hdr else ", 매직 없음(표만 사용)"))
        missing_bb = sorted(want - idx_bb)
        missing_fn = sorted(want - idx_fn)
        extra = sorted((idx_bb | idx_fn) - want)
        if missing_bb or missing_fn:
            # 누락 **번호**를 앞에 낸다 — 개수만 보면 어느 파일인지 몰라 못 고친다.
            _mi = sorted(set(missing_bb) | set(missing_fn))
            _tail = "" if len(_mi) <= 8 else f" 외 {len(_mi) - 8}개"
            bad(f"core{c} 오버레이 표",
                f"누락 ovl 번호 {_mi[:8]}{_tail}  "
                f"(있는 것: BB {len(idx_bb)}개 / 함수 {len(idx_fn)}개, 맵 {n_map}개 "
                f"= ovl0~{n_map - 1}). 누락 bank 는 bank 0 으로 접혀 분모에서 빠진다")
        elif extra:
            _ex = sorted(f.name for f in (bbs + fns)
                         if int(f.stem.rsplit("_ovl", 1)[1]) in set(extra))
            bad(f"core{c} 오버레이 표",
                f"맵에 없는 ovl 번호 {extra[:8]} — 맵은 {n_map}개(ovl0~{n_map-1})인데 "
                f"표가 더 많다. 해당 파일: {_ex[:4]}{'…' if len(_ex) > 4 else ''} | "
                f"추출 스크립트가 코어별로 걸러내지 못했거나 맵이 옛 빌드다")
        else:
            good(f"core{c} 오버레이 표", f"{n_map}개 bank 전부 (BB/함수 짝 맞음)")
    if not _any_ovl:
        good("오버레이", "자산 없음 — 오버레이 미사용으로 동작(정상)")

print("\n=== ③ 실행 의존성 ===")
try:
    import pylink  # noqa
    good("pylink", "import OK")
except Exception as e:
    bad("pylink", f"import 실패 {e}")
for name, path in (("fuzzer_config.json", ROOT / "fuzzer_config.json"),
                   ("riscv_cov.py", ROOT / "riscv_cov.py"),
                   ("pc_sampling_fuzzer_v10.0.py", ROOT / "pc_sampling_fuzzer_v10.0.py"),
                   ("elf_map.py", RV / "elf_map.py"),
                   ("sjtag_unlock.py", RV / "sjtag_unlock.py")):
    # 없을 때는 **어디를 봤는지** 절대경로로 보여준다 — 루트 오인을 바로 알 수 있게
    (good if path.exists() else bad)(name, "있음" if path.exists() else f"없음: {path}")
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
