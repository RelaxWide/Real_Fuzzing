#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BM9K1 연결 단계별 시험 — 퍼저 없이 RISC-V 경로만 격리해서 어디서 끊기는지 본다.

사용:  sudo python3 tools/check_bm9k1_connect.py            (기본 루트 /home/ssd/pc_sample)
       sudo python3 tools/check_bm9k1_connect.py --root <경로> [--samples 200]

단계: import → 세션 open(인증) → SBA → 코어별 pin → 샘플 → ELF 정합성 게이트
각 단계에서 멈추면 그 지점과 이유를 찍는다. 정적 점검은 check_bm9k1_setup.py.
"""
import argparse
import os
import sys
from pathlib import Path

DEFAULT_ROOT = "/home/ssd/pc_sample"

ap = argparse.ArgumentParser()
ap.add_argument("--root", default=os.environ.get("PCSAMPLE_ROOT") or DEFAULT_ROOT)
ap.add_argument("--samples", type=int, default=200, help="코어당 시험 샘플 수")
ap.add_argument("--power", default="both")
a = ap.parse_args()

ROOT = Path(a.root).resolve()
print(f"퍼저 루트: {ROOT}")
if not ROOT.is_dir():
    print(f"❌ 루트 디렉토리 없음: {ROOT}"); sys.exit(2)
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "risc-v"))

step = 0


def stage(msg):
    global step
    step += 1
    print(f"\n[{step}] {msg}")


def die(why, hint=""):
    print(f"  ❌ {why}")
    if hint:
        print(f"     → {hint}")
    sys.exit(1)


stage("모듈 import")
try:
    import riscv_cov
    print("  ✅ riscv_cov")
except Exception as e:
    die(f"riscv_cov import 실패: {e}", f"{ROOT}/riscv_cov.py 존재 확인")
try:
    import sjtag_unlock, sfe76_link, elf_map          # noqa
    print(f"  ✅ sjtag_unlock / sfe76_link / elf_map")
except Exception as e:
    die(f"risc-v 모듈 import 실패: {e}", "pylink 설치 여부, risc-v/ 경로 확인")
if not sfe76_link.ADDRS_REAL:
    err = (sfe76_link.RISCV_ADDRS or {}).get("_load_error")
    die("sjtag_addrs.json 이 실제 값으로 로드되지 않았다"
        + (f" (파싱 실패: {err})" if err else " (example placeholder 사용 중)"),
        "sudo 로 실행했는지, JSON 문법이 맞는지 확인")
print("  ✅ sjtag_addrs.json 실제 값 로드")

stage("★ 런타임이 실제로 읽은 값 (체커와 대조)")
# 체커는 <루트>/risc-v/sjtag_addrs.json 을 직접 읽지만, 런타임은 sfe76_link.py 가
# **자기 위치 기준**으로 읽는다. 둘이 다른 파일이면 '체커는 통과, 퍼저는 미설정'이 된다.
_mod_dir = os.path.dirname(os.path.abspath(sfe76_link.__file__))
_runtime_json = os.path.join(_mod_dir, "sjtag_addrs.json")
_checker_json = str(ROOT / "risc-v" / "sjtag_addrs.json")
print(f"  sfe76_link.py   : {sfe76_link.__file__}")
print(f"  런타임이 읽는 json: {_runtime_json}")
print(f"  체커가 읽는 json  : {_checker_json}")
if os.path.realpath(_runtime_json) != os.path.realpath(_checker_json):
    print("  ❌ ★ 서로 다른 파일이다 — 체커 통과와 퍼저 실패가 동시에 나는 원인")
    print("     → 퍼저가 쓰는 risc-v/ 트리에 값을 채워야 한다(또는 중복 트리 제거)")
else:
    print("  ✅ 같은 파일")
_rt = (sfe76_link.RISCV_ADDRS.get("runtime") or {})
_raw = _rt.get("sjtag_base", "<키없음>")
print(f"  runtime.sjtag_base 원시값: type={type(_raw).__name__} "
      f"len={len(str(_raw))} 비어있음={str(_raw).strip()==''}")
_b = getattr(sjtag_unlock, "SJTAG_BASE", None)
_t = getattr(sjtag_unlock, "SIGN_TOOL", None)
print(f"  SJTAG_BASE      : {'None(미설정)' if _b is None else f'설정됨({_b:#x})'}")
print(f"  SIGN_TOOL       : {'None(미설정)' if not _t else '설정됨'}")
if _b is None:
    die("런타임 SJTAG_BASE 가 None — 위 json 경로/내용을 확인하라",
        "체커가 통과했다면 퍼저가 다른 json 을 읽고 있거나, "
        "sjtag_unlock.py 가 구버전(0 을 falsy 로 거르던 것)일 수 있다")

stage("pcsr 설정 확인")
pc = (sjtag_unlock.RISCV_ADDRS.get("pcsr") or {})
cores = {int(c["id"]): c for c in (pc.get("cores") or [])}
if not cores:
    die("pcsr.cores 가 비었다", "sjtag_addrs.json 의 pcsr 섹션 확인")
print(f"  ✅ 코어 {len(cores)}개: " + ", ".join(
    f"{c['name']}(id={i})" for i, c in sorted(cores.items())))

stage("세션 open — Link → prepare_session → 인증 → SBA")
sess = riscv_cov.PcsrSession(cores=cores, power=a.power, verbose=True)
if not sess.open():
    die("세션 open 실패", "위 [pcsr] 로그의 마지막 줄이 원인. 인증/전원/케이블 확인")
print(f"  ✅ open OK (인증 {sess.auth_count}회, {sess.auth_ms:.0f}ms)")

try:
    stage("코어별 pin + 샘플")
    ok_cores, results = [], {}
    for cid in sorted(cores):
        name = cores[cid].get("name", str(cid))
        if not sess.pin(cid):
            print(f"  ❌ core {name}: pin 실패")
            continue
        obs = sess.burst(cid, a.samples)
        valid = [o for o in obs if o.valid and o.pc is not None]
        fresh = [o for o in valid if o.fresh]
        pcs = [o.pc for o in valid]
        results[cid] = pcs
        if not valid:
            print(f"  ⚠ core {name}: 샘플 {len(obs)}개 전부 무효 "
                  f"(halt/wfi 중이거나 PCSR 오프셋이 다를 수 있음)")
            continue
        ok_cores.append(cid)
        print(f"  ✅ core {name}: {len(valid)}/{len(obs)} 유효 "
              f"({100.0*len(valid)/max(1,len(obs)):.0f}%), fresh {len(fresh)}, "
              f"고유 PC {len(set(pcs))}")

    stage("ELF 정합성 게이트 (elf_map, 임계 95%)")
    if not ok_cores:
        die("유효 샘플이 나온 코어가 없다",
            "pcsr.offset/core_stride 가 맞는지, 코어가 실행 중인지 확인")
    for cid in ok_cores:
        c = cores[cid]
        elf = c.get("elf", "")
        if not elf or not os.path.exists(elf):
            print(f"  ⚠ core {c['name']}: ELF 없음 → 게이트 생략 ({elf})")
            continue
        off = int(str(c.get("load_offset", 0)), 0)
        ok, info = elf_map.check_gate(results[cid], elf, off, 95.0,
                                      label=f"core{c['name']}", verbose=True)
        if not ok and info.get("suggested_offset") is not None:
            print(f"     → load_offset 을 {info['suggested_offset']:#x} 로 바꿔보라")
finally:
    sess.close()
    print("\n세션 정리 완료.")

print("\n=== 여기까지 통과하면 퍼저의 connect() 도 같은 경로로 성공한다 ===")
print("  sudo python3 pc_sampling_fuzzer_v10.0.py --product BM9K1")
