#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""J-Link EMU GPIO 제어 — BM9K1 부트모드 스트랩(GP15_ROM_BOOT / GP12_ROM_DEBUG) 자동화용.

JTAGMULTI20 젠더의 3단 토글(VCC / 중립 / GND)은 EMU GPIO 의 세 상태와 1:1 이다:

    VCC  ─ high   (출력 High)
    중립 ─ hiz    (입력 = High-Z, 보드 자체 풀이 결정)
    GND  ─ low    (출력 Low)

부트 스트랩은 **리셋 해제 시점에만** 래치되므로, POR 동안만 정상부팅 레벨로 잡고
부팅이 끝나면 중립으로 놓으면 부팅도 살고 JTAG 도 산다. 이 스크립트가 그 두 동작
(`--apply` / `--release`)을 제공하고, 퍼저는 POR 전후로 이걸 호출한다.

EMU GPIO 는 **J-Link 자체의 핀**이라 타깃 인증(SJTAG)이 필요 없다. 시료가 ROM 모드로
빠져 있어도 동작한다 — 그래서 이 방법이 성립한다.

⚠ 상태 코드(hiz/low/high 의 정수값)는 SEGGER JLinkARMDLL.h 의
   JLINK_EMU_GPIO_STATE_* 에서 온다. 기본값이 장비와 다르면 --code 로 덮어쓰고,
   `--list` 의 readback 으로 확인하라(gpio_set 은 반영된 상태를 되돌려준다).

사용:
    # 1) 어떤 핀이 있는지·현재 상태는 무엇인지 (가장 먼저 이것부터)
    python3 tools/jlink_gpio.py --list

    # 2) 스트랩을 정상부팅 레벨로 (POR 직전)
    python3 tools/jlink_gpio.py --set GP15_ROM_BOOT=low,GP12_ROM_DEBUG=hiz

    # 3) 중립으로 되돌림 (부팅 완료 후, JTAG 붙이기 전)
    python3 tools/jlink_gpio.py --release GP15_ROM_BOOT,GP12_ROM_DEBUG

    # 9조합 전수 스윕을 스크립트로 돌릴 때
    python3 tools/jlink_gpio.py --set GP15_ROM_BOOT=high,GP12_ROM_DEBUG=low --quiet
"""
import argparse
import sys

# SEGGER JLINK_EMU_GPIO_STATE_* 기본 매핑. 장비/DLL 버전에 따라 다르면 --code 로 교정.
STATE_CODES = {"get": 0, "hiz": 1, "low": 2, "high": 3}
ALIASES = {"neutral": "hiz", "중립": "hiz", "input": "hiz", "z": "hiz",
           "gnd": "low", "0": "low", "vcc": "high", "1": "high"}


def _norm(name):
    n = name.strip().lower()
    return ALIASES.get(n, n)


def _open(serial=None):
    import pylink
    jl = pylink.JLink()
    jl.open(serial_no=serial) if serial else jl.open()
    return jl


def _props(jl):
    """[(index, name, caps)] — 이름은 장비가 보고하는 실제 값."""
    return [(i, str(d), d.Caps) for i, d in enumerate(jl.gpio_properties())]


def _resolve(props, token):
    """'GP15_ROM_BOOT' 또는 '3' → 핀 인덱스. 부분일치도 허용(이름이 길어서)."""
    t = token.strip()
    if t.isdigit():
        idx = int(t)
        if not any(i == idx for i, _, _ in props):
            raise SystemExit(f"[gpio] 인덱스 {idx} 없음 — --list 로 확인하라")
        return idx
    exact = [i for i, n, _ in props if n == t]
    if exact:
        return exact[0]
    part = [i for i, n, _ in props if t.lower() in n.lower()]
    if len(part) == 1:
        return part[0]
    if not part:
        raise SystemExit(f"[gpio] '{t}' 라는 GPIO 없음 — --list 로 실제 이름 확인")
    raise SystemExit(f"[gpio] '{t}' 가 여러 핀에 걸린다: "
                     + ", ".join(n for i, n, _ in props if i in part))


def cmd_list(jl, _args):
    props = _props(jl)
    if not props:
        print("[gpio] 이 J-Link 은 user-controllable GPIO 를 보고하지 않는다.")
        print("       → 스트랩이 J-Link EMU GPIO 가 아니라 다른 경로(PMU/FTDI/sysfs)일 수 있다.")
        return 1
    states = jl.gpio_get([i for i, _, _ in props])
    rev = {v: k for k, v in STATE_CODES.items()}
    print(f"{'idx':<5}{'name':<28}{'caps':<12}state")
    for (i, n, c), s in zip(props, states):
        print(f"{i:<5}{n:<28}0x{c:<10X}{s} ({rev.get(s, '?')})")
    return 0


def parse_set(spec):
    """'A=low,B=hiz' → [(name, state_name)]. 하드웨어를 열기 **전에** 검증한다 —
    오타 때문에 POR 시퀀스 한복판에서 죽으면 시료가 어중간한 상태로 남는다."""
    out = []
    for item in spec.split(','):
        if '=' not in item:
            raise SystemExit(f"[gpio] '--set' 형식은 NAME=state — 받은 값: {item!r}")
        name, st = item.split('=', 1)
        st = _norm(st)
        if st not in STATE_CODES:
            raise SystemExit(f"[gpio] 상태 {st!r} 를 모른다 "
                             f"(가능: {', '.join(STATE_CODES)} / vcc,gnd,중립)")
        if not name.strip():
            raise SystemExit(f"[gpio] 핀 이름이 비었다: {item!r}")
        out.append((name.strip(), st))
    return out


def cmd_set(jl, args):
    props = _props(jl)
    pins, states, shown = [], [], []
    for name, st in parse_set(args.set):
        idx = _resolve(props, name)
        pins.append(idx); states.append(STATE_CODES[st])
        shown.append(f"{dict((i, n) for i, n, _ in props)[idx]}={st}")
    result = jl.gpio_set(pins, states)
    if not args.quiet:
        rev = {v: k for k, v in STATE_CODES.items()}
        print(f"[gpio] set {' '.join(shown)}  → readback "
              + " ".join(f"{r}({rev.get(r, '?')})" for r in result))
    # 되돌려받은 값이 요청과 다르면 조용히 넘기지 않는다 — 스트랩은 틀리면 부팅이 바뀐다.
    if list(result) != states:
        print(f"[gpio] ⚠ 요청 {states} != 반영 {list(result)} — "
              f"상태 코드 매핑이 다를 수 있다(--code 로 교정)", file=sys.stderr)
        return 2
    return 0


def cmd_release(jl, args):
    props = _props(jl)
    pins = [_resolve(props, t) for t in args.release.split(',')]
    result = jl.gpio_set(pins, [STATE_CODES['hiz']] * len(pins))
    if not args.quiet:
        print(f"[gpio] release(hiz) {args.release} → readback {list(result)}")
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--list', action='store_true', help='GPIO 목록과 현재 상태')
    g.add_argument('--set', metavar='N=STATE[,N=STATE...]',
                   help='상태 지정 (high|hiz|low, vcc/중립/gnd 별칭 가능)')
    g.add_argument('--release', metavar='N[,N...]', help='지정 핀을 hiz(중립)로')
    p.add_argument('--serial', help='J-Link 시리얼(여러 대일 때)')
    p.add_argument('--code', action='append', metavar='STATE=INT', default=[],
                   help='상태 코드 교정, 예: --code hiz=0 --code low=1')
    p.add_argument('--quiet', action='store_true')
    args = p.parse_args()

    for c in args.code:
        k, v = c.split('=', 1)
        STATE_CODES[_norm(k)] = int(v, 0)

    # 장비를 열기 전에 문법·상태명을 검증한다(하드웨어 없이도 오타가 잡힌다).
    if args.set:
        parse_set(args.set)
    if args.release and not args.release.strip():
        raise SystemExit("[gpio] --release 에 핀이 없다")

    try:
        jl = _open(args.serial)
    except Exception as e:
        print(f"[gpio] J-Link 열기 실패: {e}", file=sys.stderr)
        print("       퍼저가 세션을 점유 중이면 USB 경합이다 — "
              "POR 훅은 링크 해제 후에 호출된다(power.por_release_link).", file=sys.stderr)
        return 3
    try:
        if args.list:
            return cmd_list(jl, args)
        if args.set:
            return cmd_set(jl, args)
        return cmd_release(jl, args)
    finally:
        try:
            jl.close()
        except Exception:
            pass


if __name__ == '__main__':
    sys.exit(main())
