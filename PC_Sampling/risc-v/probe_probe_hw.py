#!/usr/bin/env python3
"""J-Link **하드웨어 버전**을 찍는다. cJTAG KEEPER 우회 지원 여부의 전제.

SEGGER cJTAG 문서:
  "some devices (**especially in the RISC-V segment**) have a buggy KEEPER
   logic or no KEEPER logic at all ... a floating TMSC pin can cause the
   target to detect escape sequences where there are none and so cause problems."
  "In current J-Link models, a workaround ... is implemented.
   **If a specific J-Link hardware version comes with this workaround,
   can be checked via the model overview page.**"

그리고 T32 는 이 타깃에 `CJTAGFLAGS **NOKEEPER** USEOAC` 로 붙는다 —
**이 칩에 KEEPER 로직이 없다는 뜻이다.** T32 에는 그 전용 플래그가 있고,
J-Link 은 하드웨어 버전에 따라 우회가 있거나 없다.

⇒ 우리 증상(Id=0x00000001, 실행마다 결과가 바뀜, 저속에서 스캔 자체가 없음)이
   floating TMSC 의 전형이다. 설정 문제가 아닐 수 있다.

사용:  sudo python3 probe_probe_hw.py
"""
import sys
import pylink

FIELDS = [('product_name', 'product_name'), ('serial_number', 'serial_number'),
          ('firmware_version', 'firmware_version'),
          ('hardware_version', 'hardware_version'),
          ('compatible_firmware_version', 'compatible_firmware_version'),
          ('features', 'features'), ('capabilities', 'capabilities')]

jl = pylink.JLink()
jl.open()
print(f"\n{'=' * 60}\n J-Link 하드웨어 정보\n{'=' * 60}")
for label, attr in FIELDS:
    try:
        v = getattr(jl, attr)
        v = v() if callable(v) else v
        print(f"  {label:28s} = {v}")
    except Exception as e:
        print(f"  {label:28s} = (실패: {str(e)[:50]})")
try:
    jl.close()
except Exception:
    pass
print(f"\n{'=' * 60}")
print("  ★ hardware_version 을 SEGGER 'J-Link Model Overview' 페이지에서 확인할 것.")
print("    KEEPER 우회가 있는 하드웨어 버전인가?")
print("    없으면 — 이 프로브로는 이 타깃의 cJTAG 를 안정적으로 못 쓴다.")
