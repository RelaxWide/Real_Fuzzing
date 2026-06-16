#!/usr/bin/env python3
"""CMD_SCHEMAS + NVME_COMMANDS + 위험명령 가드를 cmd_schemas.json 으로 export.

2노드 설계: **Test PC**(fuzzer 있는 곳)에서 1회 실행 → 생성된 `cmd_schemas.json` 을
**Intranet PC**(RAG 서비스)로 복사. RAG 서비스는 fuzzer 본체를 import 하지 않고 이 JSON
만으로 스키마 검증/프롬프트를 구성한다(rag_schema.py 사용). 즉 스키마 ground-truth 를 한 번
떠서 넘기는 다리.

usage:
    python3 export_cmd_schemas.py [fuzzer.py 경로] [출력.json 경로]
기본: ../pc_sampling_fuzzer_v9.0.py  →  ./cmd_schemas.json
"""
import importlib.util
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_DEFAULT_FUZZER = _HERE.parent / "pc_sampling_fuzzer_v9.0.py"


def _load_fuzzer(path: Path):
    # 파일명에 '.'(v9.0)이 있어 일반 import 불가 → importlib 로 파일 경로 로드.
    spec = importlib.util.spec_from_file_location("fuzzer_mod", str(path))
    m = importlib.util.module_from_spec(spec)
    sys.modules["fuzzer_mod"] = m   # dataclass __module__ 이슈 방지(선등록)
    spec.loader.exec_module(m)
    return m


def export(fuzzer_path: Path, out_path: Path) -> dict:
    m = _load_fuzzer(fuzzer_path)

    commands = {}
    for c in m.NVME_COMMANDS:
        commands[c.name] = {
            "opcode": c.opcode,
            "cmd_type": c.cmd_type.value,          # 'admin' | 'io'
            "needs_namespace": c.needs_namespace,
            "needs_data": c.needs_data,
            "timeout_group": c.timeout_group,
        }

    schemas = {}
    for name, sch in m.CMD_SCHEMAS.items():
        schemas[name] = [
            {
                "name": f.name, "word": f.word, "hi": f.hi, "lo": f.lo,
                "ftype": f.ftype.name,             # 'ENUM','LBA','FLAGS','SLOT',...
                "valid": list(f.valid or []),
                "reserved": list(f.reserved or []),
                "vendor": list(f.vendor or []),
                "max_val": f.max_val,
            }
            for f in sch.fields
        ]

    # _DESTRUCTIVE 는 _generate_default_seeds 내부 지역 변수(모듈 전역 아님) → fallback 미러.
    _destructive = getattr(m, "_DESTRUCTIVE", None) or {"FormatNVM", "Sanitize"}
    guards = {
        "destructive": sorted(_destructive),
        "blocked_admin_opcodes": sorted(int(x) for x in m.BLOCKED_ADMIN_OPCODES),
        "blocked_security_send_secp": sorted(int(x) for x in m.BLOCKED_SECURITY_SEND_SECP),
        "security_send_opcode": m._SECURITY_SEND_OPCODE,
        "ns_mgmt_opcode": m._NS_MGMT_OPCODE,
        "ns_attach_opcode": m._NS_ATTACH_OPCODE,
        "block_ns_delete": bool(m.BLOCK_NS_DELETE),
    }

    out = {
        "fuzzer_version": m.FUZZER_VERSION,
        "commands": commands,
        "schemas": schemas,
        "guards": guards,
    }
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=False))
    return out


def main():
    fuzzer = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else _DEFAULT_FUZZER
    out = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else _HERE / "cmd_schemas.json"
    if not fuzzer.is_file():
        print(f"[ERR] fuzzer not found: {fuzzer}", file=sys.stderr)
        sys.exit(1)
    data = export(fuzzer, out)
    print(f"[OK] {out}")
    print(f"     fuzzer_version={data['fuzzer_version']} "
          f"commands={len(data['commands'])} schemas={len(data['schemas'])}")


if __name__ == "__main__":
    main()
