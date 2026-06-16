#!/usr/bin/env python3
"""RAG 서비스용 스키마 브리지 — cmd_schemas.json 기반 (fuzzer import 불필요, Intranet PC 이식 가능).

생성된 cmd_schemas.json(= export_cmd_schemas.py 산출)만 있으면 동작한다. fuzzer 의 CMD_SCHEMAS 와
동일 기준이므로, 여기서 validate_and_repair 를 통과한 시드는 fuzzer 흡수 시에도 schema-valid.

API:
  b = SchemaBridge("cmd_schemas.json")
  b.schema_to_prompt("Identify")            # LLM 프롬프트에 넣을 CDW 필드 정의 표(텍스트)
  b.is_dangerous("Sanitize", cdw)           # (bool, reason) — 위험명령이면 생성 금지
  b.validate_and_repair("Read", cdw)        # (repaired_cdw, repaired_fields, ok)

cdw 표기: {"cdw2":int,"cdw3":int,"cdw10":int,...,"cdw15":int}. 없는 word 는 0 으로 간주.
reserved_policy: "reject"(기본) = 유효하지 않은 ENUM 값이면 시드 폐기 / "clamp" = 첫 valid 값으로 보정.
"""
import json
from pathlib import Path

_DEFAULT_JSON = Path(__file__).resolve().parent / "cmd_schemas.json"


class SchemaBridge:
    def __init__(self, json_path=None, reserved_policy="reject"):
        data = json.loads(Path(json_path or _DEFAULT_JSON).read_text())
        self.fuzzer_version = data.get("fuzzer_version", "?")
        self.commands = data["commands"]
        self.schemas = data["schemas"]
        self.guards = data["guards"]
        self.reserved_policy = reserved_policy

    # ---------- bit helpers ----------
    @staticmethod
    def _get_bits(word_val, hi, lo):
        mask = (1 << (hi - lo + 1)) - 1
        return (word_val >> lo) & mask

    @staticmethod
    def _set_bits(word_val, hi, lo, v):
        mask = (1 << (hi - lo + 1)) - 1
        return (word_val & ~(mask << lo)) | ((v & mask) << lo)

    @staticmethod
    def _in_range(v, rng):
        return len(rng) == 2 and rng[0] <= v <= rng[1]

    # ---------- public ----------
    def known_commands(self):
        return sorted(self.commands.keys())

    def schema_to_prompt(self, cmd):
        """LLM 프롬프트용 필드 정의 표. 생성 모델이 schema-valid CDW 를 만들도록 주입."""
        c = self.commands.get(cmd, {})
        lines = [f"Command: {cmd} (opcode=0x{c.get('opcode', 0):02x}, "
                 f"type={c.get('cmd_type', '?')})"]
        fields = self.schemas.get(cmd, [])
        if not fields:
            lines.append("  (CDW 파라미터 정의 없음)")
        for f in fields:
            s = f"  CDW{f['word']}[{f['hi']}:{f['lo']}] {f['name']} ({f['ftype']})"
            if f["valid"]:
                s += " valid=" + ",".join(hex(v) for v in f["valid"])
            if f["vendor"]:
                s += f" vendor=0x{f['vendor'][0]:x}-0x{f['vendor'][1]:x}"
            if f["reserved"]:
                s += f" reserved=0x{f['reserved'][0]:x}-0x{f['reserved'][1]:x}"
            if f["ftype"] == "SLOT":
                s += f" max={f['max_val']}"
            lines.append(s)
        return "\n".join(lines)

    def is_dangerous(self, cmd, cdw=None):
        """device 를 파괴/잠금하거나 하네스를 깨는 명령이면 (True, 사유). 생성 금지 대상."""
        g, cdw = self.guards, (cdw or {})
        if cmd in g["destructive"]:
            return True, f"destructive ({cmd})"
        c = self.commands.get(cmd)
        if c is None:
            return False, ""
        op, typ = c["opcode"], c["cmd_type"]
        cdw10 = cdw.get("cdw10", 0)
        if typ == "admin" and op in g["blocked_admin_opcodes"]:
            return True, f"blocked admin opcode 0x{op:02x}"
        if typ == "admin" and op == g["security_send_opcode"]:
            secp = (cdw10 >> 24) & 0xFF
            if secp in g["blocked_security_send_secp"]:
                return True, f"locking SECP 0x{secp:02x}"
        if (typ == "admin" and op == g["ns_mgmt_opcode"]
                and g["block_ns_delete"] and (cdw10 & 0xF) == 1):
            return True, "NamespaceManagement Delete(SEL=1)"
        return False, ""

    def validate_and_repair(self, cmd, cdw):
        """반환 (repaired_cdw, repaired_fields, ok).
        ok=False → 시드 폐기 권장(미지 명령 / 위험명령 / reserved-reject 정책 위반).
        ENUM 은 valid 또는 vendor 범위만 허용, FLAGS/SLOT 은 clamp, LBA/SIZE/OFFSET/OPAQUE 는 자유.
        word 내 필드 미정의 비트는 원본 보존(엄격 0-재구성은 안 함)."""
        cdw = dict(cdw or {})
        repaired = []
        if cmd not in self.commands:
            return cdw, repaired, False
        danger, _ = self.is_dangerous(cmd, cdw)
        if danger:
            return cdw, repaired, False

        words = {}   # word 번호 -> 현재 값(원본 시작)
        for f in self.schemas.get(cmd, []):
            w, key = f["word"], f"cdw{f['word']}"
            words.setdefault(w, cdw.get(key, 0))
            v = self._get_bits(words[w], f["hi"], f["lo"])
            nv, ft = v, f["ftype"]
            if ft == "ENUM":
                ok_v = bool(f["valid"]) and v in f["valid"]
                if not (ok_v or self._in_range(v, f["vendor"])):
                    if self.reserved_policy == "clamp" and f["valid"]:
                        nv = f["valid"][0]
                    else:
                        return cdw, repaired, False   # invalid/reserved ENUM → reject
            elif ft == "FLAGS":
                if f["valid"] and v not in f["valid"]:
                    nv = f["valid"][0]
            elif ft == "SLOT":
                if v > f["max_val"]:
                    nv = f["max_val"]
            # LBA / LBA_CNT / SIZE_DW / OFFSET_DW / OPAQUE: 자유값 허용
            if nv != v:
                words[w] = self._set_bits(words[w], f["hi"], f["lo"], nv)
                repaired.append(f"{key}.{f['name']}: 0x{v:x}->0x{nv:x}")

        for w, val in words.items():
            cdw[f"cdw{w}"] = val
        return cdw, repaired, True


def _selftest():
    b = SchemaBridge()
    print(f"[rag_schema] cmd_schemas.json fuzzer_version={b.fuzzer_version} "
          f"commands={len(b.commands)}")
    print("--- schema_to_prompt('Identify') ---")
    print(b.schema_to_prompt("Identify"))
    print("--- validate_and_repair cases ---")
    cases = [
        ("Read",        {"cdw10": 0, "cdw11": 0, "cdw12": 7}),       # valid
        ("Identify",    {"cdw10": 0x06}),                            # CNS=6 valid
        ("Identify",    {"cdw10": 0x1F}),                            # CNS=0x1F reserved → reject
        ("Sanitize",    {"cdw10": 0x02}),                            # destructive → reject
        ("SecuritySend",{"cdw10": 0xEF000100}),                      # locking SECP → reject
        ("UnknownCmd",  {"cdw10": 0}),                               # 미지 → reject
    ]
    for cmd, cdw in cases:
        rep, fixed, ok = b.validate_and_repair(cmd, cdw)
        dang, reason = b.is_dangerous(cmd, cdw)
        print(f"  {cmd:14} cdw10=0x{cdw.get('cdw10',0):08x} -> ok={ok} "
              f"{'danger='+reason if dang else ''} {('repaired='+str(fixed)) if fixed else ''}")


if __name__ == "__main__":
    _selftest()
