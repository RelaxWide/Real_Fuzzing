#!/usr/bin/env python3
"""■ 배치: **오프라인 퍼징 PC** — 리포 안 `PC_Sampling/rag/` 그대로 (fuzzer 가 in-process 로 import).

스키마 브리지 — LLM 생성 시드/시퀀스를 fuzzer 발송 기준(CMD_SCHEMAS)으로 검증·보정.

v9.0 fuzzer 는 이 클래스를 in-process 로 쓴다: SchemaBridge.from_dict(_llm_schema_dict())
— live CMD_SCHEMAS/가드로 dict 를 만들어 넘기므로 **파일 불필요**. 여기서 validate_and_repair
를 통과한 시드는 fuzzer 흡수 시에도 schema-valid. (파일 기반 SchemaBridge(json_path) 도
가능하나 선택 — 별도 노드에서 JSON 만으로 쓸 때.)

API:
  b = SchemaBridge.from_dict(schema_dict)   # v9.0 fuzzer 경로(파일 불필요)
  b.schema_to_prompt("Identify")            # LLM 프롬프트에 넣을 CDW 필드 정의 표(텍스트)
  b.is_dangerous("Sanitize", cdw)           # (bool, reason) — 위험명령이면 생성 금지
  b.validate_and_repair("Read", cdw)        # (repaired_cdw, repaired_fields, ok)

cdw 표기: {"cdw2":int,"cdw3":int,"cdw10":int,...,"cdw15":int}. 없는 word 는 0 으로 간주.
reserved_policy: "reject"(기본) = 유효하지 않은 ENUM 값이면 시드 폐기 / "clamp" = 첫 valid 값으로 보정.
"""
import json
from pathlib import Path

# 파일 기반 SchemaBridge(json_path=None) 의 기본 경로(선택). v9.0 fuzzer 는 from_dict 를 써서 미사용.
_DEFAULT_JSON = Path(__file__).resolve().parent / "cmd_schemas.json"


class SchemaBridge:
    def __init__(self, json_path=None, reserved_policy="reject"):
        data = json.loads(Path(json_path or _DEFAULT_JSON).read_text())
        self._init_from(data, reserved_policy)

    def _init_from(self, data, reserved_policy):
        self.fuzzer_version = data.get("fuzzer_version", "?")
        self.commands = data["commands"]
        self.schemas = data["schemas"]
        self.guards = data["guards"]
        self.reserved_policy = reserved_policy

    @classmethod
    def from_dict(cls, data, reserved_policy="reject"):
        """cmd_schemas.json 파일 없이 in-memory dict 로 구성 (fuzzer in-process 용).
        data = export_cmd_schemas.py / fuzzer 의 _llm_schema_dict() 산출과 동일한
        {commands, schemas, guards[, fuzzer_version]} 형태. 검증 기준을 발송 기준(live
        CMD_SCHEMAS)과 완전 일치시키고 export 단계·파일 의존을 제거한다."""
        self = cls.__new__(cls)
        self._init_from(data, reserved_policy)
        return self

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
                # valid 값이 많은 필드(열거형)는 hex 가 줄줄이 이어져 프롬프트를 크게 부풀린다.
                #   앞 8개만 보여주고 나머지는 개수로 요약 — LLM 은 유효 범위의 '형태' 만 알면
                #   되므로 전량 나열은 낭비다.
                _vs = list(f["valid"])
                s += " valid=" + ",".join(hex(v) for v in _vs[:8])
                if len(_vs) > 8:
                    s += f",...(+{len(_vs) - 8})"
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
    # from_dict 경로 스모크(파일 불필요). fuzzer 는 실제로 live CMD_SCHEMAS 로 dict 를 만든다.
    sample = {
        "fuzzer_version": "selftest",
        "commands": {
            "Identify": {"opcode": 0x06, "cmd_type": "admin"},
            "Sanitize": {"opcode": 0x84, "cmd_type": "admin"},
        },
        "schemas": {
            "Identify": [{"name": "CNS", "word": 10, "hi": 7, "lo": 0, "ftype": "ENUM",
                          "valid": [0x00, 0x01, 0x02, 0x03, 0x06], "reserved": [],
                          "vendor": [], "max_val": 0}],
        },
        "guards": {"destructive": ["FormatNVM", "Sanitize"], "blocked_admin_opcodes": [],
                   "blocked_security_send_secp": [], "security_send_opcode": 0x81,
                   "ns_mgmt_opcode": 0x0D, "ns_attach_opcode": 0x15, "block_ns_delete": True},
    }
    b = SchemaBridge.from_dict(sample)
    print(f"[rag_schema] from_dict OK — commands={len(b.commands)}")
    print("--- schema_to_prompt('Identify') ---")
    print(b.schema_to_prompt("Identify"))
    print("--- validate_and_repair cases ---")
    for cmd, cdw in [("Identify", {"cdw10": 0x06}),   # valid
                     ("Identify", {"cdw10": 0x1F}),   # reserved ENUM → reject
                     ("Sanitize", {"cdw10": 0x02}),   # destructive → reject
                     ("UnknownCmd", {"cdw10": 0})]:    # 미지 → reject
        rep, fixed, ok = b.validate_and_repair(cmd, cdw)
        dang, reason = b.is_dangerous(cmd, cdw)
        print(f"  {cmd:12} cdw10=0x{cdw.get('cdw10', 0):08x} -> ok={ok} "
              f"{'danger=' + reason if dang else ''}")


if __name__ == "__main__":
    _selftest()
