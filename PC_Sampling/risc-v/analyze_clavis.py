#!/usr/bin/env python3
"""Read-only, secret-safe structural analysis for TRACE32 CMM authentication flows.

This tool is intentionally not an authenticator.  It extracts only the information
needed to estimate a legitimate J-Link integration: call graph, target accesses,
external dependencies, error flow, and challenge/response markers.  It never
executes CMM code or external commands.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Optional


VERSION = "analyze_clavis 2026-08-12.1"

CALL_RE = re.compile(r"^\s*(?:do|cd\.do)\s+(?P<target>[^;]+)", re.IGNORECASE)
QUOTED_RE = re.compile(r'(["\'])(.*?)(?<!\\)\1')
LONG_HEX_RE = re.compile(r"\b0x[0-9a-fA-F]{9,}\b")
LABEL_RE = re.compile(r"^\s*([A-Za-z_][\w.]*)\s*:\s*(?:;.*)?$")
SENSITIVE_ASSIGN_RE = re.compile(
    r"(?i)(key|secret|password|passwd|token|credential|private|signature)\s*="
)

CATEGORY_PATTERNS = {
    "target_read": re.compile(
        r"(?i)\b(?:data\.(?:long|word|byte|quad|in)|per\.view|register\.)\b"
    ),
    "target_write": re.compile(
        r"(?i)\b(?:data\.set|per\.set(?:\.simple)?|register\.set)\b"
    ),
    "file_io": re.compile(
        r"(?i)\b(?:open|read|write|close|data\.(?:load|save)|file\.)\b"
    ),
    "external_command": re.compile(
        r"(?i)\b(?:os\.(?:command|area)|run|exec(?:ute)?|shell|system)\b"
    ),
    "crypto_marker": re.compile(
        r"(?i)\b(?:challenge|response|clavis|authenticate|authentication|"
        r"encrypt|decrypt|cipher|hash|hmac|sha(?:1|2|256|384|512)?|aes|rsa|"
        r"ecdsa|ed25519|sign|signature|certificate|hsm)\b"
    ),
    "sensitive_material": re.compile(
        r"(?i)(?:key|secret|password|passwd|token|credential|private|certificate)"
    ),
    "error_flow": re.compile(
        r"(?i)\b(?:on\s+error|goto|return|enddo|stop|break)\b"
    ),
    "argument_flow": re.compile(r"(?i)^\s*(?:entry|parameters?)\b"),
}


@dataclass
class Finding:
    file: str
    line: int
    category: str
    snippet: str


@dataclass
class Dependency:
    caller: str
    line: int
    expression: str
    resolved: Optional[str]


@dataclass
class FileSummary:
    file: str
    sha256: str
    lines: int
    encoding: str


@dataclass
class Report:
    version: str
    roots: list[str]
    files: list[FileSummary] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    unresolved_calls: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def category_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self.findings:
            counts[item.category] = counts.get(item.category, 0) + 1
        return dict(sorted(counts.items()))


def _display_path(path: Path, roots: Iterable[Path]) -> str:
    resolved = path.resolve()
    for root in roots:
        try:
            return str(resolved.relative_to(root.resolve()))
        except ValueError:
            pass
    return path.name


def _decode(data: bytes) -> tuple[str, str]:
    if b"\x00" in data:
        raise ValueError("NUL byte detected; encrypted/binary CMM is not supported")
    for encoding in ("utf-8-sig", "cp949", "cp1252"):
        try:
            return data.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    raise ValueError("unsupported text encoding")


def _safe_quoted(match: re.Match[str]) -> str:
    value = match.group(2).strip().replace("\\", "/")
    name = value.rsplit("/", 1)[-1]
    if re.search(r"(?i)\.(?:cmm|exe|bat|cmd|py|dll|so|pem|crt|cer|key|bin)$", name):
        return f'"<file:{name}>"'
    return '"<string>"'


def sanitize(line: str) -> str:
    """Keep operations and 32-bit addresses, redact strings and key-sized values."""
    line = line.strip()
    if SENSITIVE_ASSIGN_RE.search(line):
        left = line.split("=", 1)[0].strip()
        return f"{left}=<redacted-sensitive-assignment>"
    line = QUOTED_RE.sub(_safe_quoted, line)
    line = LONG_HEX_RE.sub(lambda m: f"<hex:{(len(m.group(0)) - 2) * 4}bit>", line)
    return line[:240]


def strip_comment(line: str) -> str:
    """Remove a TRACE32 ';' comment without cutting a quoted file name."""
    quote: Optional[str] = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote:
            escaped = True
            continue
        if char in ("\"", "'"):
            quote = None if quote == char else (char if quote is None else quote)
        elif char == ";" and quote is None:
            return line[:index]
    return line


def _target_expression(raw: str) -> str:
    expression = raw.strip()
    match = QUOTED_RE.search(expression)
    if match:
        return match.group(2)
    return expression.split()[0] if expression else ""


def _build_index(search_roots: Iterable[Path]) -> dict[str, list[Path]]:
    index: dict[str, list[Path]] = {}
    for root in search_roots:
        if not root.is_dir():
            continue
        for item in root.rglob("*.cmm"):
            index.setdefault(item.name.lower(), []).append(item.resolve())
    return index


def _resolve_call(expression: str, caller: Path,
                  index: dict[str, list[Path]]) -> Optional[Path]:
    normalized = expression.replace("\\", "/")
    if "&" not in normalized:
        candidate = Path(normalized)
        if not candidate.is_absolute():
            candidate = caller.parent / candidate
        if candidate.is_file():
            return candidate.resolve()
    name = Path(normalized).name.lower()
    matches = index.get(name, [])
    return matches[0] if len(matches) == 1 else None


def analyze(entries: list[Path], search_roots: list[Path], recursive: bool) -> Report:
    roots = [p.resolve() for p in search_roots]
    report = Report(version=VERSION, roots=[p.name for p in roots])
    index = _build_index(roots)
    queue = [p.resolve() for p in entries]
    seen: set[Path] = set()

    while queue:
        path = queue.pop(0)
        if path in seen:
            continue
        seen.add(path)
        display = _display_path(path, roots)
        try:
            data = path.read_bytes()
            text, encoding = _decode(data)
        except (OSError, ValueError) as exc:
            report.warnings.append(f"{display}: {exc}")
            continue

        lines = text.splitlines()
        report.files.append(FileSummary(
            file=display,
            sha256=hashlib.sha256(data).hexdigest(),
            lines=len(lines),
            encoding=encoding,
        ))

        for number, raw_line in enumerate(lines, 1):
            code_line = strip_comment(raw_line)
            if not code_line.strip():
                continue

            call = CALL_RE.search(code_line)
            if call:
                expression = _target_expression(call.group("target"))
                resolved = _resolve_call(expression, path, index)
                safe_expr = sanitize(expression)
                dep = Dependency(
                    caller=display,
                    line=number,
                    expression=safe_expr,
                    resolved=_display_path(resolved, roots) if resolved else None,
                )
                report.dependencies.append(dep)
                report.findings.append(Finding(display, number, "cmm_call", sanitize(code_line)))
                if resolved and recursive:
                    queue.append(resolved)
                elif not resolved:
                    report.unresolved_calls.append(f"{display}:{number} {safe_expr}")

            label = LABEL_RE.match(code_line)
            if label and "error" in label.group(1).lower():
                report.findings.append(Finding(display, number, "error_handler", label.group(1)))

            for category, pattern in CATEGORY_PATTERNS.items():
                if pattern.search(code_line):
                    report.findings.append(
                        Finding(display, number, category, sanitize(code_line))
                    )

    report.files.sort(key=lambda item: item.file.lower())
    report.findings.sort(key=lambda item: (item.file.lower(), item.line, item.category))
    report.unresolved_calls = sorted(set(report.unresolved_calls))
    return report


def render_markdown(report: Report) -> str:
    out = [
        "# clavis CMM structural report",
        "",
        f"- Analyzer: `{report.version}`",
        f"- Files analyzed: {len(report.files)}",
        "- Safety: CMM was read only; strings and key-sized hex literals were redacted.",
        "",
        "## Signal counts",
        "",
        "| Category | Count |",
        "|---|---:|",
    ]
    for category, count in report.category_counts().items():
        out.append(f"| `{category}` | {count} |")

    out += ["", "## Dependencies", ""]
    if report.dependencies:
        for dep in report.dependencies:
            target = dep.resolved or "UNRESOLVED"
            out.append(f"- `{dep.caller}:{dep.line}` → `{target}` (`{dep.expression}`)")
    else:
        out.append("- None detected")

    out += ["", "## Findings", ""]
    if report.findings:
        for item in report.findings:
            out.append(
                f"- `{item.file}:{item.line}` **{item.category}** — `{item.snippet}`"
            )
    else:
        out.append("- None detected")

    if report.warnings:
        out += ["", "## Warnings", ""]
        out.extend(f"- {warning}" for warning in report.warnings)

    out += [
        "",
        "## Interpretation boundary",
        "",
        "This report identifies where to inspect. It does not prove that authentication",
        "causes the current J-Link failure and it does not contain an unlock implementation.",
        "",
    ]
    return "\n".join(out)


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Secret-safe, read-only structural analysis of TRACE32 clavis CMM flows"
    )
    parser.add_argument("entry", nargs="+", type=Path, help="clavis.cmm and optionally its caller")
    parser.add_argument(
        "--search-root", action="append", type=Path, default=[],
        help="root used to resolve recursively called CMM files (repeatable)",
    )
    parser.add_argument("--no-recursive", action="store_true", help="do not analyze resolved DO targets")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--json", dest="json_path", type=Path, help="write sanitized JSON report")
    group.add_argument("--markdown", dest="md_path", type=Path, help="write sanitized Markdown report")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    missing = [str(path) for path in args.entry if not path.is_file()]
    if missing:
        print("missing input: " + ", ".join(missing), file=sys.stderr)
        return 2
    output = args.json_path or args.md_path
    if output and output.resolve() in {path.resolve() for path in args.entry}:
        print("refusing to overwrite an input CMM file", file=sys.stderr)
        return 2
    roots = args.search_root or sorted({path.resolve().parent for path in args.entry})
    report = analyze(args.entry, roots, not args.no_recursive)

    try:
        if args.json_path:
            payload = asdict(report)
            payload["category_counts"] = report.category_counts()
            args.json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
                                      encoding="utf-8")
            print(f"wrote sanitized report: {args.json_path}")
        else:
            rendered = render_markdown(report)
            if args.md_path:
                args.md_path.write_text(rendered, encoding="utf-8")
                print(f"wrote sanitized report: {args.md_path}")
            else:
                print(rendered, end="")
    except OSError as exc:
        print(f"cannot write report: {exc}", file=sys.stderr)
        return 2
    return 0 if report.files else 3


if __name__ == "__main__":
    raise SystemExit(main())
