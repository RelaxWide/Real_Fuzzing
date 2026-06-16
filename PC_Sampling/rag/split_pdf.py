#!/usr/bin/env python3
"""대용량 PDF 를 N(기본 100)페이지 단위로 분할.

사내 PDF→JSONL 시스템이 100페이지까지만 받으므로, NVMe spec(700+p) 등을 100p 청크로 쪼갠다.
각 청크를 사내 시스템에 넣어 JSONL 을 받은 뒤 RAG ingest 에 사용한다.

usage:
    python3 split_pdf.py <input.pdf> [--pages 100] [--out DIR] [--overlap 0]

출력: <out>/<stem>_p0001-0100.pdf, <stem>_p0101-0200.pdf, ...
의존성: pip install pypdf
"""
import argparse
import sys
from pathlib import Path


def split_pdf(src: Path, pages: int, out_dir: Path, overlap: int = 0):
    from pypdf import PdfReader, PdfWriter

    reader = PdfReader(str(src))
    total = len(reader.pages)
    step = pages - overlap                     # overlap=0 이면 step=pages
    width = max(4, len(str(total)))            # 0-패딩 폭 (정렬용)
    out_dir.mkdir(parents=True, exist_ok=True)

    chunks, start = [], 0
    while start < total:
        end = min(start + pages, total)        # exclusive
        writer = PdfWriter()
        for i in range(start, end):
            writer.add_page(reader.pages[i])
        name = f"{src.stem}_p{start + 1:0{width}d}-{end:0{width}d}.pdf"
        with open(out_dir / name, "wb") as f:
            writer.write(f)
        chunks.append((name, end - start))
        start += step
    return total, chunks


def _collect_pdfs(inputs):
    """입력(파일/디렉토리 혼합) → PDF 파일 목록. 디렉토리는 내부 *.pdf 전부 확장. 중복 제거."""
    pdfs, seen = [], set()
    for raw in inputs:
        p = Path(raw)
        if p.is_dir():
            found = sorted(set(p.glob("*.pdf")) | set(p.glob("*.PDF")))
            if not found:
                print(f"[WARN] PDF 없음(디렉토리): {p}", file=sys.stderr)
            cands = found
        elif p.is_file():
            cands = [p]
        else:
            print(f"[WARN] 건너뜀(없음): {p}", file=sys.stderr)
            cands = []
        for c in cands:
            rp = c.resolve()
            if rp not in seen:
                seen.add(rp); pdfs.append(rp)
    return pdfs


def main():
    ap = argparse.ArgumentParser(description="PDF 를 N페이지 단위로 분할 (사내 PDF→JSONL 100p 제한 대응)")
    ap.add_argument("inputs", nargs="+",
                    help="입력 PDF 경로(여러 개 가능) 또는 PDF 들이 든 디렉토리")
    ap.add_argument("--pages", type=int, default=100, help="청크당 최대 페이지 (기본 100)")
    ap.add_argument("--out", default=None,
                    help="출력 디렉토리 (지정 시 모든 청크를 이 한 폴더에; "
                         "미지정 시 각 PDF 옆 <stem>_split/ 에)")
    ap.add_argument("--overlap", type=int, default=0,
                    help="청크 간 겹침 페이지 (기본 0; >0 이면 경계 섹션 보존하나 JSONL 중복 발생)")
    args = ap.parse_args()

    try:
        import pypdf  # noqa: F401
    except ImportError:
        print("[ERR] pypdf 필요: pip install pypdf", file=sys.stderr)
        sys.exit(1)

    if args.pages < 1:
        print("[ERR] --pages 는 1 이상이어야 함", file=sys.stderr); sys.exit(1)
    if not (0 <= args.overlap < args.pages):
        print("[ERR] --overlap 은 0 이상, --pages 미만이어야 함", file=sys.stderr); sys.exit(1)

    files = _collect_pdfs(args.inputs)
    if not files:
        print("[ERR] 처리할 PDF 없음", file=sys.stderr); sys.exit(1)

    grand = 0
    for src in files:
        # --out 지정 시 한 폴더에 모음(청크명이 stem 접두라 파일 간 충돌 없음), 아니면 파일별 옆 폴더.
        out_dir = Path(args.out).resolve() if args.out else src.with_name(src.stem + "_split")
        try:
            total, chunks = split_pdf(src, args.pages, out_dir, args.overlap)
        except Exception as e:
            print(f"[ERR] {src.name} 분할 실패: {e}", file=sys.stderr)
            continue
        print(f"[OK] {src.name} ({total} pages) → {len(chunks)} chunks @ {out_dir}")
        grand += len(chunks)
    print(f"[DONE] {len(files)} files → {grand} chunks total")


if __name__ == "__main__":
    main()
