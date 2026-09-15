#!/usr/bin/env python3
"""사내 PDF→JSONL 산출물을 로컬 RAG 인덱스로 만든다 (계획 P2).

    python3 tools/rag_ingest.py <JSONL...> [--index-dir rag/index]
                                [--embed-base-url http://HOST:8001/v1]
                                [--embed-model bge-m3] [--max-chars 6000]

입력 JSONL 한 줄 = {"doc_id", "title", "content", "permission_groups"}.
내부 스펙도 같은 형식이므로 **추가는 명령 한 줄**이다.

인덱스 배치
-----------
    <index_dir>/current              현재 버전 이름만 담은 포인터 파일
    <index_dir>/<version>/manifest.json    소스 sha256·모델·차원·정규화·분할 설정
    <index_dir>/<version>/chunks.jsonl     doc_id/title/content/permission_groups
    <index_dir>/<version>/vectors.f16.npy  임베딩(float16, L2 정규화됨)

왜 포인터 파일인가
------------------
기존 디렉터리를 지우고 새것으로 바꾸면 **중간에 경로가 사라지는 순간**이 생기고,
실행 중 캠페인의 버전 고정과 충돌한다. 새 버전을 완성·검증한 뒤 포인터만 원자적으로
교체하고, 사용 중인 버전은 지우지 않는다.

왜 단순 append 가 아닌가
------------------------
chunks/vectors/manifest 중 일부만 갱신된 채 중단되면 행 번호가 어긋난다. `.npy` 는
헤더에 배열 크기가 있어 파일 끝에 바이트를 붙이는 것으로 확장되지도 않는다. 그래서
**증분은 임베딩 재사용으로만** 하고(직전 버전에서 sha256 이 같은 소스의 벡터를 그대로
가져온다), 파일은 언제나 새 버전으로 통째로 쓴다.

길이 제한
---------
임베딩 상한은 질의뿐 아니라 **문서 청크에도** 걸린다. 레코드를 문자 수 기준으로 자르고,
서버가 길이 초과를 반환하면 더 잘라 제한된 횟수만 재시도한다. 처리하지 못한 청크가
있으면 **인덱스를 게시하지 않는다** — 조용히 누락된 인덱스가 가장 나쁘다.
(문자 수는 토큰 수 보장이 아니다. 토크나이저 의존성을 들이지 않기 위한 선택이다.)
"""
import argparse
import hashlib
import json
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def split_record(row, max_chars):
    """한 레코드를 길이 제한 청크로. 문단 경계를 우선하되 없으면 강제로 자른다."""
    content = (row.get("content") or "").strip()
    if not content:
        return []
    if len(content) <= max_chars:
        return [content]
    out, buf = [], ""
    for para in content.split("\n\n"):
        if len(buf) + len(para) + 2 <= max_chars:
            buf = f"{buf}\n\n{para}" if buf else para
            continue
        if buf:
            out.append(buf)
            buf = ""
        while len(para) > max_chars:                 # 문단 하나가 상한을 넘는 경우
            out.append(para[:max_chars])
            para = para[max_chars:]
        buf = para
    if buf:
        out.append(buf)
    return out


def load_jsonl(paths, max_chars):
    """JSONL → 청크 목록. 스키마 위반은 건너뛰되 개수를 보고한다."""
    chunks, skipped = [], 0
    for path in paths:
        source = Path(path).name
        for lineno, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError:
                skipped += 1
                continue
            if not isinstance(row, dict) or not (row.get("content") or "").strip():
                skipped += 1
                continue
            pieces = split_record(row, max_chars)
            for part, text in enumerate(pieces):
                chunks.append({
                    "doc_id": f"{row.get('doc_id') or f'{source}:{lineno}'}"
                              + (f"#{part}" if len(pieces) > 1 else ""),
                    "title": row.get("title") or "",
                    "content": text,
                    "permission_groups": row.get("permission_groups") or [],
                    "source_file": source,
                })
    return chunks, skipped


def embed_all(texts, base_url, model, batch, timeout):
    """임베딩. 길이 초과는 더 잘라 재시도하고, 끝내 실패하면 예외로 올린다."""
    from rag.vllm_client import _post, BackendError
    cfg = {"api_key": "not-used", "timeout_sec": timeout, "max_response_bytes": 256 << 20}
    url = base_url.rstrip("/") + "/embeddings"
    out = []
    i = 0
    while i < len(texts):
        group = texts[i:i + batch]
        try:
            data = _post(url, {"model": model, "input": group}, cfg)
        except BackendError as exc:
            over = any(t in str(exc).lower() for t in
                       ("token", "too long", "maximum context", "length"))
            if over and batch > 1:
                batch = max(1, batch // 2)
                print(f"  길이 초과 — 배치를 {batch} 로 줄여 재시도", flush=True)
                continue
            if over and len(group[0]) > 400:
                texts[i] = group[0][: len(group[0]) // 2]
                print(f"  청크 하나가 상한 초과 — {len(texts[i])}자로 줄여 재시도", flush=True)
                continue
            raise
        rows = sorted(data.get("data") or [], key=lambda r: r.get("index", 0))
        if len(rows) != len(group):
            raise BackendError(f"임베딩 개수 불일치: 요청 {len(group)} / 응답 {len(rows)}")
        out.extend(r["embedding"] for r in rows)
        i += len(group)
        print(f"  {i}/{len(texts)}", end="\r", flush=True)
    print()
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="JSONL → 로컬 RAG 인덱스 (P2)")
    ap.add_argument("inputs", nargs="+", help="사내 PDF→JSONL 산출물")
    ap.add_argument("--index-dir", default=str(ROOT / "rag" / "index"))
    ap.add_argument("--embed-base-url", default="http://127.0.0.1:8001/v1")
    ap.add_argument("--embed-model", default="bge-m3")
    ap.add_argument("--max-chars", type=int, default=6000,
                    help="청크 문자 상한(토큰 수 보장 아님)")
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--timeout", type=float, default=600.0)
    args = ap.parse_args(argv)

    import numpy as np
    index_dir = Path(args.index_dir)
    index_dir.mkdir(parents=True, exist_ok=True)

    sources = {Path(p).name: sha256_file(p) for p in args.inputs}
    chunks, skipped = load_jsonl(args.inputs, args.max_chars)
    if not chunks:
        sys.exit("[ingest] 청크가 0개입니다 — 입력을 확인하세요")
    print(f"[ingest] 소스 {len(sources)}개 → 청크 {len(chunks):,}개"
          + (f" (건너뜀 {skipped})" if skipped else ""))

    # ── 증분: 직전 버전에서 sha256 이 같은 소스의 벡터를 재사용 ──
    reuse = {}
    pointer = index_dir / "current"
    if pointer.is_file():
        try:
            prev = index_dir / pointer.read_text(encoding="utf-8").strip()
            old_manifest = json.loads((prev / "manifest.json").read_text(encoding="utf-8"))
            same = {n for n, h in old_manifest.get("sources", {}).items() if sources.get(n) == h}
            if same and old_manifest.get("embed_model") == args.embed_model:
                old_vecs = np.load(prev / "vectors.f16.npy")
                for n, row in enumerate(
                        json.loads(l) for l in (prev / "chunks.jsonl").read_text(
                            encoding="utf-8").splitlines() if l.strip()):
                    if row.get("source_file") in same:
                        reuse[(row.get("source_file"), row.get("doc_id"))] = old_vecs[n]
                print(f"[ingest] 직전 버전에서 벡터 {len(reuse):,}개 재사용 "
                      f"(변경 없는 소스 {len(same)}개)")
        except Exception as exc:
            print(f"[ingest] 직전 버전 재사용 불가(전량 재임베딩): {exc}")

    todo = [c for c in chunks if (c["source_file"], c["doc_id"]) not in reuse]
    print(f"[ingest] 새로 임베딩할 청크 {len(todo):,}개")
    fresh = {}
    if todo:
        vecs = embed_all([c["content"] for c in todo], args.embed_base_url,
                         args.embed_model, args.batch, args.timeout)
        fresh = {(c["source_file"], c["doc_id"]): v for c, v in zip(todo, vecs)}

    matrix = np.asarray([reuse.get((c["source_file"], c["doc_id"]))
                         if (c["source_file"], c["doc_id"]) in reuse
                         else fresh[(c["source_file"], c["doc_id"])]
                         for c in chunks], dtype=np.float32)
    if matrix.shape[0] != len(chunks):
        sys.exit(f"[ingest] 벡터 수 불일치 — 게시하지 않습니다 "
                 f"({matrix.shape[0]} != {len(chunks)})")
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    matrix = (matrix / norms).astype(np.float16)     # 검색은 정규화 후 내적

    version = "v" + datetime.now().strftime("%Y%m%d_%H%M%S")
    if (index_dir / version).exists():      # 같은 초에 두 번 돌면 이름이 겹친다
        suffix = 1
        while (index_dir / f"{version}_{suffix}").exists():
            suffix += 1
        version = f"{version}_{suffix}"
    staging = index_dir / (version + ".staging")
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    (staging / "chunks.jsonl").write_text(
        "".join(json.dumps(c, ensure_ascii=False) + "\n" for c in chunks), encoding="utf-8")
    np.save(staging / "vectors.f16.npy", matrix)
    (staging / "manifest.json").write_text(json.dumps({
        "version": version, "created": datetime.now().isoformat(timespec="seconds"),
        "sources": sources, "chunks": len(chunks), "dim": int(matrix.shape[1]),
        "embed_model": args.embed_model, "embed_base_url": args.embed_base_url,
        "normalization": "l2", "dtype": "float16",
        "chunk_max_chars": args.max_chars, "skipped_records": skipped,
        "note": "chunk_max_chars 는 문자 수다. 토큰 수 보장이 아니다.",
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    # ── 검증 후에만 게시 ──
    check = np.load(staging / "vectors.f16.npy")
    lines = sum(1 for l in (staging / "chunks.jsonl").read_text(
        encoding="utf-8").splitlines() if l.strip())
    if check.shape[0] != lines:
        shutil.rmtree(staging)
        sys.exit("[ingest] 검증 실패 — 게시하지 않았습니다")
    final = index_dir / version
    staging.rename(final)
    tmp = index_dir / "current.tmp"
    tmp.write_text(version, encoding="utf-8")
    tmp.replace(pointer)                      # 포인터만 원자적으로 교체
    print(f"[ingest] 게시 완료: {final}  (청크 {len(chunks):,}, {matrix.shape[1]}차원)")
    print(f"[ingest] 이전 버전은 지우지 않습니다 — 실행 중 캠페인이 쓰고 있을 수 있습니다.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
