#!/usr/bin/env python3
"""사내 PDF→JSONL 산출물을 로컬 RAG 인덱스로 만든다 (계획 P2).

    python3 tools/rag_ingest.py <JSONL|디렉터리|글롭...> [--dry-run]
                                [--index-dir rag/index]
                                [--embed-base-url http://HOST:8001/v1]
                                [--embed-model bge-m3] [--max-chars 6000]

입력은 파일·디렉터리·`*.jsonl` 같은 글롭을 모두 받는다. Windows 셸은 글롭을 펴 주지
않으므로(리터럴 `*` 를 열면 errno 22) 이 도구가 직접 편다.

임베딩 서버·모델·revision 은 기본적으로 `fuzzer_config.json` 의
`rag.vllm.retrieval` 에서 읽는다 — 퍼저가 **검색할 때** 쓰는 값과 인덱스를 **만들 때**
쓰는 값이 같아야 하기 때문이다. CLI 인자는 그것을 덮어쓰는 일회성 예외다.

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
**증분은 임베딩 재사용으로만** 하고, 파일은 언제나 새 버전으로 통째로 쓴다.
재사용 키는 (소스 파일, doc_id, **본문 sha256**) 이다 — 본문을 키에 넣어야
`--max-chars` 를 바꿔 같은 doc_id 에 다른 본문이 들어올 때 예전 벡터가 따라붙지
않는다. 임베딩 모델 이름과 revision 이 모두 같을 때만 재사용한다.

길이 제한
---------
임베딩 상한은 질의뿐 아니라 **문서 청크에도** 걸린다. 레코드를 문자 수 기준으로 자르고,
서버가 길이 초과를 반환하면 그 청크를 **둘로 쪼개 양쪽 다** 임베딩한다. 앞부분만 남기고
버리면 저장 본문과 벡터가 어긋나 뒷부분이 검색에 영영 안 걸린다. 더 쪼갤 수 없으면
예외로 올려 **인덱스를 게시하지 않는다** — 조용히 누락된 인덱스가 가장 나쁘다.
(문자 수는 토큰 수 보장이 아니다. 토크나이저 의존성을 들이지 않기 위한 선택이다.)
"""
import argparse
import contextlib
import glob as globlib
import hashlib
import json
import os
import shutil
import sys
from collections import Counter
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


def chunk_key(chunk):
    """벡터 재사용 키 — **본문 해시를 포함한다**.

    소스 파일 해시와 doc_id 만으로 키를 잡으면, 분할 설정(--max-chars)을 바꿨을 때
    같은 doc_id 에 **다른 본문**이 들어오는데도 예전 벡터를 그대로 붙인다. 소스
    파일은 안 바뀌었으니 재사용 조건도 통과한다. 본문이 키에 들어가면 그 자체로
    막힌다(같은 본문이면 재사용해도 항상 옳다).
    """
    return (chunk["source_file"], chunk["doc_id"],
            hashlib.sha256(chunk["content"].encode("utf-8")).hexdigest())


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


def _is_length_error(exc):
    return any(t in str(exc).lower() for t in
               ("token", "too long", "maximum context", "length"))


MIN_CHUNK_CHARS = 200


def split_chunk(chunk):
    """상한을 넘은 청크를 **둘로 쪼갠다**. 더 못 쪼개면 예외 — 게시를 막는다.

    앞부분만 남기고 잘라 버리면 안 된다. 저장하는 본문은 원문 그대로인데 벡터는
    앞부분만 표현하게 돼, **뒷부분의 스펙 내용이 검색에 영영 안 걸리는** 인덱스가
    정상인 얼굴로 게시된다. 조용히 누락된 인덱스가 가장 나쁘다.
    """
    text = chunk["content"]
    if len(text) < MIN_CHUNK_CHARS * 2:
        raise ValueError(
            f"청크를 더 쪼갤 수 없습니다 (doc_id={chunk['doc_id']}, {len(text)}자). "
            f"--max-chars 를 줄여 다시 실행하세요.")
    lo, hi = MIN_CHUNK_CHARS, len(text) - MIN_CHUNK_CHARS
    cut = text.rfind("\n\n", lo, hi)
    if cut < 0:
        cut = text.rfind(" ", lo, hi)
    if cut < 0:
        cut = len(text) // 2
    halves = [text[:cut].strip(), text[cut:].strip()]
    if not all(halves):
        raise ValueError(f"청크 분할 결과가 비었습니다 (doc_id={chunk['doc_id']})")
    return [dict(chunk, doc_id=f"{chunk['doc_id']}.{k}", content=part)
            for k, part in enumerate(halves)]


def embed_all(chunks, base_url, model, batch, timeout):
    """청크 목록을 임베딩한다. `chunks` 는 분할로 **늘어날 수 있다**(in-place).

    반환 벡터는 반환 시점의 `chunks` 와 1:1 로 대응한다 — 본문과 벡터가 어긋나면
    검색이 조용히 틀리므로, 둘은 언제나 같이 움직인다.
    """
    from rag.vllm_client import _post, BackendError
    cfg = {"api_key": "not-used", "timeout_sec": timeout, "max_response_bytes": 256 << 20}
    url = base_url.rstrip("/") + "/embeddings"
    out = []
    i = 0
    while i < len(chunks):
        group = chunks[i:i + batch]
        try:
            data = _post(url, {"model": model,
                               "input": [c["content"] for c in group]}, cfg)
        except BackendError as exc:
            if not _is_length_error(exc):
                raise
            if len(group) > 1:
                batch = max(1, len(group) // 2)
                print(f"  길이 초과 — 배치를 {batch} 로 줄여 재시도", flush=True)
                continue
            # 단일 청크가 상한 초과 → 쪼개서 **양쪽 다** 임베딩한다.
            halves = split_chunk(chunks[i])
            chunks[i:i + 1] = halves
            print(f"  청크 상한 초과 — {halves[0]['doc_id']}/{halves[1]['doc_id']} 로 분할 "
                  f"({len(halves[0]['content'])}+{len(halves[1]['content'])}자)", flush=True)
            continue
        rows = sorted(data.get("data") or [], key=lambda r: r.get("index", 0))
        if len(rows) != len(group):
            raise BackendError(f"임베딩 개수 불일치: 요청 {len(group)} / 응답 {len(rows)}")
        out.extend(r["embedding"] for r in rows)
        i += len(group)
        print(f"  {i}/{len(chunks)}", end="\r", flush=True)
    print()
    if len(out) != len(chunks):
        raise BackendError(f"벡터 수 불일치: 청크 {len(chunks)} / 벡터 {len(out)}")
    return out


# CLI·설정 어디에도 없을 때의 최후 기본값. 퍼징 PC 에서 바로 쓰기 위한 값이지
#   운영 값이 아니다 — 운영 값은 fuzzer_config.json 에 있다.
FALLBACK = {"embed_base_url": "http://127.0.0.1:8001/v1",
            "embed_model": "bge-m3",
            "embed_model_revision": None}


def config_defaults(path):
    """`rag.vllm.retrieval` 을 기본값으로 읽는다.

    IP·모델이 설정과 CLI 두 곳에 살면 언젠가 어긋난다. 설정이 단일 출처이고
    CLI 인자는 그것을 덮어쓰는 일회성 예외다(계획: "IP 가 바뀔 수 있어 설정값으로
    받는다"). 퍼저가 검색할 때 쓰는 값과 인덱스를 만들 때 쓰는 값이 같아야 한다 —
    다르면 벡터 공간이 달라져 조용히 엉뚱한 문서가 뽑힌다.
    """
    out = dict.fromkeys(FALLBACK)
    try:
        cfg = json.loads(Path(path).read_text(encoding="utf-8"))
        table = ((cfg.get("rag") or {}).get("vllm") or {}).get("retrieval") or {}
        for key in out:
            if table.get(key):
                out[key] = table[key]
    except Exception as exc:
        print(f"[ingest] 설정을 읽지 못했습니다(내장 기본값 사용): {path}: {exc}")
    return out


def resolve_inputs(inputs):
    """glob 패턴·디렉터리를 실제 파일 목록으로 편다.

    Windows 셸(cmd/PowerShell)은 `*.jsonl` 을 펴 주지 않아 리터럴 `*` 가 그대로
    넘어오고, 그걸 열면 EINVAL(errno 22) 이 난다. 사내 JSONL 이 그쪽에 있으니
    도구가 직접 편다 — 셸이 이미 펴 준 경우(Linux)에는 파일이 실재하므로 그대로 쓴다.

    디렉터리를 주면 그 아래 `*.jsonl` 을 재귀로 찾는다. 한 폴더를 통째로 넘기는 게
    분할된 PDF 를 다루는 가장 편한 방법이다.
    """
    found = []
    for item in inputs:
        path = Path(item)
        if path.is_dir():
            under = sorted(path.rglob("*.jsonl"))
            if not under:
                sys.exit(f"[ingest] 디렉터리에 .jsonl 이 없습니다: {item}")
            found.extend(under)
        elif path.exists():
            found.append(path)
        else:
            matched = sorted(Path(p) for p in globlib.glob(item, recursive=True))
            matched = [p for p in matched if p.is_file()]
            if not matched:
                sys.exit(f"[ingest] 입력을 찾지 못했습니다: {item}\n"
                         f"         (셸이 와일드카드를 펴 주지 않으면 이 도구가 펴지만, "
                         f"경로 자체가 틀리면 여기서 멈춘다)")
            found.extend(matched)
    seen, unique = set(), []
    for path in found:                      # 같은 파일이 여러 인자로 들어와도 한 번만
        try:
            key = str(path.resolve())
        except OSError:
            key = str(path)
        if key not in seen:
            seen.add(key)
            unique.append(str(path))
    return unique


def inspect_only(inputs, max_chars):
    """`--dry-run` — 게시를 막을 것들을 **임베딩 전에** 찾는다. 0=진행 가능, 1=거부됨.

    본 ingest 와 **같은** load_jsonl/split_record 를 쓴다. 점검을 따로 구현하면
    언젠가 갈라져서, 통과했는데 실제로는 거부되는 일이 생긴다.
    """
    rows, missing = [], Counter()
    for path in inputs:
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            print(f"  ! 읽기 실패: {path}: {exc}")
            continue
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError:
                missing["JSON 파싱 실패(레코드 버려짐)"] += 1
                continue
            if not isinstance(row, dict):
                missing["dict 아님(레코드 버려짐)"] += 1
                continue
            for key in ("doc_id", "title", "content", "permission_groups"):
                if not row.get(key):
                    missing[f"{key} 없음/빈값"] += 1
            rows.append((Path(path).name, row))

    print(f"[점검] 파일 {len(inputs)}개 · 레코드 {len(rows)}개")
    if not rows:
        print("[점검] ✗ 읽어들인 레코드가 없습니다")
        return 1
    lengths = sorted(len(r.get("content") or "") for _, r in rows)
    print(f"[점검] content 길이  최소 {lengths[0]:,}  중앙 {lengths[len(lengths) // 2]:,}  "
          f"최대 {lengths[-1]:,}")
    print(f"[점검] 레코드/파일   {len(rows) / max(1, len(inputs)):.1f}")
    for key, count in missing.items():
        print(f"  ! {key}: {count}건")

    chunks, skipped = load_jsonl(list(inputs), max_chars)
    print(f"\n[점검] --max-chars {max_chars} 기준 → 청크 {len(chunks):,}개"
          + (f" (건너뛴 레코드 {skipped})" if skipped else ""))
    if chunks:
        widest = max(len(c["content"]) for c in chunks)
        print(f"[점검] 가장 긴 청크 {widest:,}자 — 임베딩 상한을 넘으면 자동 분할된다")

    verdict = 0
    seen_ids = Counter(c["doc_id"] for c in chunks)
    dupes = [d for d, n in seen_ids.items() if n > 1]
    print(f"[점검] doc_id 원본 고유값 {len({r.get('doc_id') for _, r in rows})}개")
    if dupes:
        by_source = {}
        for chunk in chunks:
            by_source.setdefault(chunk["doc_id"], set()).add(chunk["source_file"])
        cross = [d for d in dupes if len(by_source[d]) > 1]
        print(f"  ✗ doc_id 중복 {len(dupes)}건 — 이대로는 **게시가 거부된다**")
        print(f"    예: {dupes[:3]}")
        if cross:
            print(f"    그중 {len(cross)}건은 서로 다른 파일에 같은 doc_id "
                  f"(한 PDF 를 쪽수로 쪼갠 경우 흔하다)")
        verdict = 1
    else:
        print("  ✓ doc_id 중복 없음")

    if not chunks:
        print("  ✗ 청크가 0개입니다")
        verdict = 1
    tiny = sum(1 for c in chunks if len(c["content"]) < MIN_CHUNK_CHARS)
    if tiny:
        print(f"  · {MIN_CHUNK_CHARS}자 미만 청크 {tiny}개 — 임베딩 상한에 걸리면 더 못 쪼갠다")
    print("\n[점검] " + ("그대로 색인 가능합니다." if verdict == 0
                         else "위 ✗ 를 먼저 해결해야 합니다. 인덱스는 만들지 않았습니다."))
    return verdict


def main(argv=None):
    ap = argparse.ArgumentParser(description="JSONL → 로컬 RAG 인덱스 (P2)")
    ap.add_argument("inputs", nargs="+", help="사내 PDF→JSONL 산출물")
    ap.add_argument("--index-dir", default=str(ROOT / "rag" / "index"))
    ap.add_argument("--config", default=str(ROOT / "fuzzer_config.json"),
                    help="embed_base_url·embed_model 기본값을 읽을 설정 파일")
    ap.add_argument("--embed-base-url", default=None,
                    help="기본값: 설정의 rag.vllm.retrieval.embed_base_url")
    ap.add_argument("--embed-model", default=None,
                    help="기본값: 설정의 rag.vllm.retrieval.embed_model")
    ap.add_argument("--embed-model-revision", default=None,
                    help="manifest 에 기록하고 재사용·검색 시 대조한다. 이름이 같은 채로 "
                         "모델이 교체되는 경우를 구분하는 유일한 수단이다. "
                         "기본값: 설정의 rag.vllm.retrieval.embed_model_revision")
    ap.add_argument("--max-chars", type=int, default=6000,
                    help="청크 문자 상한(토큰 수 보장 아님)")
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--timeout", type=float, default=600.0)
    ap.add_argument("--dry-run", action="store_true",
                    help="임베딩 서버 없이 JSONL 만 점검한다. 인덱스를 만들지 않고, "
                         "설정·numpy·네트워크가 없어도 돈다")
    args = ap.parse_args(argv)
    args.inputs = resolve_inputs(args.inputs)
    print(f"[ingest] 입력 {len(args.inputs)}개")

    if args.dry_run:
        # 설정 해석보다 **먼저** 갈라진다 — 점검은 엔드포인트도 numpy 도 필요 없다.
        return inspect_only(args.inputs, args.max_chars)

    # 우선순위: CLI > 설정 > 내장 기본값.
    defaults = config_defaults(args.config)
    for key, fallback in FALLBACK.items():
        if getattr(args, key) is None:
            chosen = defaults[key] if defaults[key] is not None else fallback
            setattr(args, key, chosen)
    # 어느 서버에 무엇으로 색인하는지 남긴다 — 나중에 검색이 이상할 때 첫 단서다.
    print(f"[ingest] 임베딩 서버: {args.embed_base_url}  model={args.embed_model}"
          + (f"  revision={args.embed_model_revision}"
             if args.embed_model_revision else "  revision=(미지정)"))

    import numpy as np
    index_dir = Path(args.index_dir)
    index_dir.mkdir(parents=True, exist_ok=True)
    with _ingest_lock(index_dir):
        return _build(args, index_dir, np)


@contextlib.contextmanager
def _ingest_lock(index_dir):
    """단일 writer 보장. 동시 실행은 staging 과 포인터 임시파일에서 서로를 밟는다."""
    lock = index_dir / ".ingest.lock"
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        sys.exit(f"[ingest] 다른 색인 작업이 진행 중입니다: {lock}\n"
                 f"         중단된 작업이 남긴 것이라면 이 파일을 지우고 다시 실행하세요.")
    try:
        os.write(fd, f"{os.getpid()} {datetime.now().isoformat(timespec='seconds')}\n"
                 .encode("utf-8"))
        os.close(fd)
        yield
    finally:
        try:
            lock.unlink()
        except OSError:
            pass


def _build(args, index_dir, np):
    sources = {Path(p).name: sha256_file(p) for p in args.inputs}
    chunks, skipped = load_jsonl(args.inputs, args.max_chars)
    if not chunks:
        sys.exit("[ingest] 청크가 0개입니다 — 입력을 확인하세요")
    print(f"[ingest] 소스 {len(sources)}개 → 청크 {len(chunks):,}개"
          + (f" (건너뜀 {skipped})" if skipped else ""))

    # ── 증분: 직전 버전에서 **본문이 같은** 청크의 벡터를 재사용 ──
    reuse = {}
    pointer = index_dir / "current"
    if pointer.is_file():
        try:
            prev = index_dir / pointer.read_text(encoding="utf-8").strip()
            old_manifest = json.loads((prev / "manifest.json").read_text(encoding="utf-8"))
            same = {n for n, h in old_manifest.get("sources", {}).items() if sources.get(n) == h}
            same_model = (old_manifest.get("embed_model") == args.embed_model
                          and old_manifest.get("embed_model_revision")
                          == args.embed_model_revision)
            if same and same_model:
                old_vecs = np.load(prev / "vectors.f16.npy")
                for n, row in enumerate(
                        json.loads(l) for l in (prev / "chunks.jsonl").read_text(
                            encoding="utf-8").splitlines() if l.strip()):
                    if row.get("source_file") in same and n < old_vecs.shape[0]:
                        reuse[chunk_key(row)] = old_vecs[n]
                print(f"[ingest] 직전 버전에서 벡터 {len(reuse):,}개 재사용 "
                      f"(변경 없는 소스 {len(same)}개)")
            elif same and not same_model:
                print("[ingest] 임베딩 모델/revision 이 달라 전량 재임베딩합니다")
        except Exception as exc:
            print(f"[ingest] 직전 버전 재사용 불가(전량 재임베딩): {exc}")

    kept = [c for c in chunks if chunk_key(c) in reuse]
    todo = [c for c in chunks if chunk_key(c) not in reuse]
    print(f"[ingest] 새로 임베딩할 청크 {len(todo):,}개")
    vecs = []
    if todo:
        # todo 는 분할로 늘어날 수 있다. 반환 벡터는 **반환 시점의 todo** 와 1:1.
        vecs = embed_all(todo, args.embed_base_url, args.embed_model,
                         args.batch, args.timeout)
    # 재사용분 → 새로 임베딩한 분 순서. 순서 자체에는 의미가 없고, chunks.jsonl 과
    #   vectors 가 같은 순서로 함께 쓰이는 것만이 중요하다.
    chunks = kept + todo
    matrix = np.asarray([reuse[chunk_key(c)] for c in kept] + list(vecs), dtype=np.float32)
    if matrix.shape[0] != len(chunks):
        sys.exit(f"[ingest] 벡터 수 불일치 — 게시하지 않습니다 "
                 f"({matrix.shape[0]} != {len(chunks)})")
    if matrix.ndim != 2 or matrix.shape[1] == 0:
        sys.exit(f"[ingest] 벡터 차원이 이상합니다 — 게시하지 않습니다 ({matrix.shape})")
    if not np.isfinite(matrix).all():
        sys.exit("[ingest] 벡터에 NaN/Inf 가 있습니다 — 게시하지 않습니다")
    dupes = [d for d, n in Counter(c["doc_id"] for c in chunks).items() if n > 1]
    if dupes:
        sys.exit(f"[ingest] doc_id 중복 {len(dupes)}건 — 게시하지 않습니다: {dupes[:5]}")
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    zero = int((norms == 0).sum())
    if zero:
        sys.exit(f"[ingest] 영벡터 {zero}개 — 게시하지 않습니다(임베딩 실패로 봅니다)")
    matrix = (matrix / norms).astype(np.float16)     # 검색은 정규화 후 내적

    version = "v" + datetime.now().strftime("%Y%m%d_%H%M%S")
    if (index_dir / version).exists():      # 같은 초에 두 번 돌면 이름이 겹친다
        suffix = 1
        while (index_dir / f"{version}_{suffix}").exists():
            suffix += 1
        version = f"{version}_{suffix}"
    # staging·포인터 임시파일에 pid 를 붙인다. 락이 단일 writer 를 보장하지만,
    #   락이 지워진 채 남은 잔해가 남의 것을 밟는 경우까지는 막아 둔다.
    staging = index_dir / f"{version}.{os.getpid()}.staging"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    (staging / "chunks.jsonl").write_text(
        "".join(json.dumps(c, ensure_ascii=False) + "\n" for c in chunks), encoding="utf-8")
    np.save(staging / "vectors.f16.npy", matrix)
    (staging / "manifest.json").write_text(json.dumps({
        "version": version, "created": datetime.now().isoformat(timespec="seconds"),
        "sources": sources, "chunks": len(chunks), "dim": int(matrix.shape[1]),
        "embed_model": args.embed_model,
        "embed_model_revision": args.embed_model_revision,
        "embed_base_url": args.embed_base_url,
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
    tmp = index_dir / f"current.{os.getpid()}.tmp"
    tmp.write_text(version, encoding="utf-8")
    tmp.replace(pointer)                      # 포인터만 원자적으로 교체
    print(f"[ingest] 게시 완료: {final}  (청크 {len(chunks):,}, {matrix.shape[1]}차원)")
    print(f"[ingest] 이전 버전은 지우지 않습니다 — 실행 중 캠페인이 쓰고 있을 수 있습니다.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
