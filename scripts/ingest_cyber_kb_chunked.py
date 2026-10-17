# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""One-off: chunk and embed every ``knowledge-base/**/*.md`` into Qdrant.

Discovery goes through ``rag.ingest.discover_documents`` (no symlink
following, ``MAX_FILE_BYTES`` bound, confined to the corpus root) rather than
a weaker local ``rglob``; the root is anchored at the repository, not the
working directory. ``source`` is the repo-relative path
(``knowledge-base/<category>/<file>.md``) -- the string ``str(path)`` produced
from the repo root before, so ``uuid5`` point ids are unchanged -- and never
an absolute path, which would carry the operator's directory into the store.
"""

from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from qdrant_client.models import Distance, PointStruct, VectorParams
from sentence_transformers import SentenceTransformer

from rag.ingest import discover_documents
from rag.qdrant import make_client

COLLECTION = "cybersecurity_kb_chunks"
REPO_ROOT = Path(__file__).resolve().parents[1]
KB_DIR = REPO_ROOT / "knowledge-base"
CHUNK_SIZE = 900
OVERLAP = 150

model = SentenceTransformer("all-MiniLM-L6-v2")
client = make_client()


def chunk_text(text: str):
    start = 0
    index = 0

    while start < len(text):
        chunk = text[start : start + CHUNK_SIZE].strip()
        if chunk:
            yield index, chunk
        index += 1
        start += CHUNK_SIZE - OVERLAP


existing = [c.name for c in client.get_collections().collections]

if COLLECTION not in existing:
    client.create_collection(
        collection_name=COLLECTION,
        vectors_config=VectorParams(size=384, distance=Distance.COSINE),
    )

points = []

for path in discover_documents(KB_DIR):
    if path.suffix != ".md":
        continue
    source = path.relative_to(REPO_ROOT).as_posix()
    text = path.read_text(encoding="utf-8")

    for chunk_index, chunk in chunk_text(text):
        point_id = str(uuid5(NAMESPACE_URL, f"{source}:{chunk_index}"))
        vector = model.encode(chunk).tolist()

        points.append(
            PointStruct(
                id=point_id,
                vector=vector,
                payload={
                    "source": source,
                    "category": path.parent.name,
                    "chunk_index": chunk_index,
                    "text": chunk,
                },
            )
        )

if points:
    client.upsert(collection_name=COLLECTION, points=points)

print(f"Ingested {len(points)} chunks from {KB_DIR} into {COLLECTION}")
