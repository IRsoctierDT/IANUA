# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""One-off: embed each ``knowledge-base/cybersecurity/*.md`` as a single point.

Discovery goes through ``rag.ingest.discover_documents`` (no symlink
following, ``MAX_FILE_BYTES`` bound, confined to the corpus root) rather than
a weaker local ``glob``; the root is anchored at the repository, not the
working directory; ``source`` is stored repo-relative, never absolute.
"""

from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from qdrant_client.models import PointStruct
from sentence_transformers import SentenceTransformer

from rag.ingest import discover_documents
from rag.qdrant import make_client

COLLECTION = "cybersecurity_kb"
REPO_ROOT = Path(__file__).resolve().parents[1]
KB_DIR = REPO_ROOT / "knowledge-base" / "cybersecurity"

model = SentenceTransformer("all-MiniLM-L6-v2")
client = make_client()

# Direct children only, as the original non-recursive ``glob("*.md")`` was.
docs = [p for p in discover_documents(KB_DIR) if p.suffix == ".md" and p.parent == KB_DIR]

points = []

for path in docs:
    source = path.relative_to(REPO_ROOT).as_posix()
    text = path.read_text(encoding="utf-8")
    vector = model.encode(text).tolist()

    points.append(
        PointStruct(
            # Identity, not position: an enumeration index renumbered every
            # existing point whenever a document was added (measured), so a
            # re-run's upsert overwrote unrelated points. Same scheme as the
            # chunked one-off, so a re-run upserts each document in place.
            id=str(uuid5(NAMESPACE_URL, source)),
            vector=vector,
            payload={
                "source": source,
                "text": text,
            },
        )
    )

client.upsert(collection_name=COLLECTION, points=points)

print(f"Ingested {len(points)} documents into {COLLECTION}")
