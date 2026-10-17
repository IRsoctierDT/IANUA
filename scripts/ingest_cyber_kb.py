# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""One-off: embed each ``knowledge-base/cybersecurity/*.md`` as a single point.

Discovery goes through ``rag.ingest.discover_documents`` (no symlink
following, ``MAX_FILE_BYTES`` bound, confined to the corpus root) rather than
a weaker local ``glob``; the root is anchored at the repository, not the
working directory; ``source`` is stored repo-relative, never absolute. A
symlinked corpus root (``knowledge-base`` or ``cybersecurity``) is refused
before anything is built, and ``source`` is derived relative to ``KB_DIR``.
Reads go through ``rag.ingest.read_document``; its residuals apply here.

Ids are ``uuid5(source)``, so a re-run overwrites each *present* document's
point in place -- and never deletes, so it does not converge the collection:
a removed or renamed document's point, and every integer id the earlier
``enumerate`` scheme wrote, stay searchable beside the current text (measured).
``create_cyber_collection.py`` does not clear them; it only creates a missing
collection. Clearing is a delete, so it is an operator act behind AGENTS.md
section 5.1's destructive gate: ``make_client().delete_collection(COLLECTION)``,
then ``create_cyber_collection.py``, then this script.
"""

from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from qdrant_client.models import PointStruct
from sentence_transformers import SentenceTransformer

from rag.ingest import discover_documents, read_document
from rag.qdrant import make_client

COLLECTION = "cybersecurity_kb"
REPO_ROOT = Path(__file__).resolve().parents[1]
KB_DIR = REPO_ROOT / "knowledge-base" / "cybersecurity"

if KB_DIR.resolve() != KB_DIR:
    raise SystemExit(f"refusing {KB_DIR}: the corpus root is a symlink (-> {KB_DIR.resolve()})")

model = SentenceTransformer("all-MiniLM-L6-v2")
client = make_client()

# Direct children only, as the original non-recursive ``glob("*.md")`` was.
docs = [p for p in discover_documents(KB_DIR) if p.suffix == ".md" and p.parent == KB_DIR]

points = []

for path in docs:
    source = (KB_DIR.relative_to(REPO_ROOT) / path.relative_to(KB_DIR)).as_posix()
    text = read_document(path)  # one descriptor: no link, no FIFO, bounded
    vector = model.encode(text).tolist()

    points.append(
        PointStruct(
            # Identity, not position: an enumeration index renumbered every
            # existing point whenever a document was added (measured), so a
            # re-run's upsert overwrote unrelated points. Same scheme as the
            # chunked one-off; stale points stay (see the module docstring).
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
