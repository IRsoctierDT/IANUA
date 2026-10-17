# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""One-off smoke check: embedding dimension and the reachable Qdrant collections.

The client comes from ``rag.qdrant.make_client`` -- embedded by default, a
server only when ``QDRANT_URL`` opts in -- not a hard-coded ``url=`` literal,
which AGENTS.md section 4 forbids and which made this the one script in the
block that forced server mode regardless of the documented environment keys.
"""

from sentence_transformers import SentenceTransformer

from rag.qdrant import make_client

model = SentenceTransformer("all-MiniLM-L6-v2")
client = make_client()

embedding = model.encode("A SOC analyst investigates authentication failures.")

print("Embedding dimensions:", len(embedding))
print(client.get_collections())
