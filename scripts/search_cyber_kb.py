# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

from sentence_transformers import SentenceTransformer

from rag.qdrant import make_client

COLLECTION = "cybersecurity_kb"

model = SentenceTransformer("all-MiniLM-L6-v2")
client = make_client()

query = input("Search cybersecurity knowledge base: ")
vector = model.encode(query).tolist()

results = client.query_points(
    collection_name=COLLECTION,
    query=vector,
    limit=3,
)

for point in results.points:
    # A payload is whatever wrote the collection: a non-dict payload, or a ``text``
    # that is absent, null or not a str, prints as empty instead of a TypeError
    # that would end the search and lose every later result.
    payload = point.payload if isinstance(point.payload, dict) else {}
    text = payload.get("text")
    print("\n--- RESULT ---")
    print("Score:", point.score)
    print("Source:", payload.get("source"))
    print((text if isinstance(text, str) else "")[:1000])
