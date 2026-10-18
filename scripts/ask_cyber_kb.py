# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

from sentence_transformers import SentenceTransformer

from rag.qdrant import make_client

COLLECTION = "cybersecurity_kb"

model = SentenceTransformer("all-MiniLM-L6-v2")
client = make_client()

query = input("Ask cybersecurity knowledge base: ")
vector = model.encode(query).tolist()

results = client.query_points(
    collection_name=COLLECTION,
    query=vector,
    limit=3,
)

print("\n# Cybersecurity Knowledge Base Answer\n")

for point in results.points:
    # Same rule as search_cyber_kb.py: a non-dict payload, or a ``text`` that is
    # absent, null or not a str, prints as empty instead of a TypeError.
    payload = point.payload if isinstance(point.payload, dict) else {}
    text = payload.get("text")
    text = text if isinstance(text, str) else ""
    source = payload.get("source", "unknown")

    print("## Retrieved Source")
    print(f"Source: {source}")
    print(f"Score: {point.score}")
    print()
    print(text[:1200])
    print("\n---")
