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
    print("\n--- RESULT ---")
    print("Score:", point.score)
    print("Source:", point.payload.get("source"))
    # A point without a ``text`` payload is a result to show, not a TypeError.
    print(point.payload.get("text", "")[:1000])
