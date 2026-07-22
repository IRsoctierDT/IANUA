from qdrant_client.models import Distance, VectorParams
from rag.qdrant import make_client

COLLECTION = "cybersecurity_kb"

client = make_client()

existing = [collection.name for collection in client.get_collections().collections]

if COLLECTION in existing:
    print(f"Collection already exists: {COLLECTION}")
else:
    client.create_collection(
        collection_name=COLLECTION, vectors_config=VectorParams(size=384, distance=Distance.COSINE)
    )
    print(f"Created collection: {COLLECTION}")

print(client.get_collections())
