from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams
from sentence_transformers import SentenceTransformer

COLLECTION = "cybersecurity_kb_chunks"
KB_DIR = Path("knowledge-base")
CHUNK_SIZE = 900
OVERLAP = 150

model = SentenceTransformer("all-MiniLM-L6-v2")
client = QdrantClient(url="http://localhost:6333", check_compatibility=False)


def chunk_text(text: str):
    start = 0
    index = 0

    while start < len(text):
        chunk = text[start:start + CHUNK_SIZE].strip()
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

for path in KB_DIR.rglob("*.md"):
    text = path.read_text(encoding="utf-8")

    for chunk_index, chunk in chunk_text(text):
        point_id = str(uuid5(NAMESPACE_URL, f"{path}:{chunk_index}"))
        vector = model.encode(chunk).tolist()

        points.append(
            PointStruct(
                id=point_id,
                vector=vector,
                payload={
                    "source": str(path),
                    "category": path.parent.name,
                    "chunk_index": chunk_index,
                    "text": chunk,
                },
            )
        )

if points:
    client.upsert(collection_name=COLLECTION, points=points)

print(f"Ingested {len(points)} chunks from {KB_DIR} into {COLLECTION}")
