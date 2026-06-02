from pathlib import Path
from uuid import uuid5, NAMESPACE_URL

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams
from sentence_transformers import SentenceTransformer

COLLECTION = "cybersecurity_kb_chunks"
KB_DIR = Path("knowledge-base/cybersecurity")
CHUNK_SIZE = 900
OVERLAP = 150

model = SentenceTransformer("all-MiniLM-L6-v2")
client = QdrantClient(url="http://localhost:6333", check_compatibility=False)


def chunk_text(text: str, chunk_size: int = CHUNK_SIZE, overlap: int = OVERLAP):
    start = 0
    chunk_index = 0

    while start < len(text):
        end = start + chunk_size
        chunk = text[start:end].strip()

        if chunk:
            yield chunk_index, chunk

        chunk_index += 1
        start = end - overlap


existing = [c.name for c in client.get_collections().collections]

if COLLECTION not in existing:
    client.create_collection(
        collection_name=COLLECTION,
        vectors_config=VectorParams(size=384, distance=Distance.COSINE),
    )

points = []

for path in KB_DIR.glob("*.md"):
    text = path.read_text(encoding="utf-8")

    for chunk_index, chunk in chunk_text(text):
        vector = model.encode(chunk).tolist()
        point_id = str(uuid5(NAMESPACE_URL, f"{path}:{chunk_index}"))

        points.append(
            PointStruct(
                id=point_id,
                vector=vector,
                payload={
                    "source": str(path),
                    "chunk_index": chunk_index,
                    "text": chunk,
                },
            )
        )

if points:
    client.upsert(collection_name=COLLECTION, points=points)

print(f"Ingested {len(points)} chunks into {COLLECTION}")
