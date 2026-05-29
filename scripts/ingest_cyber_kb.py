from pathlib import Path
from qdrant_client import QdrantClient
from qdrant_client.models import PointStruct
from sentence_transformers import SentenceTransformer

COLLECTION = "cybersecurity_kb"
KB_DIR = Path("knowledge-base/cybersecurity")

model = SentenceTransformer("all-MiniLM-L6-v2")
client = QdrantClient(url="http://localhost:6333")

docs = list(KB_DIR.glob("*.md"))

points = []

for idx, path in enumerate(docs, start=1):
    text = path.read_text(encoding="utf-8")
    vector = model.encode(text).tolist()

    points.append(
        PointStruct(
            id=idx,
            vector=vector,
            payload={
                "source": str(path),
                "text": text,
            },
        )
    )

client.upsert(collection_name=COLLECTION, points=points)

print(f"Ingested {len(points)} documents into {COLLECTION}")
