from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient

model = SentenceTransformer("all-MiniLM-L6-v2")
client = QdrantClient(url="http://localhost:6333")

embedding = model.encode(
    "A SOC analyst investigates authentication failures."
)

print("Embedding dimensions:", len(embedding))
print(client.get_collections())
