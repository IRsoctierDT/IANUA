from qdrant_client import QdrantClient
from sentence_transformers import SentenceTransformer

COLLECTION = "cybersecurity_kb_chunks"

model = SentenceTransformer("all-MiniLM-L6-v2")
client = QdrantClient(url="http://localhost:6333", check_compatibility=False)

query = input("Search cybersecurity KB chunks: ")
vector = model.encode(query).tolist()

results = client.query_points(
    collection_name=COLLECTION,
    query=vector,
    limit=5,
)

for i, point in enumerate(results.points, start=1):
    print(f"\n--- RESULT {i} ---")
    print("Score:", point.score)
    print("Source:", point.payload.get("source"))
    print("Chunk:", point.payload.get("chunk_index"))
    print(point.payload.get("text"))
