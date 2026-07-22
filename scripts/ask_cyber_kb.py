from rag.qdrant import make_client
from sentence_transformers import SentenceTransformer

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
    text = point.payload.get("text", "")
    source = point.payload.get("source", "unknown")

    print("## Retrieved Source")
    print(f"Source: {source}")
    print(f"Score: {point.score}")
    print()
    print(text[:1200])
    print("\n---")
