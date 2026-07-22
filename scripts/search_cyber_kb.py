from rag.qdrant import make_client
from sentence_transformers import SentenceTransformer

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
    print(point.payload.get("text")[:1000])
