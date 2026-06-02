import requests
from qdrant_client import QdrantClient
from sentence_transformers import SentenceTransformer

MODEL = "qwen3:4b"
COLLECTION = "cybersecurity_kb"

embedder = SentenceTransformer("all-MiniLM-L6-v2")
client = QdrantClient(url="http://localhost:6333")

question = input("Ask cybersecurity knowledge base: ")

vector = embedder.encode(question).tolist()

results = client.query_points(
    collection_name=COLLECTION,
    query=vector,
    limit=3,
)

context_blocks = []

for point in results.points:
    context_blocks.append(
        f"Source: {point.payload.get('source', 'unknown')}\n"
        f"Score: {point.score}\n"
        f"Text:\n{point.payload.get('text', '')}"
    )

context = "\n\n---\n\n".join(context_blocks)

prompt = f"""
You are a cybersecurity assistant.

Answer using only the supplied context.

Question:
{question}

Context:
{context}
"""

response = requests.post(
    "http://localhost:11434/api/generate",
    json={"model": MODEL, "prompt": prompt, "stream": False},
    timeout=120,
)

response.raise_for_status()

print("\n===== ANSWER =====\n")
print(response.json()["response"])
