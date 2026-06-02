import requests
from qdrant_client import QdrantClient
from sentence_transformers import SentenceTransformer

MODEL = "qwen3:4b"
COLLECTION = "cybersecurity_kb_chunks"

embedder = SentenceTransformer("all-MiniLM-L6-v2")
client = QdrantClient(url="http://localhost:6333", check_compatibility=False)

question = input("Ask chunked cybersecurity KB: ")
vector = embedder.encode(question).tolist()

results = client.query_points(
    collection_name=COLLECTION,
    query=vector,
    limit=5,
)

context_blocks = []

for i, point in enumerate(results.points, start=1):
    source = point.payload.get("source", "unknown")
    chunk = point.payload.get("chunk_index", "unknown")
    text = point.payload.get("text", "")

    context_blocks.append(
        f"[Source {i}]\n"
        f"File: {source}\n"
        f"Chunk: {chunk}\n"
        f"Relevance Score: {point.score}\n"
        f"Text:\n{text}"
    )

context = "\n\n---\n\n".join(context_blocks)

prompt = f"""
You are a cybersecurity knowledge assistant.

Use only the supplied context. If the answer is not supported by the context, say so.

Answer format:
1. Direct answer
2. Supporting evidence with source numbers
3. Assumptions
4. Unknowns
5. Recommended next step

Question:
{question}

Context:
{context}
"""

response = requests.post(
    "http://localhost:11434/api/generate",
    json={
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
    },
    timeout=180,
)

response.raise_for_status()

print("\n===== CITATION-AWARE ANSWER =====\n")
print(response.json()["response"])
