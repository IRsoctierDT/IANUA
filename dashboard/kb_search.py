from qdrant_client import QdrantClient
from qdrant_client.models import FieldCondition, Filter, MatchValue
from sentence_transformers import SentenceTransformer

COLLECTION = "cybersecurity_kb_chunks"

model = SentenceTransformer("all-MiniLM-L6-v2")
client = QdrantClient(url="http://localhost:6333", check_compatibility=False)


def search_kb(query: str, category: str | None = None, limit: int = 5):
    vector = model.encode(query).tolist()

    query_filter = None

    if category and category != "all":
        query_filter = Filter(
            must=[
                FieldCondition(
                    key="category",
                    match=MatchValue(value=category),
                )
            ]
        )

    results = client.query_points(
        collection_name=COLLECTION,
        query=vector,
        query_filter=query_filter,
        limit=limit,
    )

    return results.points
