import argparse

from qdrant_client import QdrantClient
from qdrant_client.models import FieldCondition, Filter, MatchValue
from sentence_transformers import SentenceTransformer

COLLECTION = "cybersecurity_kb_chunks"

model = SentenceTransformer("all-MiniLM-L6-v2")
client = QdrantClient(url="http://localhost:6333", check_compatibility=False)


def main():
    parser = argparse.ArgumentParser(description="Search cybersecurity knowledge base chunks.")
    parser.add_argument("--query", help="Search query")
    parser.add_argument(
        "--category",
        choices=["mitre", "nist", "owasp", "cis", "security-plus", "cybersecurity"],
        help="Optional knowledge-base category filter",
    )

    args = parser.parse_args()

    query = args.query or input("Search cybersecurity KB chunks: ")
    vector = model.encode(query).tolist()

    query_filter = None

    if args.category:
        query_filter = Filter(
            must=[
                FieldCondition(
                    key="category",
                    match=MatchValue(value=args.category),
                )
            ]
        )

    results = client.query_points(
        collection_name=COLLECTION,
        query=vector,
        query_filter=query_filter,
        limit=5,
    )

    for i, point in enumerate(results.points, start=1):
        print(f"\n--- RESULT {i} ---")
        print("Score:", point.score)
        print("Source:", point.payload.get("source"))
        print("Category:", point.payload.get("category"))
        print("Chunk:", point.payload.get("chunk_index"))
        print(point.payload.get("text"))


if __name__ == "__main__":
    main()
