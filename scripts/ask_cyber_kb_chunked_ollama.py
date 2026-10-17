# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""One-off: citation-aware answer from the chunked KB with a local Ollama model.

Generation goes through ``agents.tools.llm.OllamaGenerator``: the host comes
from ``OLLAMA_HOST`` (loopback by default), is checked against the egress
allow-list before any request, has a bounded timeout and fails closed -- no
hard-coded host literal and no third-party HTTP client. Retrieved passages are
untrusted content (DESIGN.md section 5, boundary 3); they reach the prompt and
the printed answer only, never a tool call.
"""

import sys
from urllib import request as _rq

from sentence_transformers import SentenceTransformer

from agents.tools.llm import OllamaGenerator
from agents.tools.validation import ValidationError
from rag.qdrant import make_client

MODEL = "qwen3:4b"
COLLECTION = "cybersecurity_kb_chunks"
TIMEOUT_SECONDS = 180.0

embedder = SentenceTransformer("all-MiniLM-L6-v2")
client = make_client()
_opener = _rq.OpenerDirector()  # direct HTTP(S): no ProxyHandler, no HTTPRedirectHandler
for _h in (_rq.HTTPHandler, _rq.HTTPSHandler, _rq.HTTPErrorProcessor, _rq.HTTPDefaultErrorHandler):
    _opener.add_handler(_h())
_rq.install_opener(_opener)  # the default dialled http(s)_proxy and followed a 3xx (measured)
try:
    generator = OllamaGenerator(model=MODEL, timeout=TIMEOUT_SECONDS)
except ValidationError as exc:  # host outside the allow-list, bad scheme
    sys.exit(f"error: {exc}")

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

try:
    answer = generator.generate(prompt)
except ValidationError as exc:  # unreachable model, empty response
    sys.exit(f"error: {exc}")

print("\n===== CITATION-AWARE ANSWER =====\n")
print(answer)
