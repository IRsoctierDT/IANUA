# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

from qdrant_client import QdrantClient

client = QdrantClient(url="http://localhost:6333")

print(client.get_collections())
