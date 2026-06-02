## 2026-06-02

Implemented MITRE Mapper Agent.

Lessons Learned:
- MITRE mappings should be deterministic first.
- LLM reasoning can be added later.
- Unit tests created for T1110 and T1078 mappings.

Future Work:
- Add ATT&CK data ingestion.
- Add confidence scoring.

# Engineering Log

## 2026-06-02

### Local AI Stack

Completed local AI stack with:

- Ollama
- Qwen3:4B
- Qdrant
- Sentence Transformers

Lessons Learned:

- Virtual environments must be explicitly activated.
- VS Code interpreter selection matters.
- Qdrant collections should be versioned.

---

### MITRE Mapper Agent

Implemented ATT&CK mapping.

Lessons Learned:

- Deterministic mappings should precede LLM inference.
- Confidence scoring is necessary.

---

### Threat Intelligence Agent

Implemented indicator classification.

Future Work:

- AbuseIPDB integration
- VirusTotal integration
- AlienVault OTX integration