# Dependency Vulnerability Triage

> **Companion to** [`sbom.cdx.json`](./sbom.cdx.json). **Source:** `pip-audit`
> (PyPI/OSV advisory DB) against the pyenv 3.12.4 project environment.
> **Risk level:** Informational (triage record; no secrets/PII).
> **Snapshot date:** 2026-06-22. Counts drift as advisories publish — regenerate
> (`security/sbom/README.md` → Implementation Steps) before acting.

---

## Executive Summary

Auditing the maintainer's **shared pyenv 3.12.4** environment, `pip-audit`
reported **168 known vulnerabilities across 38 Python packages** (163 fixable, 5
without a fix — Tier 0).

**Verified finding — the project itself is clean.** A clean install of the
declared dependency closure (`pip install -e ".[dev,dashboard]"`, **118
packages**) re-audited to **0 known vulnerabilities**. Every one of the 168
advisories traces to **stale or ambient packages in the shared environment that
are NOT declared dependencies** of this project — chiefly an LLM/agent/RAG stack
(`litellm`, `langchain*`, `mem0ai`, `google-cloud-aiplatform`, `aiohttp`,
`langsmith`) left over from other work in the same interpreter.

| Scope | Packages | Known vulns |
|---|---|---|
| Shared pyenv 3.12.4 (as found) | 277 | **168** |
| **Declared closure, clean install** (`[dev,dashboard]`) | **118** | **0** |

> **Method:** the table is reproduced facts, not inference — both rows were
> produced by `pip-audit`. The canonical `sbom.cdx.json` is generated from the
> clean row. **Primary remediation is environmental, not a mass upgrade.**

## Objectives

1. Separate **project-owned** exposure from **ambient environment** noise.
2. Prioritise the project-owned set by security relevance, not raw count.
3. Record concrete upgrade targets and the un-fixable residue.

## Tier 0 — No fix available (track / mitigate, cannot upgrade)

| Package | Installed | Advisory | Note |
|---|---|---|---|
| `mem0ai` | 0.1.27 | CVE-2026-31240/31241/31245 | Memory API lacks authN/authZ. **Ambient** — not a declared dep. If unused, remove from env; if used, never expose its server. |
| `litellm` | 1.51.3 | CVE-2025-0330 | Langfuse API-key leakage on error. **Ambient.** Remove if unused. |
| `pyjwt` | 2.9.0 | PYSEC-2025-183 | Weak-encryption claim **disputed by maintainer** (key-length dependent). Low priority; verify usage. |

All three are in the ambient LLM stack — **the cleanest remediation is removing
them from the working environment**, which eliminates these outright.

## Tier 1 — Also in the declared closure, but outdated in the shared env

These packages appear in the declared `dashboard` / `sentence-transformers`
closure **and** process untrusted input (HTTP, TLS trust, file parsing,
templating). In a **clean install they are already on patched versions** (0
vulns); the rows below are the *outdated* versions found in the shared pyenv.
They matter only if you audit/run from that shared environment:

| Package | Installed | → Fixed | Why it matters | Vulns |
|---|---|---|---|---|
| `urllib3` | 2.2.2 | 2.5.0 | HTTP client; redirect/proxy handling | 6 |
| `requests` | 2.32.3 | 2.32.4 | HTTP client | 2 |
| `certifi` | 2024.6.2 | 2024.7.4 | **TLS trust store** — removes a compromised CA | 2 |
| `idna` | 3.7 | 3.15 | Hostname parsing (request routing) | 1 |
| `cryptography` | 43.0.3 | 44.0.1+ | Crypto primitives | 5 |
| `jinja2` | 3.1.4 | 3.1.6 | **Template injection (SSTI)** surface | 3 |
| `mako` | 1.3.6 | 1.3.12 | Template engine (SSTI) | 1 |
| `pillow` | 10.4.0 | 12.1.1+ | Image parsing of untrusted files | 6 |
| `pypdf` | 5.1.0 | 6.x | **PDF parsing** — directly relevant to RAG ingestion | 30 |
| `lxml` | 5.2.2 | 6.1.0 | XML/HTML parsing of untrusted docs | 2 |
| `gitpython` | 3.1.43 | 3.1.50 | Pulled by Streamlit | 4 |

`pypdf` and `pillow` are the standouts for a RAG pipeline that ingests
user-supplied documents — prioritise these regardless of the ambient/declared
question.

## Tier 2 — Toolchain / build (upgrade opportunistically)

`pip` (24.3.1→26.x), `setuptools` (75.3.0→78.1.1), `uv` (0.4.29→latest),
`pytest` (8.3.3→9.0.3), `pygments`, `pyarrow`, `protobuf`, `orjson`,
`marshmallow`, `msgpack`, `fonttools`, `h11`, `h2`, `pyasn1`, `python-dotenv`.
Lower exposure (build-time or low-reachability); fold into routine maintenance.

## Tier 3 — Ambient LLM/agent stack (resolve by env hygiene)

`aiohttp` (32 vulns), `starlette` (8), `langchain*` (10 across packages),
`langsmith` (3), `langchain-openai`/`langchain-community`,
`google-cloud-aiplatform`. **Not declared** in `pyproject.toml`. If this stack
is intended, it should be added to a declared, **pinned** extra and upgraded as
a unit; if it is leftover from other work, remove it from the environment.

## Remediation Plan (ordered)

1. **Use a clean project virtualenv (done — confirms 0 vulns).** Working in a
   fresh `pip install -e ".[dev,dashboard]"` venv — rather than the shared pyenv
   — already eliminates all 168 findings. This is the single highest-value step
   and resolves Tiers 0–3 for the project's purposes.
2. **Pin the closure** (compiled `requirements.txt` / lockfile) so the SBOM is
   reproducible bit-for-bit and CI can gate with `pip-audit --locked`.
3. **(Maintainer env hygiene, optional)** In the shared pyenv, upgrade Tier 1
   packages and remove the unused ambient LLM stack (`mem0ai`, `litellm`,
   `langchain*`) to clear the Tier 0 no-fix advisories at their source.
4. Keep the CI SBOM job (`.github/workflows/ci.yml`) green; once the closure is
   pinned, extend it to **fail on newly introduced advisories**.

## Risks & Cost

- **Risk of mass upgrade:** bumping ambient packages the project doesn't use
  spends effort and churn for no real risk reduction — hence the env-first plan.
- **Cost:** remediation is upgrade + test time; no new third-party dependency is
  required. Pinning adds a one-time lockfile-generation step.

## Future Enhancements

- CI `sbom` job (see `.github/workflows/`) regenerates the SBOM and **fails on
  newly introduced advisories** once the environment is pinned.
- Optional Dependabot/Renovate to automate Tier 1/2 upgrade PRs.
