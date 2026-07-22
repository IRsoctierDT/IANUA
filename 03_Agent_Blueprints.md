# Agent Blueprints

All eight blueprints are **built and operational** (v2.0.0). Every agent
derives its version from `pyproject.toml` automatically and announces itself
as `<Agent> v<platform version>`.

## SOC Analyst Agent — built

Analyzes logs and alerts (string or structured JSON). Produces severity +
score, event type, indicators, recommended actions, assumptions, and
evidence. Correlates ordered event batches into multi-event findings:
brute force and failure-then-success credential compromise.

## Threat Intelligence Agent — built

Classifies and enriches indicators from single events or sequence-wide
indicator unions; deterministic and network-free.

## Vulnerability Assessment Agent — built

Converts scan results into remediation priorities.

## Legal/Compliance Research Agent — built

Supports issue analysis, authority review, citation checklists, and draft
preparation. It does not replace legal counsel.

## Business Proposal Agent — built

Converts client needs into structured proposals and scopes of work.

## Knowledge Curator Agent — built

Organizes notes, transcripts, PDFs, and research into retrieval-ready
knowledge.

## Portfolio Documentation Agent — built

Turns lab work into GitHub-ready README files, reports, and case studies.

## Executive Assistant Agent — built

Supports planning, prioritization, review cycles, and decision logs.

## Supporting agents (beyond the original blueprints)

MITRE Mapper (ATT&CK technique mapping), Incident Report (Markdown/PDF with
sequence findings and verified citations), Knowledge Base (rarity-weighted
retrieval with provenance), Detection Matcher (Sigma content via ATT&CK
tags), and the Orchestrator (single-event and sequence pipelines).
