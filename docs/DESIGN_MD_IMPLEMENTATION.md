# STICHES / DESIGN.md Implementation

## Purpose

This project uses `DESIGN.md` as the canonical design and documentation identity.

## What DESIGN.md Controls

- Visual identity
- Documentation tone
- Color and typography tokens
- UI and dashboard guidance
- Agent-facing design rationale
- Governance-aware documentation style

## Regenerate Markdown

```bash
python scripts/generate_docs_from_design.py
```

## Validate DESIGN.md

```bash
npx @google/design.md lint DESIGN.md
```

## Export Tokens

```bash
npx @google/design.md export --format json-tailwind DESIGN.md > tailwind.theme.json
npx @google/design.md export --format css-tailwind DESIGN.md > theme.css
```
