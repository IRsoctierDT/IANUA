---
version: "alpha"
name: "AI Operator Cyber Command Center"
description: "STICHES/DESIGN.md identity system for AI operations, cybersecurity automation, RAG systems, governance, dashboard design, and portfolio documentation."
colors:
  primary: "#111827"
  secondary: "#374151"
  tertiary: "#2563EB"
  accent: "#10B981"
  warning: "#F59E0B"
  danger: "#DC2626"
  neutral: "#F9FAFB"
  surface: "#FFFFFF"
  border: "#D1D5DB"
  muted: "#6B7280"
  on-primary: "#FFFFFF"
  on-tertiary: "#FFFFFF"
typography:
  h1:
    fontFamily: "Inter"
    fontSize: "2.75rem"
    fontWeight: 800
    lineHeight: "1.1"
    letterSpacing: "-0.03em"
  h2:
    fontFamily: "Inter"
    fontSize: "2rem"
    fontWeight: 750
    lineHeight: "1.2"
    letterSpacing: "-0.02em"
  h3:
    fontFamily: "Inter"
    fontSize: "1.35rem"
    fontWeight: 700
    lineHeight: "1.25"
  body-md:
    fontFamily: "Inter"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: "1.65"
  code:
    fontFamily: "JetBrains Mono"
    fontSize: "0.92rem"
    fontWeight: 500
    lineHeight: "1.55"
rounded:
  sm: "4px"
  md: "8px"
  lg: "14px"
  xl: "22px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "16px"
  lg: "24px"
  xl: "40px"
  xxl: "64px"
components:
  command-card:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.primary}"
    borderColor: "{colors.border}"
    rounded: "{rounded.lg}"
    padding: "24px"
  agent-status-panel:
    backgroundColor: "{colors.neutral}"
    textColor: "{colors.primary}"
    borderColor: "{colors.border}"
    rounded: "{rounded.md}"
    padding: "16px"
  governance-warning:
    backgroundColor: "{colors.warning}"
    textColor: "{colors.primary}"
    rounded: "{rounded.md}"
    padding: "16px"
  risk-alert:
    backgroundColor: "{colors.danger}"
    textColor: "{colors.on-primary}"
    rounded: "{rounded.md}"
    padding: "16px"
---

# STICHES / DESIGN.md System

## Overview

This file is the canonical design and documentation identity for the AI Operator Cyber Command Center.

It is designed to guide:
- Markdown documentation
- Dashboard design
- Agent-generated reports
- Portfolio case studies
- Governance warnings
- Cybersecurity incident reports
- Future UI tokens

## Visual Principle

The system must feel like a professional security operations console combined with an executive research archive.

## Documentation Principle

Every serious document should separate:
- Facts
- Assumptions
- Analysis
- Recommendations
- Unknowns
- Evidence

## Color Rules

Blue means action.  
Green means validated success.  
Amber means caution or review required.  
Red means security risk or failed control.  
Dark neutral means authority, structure, and command focus.

## Agent Instruction

Before creating documentation, dashboard components, or portfolio surfaces, agents should inspect `DESIGN.md`, `AGENTS.md`, and the existing repository structure.

## Prohibited Style

Do not generate casual, playful, generic startup-style documentation.  
Do not hide governance controls.  
Do not create agents that perform destructive or external actions without human approval.
