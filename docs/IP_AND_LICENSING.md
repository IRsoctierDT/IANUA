# IP & Licensing Posture

> **Not legal advice.** This document records engineering and business
> decisions and the reasoning behind them, so that future maintainers (and
> future-you) do not have to reconstruct it. Entity, tax, trademark, and patent
> rules vary by jurisdiction and change over time. Anything with money or a
> filing deadline attached warrants a licensed attorney or CPA — the sections
> below flag exactly where.
>
> | | |
> |---|---|
> | **Status** | Current as of v2.0.0 |
> | **Owner** | Repository maintainer (human) |
> | **Companion docs** | [`LICENSE`](../LICENSE), [`NOTICE`](../NOTICE), [`CONTRIBUTING.md`](../CONTRIBUTING.md) |
> | **Review trigger** | Forming an entity · taking paying work · filing a mark · considering a patent |

---

## 1. Executive Summary

IANUA is released under the **Apache License 2.0**. Copyright is held by the
individual author; there is no entity in the chain today. The IANUA name and
marks are **reserved** and deliberately excluded from the code grant.

The practical stack for a project like this is **copyright + trademark + trade
secret**, not patents. Patents are largely foreclosed for already-published
work (see §5) and are a poor fit for the economics of a portfolio-grade
open-source platform.

---

## 2. Objectives

1. Let anyone read, run, fork, and build on the code — including commercially —
   because that is what makes the work credible as a portfolio artifact.
2. Keep the **IANUA identity** distinct from the code grant, so derivative
   works cannot trade on the name.
3. Preserve future commercial options (consulting, dual-licensing, an entity)
   without paying entity overhead before there is revenue.
4. Attribute honestly and make the provenance of every bundled artifact
   checkable.

---

## 3. Decisions on record

### 3.1 License: Apache-2.0

**Decision.** Apache-2.0, chosen over MIT.

**Reasoning.** Two clauses MIT does not have, both of which this project needs:

- **§3 — express patent grant.** Contributors grant users a patent license to
  their contributions. This is what makes the license safe for enterprise
  adoption, and it removes ambiguity that MIT leaves open.
- **§6 — explicit non-grant of trademark rights.** The license grants no
  permission to use the licensor's names or marks. That is the clause keeping
  IANUA reserved while the code itself is fully open. Under MIT the mark would
  rely on trademark law alone, with nothing in the license text.

Apache-2.0 also carries the standard warranty and liability disclaimers
(§§7–8), which matter for security tooling regardless of what entity ships it.

**Consequence to understand.** Publishing under Apache-2.0 means users receive
a royalty-free patent license covering the published contributions. You cannot
publish code under this license and later charge those same users patent
royalties for it. That is the bargain, and it is intentional.

### 3.2 Copyright holder: the individual author

**Decision.** `Copyright 2026 Ivan Rozenblad` — legal name, not the GitHub
handle, and not an entity.

**Reasoning.**

- Copyright arises automatically on creation and vests in the human author. No
  filing, entity, or notice is required for the right to exist; the notice is
  evidentiary and deterrent.
- A **pseudonym is workable but adds friction.** In the US, pseudonymous works
  are given a different copyright term — 95 years from publication or 120 from
  creation, whichever expires first — unless the author's identity is on
  record with the Copyright Office, in which case the ordinary life + 70 term
  applies (17 U.S.C. §302(c)). Separately, enforcing, registering, assigning,
  or dual-licensing under a handle means first proving you are the handle.
- **Nothing is foreclosed.** Copyright is freely assignable. If an entity is
  formed later, a short written assignment moves ownership and the notice is
  updated going forward. That is why this decision did not need to wait on the
  entity question.

### 3.3 Entity (LLC): deferred, deliberately

**Decision.** No entity today. Revisit when commercial activity begins.

**Reasoning.** An entity is driven by *commercial activity*, not by publishing
code. Forming one changes nothing about whether the copyright exists or whether
the license is valid.

| An entity helps with | It does not help with |
|---|---|
| Liability separation when consulting, deploying for clients, or when others rely on the tooling | Copyright existence or validity — automatic either way |
| Contracting: many clients will not contract with an individual; invoicing and insurance get simpler | The Apache-2.0 warranty/liability disclaimers, which apply regardless of entity |
| A clean IP chain for dual-licensing, acquisition, or adding contributors (work-for-hire and assignment flow to the entity) | Your own negligent or wrongful acts — the liability shield does not cover those |
| Owning the trademark, if the entity is what uses the mark in commerce | Anything at all, if funds are commingled and formalities are skipped |

**Costs to weigh** (verify current figures for your state — they change):
formation fee, registered agent, annual report and/or franchise tax, a separate
business bank account, bookkeeping, and possibly a separate tax return. Some
states levy a minimum annual franchise tax regardless of revenue — California's
is the well-known example — so an entity formed before there is income is
usually pure overhead.

**Trigger to revisit:** first paying client, first dual-license conversation,
first contributor who is not the owner, or a trademark filing (see §4).

---

## 4. Trademark posture — IANUA

**Current state.** The mark is used in commerce-adjacent public materials and
marked **™** (unregistered). `NOTICE` reserves it and states that the license
grants no rights to it.

**Rules that matter here (facts).**

- **™ vs ®.** ® may only be used with a federally registered mark. Until a
  registration issues, ™ is the correct symbol. Do not switch early.
- **File in the name of the owner.** A US application must be filed by the
  party that owns the mark — the one using it in commerce. Naming the wrong
  applicant is a substantive defect, and it is not always freely correctable.

**Sequencing consequence.** This is the one place where the entity decision has
a hard ordering constraint: **if an LLC is going to do business under IANUA,
form it before filing the trademark.** If the mark will stay with the
individual, file as the individual. Deciding after filing is the expensive
path.

**Recommended:** a trademark attorney for the filing. Owner identification,
class selection, and specimen requirements are the three places DIY filings
commonly fail.

---

## 5. Patents — largely foreclosed, and that is fine

**Facts.**

- **Public disclosure starts a clock.** US law provides a one-year grace period
  for disclosures made by the inventor (35 U.S.C. §102(b)(1)). Most other
  jurisdictions — including Europe and China — apply **absolute novelty**: a
  public disclosure before filing generally destroys patentability there
  immediately, with no grace period.
- **This repository has been public since well before v2.0.0.** Foreign patent
  rights on anything already published should be treated as gone. A US filing
  may still be possible for material disclosed within the past year, measured
  from first public disclosure — an attorney would need to date that precisely.
- **Inventors must be natural persons** under US law; applications are filed by
  inventors and then assigned to an entity if one exists. An entity is not a
  prerequisite for filing.
- **Apache-2.0 §3 already licenses your patents** to users, for the
  contributions you publish under it (see §3.1).

**Assessment (judgment, not fact).** For this project patents are the wrong
instrument: prosecution through issuance commonly runs into five figures,
software claims face significant subject-matter eligibility risk after
*Alice v. CLS Bank*, and the license already grants users what a patent would
otherwise let you charge for.

**The one rule to remember:** if something is genuinely patent-worthy, it must
be **held back from the public repository and filed before disclosure**.
Publishing first is the irreversible step.

---

## 6. Contribution terms

Inbound matches outbound: contributions submitted for inclusion are licensed
under Apache-2.0 (§5 of the license), with no separate CLA. See
[`CONTRIBUTING.md`](../CONTRIBUTING.md).

Contributors must have the right to license what they submit. Third-party code
or content must be disclosed in the pull request with its license named;
anything imposing additional restrictions on downstream users requires a
maintainer decision before merge.

---

## 7. Provenance of bundled content

Verified and recorded in [`NOTICE`](../NOTICE):

| Content | Provenance |
|---|---|
| `detections/sigma/` | Original rules authored for this project (`author: IANUA`), expressed in the Sigma format |
| `knowledge-base/` | Original summaries written for this project; each file cites its authoritative source, no source text reproduced |
| `compliance/` | This project's own control-to-framework interpretation — not certification, audit, or advice, and not endorsed by any framework owner |
| `sample-logs/` | Synthetic fixtures; no real hosts, users, addresses, or captured production data |
| Dependencies | Third-party, each under its own license; the full set with available license metadata is published as CycloneDX SBOMs in `security/sbom/` |

Third-party marks (MITRE ATT&CK®, NIST, OWASP®, CIS®, CompTIA®, SOC 2®,
ISO/IEC 27001, Sigma) are referenced descriptively only, with no implied
affiliation or endorsement.

---

## 8. Risks

| Risk | Mitigation |
|---|---|
| Publishing under Apache-2.0 is effectively irreversible for released code — the grant stands for what was published | Accepted deliberately; future releases could change license, but already-published versions remain under Apache-2.0 |
| A contributor submits third-party code without disclosure | `CONTRIBUTING.md` requires disclosure; review checks provenance for anything unusual |
| Trademark filed under the wrong owner | Settle the entity question **before** filing (§4) |
| Someone forks and ships under the IANUA name | `NOTICE` + Apache-2.0 §6 reserve the marks; common-law rights exist from use; registration would strengthen enforcement |
| Security tooling misused against systems the operator does not own | `LICENSE` §§7–8 disclaim warranty and liability; `SECURITY.md` and `AGENTS.md` §5 state the lawful-lab scope explicitly |

---

## 9. Open items for professional review

1. **Entity choice and state** — attorney and/or CPA. Driven by where you live
   and work, expected revenue, and client contracting requirements.
2. **Trademark filing** — trademark attorney. Blocked on the entity decision
   (§4), not on anything technical.
3. **Any patent question** — patent attorney, and quickly if it applies, given
   the grace-period clock (§5).

---

## 10. Sources

Consult primary sources; they govern, and this summary does not.

- Apache License, Version 2.0 — <https://www.apache.org/licenses/LICENSE-2.0>
  (see §3 patent grant, §5 contributions, §6 trademarks, §§7–8 warranty and
  liability)
- 17 U.S.C. §302 — Duration of copyright — <https://www.law.cornell.edu/uscode/text/17/302>
- 35 U.S.C. §102 — Conditions for patentability; novelty —
  <https://www.law.cornell.edu/uscode/text/35/102>
- U.S. Copyright Office — <https://www.copyright.gov/>
- USPTO, trademark basics — <https://www.uspto.gov/trademarks/basics>
- SPDX license list (identifier used in project metadata) —
  <https://spdx.org/licenses/>
