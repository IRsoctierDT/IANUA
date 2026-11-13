# pfSense containment runbook

> **Phase 2 status: dry run only.** IANUA prepares and audits the exact pfSense
> API requests for an approved action and **sends nothing**. `agents/tools/pfsense.py`
> has no network transport at all. Live execution is phase 3, which needs its own
> `AGENTS.md` §5 amendment and your approval again.

**Purpose** · Block, unblock, isolate and restore one IP address on the lab pfSense
firewall, each action authorized by its own signed, expiring, single-use approval.

**Risk level** · Low in phase 2, since nothing is sent. High once live, because a wrong
block can cut off a host or the operator's own access.

**Skill level required** · Comfortable with pfSense aliases and rule ordering, and with
handling a private key.

**Deployment complexity** · Moderate. Two aliases and two rules on the firewall, one key
pair, and one reviewed pull request adding your public key.

## Executive Summary

Containment in IANUA edits exactly two pfSense **host aliases** that you create and
reference from rules you write: `IANUA_BLOCK` and `IANUA_ISOLATE`. IANUA never creates,
edits or deletes a firewall rule. Each action adds or removes one address from one
alias, and only after `agents/policies/execution_approval.py` has verified an Ed25519
approval you signed for that exact capability, address and plan.

## Objectives

1. A human decision, cryptographically bound to one action, before anything changes.
2. The smallest possible blast radius: one address, one alias, a rule you reviewed.
3. A tamper-evident record linking the signed approval to the exact request.
4. Rollback that is itself an approved action (`unblock_indicator`, `restore_host`).

## Architecture

```
operator signs approval ──► authorize() ──► VerifiedApproval ──► PfSenseDryRun.dry_run()
  (your private key)         verifies sig,      (only type the        builds GET alias lookup
                             binding, expiry,    adapter accepts)      + PATCH append/remove,
                             consumes once                             audits both digests,
                                                                       sends nothing
```

| Capability | Alias | pfREST request (prepared, not sent) |
|---|---|---|
| `block_indicator` | `IANUA_BLOCK` | `PATCH /api/v2/firewall/alias` with `append: true` |
| `unblock_indicator` | `IANUA_BLOCK` | same, `remove: true` |
| `isolate_host` | `IANUA_ISOLATE` | same, `append: true` |
| `restore_host` | `IANUA_ISOLATE` | same, `remove: true` |

Each PATCH is preceded by `GET /api/v2/firewall/aliases?name=<alias>`, because pfREST
addresses an alias by an index that changes when aliases are deleted. A live transport
must refuse unless that lookup returns exactly one alias with exactly that name and type
`host`. `disable_account` and `enable_account` are approvable but are not firewall
actions; this adapter refuses them.

**What has not been verified.** The request shapes come from the pfREST package
documentation (`COMMON_CONTROL_PARAMETERS.md`: `append`, `remove` and `apply` on PATCH)
and its maintainer's guidance on alias updates. They have **not** been run against your
firewall. Before phase 3, compare them with your device's own `/api/v2/documentation`
page.

## Implementation Steps

**On the firewall (Netgate 4200, pfSense):**

1. *Firewall → Aliases → IP → Add.* Create `IANUA_BLOCK`, type **Host(s)**, empty.
   Create `IANUA_ISOLATE` the same way. Description: "Managed by IANUA — edit by approval."
2. *Firewall → Rules.* Add a rule that blocks traffic to and from `IANUA_BLOCK` (a
   floating rule, or one per interface). On each internal VLAN, add a rule blocking
   source `IANUA_ISOLATE` to any destination, placed **above** the allow rules, with a
   pass rule above it for your management address only. Review the ordering yourself;
   an isolate rule below an allow rule does nothing.
3. Note the firewall's management address and your workstation's address. They go in
   `PfSenseConfig(protected=...)` so IANUA can never block or isolate them.

**Your approver key (on your Mac, never in this repository):**

4. From the repository root, generate a key pair:

   ```zsh
   python -c 'from agents.policies.signing import generate_ed25519_keypair as g; k, p = g(); print("PRIVATE (store in your password manager, never share):", k.hex()); print("public:", p.hex())'
   clear
   ```

   Store the private key in the macOS Keychain. This form prompts for the value, so it
   never appears in your shell history or the process list:

   ```zsh
   security add-generic-password -s ianua-approver -a "$USER" -w
   ```

   Do not paste it into chat, a ticket, a `.env` file, or this repository.
5. Open a pull request adding the **public** key to `agents/policies/approvers.json`:

   ```json
   {
     "version": 1,
     "approvers": [
       {"id": "owner", "public_key": "<64 hex chars>", "authorization": "Repository owner; lab firewall owner"}
     ]
   }
   ```

**A dry run:**

6. Sign an approval, authorize it and prepare the change. The private key is read from
   the Keychain into the process environment for one command only:

   ```zsh
   IANUA_APPROVER_KEY="$(security find-generic-password -s ianua-approver -w)" python - <<'PY'
   import os
   from pathlib import Path
   from agents.policies import execution_approval as ea
   from agents.policies.audit import AuditLogger
   from agents.policies.signing import Ed25519Signer
   from agents.tools.pfsense import PfSenseConfig, PfSenseDryRun

   signer = Ed25519Signer(bytes.fromhex(os.environ.pop("IANUA_APPROVER_KEY")))
   token = ea.issue_approval(signer, approver="owner", capability="block_indicator",
                             target="203.0.113.7", plan_id="plan-0123456789abcdef", ttl_seconds=300)
   approval = ea.authorize(token, capability="block_indicator", target="203.0.113.7",
                           plan_id="plan-0123456789abcdef", approvers=ea.load_approvers(),
                           ledger=ea.ApprovalLedger(Path("data/approvals.ledger")),
                           audit=AuditLogger(Path("data/audit.log")))
   adapter = PfSenseDryRun(PfSenseConfig(protected=frozenset({"192.0.2.1"})),
                           audit=AuditLogger(Path("data/audit.log")))
   print(adapter.dry_run(approval).as_dict())
   PY
   ```

   Replace `192.0.2.1` with your firewall's management address. The output is the
   request phase 3 would send. The audit log gains an `allow` record from `authorize`
   and a `dry-run` record carrying both digests.

## Risks

| Risk | Control | Residual |
|---|---|---|
| Blocking the firewall's own management path | `protected` addresses cannot be added to either alias; your isolate rule exempts management | You must list them; an empty `protected` set protects nothing |
| A stolen approver key | Approvals expire within 900 s, are single use, and name one address | Until you remove the key from `approvers.json`, it can sign any listed action |
| An approval replayed | Ledger consumption at `authorize`, plus a per-adapter used-set | The ledger is not pruned yet |
| A request for something other than what was signed | The adapter's only input is the `VerifiedApproval` | None for this adapter; phase 3's transport must not add a second input |
| The pfREST API differs from the documented shape | Phase 3 must verify against the device's own documentation | Unverified today, and stated as such |

## Cost Considerations

No new dependency, licence or service. pfREST is a free, open-source package for pfSense.
The operator cost is one-time setup (about 30 minutes) and the discipline of signing each
action.

## Future Enhancements

- **Phase 3 — live:** a stdlib HTTPS transport pinned to the firewall's certificate; the
  firewall's address declared in `agents/policies/egress.json`; a committed grant naming
  the action; a least-privilege pfREST API user allowed only the alias GET and PATCH
  endpoints; and the API key entered through the secure credential form.
- A CLI wrapper for step 6, so an approval can be issued without writing Python.
- Ledger pruning of entries past their expiry.
