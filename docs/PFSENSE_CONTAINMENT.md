# pfSense containment runbook

> **Stage 8, phase 3: live.** A named operator can add or remove **one IP address** in one
> operator-created pfSense alias, through `scripts/pfsense_containment.py`, and only with
> their own signed, single-use approval. Nothing automatic sends, and no response plan is
> executed. Run the read-only `probe` before the first `send`.

**Purpose** · Block, unblock, isolate and restore one IP address on the lab pfSense
firewall, each action authorized by its own signed, expiring, single-use approval.

**Risk level** · High once live. A wrong block can cut off a host or the operator's own
access, which is why the firewall's own address is always protected and every action has
an approved inverse.

**Skill level required** · Comfortable with pfSense aliases, rule ordering and API users,
and with handling a private key.

**Deployment complexity** · Moderate. Two aliases and their rules, one API user, two local
files, one approver key pair, and two reviewed edits to committed files.

## Executive Summary

Containment in IANUA edits exactly two pfSense **host aliases** that you create and
reference from rules you write: `IANUA_BLOCK` and `IANUA_ISOLATE`. IANUA never creates,
edits or deletes a firewall rule. Each action adds or removes one address from one alias,
and only after `agents/policies/execution_approval.py` has verified an Ed25519 approval
you signed for that exact capability, address and plan.

## Objectives

1. A human decision, cryptographically bound to one action, before anything changes.
2. The smallest possible blast radius: one address, one alias, a rule you reviewed.
3. A tamper-evident record linking the signed approval to the exact request and answer.
4. Rollback that is itself an approved action (`unblock_indicator`, `restore_host`).

## Architecture

```
issue (your Mac, your key) ──► token ──► send ──► authorize() ──► PfSenseLive.send()
                                                   verifies sig,     grant pfsense:send?
                                                   binding, expiry,  firewall declared twice?
                                                   consumes once     API key present?
                                                                     TLS pin matches?  ── no byte sent until here
                                                                     GET alias: exactly one, host?
                                                                     PATCH append/remove + apply
```

| Capability | Alias | Request |
|---|---|---|
| `block_indicator` | `IANUA_BLOCK` | `PATCH /api/v2/firewall/alias` with `append: true` |
| `unblock_indicator` | `IANUA_BLOCK` | same, `remove: true` |
| `isolate_host` | `IANUA_ISOLATE` | same, `append: true` |
| `restore_host` | `IANUA_ISOLATE` | same, `remove: true` |

Each PATCH is preceded by `GET /api/v2/firewall/aliases?name=<alias>`, because pfREST
addresses an alias by an index that changes when aliases are deleted. The send refuses
unless that returns exactly one alias with exactly that name, type `host` and an integer
`id`. `disable_account` and `enable_account` are not firewall actions and are refused.

**Exit codes:** `0` done · `1` refused, nothing changed · `3` not granted · `4` the change
was sent and its outcome is unknown — check the alias on the firewall before retrying.

## Implementation Steps

**On the firewall (Netgate 4200, pfSense):**

1. *Firewall → Aliases → IP → Add.* Create `IANUA_BLOCK`, type **Host(s)**, empty.
   Create `IANUA_ISOLATE` the same way. Description: "Managed by IANUA — edit by approval."
2. *Firewall → Rules.* Add a rule that blocks traffic to and from `IANUA_BLOCK`. On each
   internal VLAN, add a rule blocking source `IANUA_ISOLATE` to any destination, placed
   **above** the allow rules, with a pass rule above it for your management address only.
   Review the ordering yourself; an isolate rule below an allow rule does nothing.
3. Install the pfREST package, create a **dedicated user** (not `admin`) whose privileges
   allow only the firewall alias lookup (`GET /api/v2/firewall/aliases`) and alias update
   (`PATCH /api/v2/firewall/alias`), and generate an API key for that user. Then open
   `https://<firewall>/api/v2/documentation` and confirm both endpoints, and the `append`,
   `remove` and `apply` parameters, are as described above. This is the check that has
   not yet been made against your device.

**On your Mac (never in this repository):**

4. Store the API key and your approver key in the Keychain. Each `security` form prompts
   for the value, so it never reaches shell history or the process list:

   ```zsh
   security add-generic-password -s ianua-pfsense -a "$USER" -w
   python -c 'from agents.policies.signing import generate_ed25519_keypair as g; k, p = g(); print("PRIVATE:", k.hex()); print("public:", p.hex())'
   security add-generic-password -s ianua-approver -a "$USER" -w   # paste the PRIVATE value
   clear
   ```

5. Record the firewall certificate's fingerprint (64 lowercase hex characters):

   ```zsh
   openssl s_client -connect <firewall-ip>:443 </dev/null 2>/dev/null \
     | openssl x509 -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f'
   ```

6. Write the two **gitignored** local files. Both must name the same address and port.
   `data/pfsense.local.json`:

   ```json
   {"version": 1, "address": "<firewall-ip>", "port": 443,
    "certificate_sha256": "<64 hex>", "protected": ["<your workstation IP>"]}
   ```

   `data/egress.local.json`:

   ```json
   {"version": 1, "hosts": [{"address": "<firewall-ip>", "port": 443,
     "authorization": "Owner's lab firewall; containment by signed approval"}]}
   ```

   The firewall's own address is always protected, whether or not you list it.

**Reviewed edits (pull requests):**

7. Add your **public** key to `agents/policies/approvers.json` as
   `{"id": "owner", "public_key": "<64 hex>", "authorization": "Repository owner; lab firewall owner"}`.
8. Add `pfsense:probe` to the `allow` list in `agents/policies/policy.json`. Add
   `pfsense:send` only once the probe has succeeded.

**Probe, then send:**

9. Read-only check, which changes nothing:

   ```zsh
   IANUA_PFSENSE_API_KEY="$(security find-generic-password -s ianua-pfsense -w)" \
     python scripts/pfsense_containment.py probe
   ```

   It prints both aliases' ids. Any refusal names what is missing.

10. Issue an approval and send it. Each key is set for one command only:

    ```zsh
    ACTION=(--capability block_indicator --target 203.0.113.7 --plan plan-0123456789abcdef)
    IANUA_APPROVER_KEY="$(security find-generic-password -s ianua-approver -w)" \
      python scripts/pfsense_containment.py issue "${ACTION[@]}" --approver owner \
    | IANUA_PFSENSE_API_KEY="$(security find-generic-password -s ianua-pfsense -w)" \
      python scripts/pfsense_containment.py send "${ACTION[@]}"
    ```

    The approval expires in five minutes and works once. To undo, approve and send
    `unblock_indicator` for the same address. The audit chain is
    `data/containment/audit.log`.

## Risks

| Risk | Control | Residual |
|---|---|---|
| Blocking the firewall's own management path | The firewall's address is always protected; your `protected` list adds more; your isolate rule exempts management | Only addresses you list are protected beyond the firewall itself |
| A stolen approver key | Approvals expire within 900 s, work once, and name one address | Until you remove the key from `approvers.json`, it can sign any listed action |
| A stolen API key | Limited to the two alias endpoints by the pfREST user's privileges | It can edit those aliases until you revoke it on the firewall |
| A redirected destination | The address must match in both local files, and the certificate pin must match | Whoever can write `data/` on the node can retarget a send (and could equally edit the code) |
| An interception on the LAN | TLS pinned to the exact certificate, checked before any byte is sent; no proxy is used | A regenerated firewall certificate stops sending until you re-pin (step 5) |
| A lost answer after sending | Reported as `unknown`, exit `4`, audited | You must check the alias by hand before retrying |
| The API differs from the documented shape | Step 3's documentation check, and the read-only probe | Unverified until you run them |

## Cost Considerations

No new dependency, licence or service. pfREST is a free, open-source package for pfSense.
One-time setup is roughly an hour; each action then costs one signed approval.

## Future Enhancements

- A `verify` subcommand that reads an alias back after a send, to settle an `unknown`.
- Ledger pruning of entries past their expiry.
- Whether a draft response plan may *propose* the exact `issue` command for an operator
  to sign — never execute it — is an open decision for the owner.
