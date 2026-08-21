"""MITRE ATT&CK® mapping for the agents' containment capabilities.

Every containment capability in :mod:`agents.tools.containment` is mapped to the
ATT&CK Enterprise techniques it counters and the ATT&CK mitigation it implements,
each with a description — so a reviewer, a report, or a dashboard can state
*exactly* what adversary behavior a capability addresses and why it exists.
Technique/mitigation IDs and names follow ATT&CK Enterprise **v16**, the same
version pinned by ``scripts/build_attack_navigator.py`` (source:
https://attack.mitre.org — verify IDs there before extending this catalog).

The mapping is deterministic, read-only data: frozen dataclasses in a
module-level registry, no network access, no untrusted input. ``get_mapping``
fails closed on an unknown capability instead of guessing.

Security consideration: this module is documentation-as-data only — it grants no
capability itself. The capabilities it describes are policy-gated and audited in
:mod:`agents.tools.containment`.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from types import MappingProxyType
from typing import Any

from agents.policies import ActionClass


@dataclass(frozen=True)
class AttackTechnique:
    """One ATT&CK Enterprise technique a capability counters.

    ``tactic`` lists the tactic(s) ATT&CK files the technique under;
    ``description`` states the adversary behavior and why it matters here.
    """

    technique_id: str
    name: str
    tactic: str
    description: str

    @property
    def url(self) -> str:
        """Authoritative ATT&CK page for this technique."""
        return f"https://attack.mitre.org/techniques/{self.technique_id.replace('.', '/')}/"


@dataclass(frozen=True)
class AttackMitigation:
    """The ATT&CK mitigation a capability implements."""

    mitigation_id: str
    name: str
    description: str

    @property
    def url(self) -> str:
        """Authoritative ATT&CK page for this mitigation."""
        return f"https://attack.mitre.org/mitigations/{self.mitigation_id}/"


@dataclass(frozen=True)
class CapabilityAttackMapping:
    """ATT&CK mapping for one containment capability, with descriptions."""

    capability: str
    description: str
    action_class: ActionClass
    counters: tuple[AttackTechnique, ...]
    mitigation: AttackMitigation

    def technique_ids(self) -> tuple[str, ...]:
        """The IDs of the techniques this capability counters, in catalog order."""
        return tuple(t.technique_id for t in self.counters)


# --- technique catalog (shared across capabilities) -------------------------

_T1486 = AttackTechnique(
    technique_id="T1486",
    name="Data Encrypted for Impact",
    tactic="Impact",
    description=(
        "Ransomware encrypts data on target systems to interrupt availability "
        "and extort payment. Stopping the encrypting process and quarantining "
        "the payload limits how much data is lost."
    ),
)
_T1490 = AttackTechnique(
    technique_id="T1490",
    name="Inhibit System Recovery",
    tactic="Impact",
    description=(
        "Adversaries delete or disable backups, shadow copies, and recovery "
        "features so victims cannot restore without paying. Halting the payload "
        "early preserves the recovery material it would destroy."
    ),
)
_T1489 = AttackTechnique(
    technique_id="T1489",
    name="Service Stop",
    tactic="Impact",
    description=(
        "Ransomware stops services (databases, backup agents, security tools) "
        "to unlock files for encryption and blind defenders. Stopping the "
        "malicious process interrupts this preparation phase."
    ),
)
_T1657 = AttackTechnique(
    technique_id="T1657",
    name="Financial Theft",
    tactic="Impact",
    description=(
        "Extortion, ransomware payments, and fraudulent transfers monetize an "
        "intrusion. Containing the payload and cutting its data-theft channels "
        "removes the leverage the extortion depends on."
    ),
)
_T1059 = AttackTechnique(
    technique_id="T1059",
    name="Command and Scripting Interpreter",
    tactic="Execution",
    description=(
        "Payloads commonly run through shells and script interpreters. "
        "Suspending or killing the interpreter process stops the payload's "
        "execution chain."
    ),
)
_T1204 = AttackTechnique(
    technique_id="T1204",
    name="User Execution",
    tactic="Execution",
    description=(
        "A user is lured into opening a malicious file or link. Quarantining "
        "the dropped file prevents (re-)execution of the lure."
    ),
)
_T1105 = AttackTechnique(
    technique_id="T1105",
    name="Ingress Tool Transfer",
    tactic="Command and Control",
    description=(
        "Adversaries transfer tools and payloads onto a compromised host. "
        "Quarantining the transferred file and blocking the delivery indicator "
        "breaks staged delivery of follow-on stages."
    ),
)
_T1071 = AttackTechnique(
    technique_id="T1071",
    name="Application Layer Protocol",
    tactic="Command and Control",
    description=(
        "Command-and-control traffic hides in HTTP(S), DNS, and other common "
        "protocols. Isolating the host or blocking the C2 indicator severs the "
        "operator's control channel."
    ),
)
_T1041 = AttackTechnique(
    technique_id="T1041",
    name="Exfiltration Over C2 Channel",
    tactic="Exfiltration",
    description=(
        "Stolen data leaves over the existing C2 channel — the theft that powers "
        "double-extortion. Host isolation cuts the channel before more data "
        "leaves."
    ),
)
_T1567 = AttackTechnique(
    technique_id="T1567",
    name="Exfiltration Over Web Service",
    tactic="Exfiltration",
    description=(
        "Data is exfiltrated to legitimate web services (cloud storage, code "
        "repos) to blend in. Blocking the destination indicator stops the "
        "upload path."
    ),
)
_T1021 = AttackTechnique(
    technique_id="T1021",
    name="Remote Services",
    tactic="Lateral Movement",
    description=(
        "Adversaries spread with SSH, RDP, and SMB using valid accounts. "
        "Isolating the compromised host stops it from reaching its neighbors."
    ),
)
_T1078 = AttackTechnique(
    technique_id="T1078",
    name="Valid Accounts",
    tactic="Defense Evasion / Persistence / Privilege Escalation / Initial Access",
    description=(
        "Compromised credentials give adversaries legitimate-looking access. "
        "Disabling the compromised account revokes that access at the source."
    ),
)
_T1098 = AttackTechnique(
    technique_id="T1098",
    name="Account Manipulation",
    tactic="Persistence / Privilege Escalation",
    description=(
        "Adversaries modify accounts (group membership, credentials, "
        "permissions) to keep access. Disabling the manipulated account cuts "
        "the persistence it grants."
    ),
)
_T1133 = AttackTechnique(
    technique_id="T1133",
    name="External Remote Services",
    tactic="Persistence / Initial Access",
    description=(
        "VPNs and other externally facing services are entered with stolen "
        "credentials. Disabling the compromised account closes that entry "
        "point."
    ),
)

# --- capability → ATT&CK registry -------------------------------------------

_MAPPINGS: tuple[CapabilityAttackMapping, ...] = (
    CapabilityAttackMapping(
        capability="quarantine_file",
        description=(
            "Move a suspected payload into a permission-stripped quarantine "
            "vault inside the lab root so it can no longer execute. Reversible "
            "via release_file for confirmed false positives."
        ),
        action_class="containment",
        counters=(_T1486, _T1105, _T1204),
        mitigation=AttackMitigation(
            mitigation_id="M1049",
            name="Antivirus/Antimalware",
            description=(
                "Quarantine of malicious files is the canonical antimalware "
                "response: the payload is preserved for forensics but can no "
                "longer run."
            ),
        ),
    ),
    CapabilityAttackMapping(
        capability="stop_process",
        description=(
            "Suspend (SIGSTOP, reversible via resume_process) or — with "
            "force=True — kill (SIGKILL) a running payload process, halting "
            "active encryption or staging immediately."
        ),
        action_class="containment",
        counters=(_T1486, _T1489, _T1490, _T1059),
        mitigation=AttackMitigation(
            mitigation_id="M1040",
            name="Behavior Prevention on Endpoint",
            description=(
                "Terminating or suspending a process exhibiting ransomware "
                "behavior stops the impact at the endpoint before it completes."
            ),
        ),
    ),
    CapabilityAttackMapping(
        capability="isolate_host",
        description=(
            "Cut a compromised lab host off from the network via the configured "
            "lab executor, severing command-and-control, lateral movement, and "
            "exfiltration. Reversible via restore_host."
        ),
        action_class="containment",
        counters=(_T1021, _T1071, _T1041, _T1657),
        mitigation=AttackMitigation(
            mitigation_id="M1030",
            name="Network Segmentation",
            description=(
                "Emergency isolation is segmentation applied at incident time: "
                "the compromised host is separated from everything it could "
                "infect or leak through."
            ),
        ),
    ),
    CapabilityAttackMapping(
        capability="block_indicator",
        description=(
            "Block a validated indicator of compromise (IP address, domain, or "
            "file hash) at the lab boundary via the configured executor, "
            "cutting payload delivery and C2/exfiltration paths. Reversible via "
            "unblock_indicator."
        ),
        action_class="containment",
        counters=(_T1071, _T1105, _T1567),
        mitigation=AttackMitigation(
            mitigation_id="M1037",
            name="Filter Network Traffic",
            description=(
                "Blocking known-bad indicators filters the specific traffic the "
                "intrusion depends on without taking the whole host offline."
            ),
        ),
    ),
    CapabilityAttackMapping(
        capability="disable_account",
        description=(
            "Disable a compromised lab account via the configured executor, "
            "revoking the access behind credential-driven ransomware and "
            "extortion operations. Reversible via enable_account."
        ),
        action_class="containment",
        counters=(_T1078, _T1098, _T1133),
        mitigation=AttackMitigation(
            mitigation_id="M1026",
            name="Privileged Account Management",
            description=(
                "Disabling a compromised account is the incident-time form of "
                "account management: the credential is useless to the adversary "
                "while the investigation runs."
            ),
        ),
    ),
)

#: Rollback and variant capabilities share the mapping of the primary action
#: they reverse or specialize (``stop_process_force`` is the separately
#: gateable SIGKILL variant of ``stop_process``).
_ALIASES: MappingProxyType[str, str] = MappingProxyType(
    {
        "release_file": "quarantine_file",
        "resume_process": "stop_process",
        "stop_process_force": "stop_process",
        "restore_host": "isolate_host",
        "unblock_indicator": "block_indicator",
        "enable_account": "disable_account",
    }
)

_BY_CAPABILITY: MappingProxyType[str, CapabilityAttackMapping] = MappingProxyType(
    {m.capability: m for m in _MAPPINGS}
)


def all_mappings() -> tuple[CapabilityAttackMapping, ...]:
    """Return the full capability → ATT&CK mapping catalog, in registry order."""
    return _MAPPINGS


def get_mapping(capability: str) -> CapabilityAttackMapping:
    """Return the ATT&CK mapping for ``capability`` (fail closed on unknown).

    Rollback and variant capabilities (e.g. ``release_file``,
    ``stop_process_force``) resolve to the mapping of the primary action they
    reverse or specialize.

    Raises:
        ValueError: if ``capability`` is not a known containment capability.
    """
    key = _ALIASES.get(capability, capability)
    mapping = _BY_CAPABILITY.get(key)
    if mapping is None:
        known = sorted(set(_BY_CAPABILITY) | set(_ALIASES))
        raise ValueError(f"unknown containment capability: {capability!r}; known: {known}")
    return mapping


def describe_capability(capability: str) -> dict[str, Any]:
    """Return a JSON-serializable description of one capability's ATT&CK mapping.

    Suitable for embedding in reports or the dashboard: includes the capability
    description, countered techniques (with tactics, descriptions, and URLs),
    and the implemented mitigation.
    """
    mapping = get_mapping(capability)
    data = asdict(mapping)
    data["counters"] = [{**asdict(t), "url": t.url} for t in mapping.counters]
    data["mitigation"] = {**asdict(mapping.mitigation), "url": mapping.mitigation.url}
    return data


def attack_coverage() -> dict[str, Any]:
    """Return the whole catalog as JSON-serializable data (report/dashboard-ready)."""
    return {
        "attack_version": "16",
        "domain": "enterprise-attack",
        "capabilities": [describe_capability(m.capability) for m in _MAPPINGS],
    }
