# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed access policy for security analytics datasets.

No browser-supplied role is trusted. Non-public data requires authenticated
OIDC identity and a server-configured allowlist. This does not replace network
isolation, IdP MFA, audit logging or an organizational security review.
"""
from __future__ import annotations

import os
from typing import Any

ROLES: dict[str, frozenset[str]] = {
    "viewer": frozenset({"view"}),
    "analyst": frozenset({"view", "export"}),
    "compliance": frozenset({"view", "export", "pci"}),
    "admin": frozenset({"view", "export", "pci", "admin"}),
}


def authorized(*, classification: str, identity: str | None,
               assignments: dict[str, str], permission: str = "view") -> bool:
    """Authorize only explicit roles for non-public classifications.

    Synthetic demo data can be viewed locally without identity. All other
    classifications fail closed unless a known identity has an assigned role.
    """
    if classification == "synthetic" and permission == "view":
        return True
    if classification not in {"synthetic", "internal", "confidential"}:
        return False
    if not identity:
        return False
    role = assignments.get(identity.strip().lower(), "")
    return permission in ROLES.get(role, frozenset())


def classification() -> str:
    """Read administrator-controlled classification, defaulting to synthetic."""
    return os.environ.get("IANUA_ANALYTICS_CLASSIFICATION", "synthetic").strip().lower()


def identity_from_streamlit(user: Any) -> str | None:
    """Use server-verified Streamlit OIDC user only, never an input widget."""
    try:
        if user.is_logged_in:
            email = str(user.email).strip().lower()
            return email or None
    except (AttributeError, KeyError, RuntimeError):
        pass
    return None
