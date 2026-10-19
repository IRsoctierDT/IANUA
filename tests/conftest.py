# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Shared test fixtures.

Keep the suite deterministic and network-free: the orchestrator enables the LLM
narrative by default (``LLM_NARRATIVE=auto``), so disable it for tests unless a
test opts in explicitly. Tests that exercise the LLM path inject a fake generator.

Audit-signing keys are cleared for the same reason. Every chain writer and
reader resolves its scheme from the environment, so a key exported in the shell
running the suite would change what a test signs and verifies. Measured: the
promotion gate's own control test went red under an exported ``AUDIT_HMAC_KEY``
before #256. A test that needs a key sets one, generated at run time.
"""

from __future__ import annotations

import pytest

#: Every variable :func:`agents.policies.audit.signer_from_env` and
#: :func:`agents.policies.audit.verifier_from_env` read.
_AUDIT_KEY_VARS = ("AUDIT_HMAC_KEY", "AUDIT_ED25519_PRIVATE_KEY", "AUDIT_ED25519_PUBLIC_KEY")


@pytest.fixture(autouse=True)
def _disable_llm_narrative(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_NARRATIVE", "off")


@pytest.fixture(autouse=True)
def _no_ambient_audit_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _AUDIT_KEY_VARS:
        monkeypatch.delenv(name, raising=False)
