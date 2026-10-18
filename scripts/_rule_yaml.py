# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Bounded YAML loading for the two detection-content gates.

``build_attack_navigator.py`` and ``build_behavior_index.py`` parse rule files
a pull request controls, and ``yaml.safe_load`` bounds none of input size,
nesting depth or alias expansion. Review of 965e4cd measured each escaping
both gates' handlers as an exit-1 traceback with no ``error:`` line: flow
nesting of depth 493 (a 1002-byte rule) raised ``RecursionError`` in the
composer; a 3000-link alias chain loaded and then raised ``RecursionError``
in ``str()``; a billion-laughs title and a rule symlinked to ``/dev/zero``
raised ``MemoryError`` under a 1.5 GB cap. Listing those classes in each
handler would turn the tracebacks into exit 2 and leave the work unbounded,
so :func:`load_rule` refuses the inputs instead, as a ``ValueError`` or a
``yaml.YAMLError`` both gates already map to their bad-input exit.

Refused: a path that is not a regular file once symlinks are followed; more
than :data:`MAX_RULE_BYTES`; bytes that are not UTF-8; any YAML alias (an
anchor alone is harmless, since only an alias shares a node, and no
committed rule uses either); nesting deeper than :data:`MAX_RULE_DEPTH`.
Measured on the committed corpus: 20 rules, at most 1628 bytes and depth 4.
The runtime matcher (``agents/detection_matcher_agent.py``) still uses plain
``yaml.safe_load``, so the gate is the stricter of the two.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

MAX_RULE_BYTES = 256 * 1024
MAX_RULE_DEPTH = 32


class _BoundedSafeLoader(yaml.SafeLoader):
    """``SafeLoader`` that refuses aliases and bounds composer recursion."""

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._depth = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            mark = self.peek_event().start_mark
            raise yaml.composer.ComposerError(
                None, None, "YAML aliases are not accepted in a rule", mark
            )
        if self._depth >= MAX_RULE_DEPTH:
            mark = self.peek_event().start_mark
            raise yaml.composer.ComposerError(
                None, None, f"nesting exceeds depth {MAX_RULE_DEPTH}", mark
            )
        self._depth += 1
        try:
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1


def load_rule(path: Path) -> Any:
    """Parse one rule file within the bounds above; raise on anything outside them."""
    if not path.is_file():
        raise ValueError(f"{path.name}: not a regular file")
    with path.open("rb") as handle:
        raw = handle.read(MAX_RULE_BYTES + 1)
    if len(raw) > MAX_RULE_BYTES:
        raise ValueError(f"{path.name}: rule exceeds {MAX_RULE_BYTES} bytes")
    # What yaml.safe_load does, with the bounded SafeLoader subclass.
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{path.name}: not UTF-8 ({exc})") from exc
    loader = _BoundedSafeLoader(text)
    loader.name = path.name  # marks in an error name the rule, not "<unicode string>"
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()
