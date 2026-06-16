"""Security test: tool input validation must block path traversal.

This is the day-one example for the `tests/security` suite required by
AGENTS.md §6.2. Boundary-crossing changes must keep this suite green.
"""

from pathlib import Path

import pytest
from agents.tools.validation import ValidationError, resolve_within


@pytest.mark.security
def test_allows_path_inside_base(tmp_path: Path) -> None:
    result = resolve_within(tmp_path, "reports/output.txt")
    assert str(result).startswith(str(tmp_path.resolve()))


@pytest.mark.security
@pytest.mark.parametrize(
    "evil",
    [
        "../../etc/passwd",
        "../secrets.env",
        "subdir/../../escape",
    ],
)
def test_blocks_traversal(tmp_path: Path, evil: str) -> None:
    with pytest.raises(ValidationError):
        resolve_within(tmp_path, evil)
