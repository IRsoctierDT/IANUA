# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The IANUA-rename gate writes only the inode it read, and only if it has one name.

`eligible()` judges a *path*, so a hard link (one inode, a second name outside
the tree) and a path swapped after the check both passed it. Measured on
98350ca: `--apply` rewrote an outside file through a `docs/*.md` hard link,
rewrote the gate's own source through a hard link to it, and followed a file,
or an ancestor directory, swapped for a link between the check and the read or
the write; a FIFO swapped in hung it. Each case drives that state against a
throwaway ROOT, so `--apply` runs end to end without touching the checkout.

A hard link is still *read*, deliberately (see `eligible`): these tests pin the
write and the swap, not the read.
"""

from __future__ import annotations

import os
import signal
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from types import FrameType

import pytest

from scripts import rename_to_ianua as gate

LEGACY = gate.REPLACEMENTS[5][0]
Swap = Callable[[Path, Path], None]


def _to_symlink(probe: Path, out: Path) -> None:
    probe.unlink()
    probe.symlink_to(out)


def _to_hardlink(probe: Path, out: Path) -> None:
    probe.unlink()
    os.link(out, probe)


def _ancestor_to_symlink(probe: Path, out: Path) -> None:
    probe.parent.rename(probe.parent.with_name("aside"))
    probe.parent.symlink_to(out.parent)


def _to_fifo(probe: Path, out: Path) -> None:
    probe.unlink()
    os.mkfifo(probe)


def _to_new_file(probe: Path, out: Path) -> None:
    probe.unlink()
    probe.write_text("new\n", encoding="utf-8")


SWAPS: dict[str, Swap] = {
    "file-to-symlink": _to_symlink,
    "file-to-hardlink": _to_hardlink,
    "ancestor-to-symlink": _ancestor_to_symlink,
}


@pytest.fixture
def tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """A throwaway ROOT holding ``docs/sub/x.md``, and an outside ``x.md``, both legacy."""
    root, outside = tmp_path.resolve() / "repo", tmp_path.resolve() / "outside"
    for directory in (root / "docs" / "sub", outside):
        directory.mkdir(parents=True)
    monkeypatch.setattr(gate, "ROOT", root)
    probe, target = root / "docs" / "sub" / "x.md", outside / "x.md"
    for path in (probe, target):
        path.write_text(f"legacy {LEGACY} identifier\n", encoding="utf-8")
    return probe, target


@contextmanager
def _deadline(seconds: int = 10) -> Iterator[None]:
    """Fail, rather than hang, a gate blocked opening a FIFO.

    ``pytest.fail``, not ``TimeoutError``: that is an ``OSError``, which the walk
    turns into a refusal (measured: it let a blocking open pass the FIFO case).
    """

    def expire(signum: int, frame: FrameType | None) -> None:
        pytest.fail("the gate blocked opening a FIFO")

    previous = signal.signal(signal.SIGALRM, expire)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


@pytest.mark.security
def test_apply_still_rewrites_an_ordinary_file(tree: tuple[Path, Path]) -> None:
    """Not vacuous: the descriptor path does rewrite, so a refusal below means something."""
    probe, _ = tree
    assert gate.migrate(apply=True) == ([Path("docs/sub/x.md")], [])
    assert probe.read_text(encoding="utf-8") == "legacy IANUA identifier\n"


@pytest.mark.security
def test_apply_refuses_to_write_through_a_hard_link(
    tree: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    probe, target = tree
    probe.unlink()
    os.link(target, probe)
    assert gate.eligible(probe), "a hard link is scanned; refusing it would empty a cp -al copy"
    assert gate.migrate(apply=False)[0] == [Path("docs/sub/x.md")]
    monkeypatch.setattr("sys.argv", ["rename_to_ianua.py", "--apply"])
    assert gate.main() == 2
    assert "has 2 names" in capsys.readouterr().err
    assert LEGACY in target.read_text(encoding="utf-8"), "the outside file was rewritten"


@pytest.mark.security
def test_a_second_name_for_the_script_is_not_scanned(
    tree: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    probe, _ = tree
    me = gate.ROOT / "scripts" / "rename_to_ianua.py"
    me.parent.mkdir()
    me.write_bytes(Path(gate.__file__).read_bytes())
    monkeypatch.setattr(gate, "SELF", me)
    probe.unlink()
    os.link(me, gate.ROOT / "docs" / "alias.py")
    before = me.read_bytes()
    assert gate.migrate(apply=True) == ([], []), "the script was scanned through a second name"
    assert me.read_bytes() == before


@pytest.mark.security
@pytest.mark.parametrize("swap", [*SWAPS.values(), _to_fifo], ids=[*SWAPS, "file-to-fifo"])
def test_a_path_swapped_after_the_check_is_not_followed(
    tree: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch, swap: Swap
) -> None:
    """The check-to-open window: ``eligible`` approved a regular file, then it changed."""
    probe, target = tree
    real = gate.eligible

    def racing(path: Path) -> bool:
        approved = real(path)
        if approved and path == probe:
            swap(probe, target)
        return approved

    monkeypatch.setattr(gate, "eligible", racing)
    with _deadline(), pytest.raises(gate.RefusedPath):
        gate.migrate(apply=True)
    assert LEGACY in target.read_text(encoding="utf-8"), "the outside file was rewritten"


@pytest.mark.security
@pytest.mark.parametrize("swap", [*SWAPS.values(), _to_new_file], ids=[*SWAPS, "file-to-new"])
def test_a_path_swapped_between_read_and_write_is_not_written(
    tree: tuple[Path, Path], swap: Swap
) -> None:
    """The read-to-write window, with the read descriptor held open as ``migrate`` holds it.

    ``file-to-new`` pins the inode check on its own: the other swaps are
    also refused by the walk or by the name count.
    """
    probe, target = tree
    with os.fdopen(gate._open_beneath(probe, os.O_RDONLY), encoding="utf-8") as source:
        text = source.read()
        swap(probe, target)
        with pytest.raises(gate.RefusedPath):
            gate._rewrite(probe, text.replace(LEGACY, "IANUA"), os.fstat(source.fileno()))
    assert LEGACY in target.read_text(encoding="utf-8"), "the outside file was rewritten"


@pytest.mark.security
def test_migrate_holds_the_read_descriptor_until_the_write(
    tree: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Closed first, a file recreated in place reused the inode number and was written.

    Measured on ext4; on a filesystem that does not reuse numbers this cannot tell.
    """
    probe, _ = tree
    real = gate._rewrite

    def recreated_first(path: Path, text: str, read: os.stat_result) -> None:
        _to_new_file(probe, probe)
        real(path, text, read)

    monkeypatch.setattr(gate, "_rewrite", recreated_first)
    with pytest.raises(gate.RefusedPath):
        gate.migrate(apply=True)
    assert probe.read_text(encoding="utf-8") == "new\n"
