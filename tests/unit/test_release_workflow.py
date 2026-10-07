"""Prevent release dispatch and asset-publication regressions."""

from pathlib import Path

import yaml


# PyYAML's YAML 1.1 loader treats the GitHub Actions key `on` as a boolean.
def _workflow() -> dict:
    path = Path(__file__).resolve().parents[2] / ".github/workflows/release.yml"
    result = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(result, dict)
    return result


def test_publication_requires_explicit_human_trigger() -> None:
    workflow = _workflow()
    triggers = workflow[True]
    assert set(triggers) == {"release", "workflow_dispatch"}
    assert triggers["release"]["types"] == ["published"]
    assert triggers["workflow_dispatch"]["inputs"]["tag"]["required"] is True
    assert "github.event.repository.default_branch" in workflow["jobs"]["publish-assets"]["if"]


def test_build_and_recovery_assets_precede_publication() -> None:
    steps = _workflow()["jobs"]["publish-assets"]["steps"]
    names = [step.get("name", "") for step in steps]
    publication = names.index("Create release with assets or repair existing release")
    for required in [
        "Verify canonical release tag and version chain",
        "Validate release source",
        "Build distributions from the tagged commit",
        "Stage complete release assets and checksums",
        "Retain assets even if GitHub release publication fails",
    ]:
        assert names.index(required) < publication
    script = steps[publication]["run"]
    assert 'gh release create "$TAG" release-assets/*' in script
    assert 'gh release upload "$TAG" release-assets/* --clobber' in script
    assert 'gh release view "$TAG" --json assets' in script


def test_existing_tags_are_immutable_and_must_belong_to_default_branch() -> None:
    steps = _workflow()["jobs"]["publish-assets"]["steps"]
    resolve = next(step for step in steps if step.get("name") == "Resolve immutable release source")
    assert 'git checkout --detach "refs/tags/$TAG"' in resolve["run"]
    assert "git merge-base --is-ancestor HEAD" in resolve["run"]
    assert "git tag -f" not in resolve["run"]
    assert "--force" not in resolve["run"]
