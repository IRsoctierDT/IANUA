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


def _on_merge() -> dict:
    path = Path(__file__).resolve().parents[2] / ".github/workflows/release-on-merge.yml"
    result = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(result, dict)
    return result


def test_release_on_merge_only_follows_green_ci_on_main() -> None:
    workflow = _on_merge()
    triggers = workflow[True]
    assert set(triggers) == {"workflow_run"}
    assert triggers["workflow_run"]["workflows"] == ["CI"]
    assert triggers["workflow_run"]["branches"] == ["main"]
    assert workflow["permissions"] == {"contents": "read"}
    gate = workflow["jobs"]["detect"]["if"]
    for condition in [
        "github.event.workflow_run.conclusion == 'success'",
        "github.event.workflow_run.event == 'push'",
        "github.event.workflow_run.head_branch == 'main'",
        "github.event.workflow_run.head_repository.full_name == github.repository",
    ]:
        assert condition in gate
    detect = "\n".join(step.get("run", "") for step in workflow["jobs"]["detect"]["steps"])
    assert 'check_version_sync.py --tag "$tag"' in detect


def test_release_on_merge_publication_is_human_gated_and_never_moves_tags() -> None:
    publish = _on_merge()["jobs"]["publish"]
    assert publish["environment"]["name"] == "release"
    assert publish["permissions"] == {"contents": "write", "actions": "write"}
    names = [step.get("name", "") for step in publish["steps"]]
    reviewer = names.index("Require a human reviewer on the release environment")
    tag = names.index("Create the tag at the CI-verified commit")
    dispatch = names.index("Build, sign and publish the release")
    assert reviewer < tag < dispatch
    scripts = "\n".join(step.get("run", "") for step in publish["steps"])
    assert 'select(.type == "required_reviewers")' in scripts
    assert 'gh api "repos/$GH_REPO/git/refs" -f ref="refs/tags/$TAG"' in scripts
    assert "PATCH" not in scripts and "force" not in scripts
    assert 'gh workflow run release.yml --ref main -f tag="$TAG"' in scripts


def test_release_on_merge_resumes_without_moving_tags() -> None:
    """A failed dispatch after tagging is resumable; a tag is never repointed."""
    workflow = _on_merge()
    detect = "\n".join(step.get("run", "") for step in workflow["jobs"]["detect"]["steps"])
    assert 'gh api "repos/$GH_REPO/releases/tags/$tag"' in detect
    assert 'grep -q "HTTP 404"' in detect  # only "no release" resumes; other errors fail
    assert 'git rev-parse "refs/tags/$tag^{commit}"' in detect
    publish = workflow["jobs"]["publish"]["steps"]
    tag_step = next(
        s for s in publish if s.get("name") == "Create the tag at the CI-verified commit"
    )
    assert '[ "$existing" != "commit $SHA" ]' in tag_step["run"]
    assert 'grep -q "HTTP 404" /tmp/ref.err' in tag_step["run"]
