"""What auto-tag.yml decides when the release tag already exists.

This is the one workflow step whose mistake is silent by construction. It used to match
``refs/tags/v<version>`` by NAME, report success with ``created=false``, and let the ``images`` job
skip - so an account with push access but no right to merge could create the upcoming tag on a
commit of its own, the run would end green, and the ruleset would then make that foreign commit the
permanent release tag. Every documented install URL fetches ``scripts/bootstrap.sh`` and the
Kubernetes manifest from exactly that tag, before any cosign check the genuine script would do
(ARES-2351).

Nothing about that failure is visible: no error, no alert, and the only symptom is a release with
no images - which the README used to describe as a footgun rather than an attack. So the step is
executed here, against real throwaway repositories, rather than asserted structurally: the whole
question is which commit it accepts, and only git can answer that.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import NamedTuple, Protocol

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[1]
AUTO_TAG = _REPO / ".github/workflows/auto-tag.yml"

# A committer identity and a predictable default branch, so these tests do not depend on the
# machine's ~/.gitconfig and cannot pick up this repository's own hooks or commit templates.
_GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.com",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
}


def _release_step() -> str:
    """The `run:` body of auto-tag.yml's tag-and-release step."""
    document = yaml.safe_load(AUTO_TAG.read_text())
    steps = document["jobs"]["tag"]["steps"]
    matching = [step for step in steps if step.get("id") == "release"]
    assert len(matching) == 1, "auto-tag.yml no longer has exactly one step with id: release"
    return matching[0]["run"]


def _git(cwd: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True, env=_GIT_ENV
    )
    return done.stdout.strip()


class Rehearsal(NamedTuple):
    """One rehearsed release: what the step printed, what it decided, and where it ran."""

    returncode: int
    output: str
    decisions: dict[str, str]
    repo: Path

    @property
    def build(self) -> str | None:
        """What the step told the `images` job, or None when it refused to say."""
        return self.decisions.get("build")


class Release(Protocol):
    def __call__(self, *, tag_at: str | None = ..., moved_on: bool = ...) -> Rehearsal: ...


@pytest.fixture
def release(tmp_path: Path) -> Release:
    """Run auto-tag.yml's release step in a throwaway repo, the way Actions would run it.

    Each call builds a `main` of three commits - 3.14.3, then 3.15.0, then the 3.15.1 bump this
    release is cutting - plus a `sidequest` commit that is NOT reachable from main, which is the
    attacker's commit in the finding. `tag_at` parks `v3.15.1` on one of them by name:

        "bump"         the commit that set 3.15.1 (the honest answer)
        "previous"     an older main commit, reachable but for a different version
        "unreachable"  the commit on no branch
        None           no tag at all

    `moved_on` adds one more commit to main that does not touch the version, so HEAD is past the
    bump - what a `workflow_dispatch` on main looks like once the release has landed.

    `origin` is a real bare repository, so `git push origin "$TAG"` is exercised rather than
    stubbed. Only `gh` is a shim: a GitHub release says nothing about which commit the tag names.
    """

    def _run(*, tag_at: str | None = None, moved_on: bool = False) -> Rehearsal:
        version = "3.15.1"
        repo, remote, shims = tmp_path / "repo", tmp_path / "origin.git", tmp_path / "bin"
        shims.mkdir()
        (shims / "gh").write_text("#!/bin/sh\nexit 0\n")
        (shims / "gh").chmod(0o755)
        subprocess.run(
            ["git", "init", "-q", "--bare", "-b", "main", str(remote)], check=True, env=_GIT_ENV
        )
        repo.mkdir()
        _git(repo, "init", "-q", "-b", "main")
        _git(repo, "remote", "add", "origin", str(remote))
        (repo / "agent").mkdir()

        commits: dict[str, str] = {}
        for name, marker in (("old", "3.14.3"), ("previous", "3.15.0"), ("bump", version)):
            (repo / "agent/__version__.py").write_text(f'__version__ = "{marker}"\n')
            _git(repo, "add", "-A")
            _git(repo, "commit", "-q", "-m", f"release {marker}")
            commits[name] = _git(repo, "rev-parse", "HEAD")

        if moved_on:
            (repo / "README.md").write_text("a change that is not a release\n")
            _git(repo, "add", "-A")
            _git(repo, "commit", "-q", "-m", "docs: something else")
        head = _git(repo, "rev-parse", "HEAD")

        # the attacker's commit: real, on no branch, unreachable from main - and it carries the
        # version the release is about to cut, so only the ancestry check can catch it
        _git(repo, "checkout", "-q", "-b", "sidequest", commits["old"])
        (repo / "agent/__version__.py").write_text(f'__version__ = "{version}"\n')
        (repo / "backdoor").write_text("whatever the operator curls from the tag\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "unreviewed")
        commits["unreachable"] = _git(repo, "rev-parse", "HEAD")
        _git(repo, "checkout", "-q", "main")

        if tag_at is not None:
            _git(repo, "tag", "-a", f"v{version}", "-m", "parked", commits[tag_at])

        out_file = tmp_path / "github_output"
        out_file.write_text("")
        done = subprocess.run(
            ["bash", "-e", "-c", _release_step()],
            cwd=repo,
            capture_output=True,
            text=True,
            env={
                **_GIT_ENV,
                "PATH": f"{shims}{os.pathsep}{os.environ['PATH']}",
                "GITHUB_SHA": head,
                "GITHUB_OUTPUT": str(out_file),
                "GH_TOKEN": "not-a-real-token",
                "TAG": f"v{version}",
                "VERSION": version,
            },
        )
        decisions = dict(
            line.split("=", 1) for line in out_file.read_text().splitlines() if "=" in line
        )
        return Rehearsal(done.returncode, done.stdout + done.stderr, decisions, repo)

    return _run


def test_given_no_tag_then_the_release_is_cut_and_the_images_are_built(release: Release) -> None:
    # given a version bump that has merged with no tag for it yet
    cut = release()

    # then the tag is created, pushed, and the images job is told to run
    assert cut.returncode == 0, cut.output
    assert cut.build == "true"
    assert _git(cut.repo, "ls-remote", "--tags", "origin", "v3.15.1"), "the tag was never pushed"


def test_given_a_tag_on_a_commit_outside_main_then_the_run_fails(release: Release) -> None:
    # given the finding's attack: v<version> created on a commit that is not in main's history,
    # before the version bump merged
    cut = release(tag_at="unreachable")

    # then the run FAILS. It used to succeed here with the build skipped, which is what made the
    # foreign commit the permanent release tag with nobody notified
    assert cut.returncode == 1, cut.output
    assert "not in the history of main" in cut.output
    assert cut.build is None, "a refused tag must not tell the images job anything"


def test_given_a_tag_on_an_older_main_commit_then_the_run_fails(release: Release) -> None:
    # given a tag that IS reachable from main but sits on the wrong commit - which the ancestry
    # check on its own would wave through
    cut = release(tag_at="previous")

    # then the version file at that commit gives it away
    assert cut.returncode == 1, cut.output
    assert "reads '3.15.0' rather than 3.15.1" in cut.output
    assert cut.build is None


def test_given_a_tag_already_on_this_commit_then_the_images_are_still_built(
    release: Release,
) -> None:
    # given a release that was tagged but whose images never published: a hand-pushed tag, or an
    # earlier run that died after `git push origin "$TAG"`
    cut = release(tag_at="bump")

    # then the build runs rather than being skipped. Skipping it is what left "a tag and a release
    # but no images", which the README used to document as something to avoid by hand
    assert cut.returncode == 0, cut.output
    assert cut.build == "true"


def test_given_an_earlier_releases_tag_then_nothing_is_rebuilt(release: Release) -> None:
    # given main that has moved past the commit this version's tag names - a dispatch, say
    cut = release(tag_at="bump", moved_on=True)

    # then the past release is left alone: rebuilding it would publish a different digest under a
    # semver tag that is supposed to name one set of bytes forever
    assert cut.returncode == 0, cut.output
    assert cut.build == "false"
    assert "earlier release" in cut.output
