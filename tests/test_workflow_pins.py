"""What the release workflows are allowed to run, and with what rights.

Nothing visible breaks when one of these goes wrong, which is the whole problem: a workflow that
loads a third-party action by a tag the upstream can move keeps working perfectly right up to the
moment someone else decides what it runs. The signing job holds the Docker Hub token and
`id-token: write`, so code that lands in it can push and cosign-sign under the identity every
deployed updater trusts. That is the 2025 tj-actions/changed-files shape, and these tests are the
only place it fails.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml

WORKFLOWS = sorted((Path(__file__).resolve().parent.parent / ".github/workflows").glob("*.yml"))
# `uses:` with its ref, as a step or a reusable-workflow call. Local `./...` calls have no ref.
_USES = re.compile(r"^\s*(?:-\s+)?uses:\s+(?P<ref>\S+)", re.M)
_SHA_PINNED = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")


def _uses(workflow: Path) -> list[str]:
    return _USES.findall(workflow.read_text())


def test_there_are_workflows_to_check() -> None:
    # the glob silently passing is the one way every test below becomes a no-op
    assert WORKFLOWS, "no workflows found"


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_every_third_party_action_is_pinned_to_a_commit(workflow: Path) -> None:
    # given every action this workflow loads
    refs = _uses(workflow)

    # when the ones from outside this repository are picked out (a ./ reference is this repo's own
    # file at this repo's own commit, so there is nothing for an upstream to move)
    external = [ref for ref in refs if not ref.startswith("./")]

    # then each resolves to a full commit id, never a tag. The version lives in a trailing comment
    # so Dependabot can still propose the bump, as a reviewable change rather than a silent one.
    unpinned = [ref for ref in external if not _SHA_PINNED.match(ref)]
    assert not unpinned, f"{workflow.name}: tag-pinned action(s): {unpinned}"


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_every_pinned_action_records_the_version_it_is(workflow: Path) -> None:
    # given the lines that pin an action by commit
    lines = [
        line
        for line in workflow.read_text().splitlines()
        if re.search(r"uses:\s+[^.\s][^\s]*@[0-9a-f]{40}", line)
    ]

    # then each carries the version as a comment: a bare 40-hex id tells a reviewer nothing, and
    # Dependabot reads that comment to know what it is bumping from
    missing = [line.strip() for line in lines if not re.search(r"#\s*v?\d+\.\d+", line)]
    assert not missing, f"{workflow.name}: pinned without a version comment: {missing}"


def _driver_opts_image(step: dict) -> str | None:
    """The builder image inside setup-buildx-action's `driver-opts`, if it names one.

    That value is a newline-separated list of driver-specific `key=value` settings, of which
    `image=` is the one deciding which BuildKit container the job starts.
    """
    opts = (step.get("with") or {}).get("driver-opts")
    if isinstance(opts, str):
        opts = opts.splitlines()
    if not isinstance(opts, list):
        return None
    for opt in opts:
        key, sep, value = str(opt).strip().partition("=")
        if sep and key == "image":
            return value
    return None


def _images_run(workflow: Path) -> list[str]:
    """Every image reference a workflow asks a runner to *execute*, with where it came from.

    Four places: a job `container:`, a `services:` entry, the `image:` input of a step, and the
    `image=` setting inside a step's `driver-opts` - buildx's builder is named there rather than in
    a plain `image:`. Not the matrix entries that name what is being built - those are push
    destinations, and a digest is the output of that build rather than an input to it.
    """
    document = yaml.safe_load(workflow.read_text())
    found: list[str] = []
    for job in (document.get("jobs") or {}).values():
        if not isinstance(job, dict):
            continue
        for spec in [job.get("container"), *(job.get("services") or {}).values()]:
            if isinstance(spec, str):
                found.append(spec)
            elif isinstance(spec, dict) and spec.get("image"):
                found.append(spec["image"])
        for step in job.get("steps") or []:
            image = (step.get("with") or {}).get("image")
            if isinstance(image, str):
                found.append(image)
            driver_image = _driver_opts_image(step)
            if driver_image:
                found.append(driver_image)
    return [ref for ref in found if "${{" not in ref]


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_every_container_image_a_workflow_runs_is_pinned_by_digest(workflow: Path) -> None:
    # given every image this workflow asks a runner to execute
    images = _images_run(workflow)

    # then each is a digest. setup-qemu-action defaults to tonistiigi/binfmt:latest and runs it
    # --privileged in the job holding the Docker Hub token and id-token: write, so a pinned action
    # with a floating image pins nothing at all - it just moves who gets to decide what runs
    # (ARES-2327 review). An action whose image is left implicit says nothing here at all, which
    # is what the companion test below is for.
    floating = [ref for ref in images if "@sha256:" not in ref]
    assert not floating, f"{workflow.name}: image(s) not pinned by digest: {floating}"


# Actions that start a container of their own and name the image to run only if told to. Leaving
# the value out is NOT neutral: each one then runs the upstream tag below, which is precisely what
# whoever can move that tag wants. The test above cannot see any of these, because there is nothing
# in the workflow file to see - which is what this table is for.
_IMPLICIT_IMAGE_ACTIONS = [
    # action, how to read the image out of one of its steps, what it runs when that is left unset
    (
        "docker/setup-qemu-action",
        lambda step: (step.get("with") or {}).get("image"),
        "tonistiigi/binfmt:latest",
    ),
    ("docker/setup-buildx-action", _driver_opts_image, "moby/buildkit:buildx-stable-1"),
]


def _steps_using(action: str) -> list[tuple[Path, dict]]:
    return [
        (workflow, step)
        for workflow in WORKFLOWS
        for job in (yaml.safe_load(workflow.read_text()).get("jobs") or {}).values()
        for step in (isinstance(job, dict) and job.get("steps")) or []
        if str(step.get("uses", "")).startswith(f"{action}@")
    ]


@pytest.mark.parametrize(
    ("action", "read_image", "upstream_default"),
    _IMPLICIT_IMAGE_ACTIONS,
    ids=[action for action, _, _ in _IMPLICIT_IMAGE_ACTIONS],
)
def test_the_signing_job_pins_every_image_an_action_runs_for_it(
    action: str, read_image: Callable[[dict], str | None], upstream_default: str
) -> None:
    # given every step that loads this action
    steps = _steps_using(action)

    # then each says which image to run, by digest. Both of these start a container in the job
    # holding the Docker Hub token and id-token: write - the emulator --privileged, and the builder
    # as the thing that actually produces the bytes `cosign sign` signs (ARES-2351)
    assert steps, f"no workflow uses {action} any more; drop its row from _IMPLICIT_IMAGE_ACTIONS"
    for workflow, step in steps:
        image = read_image(step) or ""
        assert re.fullmatch(r"\S+@sha256:[0-9a-f]{64}", image), (
            f"{workflow.name}: {action} runs its default {upstream_default}, "
            f"not a pinned image (got {image!r})"
        )


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_every_workflow_declares_its_permissions(workflow: Path) -> None:
    # given the workflow source
    text = workflow.read_text()

    # then it says what the GITHUB_TOKEN may do, at the workflow or the job level. Without a
    # block it takes the repository default, which an org setting can widen underneath it with no
    # change here - tests.yml ran that way until ARES-2327.
    assert re.search(r"^\s*permissions:\s*$", text, re.M), (
        f"{workflow.name}: no permissions: block, so it runs with the repository default"
    )
