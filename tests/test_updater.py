"""Companion updater: image-ref parsing, target read, the signature gate, and the backends."""

from __future__ import annotations

import json
import logging
import os
import re
import types
from pathlib import Path

import httpx
import pytest

from updater import dockerd, kube, main, tlsconf, verify
from updater.backend import Role, SelfInspection, UpdatePlan
from updater.config import UpdaterSettings, repo_of, tag_of
from updater.dockerd import DockerBackend
from updater.kube import K8sBackend


def _settings(**over) -> UpdaterSettings:
    return UpdaterSettings(require_signature=False, **over)


@pytest.fixture(autouse=True)
def _clear_verified_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # the verified-digest caches and the retry clock are module globals; isolate them between tests.
    main._verified.clear()
    main._verified_self.clear()
    main._self_retry_after.clear()
    main._apply_retry_after.clear()
    main._declined_downgrades.clear()
    main._declined_rollbacks.clear()
    monkeypatch.setattr(main, "_predecessor_removed", False)
    # Dockerfile.updater writes updater/RELEASE into the image; a checkout has none, and the whole
    # suite quietly depends on that (targets here are older than the repo's own version). Pin it
    # rather than leave it to whether someone built in the working tree.
    monkeypatch.setattr(main, "_RELEASE_FILE", tmp_path / "no-release")
    yield


def test_container_name_reads_the_documented_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # the docs / compose / k8s use ARES_UPDATE_CONTAINER; it must actually set container_name
    # (reading only the *_NAME alias was a silent-misconfig bug).
    monkeypatch.setenv("ARES_UPDATE_CONTAINER", "custom-agent")
    assert _settings().container_name == "custom-agent"


def test_image_ref_parsing() -> None:
    assert tag_of("assailai/ares-agent:2.5.0") == "2.5.0"
    assert repo_of("assailai/ares-agent:2.5.0") == "assailai/ares-agent"
    assert tag_of("assailai/ares-agent") == ""  # no tag
    assert repo_of("reg:5000/ares-agent") == "reg:5000/ares-agent"  # the ":" is a registry port
    assert repo_of("assailai/ares-agent@sha256:abc123") == "assailai/ares-agent"  # digest ref
    assert tag_of("assailai/ares-agent@sha256:abc123") == ""  # a digest is not a tag


def test_read_target(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "update-target.json"
    monkeypatch.setattr(main, "settings", _settings(target_file=target))
    assert main._read_target() is None  # not written yet
    target.write_text('{"version": "2.5.0"}')
    assert main._read_target() == "2.5.0"
    target.write_text("not json")  # malformed is ignored, not crashed on
    assert main._read_target() is None


def test_verify_gate() -> None:
    # dev override returns the ref unpinned (with a warning); fail-closed (None) when on but
    # unconfigured (identity + issuer cleared, no key), even though the image now ships a default
    # signer identity.
    assert verify.verify("img:1", UpdaterSettings(require_signature=False)) == "img:1"
    unconfigured = UpdaterSettings(require_signature=True, cosign_identity="", cosign_issuer="")
    assert verify.verify("img:1", unconfigured) is None


def _san(workflow: str, ref: str, repo: str = "assailai/docker-agent-ares") -> str:
    """A GitHub Actions signer identity as Fulcio writes it into the certificate SAN."""
    return f"https://github.com/{repo}/.github/workflows/{workflow}@{ref}"


def test_default_signer_identity_matches_what_ci_actually_signs_with() -> None:
    # a stock updater (no env) verifies signatures out of the box: identity + issuer are baked in,
    # so the docker-run / compose / k8s install commands do not each spell the regexp out.
    # Assert on the regexp's BEHAVIOUR, not its text: a substring check on the repo name let the
    # default drift to a workflow file that never signs anything, and every update failed closed.
    settings = UpdaterSettings()
    assert settings.require_signature is True
    assert settings.cosign_issuer == "https://token.actions.githubusercontent.com"

    identity = re.compile(settings.cosign_identity)
    # the release path (auto-tag.yml -> docker-build.yml) signs at the caller's ref, refs/heads/main.
    # That is the protected branch, so a merge there has been reviewed.
    assert identity.search(_san("docker-build.yml", "refs/heads/main"))
    # a TAG ref is not ours, whatever it is named. Anyone with push access can create a tag, and
    # nothing in GitHub stopped it, so a v* build would have been an unreviewed commit signed
    # under the identity the whole fleet trusts (ARES-2327).
    assert not identity.search(_san("docker-build.yml", "refs/tags/v3.3.1"))
    assert not identity.search(_san("docker-build.yml", "refs/tags/v99.0.0"))
    # nor is another branch, for the same reason: only main is protected.
    assert not identity.search(_san("docker-build.yml", "refs/heads/feature"))
    # not ours, or not a signer: another owner/repo, the caller workflow that holds no cosign step,
    # and an unmerged PR build (which does not push or sign at all).
    assert not identity.search(_san("docker-build.yml", "refs/heads/main", repo="attacker/evil"))
    assert not identity.search(_san("docker-publish.yml", "refs/heads/main"))
    assert not identity.search(_san("docker-build.yml", "refs/pull/30/merge"))
    # cosign's -regexp flags are substring matches, so the anchors have to hold on both ends.
    assert not identity.search(_san("docker-build.yml", "refs/heads/main") + ".evil.example")
    assert not identity.search("https://evil.example/" + _san("docker-build.yml", "refs/heads/main"))


def test_the_readme_publishes_the_identity_the_updater_actually_uses() -> None:
    # customers verify images by hand with the regexp README.md prints, so a drift between the two
    # sends them chasing a failure that is not there. It has drifted once already.
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()
    assert UpdaterSettings().cosign_identity in readme, (
        "README.md does not publish the updater's current --certificate-identity-regexp"
    )


def test_only_main_can_reach_the_signing_step() -> None:
    # the identity above is only worth what CI will produce. If any workflow can push and sign
    # from another ref, narrowing the regexp just moves the hole rather than closing it.
    workflows = Path(__file__).resolve().parents[1] / ".github" / "workflows"
    if not workflows.is_dir():
        pytest.skip("no .github/workflows checkout (e.g. running inside the built image)")

    build = (workflows / "docker-build.yml").read_text()
    assert "github.ref != 'refs/heads/main'" in build, "no ref guard in front of the push and sign"
    assert "environment:" in build, "the Docker Hub credentials are not held in an environment"

    # no entry workflow may build release images off a tag push: any pusher can create a tag.
    for name in ("docker-publish.yml", "auto-tag.yml"):
        triggers = (workflows / name).read_text().split("\njobs:")[0]
        live = [line for line in triggers.splitlines() if not line.lstrip().startswith("#")]
        assert not [line for line in live if re.match(r"\s*tags:", line)], (
            f"{name} still triggers on a tag push"
        )


def test_default_signer_identity_names_the_workflow_that_signs() -> None:
    # the regexp must name the workflow file containing the `cosign sign` step, because Fulcio takes
    # the certificate SAN from the OIDC job_workflow_ref claim - the file holding the signing job,
    # not the entrypoint workflow that calls it. Deriving the expected file from CI (rather than
    # hardcoding it here) is what catches the signing step moving between workflows again.
    workflows = Path(__file__).resolve().parents[1] / ".github" / "workflows"
    if not workflows.is_dir():
        pytest.skip("no .github/workflows checkout (e.g. running inside the built image)")
    signing = sorted(p.name for p in workflows.glob("*.yml") if "cosign sign" in p.read_text())
    assert signing, "no workflow runs `cosign sign`; the updater's identity regexp is unverifiable"

    identity = re.compile(UpdaterSettings().cosign_identity)
    for workflow in signing:
        assert identity.search(_san(workflow, "refs/heads/main")), (
            f"{workflow} signs images but its identity does not match the updater's regexp"
        )


def test_verify_pins_the_cosign_verified_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    # cosign resolves the tag and attests a digest; verify returns that exact digest pinned to
    # the repo, so the caller applies the verified content rather than re-resolving the tag.
    payload = '[{"critical": {"image": {"docker-manifest-digest": "sha256:abc123"}}}]'
    monkeypatch.setattr(
        verify.subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=payload, stderr=""),
    )
    pinned = verify.verify(
        "assailai/ares-agent:3.0.0",
        UpdaterSettings(require_signature=True, cosign_identity="^id$", cosign_issuer="iss"),
    )
    assert pinned == "assailai/ares-agent@sha256:abc123"


def test_docker_running_image(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"Config": {"Image": "assailai/ares-agent:2.4.0"}})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://docker")
    monkeypatch.setattr(dockerd, "_client", lambda: client)
    assert DockerBackend().running_image(_settings()) == "assailai/ares-agent:2.4.0"


def test_docker_apply_verifies_new_then_swaps(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.url.path == "/containers/create":
            return httpx.Response(201, json={"Id": "new123"})
        if request.url.path.endswith("/json"):
            return httpx.Response(200, json={"Config": {}, "HostConfig": {}, "State": {"Running": True}})
        return httpx.Response(200, text="")

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://docker")
    monkeypatch.setattr(dockerd, "_client", lambda: client)
    monkeypatch.setattr(dockerd.time, "sleep", lambda _s: None)
    monkeypatch.setattr(dockerd, "_VERIFY_CHECKS", 1)

    DockerBackend().apply(_settings(), UpdatePlan(agent="assailai/ares-agent:2.5.0"))

    # pulled, created the replacement, started it, then removed the old and renamed the new in.
    assert ("POST", "/images/create") in calls
    assert ("POST", "/containers/create") in calls
    assert ("POST", "/containers/new123/start") in calls
    assert ("DELETE", "/containers/ares-agent") in calls
    assert ("POST", "/containers/new123/rename") in calls


def _apply_capturing_create_body(
    monkeypatch: pytest.MonkeyPatch, *, old_container: dict, image_response: httpx.Response
) -> dict:
    """Run one ``apply`` against a mocked dockerd and return the ``/containers/create`` body."""
    bodies: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/containers/create":
            bodies.append(json.loads(request.content))
            return httpx.Response(201, json={"Id": "new123"})
        if path.startswith("/images/") and path.endswith("/json"):
            return image_response
        if path.endswith("/json"):
            return httpx.Response(200, json=old_container)
        return httpx.Response(200, text="")

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://docker")
    monkeypatch.setattr(dockerd, "_client", lambda: client)
    monkeypatch.setattr(dockerd.time, "sleep", lambda _s: None)
    monkeypatch.setattr(dockerd, "_VERIFY_CHECKS", 1)

    DockerBackend().apply(_settings(), UpdatePlan(agent="assailai/ares-agent:3.3.3"))

    assert len(bodies) == 1
    return bodies[0]


_OLD_CONTAINER = {
    "Image": "sha256:oldimage",
    "Config": {
        "Env": ["ARES_TOKEN=t", "PATH=/usr/bin"],
        # the version label was inherited from the OLD image; customer.tier is the operator's own.
        "Labels": {"org.opencontainers.image.version": "3.3.0", "customer.tier": "gold"},
        "Entrypoint": ["/old-entrypoint"],
        "Cmd": ["serve"],
        "Healthcheck": {"Test": ["CMD", "/old-check"]},
        "User": "10001",
        "WorkingDir": "/old-app",
    },
    "HostConfig": {
        "Binds": ["ares-agent-data:/data", "/etc/ssl/certs:/host-ca:ro"],
        "RestartPolicy": {"Name": "always"},
    },
    "State": {"Running": True},
}


def test_docker_apply_carries_only_the_operator_owned_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The replacement must not shadow the new image's own config with the old image's.

    Regression (July 2026): ``apply`` copied the old container's whole ``Config`` forward, so an
    updated agent kept reporting ``org.opencontainers.image.version`` from the version it was FIRST
    deployed at - ``docker inspect`` claimed 3.3.0 on a container genuinely running 3.3.2 - and a
    release that changed its entrypoint or healthcheck would have been silently ignored.
    """
    body = _apply_capturing_create_body(
        monkeypatch,
        old_container=_OLD_CONTAINER,
        image_response=httpx.Response(
            200, json={"Config": {"Labels": {"org.opencontainers.image.version": "3.3.0"}}}
        ),
    )

    # the image-contributed label is left unset, so the NEW image's real version comes through and
    # docker inspect reports what the agent is actually running.
    assert body["Labels"] == {"customer.tier": "gold"}
    # what the operator owns survives: env (ARES_TOKEN et al) and the whole HostConfig.
    assert body["Env"] == ["ARES_TOKEN=t", "PATH=/usr/bin"]
    assert body["HostConfig"] == _OLD_CONTAINER["HostConfig"]
    # the host CA mount specifically. This is why the fix is a mount rather than a `docker cp`
    # into the container: a copied-in root CA lives in the writable layer, which the recreate
    # throws away, so an auto-update would silently break TLS again on a customer's inspecting
    # network. A bind is HostConfig, and HostConfig is carried over whole.
    assert "/etc/ssl/certs:/host-ca:ro" in body["HostConfig"]["Binds"]
    assert body["Image"] == "assailai/ares-agent:3.3.3"
    # everything the image owns is left to the new image rather than pinned to the old one.
    for key in ("Entrypoint", "Cmd", "Healthcheck", "User", "WorkingDir"):
        assert key not in body, f"{key} must come from the new image, not the old container"


@pytest.mark.parametrize("reported", [0, -1, None])
def test_docker_apply_does_not_replay_an_unset_swappiness(
    monkeypatch: pytest.MonkeyPatch, reported: int | None
) -> None:
    # given Podman's inspect of a container that never set a swappiness (it reports 0; Docker
    # reports null or -1), on a cgroup v2 host where crun refuses any explicit value
    host_config = {**_OLD_CONTAINER["HostConfig"], "MemorySwappiness": reported}
    old = {**_OLD_CONTAINER, "HostConfig": host_config}

    # when the updater re-creates the agent from it
    body = _apply_capturing_create_body(
        monkeypatch, old_container=old, image_response=httpx.Response(200, json={"Config": {}})
    )

    # then the swappiness is left unset, and everything else the operator set is carried over
    assert "MemorySwappiness" not in body["HostConfig"]
    assert body["HostConfig"]["Binds"] == _OLD_CONTAINER["HostConfig"]["Binds"]
    assert body["HostConfig"]["RestartPolicy"] == {"Name": "always"}


def test_docker_apply_keeps_a_swappiness_the_operator_actually_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host_config = {**_OLD_CONTAINER["HostConfig"], "MemorySwappiness": 10}
    old = {**_OLD_CONTAINER, "HostConfig": host_config}

    body = _apply_capturing_create_body(
        monkeypatch, old_container=old, image_response=httpx.Response(200, json={"Config": {}})
    )

    assert body["HostConfig"]["MemorySwappiness"] == 10


def test_docker_apply_replays_a_podman_cpu_limit_without_the_conflicting_nanocpus(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given Podman's inspect of an agent run with --cpus=1.5: the limit three ways at once, which
    # its own compat create refuses ("NanoCpus conflicts with CpuPeriod and CpuQuota")
    cpu = {"CpuPeriod": 100000, "CpuQuota": 150000, "NanoCpus": 1500000000}
    host_config = {**_OLD_CONTAINER["HostConfig"], **cpu}
    old = {**_OLD_CONTAINER, "HostConfig": host_config}

    # when the updater re-creates the agent from it
    body = _apply_capturing_create_body(
        monkeypatch, old_container=old, image_response=httpx.Response(200, json={"Config": {}})
    )

    # then the limit survives as period and quota, which are the exact original
    assert "NanoCpus" not in body["HostConfig"]
    assert body["HostConfig"]["CpuPeriod"] == 100000
    assert body["HostConfig"]["CpuQuota"] == 150000


def test_docker_apply_keeps_a_docker_cpu_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    # Docker reports --cpus as NanoCpus alone, with period and quota zero: nothing to drop.
    host_config = {**_OLD_CONTAINER["HostConfig"], "NanoCpus": 1500000000, "CpuPeriod": 0}
    old = {**_OLD_CONTAINER, "HostConfig": host_config}

    body = _apply_capturing_create_body(
        monkeypatch, old_container=old, image_response=httpx.Response(200, json={"Config": {}})
    )

    assert body["HostConfig"]["NanoCpus"] == 1500000000


def test_docker_apply_removes_a_replacement_it_could_not_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given an engine that creates the replacement but refuses to start it (as Podman did on
    # cgroup v2 before the swappiness fix)
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        path = request.url.path
        if path == "/containers/create":
            return httpx.Response(201, json={"Id": "new123"})
        if path == "/containers/new123/start":
            return httpx.Response(500, json={"message": "crun: OCI runtime error"})
        if path.startswith("/images/") and path.endswith("/json"):
            return httpx.Response(200, json={"Config": {}})
        if path.endswith("/json"):
            return httpx.Response(200, json=_OLD_CONTAINER)
        return httpx.Response(204)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://docker")
    monkeypatch.setattr(dockerd, "_client", lambda: client)

    # when the updater applies an update, then the failure still surfaces to the caller
    with pytest.raises(httpx.HTTPStatusError):
        DockerBackend().apply(_settings(), UpdatePlan(agent="assailai/ares-agent:3.3.3"))

    # and the half-made replacement is gone, while the running agent is untouched
    after_start = calls[calls.index(("POST", "/containers/new123/start")) + 1 :]
    assert ("DELETE", "/containers/ares-agent-next") in after_start
    assert ("DELETE", "/containers/ares-agent") not in calls


def test_docker_apply_drops_labels_when_the_old_image_is_unreadable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unreadable old image: keep no labels at all rather than carrying the stale ones.

    Losing a custom operator label is the safe direction; reporting a version the agent is not
    running is not.
    """
    body = _apply_capturing_create_body(
        monkeypatch,
        old_container=_OLD_CONTAINER,
        image_response=httpx.Response(404, json={"message": "no such image"}),
    )

    assert "Labels" not in body
    assert body["Env"] == ["ARES_TOKEN=t", "PATH=/usr/bin"]  # env still survives


def test_k8s_apply_patches_the_deployment_image(monkeypatch: pytest.MonkeyPatch) -> None:
    deployment = _FakeDeployment().install(monkeypatch)

    assert K8sBackend().apply(_settings(), UpdatePlan(agent="assailai/ares-agent:2.5.0")) is True
    assert deployment.patched(0)[0] == {"name": "ares-agent", "image": "assailai/ares-agent:2.5.0"}


class _FakeBackend:
    """Stand-in backend that records what it was asked to apply. Unmanaged by default, so a test
    about the agent sees only the agent."""

    def __init__(
        self,
        running: str | None,
        me: SelfInspection | None = None,
        apply_result: bool = True,
    ) -> None:
        self.running = running
        self.me = me or SelfInspection(role=Role.UNMANAGED)
        self.plan: UpdatePlan | None = None
        self.predecessor_removals = 0
        self.apply_result = apply_result  # False = the agent was left where it was

    @property
    def applied(self) -> str | None:
        return self.plan.agent if self.plan else None

    def available(self) -> bool:
        return True

    def running_image(self, settings: UpdaterSettings) -> str | None:
        return self.running

    def inspect_self(self, settings: UpdaterSettings) -> SelfInspection:
        return self.me

    def remove_predecessor(self, settings: UpdaterSettings) -> None:
        self.predecessor_removals += 1

    def apply(self, settings: UpdaterSettings, plan: UpdatePlan) -> bool:
        self.plan = plan
        return self.apply_result


def test_tick_derives_repo_from_the_running_image(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "settings", _settings())  # image_repo unset -> derive
    monkeypatch.setattr(main, "_read_target", lambda: "2.5.0")
    backend = _FakeBackend(running="assailai/ares-agent:2.4.0")
    main._tick(backend)
    assert backend.applied == "assailai/ares-agent:2.5.0"


def test_tick_noop_when_already_on_target(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "2.5.0")
    backend = _FakeBackend(running="assailai/ares-agent:2.5.0")
    main._tick(backend)
    assert backend.applied is None


def test_tick_applies_the_verified_digest_then_noops(monkeypatch: pytest.MonkeyPatch) -> None:
    # the tick applies the DIGEST verify returned (not the tag), closing the TOCTOU; once the
    # agent runs that digest, the cache makes a re-tick a noop (no churn, no re-verify).
    monkeypatch.setattr(main, "settings", _settings())  # verify is mocked below, so the gate is moot
    monkeypatch.setattr(main, "_read_target", lambda: "2.5.0")
    pinned = "assailai/ares-agent@sha256:abc123"
    monkeypatch.setattr(main.verify, "verify", lambda image, settings: pinned)

    backend = _FakeBackend(running="assailai/ares-agent:2.4.0")
    main._tick(backend)
    assert backend.applied == pinned  # the verified digest, not the 2.5.0 tag

    backend.running, backend.plan = pinned, None  # agent now runs the pinned digest
    main._tick(backend)
    assert backend.applied is None  # cache hit -> no re-apply


# --- the updater updating itself (ARES-2049) ------------------------------------------------------

_UPDATER = "docker.io/assailai/ares-updater"
_MY_ID = "a1b2c3d4e5f6" + "0" * 52  # the engine sets a container's hostname to its first 12 chars


def _updater_container(*, instance: str = "", container_id: str = _MY_ID) -> dict:
    """An updater container as the engine reports it: its env, its socket mount, its image."""
    env = ["ARES_UPDATE_CONTAINER=ares-agent", "PATH=/usr/bin"]
    if instance:
        env.append(f"ARES_UPDATE_INSTANCE={instance}")
    return {
        "Id": container_id,
        "Image": "sha256:updaterimage",
        "Config": {"Image": f"{_UPDATER}:3.13.2", "Env": env, "Labels": {}},
        "HostConfig": {
            "Binds": ["ares-agent-data:/data:ro", "/var/run/docker.sock:/var/run/docker.sock"],
            "RestartPolicy": {"Name": "always"},
        },
        "State": {"Running": True},
    }


class _FakeEngine:
    """A Docker engine that records every call in order, for asserting the handoff's sequence."""

    def __init__(
        self,
        *,
        me: dict | None,
        successor_runs: bool = True,
        successor_restarting: bool = False,
        successor_restarts: int = 0,
        take_fails: bool = False,
    ) -> None:
        self.me = me
        self.successor = {
            "State": {"Running": successor_runs, "Restarting": successor_restarting},
            "RestartCount": successor_restarts,
        }
        self.take_fails = take_fails
        self.calls: list[tuple[str, str, str]] = []  # (method, path, name param)
        self.created: list[dict] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        self.calls.append((method, path, request.url.params.get("name", "")))
        if path == "/containers/create":
            self.created.append(json.loads(request.content))
            return httpx.Response(201, json={"Id": f"new{len(self.created)}"})
        if path in ("/containers/ares-updater/json", "/containers/ares-agent/json"):
            if self.me is None:
                return httpx.Response(404, json={})
            return httpx.Response(200, json=self.me)
        if path.startswith("/containers/new") and path.endswith("/json"):
            return httpx.Response(200, json=self.successor)
        if path.endswith("/rename") and self.take_fails and path.startswith("/containers/new"):
            return httpx.Response(409, json={"message": "name in use"})
        return httpx.Response(200, text="")

    def install(self, monkeypatch: pytest.MonkeyPatch, *, hostname: str = _MY_ID[:12]) -> None:
        monkeypatch.setattr(dockerd.socket, "gethostname", lambda: hostname)
        # a fresh client per call, as the real one is: a plan that moves both opens it twice
        transport = httpx.MockTransport(self.handler)
        monkeypatch.setattr(
            dockerd, "_client", lambda: httpx.Client(transport=transport, base_url="http://docker")
        )
        monkeypatch.setattr(dockerd.time, "sleep", lambda _s: None)
        monkeypatch.setattr(dockerd, "_VERIFY_CHECKS", 1)

    def index(self, method: str, path: str, name: str = "") -> int:
        """Where a call LAST happened: the handoff also clears leftovers by the same names first."""
        return len(self.calls) - 1 - self.calls[::-1].index((method, path, name))


def test_a_manually_installed_updater_owns_its_container(monkeypatch: pytest.MonkeyPatch) -> None:
    # given the updater an install started (no stamp), whose hostname is that container's short id
    _FakeEngine(me=_updater_container()).install(monkeypatch)

    # when it inspects the container that holds its name
    me = DockerBackend().inspect_self(_settings())

    # then that container is its own, and it reports the image it runs
    assert me == SelfInspection(role=Role.OWNER, image=f"{_UPDATER}:3.13.2")


@pytest.mark.parametrize(
    "hostname",
    ["0f0f0f0f0f0f", "agent-host-01"],
    ids=["another-installs-updater", "operator-set-hostname"],
)
def test_an_installed_updater_that_cannot_prove_the_container_is_its_own_leaves_it_alone(
    hostname: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # given a second install on the host whose updater kept the default name, so "ares-updater" is
    # the FIRST install's updater; or an operator-set hostname that is no container id
    _FakeEngine(me=_updater_container()).install(monkeypatch, hostname=hostname)

    # when it inspects ares-updater
    me = DockerBackend().inspect_self(_settings())

    # then it is unmanaged: it keeps updating its agent and never hands over a container it cannot
    # prove is its own (standing by instead would stop its agent's updates)
    assert me.role is Role.UNMANAGED


def test_a_successor_stands_by_while_its_predecessor_holds_the_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given a successor (stamped "abc") whose predecessor still holds the ares-updater name
    _FakeEngine(me=_updater_container()).install(monkeypatch)

    # when the successor inspects ares-updater mid-handoff
    me = DockerBackend().inspect_self(_settings(instance="abc"))

    # then it is not its own: acting on it would start a handoff of the predecessor
    assert me.role is Role.STANDBY


def test_a_successor_owns_the_name_once_it_holds_it(monkeypatch: pytest.MonkeyPatch) -> None:
    # given the handoff finished: ares-updater now carries the successor's own stamp
    _FakeEngine(me=_updater_container(instance="abc")).install(monkeypatch)

    # when the successor inspects it, then it is the owner
    assert DockerBackend().inspect_self(_settings(instance="abc")).role is Role.OWNER


def test_an_updater_run_under_another_name_is_unmanaged(monkeypatch: pytest.MonkeyPatch) -> None:
    # given nothing named ares-updater (e.g. a compose project that never set container_name)
    _FakeEngine(me=None).install(monkeypatch)

    # when it inspects, then it cannot find itself: it updates the agent and never itself
    assert DockerBackend().inspect_self(_settings()).role is Role.UNMANAGED


def test_docker_hands_over_to_a_successor_then_removes_itself(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given an updater that a previous handoff started (it carries stamp "old")
    engine = _FakeEngine(me=_updater_container(instance="old"))
    engine.install(monkeypatch)

    # when it moves itself to the new release
    DockerBackend().apply(_settings(), UpdatePlan(updater=f"{_UPDATER}@sha256:new"))

    # then the successor runs the new image with this container's settings and socket...
    (body,) = engine.created
    assert body["Image"] == f"{_UPDATER}@sha256:new"
    assert "/var/run/docker.sock:/var/run/docker.sock" in body["HostConfig"]["Binds"]
    assert "ARES_UPDATE_CONTAINER=ares-agent" in body["Env"]
    # ...under a fresh stamp that REPLACES the inherited one: two containers must never share one
    stamps = [e for e in body["Env"] if e.startswith("ARES_UPDATE_INSTANCE=")]
    assert len(stamps) == 1 and stamps != ["ARES_UPDATE_INSTANCE=old"]
    # and only once it stays up does this updater step aside, hand over the name, and go
    started = engine.index("POST", "/containers/new1/start")
    aside = engine.index("POST", "/containers/ares-updater/rename", name="ares-updater-old")
    taken = engine.index("POST", "/containers/new1/rename", name="ares-updater")
    removed = engine.index("DELETE", "/containers/ares-updater-old")
    assert started < aside < taken < removed
    assert removed == len(engine.calls) - 1  # removing itself is the last thing it does


def test_docker_keeps_the_updater_when_its_successor_does_not_stay_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given a successor that crashes as soon as it starts
    engine = _FakeEngine(me=_updater_container(), successor_runs=False)
    engine.install(monkeypatch)

    # when the updater tries to hand over
    DockerBackend().apply(_settings(), UpdatePlan(updater=f"{_UPDATER}@sha256:new"))

    # then the successor is removed and this updater never gave up its name
    assert ("DELETE", "/containers/new1", "") in engine.calls
    assert not [c for c in engine.calls if c[1].endswith("/rename")]


@pytest.mark.parametrize(
    "crash",
    [{"successor_restarting": True}, {"successor_restarts": 1}],
    ids=["restarting", "restarted-once"],
)
def test_docker_keeps_the_updater_when_its_successor_is_crash_looping(
    crash: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    # given a successor that dies on start and comes back under the restart policy it inherited:
    # the engine still reports it Running, with Restarting set or a RestartCount above zero
    engine = _FakeEngine(me=_updater_container(), **crash)
    engine.install(monkeypatch)

    # when the updater tries to hand over
    DockerBackend().apply(_settings(), UpdatePlan(updater=f"{_UPDATER}@sha256:new"))

    # then it does not hand its name to a container that cannot stay up (the e2e found this one)
    assert ("DELETE", "/containers/new1", "") in engine.calls
    assert not [c for c in engine.calls if c[1].endswith("/rename")]


def test_docker_keeps_the_old_agent_when_the_new_one_is_crash_looping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given a new agent the engine reports Running while its restart policy brings it back
    engine = _FakeEngine(me=_updater_container(), successor_restarts=3)
    engine.install(monkeypatch)

    # when the agent is moved
    DockerBackend().apply(_settings(), UpdatePlan(agent="assailai/ares-agent@sha256:a"))

    # then the old agent is kept, not deleted for a replacement that never stays up
    assert ("DELETE", "/containers/ares-agent", "") not in engine.calls
    assert ("DELETE", "/containers/new1", "") in engine.calls


def test_docker_apply_reports_whether_the_agent_moved(monkeypatch: pytest.MonkeyPatch) -> None:
    # _tick keys its backoff off this answer, so the backend has to give a real one rather than
    # let a crash-looping image be retried every poll_seconds forever
    healthy = _FakeEngine(me=_updater_container())
    healthy.install(monkeypatch)
    moved = DockerBackend().apply(_settings(), UpdatePlan(agent="assailai/ares-agent@sha256:a"))

    crash_looping = _FakeEngine(me=_updater_container(), successor_restarts=3)
    crash_looping.install(monkeypatch)
    left = DockerBackend().apply(_settings(), UpdatePlan(agent="assailai/ares-agent@sha256:a"))

    assert moved is True
    assert left is False


def test_docker_takes_its_name_back_when_the_successor_cannot_take_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given a successor that comes up but cannot be renamed into ares-updater
    engine = _FakeEngine(me=_updater_container(), take_fails=True)
    engine.install(monkeypatch)

    # when the updater hands over, then the failure surfaces...
    with pytest.raises(httpx.HTTPStatusError):
        DockerBackend().apply(_settings(), UpdatePlan(updater=f"{_UPDATER}@sha256:new"))

    # ...after it took its own name back and removed the successor, rather than removing itself
    back = engine.index("POST", "/containers/ares-updater-old/rename", name="ares-updater")
    assert engine.index("DELETE", "/containers/new1") > back
    assert ("DELETE", "/containers/ares-updater-old", "") not in engine.calls[back:]


def test_docker_moves_the_agent_before_the_updater(monkeypatch: pytest.MonkeyPatch) -> None:
    # given both behind
    engine = _FakeEngine(me=_updater_container())
    engine.install(monkeypatch)

    # when one plan moves both
    plan = UpdatePlan(agent="assailai/ares-agent@sha256:a", updater=f"{_UPDATER}@sha256:u")
    DockerBackend().apply(_settings(), plan)

    # then the agent's replacement is created and renamed in before the updater's successor exists
    assert [b["Image"] for b in engine.created] == [plan.agent, plan.updater]
    agent_done = engine.index("POST", "/containers/new1/rename", name="ares-agent")
    assert agent_done < engine.index("POST", "/containers/new2/start")


def test_docker_leaves_the_updater_alone_when_the_agent_swap_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given an agent replacement that does not stay up
    engine = _FakeEngine(me=_updater_container(), successor_runs=False)
    engine.install(monkeypatch)

    # when one plan moves both
    plan = UpdatePlan(agent="assailai/ares-agent@sha256:a", updater=f"{_UPDATER}@sha256:u")
    DockerBackend().apply(_settings(), plan)

    # then the updater does not move while the agent is not on the target
    assert [b["Image"] for b in engine.created] == [plan.agent]


def test_docker_removes_a_predecessor_that_failed_to_remove_itself(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given a successor that now holds the name
    engine = _FakeEngine(me=_updater_container())
    engine.install(monkeypatch)

    # when it removes its predecessor
    DockerBackend().remove_predecessor(_settings())

    # then that is the stepped-aside container, and nothing else
    assert engine.calls == [("DELETE", "/containers/ares-updater-old", "")]


class _FakeDeployment:
    """The agent Deployment as the API server reports it.

    PATCHes mutate the pod template and bump metadata.generation, the way the apiserver does
    synchronously; GETs return that spec plus the status the test drives. ``ready_after`` is how
    many polls the rollout takes to report itself up, and ``ready_for`` how long it stays that way
    before falling over again (a crash loop is Ready between restarts).
    """

    def __init__(
        self,
        *,
        containers: list[dict] | None = None,
        replicas: int = 1,
        ready_after: int = 0,
        ready_for: int | None = None,
        observes_after: int = 0,
        rollback_status: int = 200,
    ) -> None:
        self.containers = containers if containers is not None else [
            {"name": "ares-agent", "image": "assailai/ares-agent:2.4.0"},
            {"name": "ares-updater", "image": f"{_UPDATER}:2.4.0"},
        ]
        self.replicas = replicas
        self.ready_after = ready_after
        self.ready_for = ready_for
        self.observes_after = observes_after
        self.rollback_status = rollback_status
        self.generation = 1
        self.observed = 1
        self.patches: list[dict] = []
        self.polls = 0

    def _status(self) -> dict:
        # before the first patch the Deployment is simply up; afterwards the test drives it.
        if not self.patches:
            return {
                "observedGeneration": self.generation,
                "updatedReplicas": self.replicas,
                "readyReplicas": self.replicas,
                "availableReplicas": self.replicas,
            }
        observed = self.generation if self.polls >= self.observes_after else self.generation - 1
        up = self.polls >= self.ready_after
        if up and self.ready_for is not None and self.polls >= self.ready_after + self.ready_for:
            up = False  # came up, then fell over: CrashLoopBackOff
        return {
            "observedGeneration": observed,
            "updatedReplicas": self.replicas if up else 0,
            "readyReplicas": self.replicas if up else 0,
            "availableReplicas": self.replicas if up else 0,
        }

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.method == "PATCH":
            body = json.loads(request.read())
            self.patches.append(body)
            if len(self.patches) > 1 and self.rollback_status != 200:
                return httpx.Response(self.rollback_status, json={})
            wanted = {c["name"]: c["image"] for c in body["spec"]["template"]["spec"]["containers"]}
            for container in self.containers:
                if container["name"] in wanted:
                    container["image"] = wanted[container["name"]]
            self.generation += 1
            self.polls = 0
            return httpx.Response(200, json={})
        self.polls += 1
        return httpx.Response(
            200,
            json={
                "metadata": {"generation": self.generation},
                "spec": {"replicas": self.replicas, "template": {"spec": {"containers": self.containers}}},
                "status": self._status(),
            },
        )

    def install(self, monkeypatch: pytest.MonkeyPatch) -> _FakeDeployment:
        # a fresh client per call, as the real _client() is: it reads the SA token each time, and
        # an httpx.Client cannot be reopened once a `with` block has closed it.
        monkeypatch.setattr(
            kube,
            "_client",
            lambda: httpx.Client(transport=httpx.MockTransport(self.handler), base_url="https://k8s"),
        )
        monkeypatch.setattr(kube, "_namespace", lambda _s: "default")
        # A fake clock advanced by sleep, not a no-op sleep: the gate polls against a wall-clock
        # deadline, so a no-op would spin forever, and patching the deadline down to 1 would stop
        # the tests exercising the real constant.
        clock = types.SimpleNamespace(now=1000.0)
        self.clock = clock
        monkeypatch.setattr(kube.time, "sleep", lambda s: setattr(clock, "now", clock.now + s))
        monkeypatch.setattr(kube.time, "monotonic", lambda: clock.now)
        monkeypatch.setattr(kube, "_said_not_rolled_out", False)
        return self

    def patched(self, index: int) -> list[dict]:
        return self.patches[index]["spec"]["template"]["spec"]["containers"]

    @property
    def images(self) -> dict[str, str]:
        return {c["name"]: c["image"] for c in self.containers}


def _k8s_deployment(monkeypatch: pytest.MonkeyPatch, containers: list[dict]) -> list[dict]:
    """Serve a healthy Deployment with ``containers``; return the patches the backend sends."""
    return _FakeDeployment(containers=containers).install(monkeypatch).patches


def test_k8s_moves_the_agent_and_the_updater_in_one_rollout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given the agent Deployment, with the updater as its sidecar
    deployment = _FakeDeployment().install(monkeypatch)

    # when both are behind
    plan = UpdatePlan(agent="assailai/ares-agent@sha256:a", updater=f"{_UPDATER}@sha256:u")
    assert K8sBackend().apply(_settings(), plan) is True

    # then one patch sets both images, so the pod rolls once rather than twice, and the rollback
    # never ran
    assert len(deployment.patches) == 1
    assert deployment.patched(0) == [
        {"name": "ares-agent", "image": plan.agent},
        {"name": "ares-updater", "image": plan.updater},
    ]


def test_k8s_moves_only_the_updater_when_the_agent_is_current(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given an agent already on the target
    deployment = _FakeDeployment().install(monkeypatch)

    # when only the updater moves
    assert K8sBackend().apply(_settings(), UpdatePlan(updater=f"{_UPDATER}@sha256:u")) is True

    # then the patch names the updater container alone
    assert len(deployment.patches) == 1
    assert deployment.patched(0) == [{"name": "ares-updater", "image": f"{_UPDATER}@sha256:u"}]


def test_k8s_apply_waits_for_the_rollout_before_reporting_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given a rollout that comes up straight away
    deployment = _FakeDeployment().install(monkeypatch)

    # when the agent is moved
    assert K8sBackend().apply(_settings(), UpdatePlan(agent="assailai/ares-agent@sha256:a")) is True

    # then it did not take the first Ready as proof: a crash-looping container is Ready between
    # restarts, so the condition has to hold across consecutive polls (as dockerd's _stays_up does)
    assert deployment.polls >= kube._ROLLOUT_SETTLE_CHECKS
    assert len(deployment.patches) == 1


def test_k8s_apply_does_not_read_the_pre_patch_status_as_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given a controller that takes four polls to notice the patch at all. Until it does, status
    # is the one from BEFORE the patch - which says Ready.
    deployment = _FakeDeployment(observes_after=4).install(monkeypatch)

    # when the agent is moved
    assert K8sBackend().apply(_settings(), UpdatePlan(agent="assailai/ares-agent@sha256:a")) is True

    # then observedGeneration held it back. Without that check the first three polls would have
    # settled it, because the status they carry is the pre-patch one and it says Ready - which is
    # how every failed rollout used to read as a success.
    assert deployment.polls > kube._ROLLOUT_SETTLE_CHECKS


def test_k8s_apply_rolls_back_the_agent_when_the_new_pod_never_becomes_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given a signed image that cannot run here at all (a wrong-architecture platform digest, or
    # any signed build that dies at startup): the pod never reports Ready
    deployment = _FakeDeployment(ready_after=10**6).install(monkeypatch)
    started = deployment.clock.now

    # when the agent is moved to it
    moved = K8sBackend().apply(_settings(), UpdatePlan(agent="assailai/ares-agent@sha256:broken"))

    # then the previous image is put back, and the caller is told the agent did not move. k8s does
    # not do this by itself: progressDeadlineSeconds only writes a status condition.
    assert moved is False
    assert deployment.patched(1) == [{"name": "ares-agent", "image": "assailai/ares-agent:2.4.0"}]
    assert deployment.images["ares-agent"] == "assailai/ares-agent:2.4.0"
    assert deployment.clock.now - started >= kube._ROLLOUT_DEADLINE


def test_k8s_apply_rolls_back_the_agent_when_it_does_not_stay_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given a pod that comes up and then falls over before the settle window closes: the k8s twin
    # of test_docker_keeps_the_old_agent_when_the_new_one_is_crash_looping
    deployment = _FakeDeployment(ready_after=1, ready_for=1).install(monkeypatch)

    moved = K8sBackend().apply(_settings(), UpdatePlan(agent="assailai/ares-agent@sha256:flaky"))

    assert moved is False
    assert deployment.images["ares-agent"] == "assailai/ares-agent:2.4.0"


def test_k8s_apply_restores_both_images_when_a_combined_rollout_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # one patch is one rollout, so "skip the updater" has no meaning here the way it does on
    # Docker; the coherent equivalent is that nothing moved
    deployment = _FakeDeployment(ready_after=10**6).install(monkeypatch)

    plan = UpdatePlan(agent="assailai/ares-agent@sha256:a", updater=f"{_UPDATER}@sha256:u")
    assert K8sBackend().apply(_settings(), plan) is False

    assert deployment.patched(1) == [
        {"name": "ares-agent", "image": "assailai/ares-agent:2.4.0"},
        {"name": "ares-updater", "image": f"{_UPDATER}:2.4.0"},
    ]


def test_k8s_apply_says_so_when_it_cannot_roll_back(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # the agent is down and we cannot put it back: the log is the only thing standing between an
    # operator and a silent outage, so it has to name what to restore
    deployment = _FakeDeployment(ready_after=10**6, rollback_status=403).install(monkeypatch)

    with caplog.at_level(logging.ERROR, logger="ares.updater.k8s"):
        moved = K8sBackend().apply(_settings(), UpdatePlan(agent="assailai/ares-agent@sha256:a"))

    assert moved is False
    assert "assailai/ares-agent:2.4.0" in caplog.text
    assert "rollout undo" in caplog.text
    assert len(deployment.patches) == 2


def test_k8s_apply_treats_a_scaled_down_deployment_as_rolled_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # an operator who scaled the agent to zero must not get an infinite wait and a spurious
    # rollback on every tick
    deployment = _FakeDeployment(replicas=0, ready_after=10**6).install(monkeypatch)

    assert K8sBackend().apply(_settings(), UpdatePlan(agent="assailai/ares-agent@sha256:a")) is True
    assert len(deployment.patches) == 1


def test_k8s_apply_skips_a_container_the_deployment_does_not_have(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # an operator who deleted the sidecar. A strategic-merge patch naming an unknown container
    # tries to ADD one and is rejected for the fields it cannot invent, so every update would
    # break rather than just the updater's own move.
    deployment = _FakeDeployment(
        containers=[{"name": "ares-agent", "image": "assailai/ares-agent:2.4.0"}]
    ).install(monkeypatch)

    plan = UpdatePlan(agent="assailai/ares-agent@sha256:a", updater=f"{_UPDATER}@sha256:u")
    assert K8sBackend().apply(_settings(), plan) is True

    assert deployment.patched(0) == [{"name": "ares-agent", "image": "assailai/ares-agent@sha256:a"}]


def test_k8s_running_image_waits_for_the_rollout_to_finish(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # running_image read the Deployment SPEC, so right after a patch it reported the target as
    # running. That is what made a failed rollout indistinguishable from a successful one - on
    # that tick and every later one, including after an updater restart, because the spec outlives
    # the in-memory cache.
    deployment = _FakeDeployment(ready_after=2).install(monkeypatch)
    deployment.patches.append({})  # pretend a patch landed, so the status is the driven one
    deployment.generation = 2

    assert K8sBackend().running_image(_settings()) is None  # not rolled out yet
    deployment.polls = 5
    assert K8sBackend().running_image(_settings()) == "assailai/ares-agent:2.4.0"


def test_k8s_inspect_self_still_finds_its_own_image_mid_rollout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # the rollout gate is deliberately NOT on inspect_self: an updater that cannot name its own
    # image mid-roll could never compute a self-target
    deployment = _FakeDeployment(ready_after=10**6).install(monkeypatch)
    deployment.patches.append({})
    deployment.generation = 2

    assert K8sBackend().inspect_self(_settings()) == SelfInspection(
        role=Role.OWNER, image=f"{_UPDATER}:2.4.0"
    )


def test_k8s_finds_the_updater_sidecar_or_reports_it_unmanaged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given a Deployment with the sidecar, it is the owner of that container and reports its image
    _k8s_deployment(
        monkeypatch,
        containers=[
            {"name": "ares-agent", "image": "assailai/ares-agent:3.13.2"},
            {"name": "ares-updater", "image": f"{_UPDATER}:3.13.2"},
        ],
    )
    assert K8sBackend().inspect_self(_settings()) == SelfInspection(
        role=Role.OWNER, image=f"{_UPDATER}:3.13.2"
    )

    # and without one (an operator who removed it), it updates nothing of its own
    _k8s_deployment(monkeypatch, containers=[{"name": "ares-agent", "image": "a:1"}])
    assert K8sBackend().inspect_self(_settings()).role is Role.UNMANAGED


def _owner(image: str = f"{_UPDATER}:3.13.2") -> SelfInspection:
    return SelfInspection(role=Role.OWNER, image=image)


def _verify_to_digest(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Stand cosign in with one pinning ``repo:tag`` to ``repo@sha256:tag``; return what it saw."""
    seen: list[str] = []

    def fake(image: str, settings: UpdaterSettings) -> str:
        seen.append(image)
        repo, _, tag = image.rpartition(":")
        return f"{repo}@sha256:{tag}"

    monkeypatch.setattr(main.verify, "verify", fake)
    return seen


def test_tick_moves_the_agent_and_the_updater_together(monkeypatch: pytest.MonkeyPatch) -> None:
    # given both on 3.13.2, a 3.14.0 target, and this updater the owner of its container
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.14.0")
    _verify_to_digest(monkeypatch)
    backend = _FakeBackend(running="docker.io/assailai/ares-agent:3.13.2", me=_owner())

    # when it ticks
    main._tick(backend)

    # then one plan moves both, each verified from its own repo
    assert backend.plan == UpdatePlan(
        agent="docker.io/assailai/ares-agent@sha256:3.14.0",
        updater=f"{_UPDATER}@sha256:3.14.0",
    )


def test_tick_does_nothing_while_another_container_holds_the_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given a successor mid-handoff, with the agent behind
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.14.0")
    seen = _verify_to_digest(monkeypatch)
    backend = _FakeBackend(
        running="docker.io/assailai/ares-agent:3.13.2", me=SelfInspection(role=Role.STANDBY)
    )

    # when it ticks, then it moves nothing, not even the agent: only one updater acts at a time
    main._tick(backend)
    assert backend.plan is None and seen == []


def test_tick_holds_the_updater_back_when_the_agent_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given an agent image cosign refuses
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.14.0")
    monkeypatch.setattr(main.verify, "verify", lambda image, settings: None)
    backend = _FakeBackend(running="docker.io/assailai/ares-agent:3.13.2", me=_owner())

    # when it ticks, then nothing moves: the updater follows the agent, never leads it
    main._tick(backend)
    assert backend.plan is None


def test_tick_moves_only_the_updater_once_the_agent_is_on_the_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given an agent already on 3.14.0 and an updater still on 3.13.2 (installed before the release)
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.14.0")
    _verify_to_digest(monkeypatch)
    backend = _FakeBackend(running="docker.io/assailai/ares-agent:3.14.0", me=_owner())

    # when it ticks
    main._tick(backend)

    # then the updater catches up on its own
    assert backend.plan == UpdatePlan(updater=f"{_UPDATER}@sha256:3.14.0")


@pytest.mark.parametrize(
    "me",
    [SelfInspection(role=Role.UNMANAGED), _owner(image=f"{_UPDATER}:3.14.0")],
    ids=["unmanaged", "already-on-target"],
)
def test_tick_leaves_the_updater_where_it_is(
    me: SelfInspection, monkeypatch: pytest.MonkeyPatch
) -> None:
    # given an agent behind, and an updater that cannot find itself or is already on the target
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.14.0")
    _verify_to_digest(monkeypatch)
    backend = _FakeBackend(running="docker.io/assailai/ares-agent:3.13.2", me=me)

    # when it ticks
    main._tick(backend)

    # then only the agent moves
    assert backend.plan == UpdatePlan(agent="docker.io/assailai/ares-agent@sha256:3.14.0")


def test_tick_honours_self_update_off(monkeypatch: pytest.MonkeyPatch) -> None:
    # given an operator who manages the updater elsewhere
    monkeypatch.setattr(main, "settings", _settings(self_update=False))
    monkeypatch.setattr(main, "_read_target", lambda: "3.14.0")
    _verify_to_digest(monkeypatch)
    backend = _FakeBackend(running="docker.io/assailai/ares-agent:3.13.2", me=_owner())

    main._tick(backend)

    # then the agent moves and the updater does not
    assert backend.plan == UpdatePlan(agent="docker.io/assailai/ares-agent@sha256:3.14.0")


def test_a_failed_updater_move_waits_before_it_is_tried_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given an agent on the target and an updater whose new image cosign cannot verify
    # (e.g. a private mirror that carries the agent's tag and not the updater's)
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.14.0")
    seen: list[str] = []
    monkeypatch.setattr(main.verify, "verify", lambda image, settings: seen.append(image))
    clock = types.SimpleNamespace(now=1000.0)
    monkeypatch.setattr(main.time, "monotonic", lambda: clock.now)
    backend = _FakeBackend(running="docker.io/assailai/ares-agent:3.14.0", me=_owner())

    # when it ticks twice in a row, then cosign is asked once, not every poll
    main._tick(backend)
    main._tick(backend)
    assert seen == [f"{_UPDATER}:3.14.0"]

    # and once the wait has passed, it tries again
    clock.now += main._SELF_RETRY_SECONDS
    main._tick(backend)
    assert len(seen) == 2


def test_a_handoff_that_returns_waits_before_it_is_tried_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given a backend whose handoff comes back (a successor that did not stay up)
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.14.0")
    _verify_to_digest(monkeypatch)
    backend = _FakeBackend(running="docker.io/assailai/ares-agent:3.14.0", me=_owner())

    # when it ticks twice, then the second tick does not start another successor straight away
    main._tick(backend)
    assert backend.plan == UpdatePlan(updater=f"{_UPDATER}@sha256:3.14.0")
    backend.plan = None
    main._tick(backend)
    assert backend.plan is None


@pytest.mark.parametrize(
    "target", ["3.13.2", "nightly"], ids=["an-older-release", "no-release-at-all"]
)
def test_the_updater_never_moves_itself_backwards(
    target: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # given an updater built as 3.14.0 with the agent's rollback guard opted out of (the only way
    # the agent moves back at all), and a target older than that, or one it cannot read as a
    # release. The opt-out is deliberately agent-only: see
    # test_the_agent_never_moves_back_below_the_updaters_release for the default.
    monkeypatch.setattr(main, "settings", _settings(allow_downgrade=True))
    monkeypatch.setattr(main, "_read_target", lambda: target)
    monkeypatch.setattr(main, "_own_release", lambda: "3.14.0")
    _verify_to_digest(monkeypatch)
    backend = _FakeBackend(
        running="docker.io/assailai/ares-agent:3.14.0", me=_owner(f"{_UPDATER}:3.14.0")
    )

    # when it ticks
    main._tick(backend)

    # then the agent follows the target and the updater stays: one taken below 3.14.0 could never
    # update itself again
    assert backend.plan == UpdatePlan(agent=f"docker.io/assailai/ares-agent@sha256:{target}")


def test_the_updater_moves_forward_past_its_own_release(monkeypatch: pytest.MonkeyPatch) -> None:
    # given an updater built as 3.14.0-rc1 (a suffix reads as its release) and a 3.15.0 target
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.15.0")
    monkeypatch.setattr(main, "_own_release", lambda: "3.14.0-rc1")
    _verify_to_digest(monkeypatch)
    backend = _FakeBackend(
        running="docker.io/assailai/ares-agent:3.15.0", me=_owner(f"{_UPDATER}:3.14.0")
    )

    # when it ticks, then it moves itself forward as usual
    main._tick(backend)
    assert backend.plan == UpdatePlan(updater=f"{_UPDATER}@sha256:3.15.0")


@pytest.mark.parametrize(
    "target",
    ["3.13.2", "latest", "sha-deadbeef"],
    ids=["an-older-release", "a-floating-tag", "a-branch-build"],
)
def test_the_agent_never_moves_back_below_the_updaters_release(
    target: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # given an updater built as 3.14.0 and a handoff naming something CI did sign, but that is not
    # a step forward: an older release, or a build that is no release at all
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: target)
    monkeypatch.setattr(main, "_own_release", lambda: "3.14.0")
    seen = _verify_to_digest(monkeypatch)
    backend = _FakeBackend(
        running="docker.io/assailai/ares-agent:3.14.0", me=_owner(f"{_UPDATER}:3.14.0")
    )

    # when it ticks
    main._tick(backend)

    # then nothing moves, and cosign was never asked: the signature would have PASSED, which is
    # the whole point - it proves the artifact, not that the version is the current one
    assert backend.plan is None
    assert seen == []
    assert backend.running == "docker.io/assailai/ares-agent:3.14.0"


def test_the_agent_moves_forward_past_the_updaters_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given an updater built as 3.14.0 and the next release marked current
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.15.0")
    monkeypatch.setattr(main, "_own_release", lambda: "3.14.0")
    _verify_to_digest(monkeypatch)
    backend = _FakeBackend(
        running="docker.io/assailai/ares-agent:3.14.0", me=_owner(f"{_UPDATER}:3.14.0")
    )

    # when it ticks, then the ordinary path is untouched
    main._tick(backend)
    assert backend.plan.agent == f"docker.io/assailai/ares-agent@sha256:3.15.0"


def test_the_agent_may_catch_up_to_the_release_the_updater_is_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given an install whose agent lags its own updater (the updater moves second, so a half-done
    # rollout looks exactly like this)
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.14.0")
    monkeypatch.setattr(main, "_own_release", lambda: "3.14.0")
    _verify_to_digest(monkeypatch)
    backend = _FakeBackend(
        running="docker.io/assailai/ares-agent:3.13.2", me=_owner(f"{_UPDATER}:3.14.0")
    )

    # when it ticks, then equal is allowed: the floor is "older than", not "not newer than"
    main._tick(backend)
    assert backend.plan.agent == f"docker.io/assailai/ares-agent@sha256:3.14.0"


def test_a_prerelease_target_reads_as_its_release(monkeypatch: pytest.MonkeyPatch) -> None:
    # given a 3.14.1-rc1 target on a 3.14.0 updater: a suffix reads as its release, as it does for
    # the updater's own guard
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.14.1-rc1")
    monkeypatch.setattr(main, "_own_release", lambda: "3.14.0")
    _verify_to_digest(monkeypatch)
    backend = _FakeBackend(
        running="docker.io/assailai/ares-agent:3.14.0", me=_owner(f"{_UPDATER}:3.14.0")
    )

    main._tick(backend)
    assert backend.plan.agent == f"docker.io/assailai/ares-agent@sha256:3.14.1-rc1"


def test_the_rollback_guard_is_off_without_a_baked_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given a checkout rather than an image: updater/RELEASE does not exist, so there is no floor
    # to compare against. This is what keeps scripts/e2e_updater.sh working - it ticks from the
    # host with uv and targets 3.19 and 99.99.99-nope - and it is a deliberate fail-open, since
    # that path already requires host access.
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.13.2")
    _verify_to_digest(monkeypatch)
    backend = _FakeBackend(running="docker.io/assailai/ares-agent:3.14.0")

    main._tick(backend)
    assert backend.plan.agent == f"docker.io/assailai/ares-agent@sha256:3.13.2"


def test_a_refused_target_is_logged_once(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # a standing target is read every poll_seconds; saying so every 30 seconds forever would bury
    # everything else in the log
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_own_release", lambda: "3.14.0")
    _verify_to_digest(monkeypatch)
    backend = _FakeBackend(running="docker.io/assailai/ares-agent:3.14.0")

    with caplog.at_level(logging.WARNING, logger="ares.updater"):
        monkeypatch.setattr(main, "_read_target", lambda: "3.13.2")
        for _ in range(3):
            main._tick(backend)
        assert len(caplog.records) == 1
        assert "refusing to move the agent to 3.13.2" in caplog.text

        # a different refused target is its own line
        monkeypatch.setattr(main, "_read_target", lambda: "3.12.0")
        main._tick(backend)

    assert len(caplog.records) == 2


def test_allow_downgrade_lets_an_operator_move_the_agent_back(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # the lever for a deliberate, vendor-initiated rollback. Reachable only by someone who already
    # has host/cluster config access, so it hands the control-plane attacker nothing.
    monkeypatch.setattr(main, "settings", _settings(allow_downgrade=True))
    monkeypatch.setattr(main, "_read_target", lambda: "3.13.2")
    monkeypatch.setattr(main, "_own_release", lambda: "3.14.0")
    _verify_to_digest(monkeypatch)
    backend = _FakeBackend(running="docker.io/assailai/ares-agent:3.14.0")

    with caplog.at_level(logging.WARNING, logger="ares.updater"):
        main._tick(backend)

    assert backend.plan.agent == f"docker.io/assailai/ares-agent@sha256:3.13.2"
    assert "ARES_UPDATE_ALLOW_DOWNGRADE is set" in caplog.text


def test_allow_downgrade_never_moves_the_updater_backwards(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # the two guards are separate predicates on purpose: one lever must not quietly disable the
    # other. An updater taken below 3.14.0 could never update itself again (ARES-2049).
    monkeypatch.setattr(main, "settings", _settings(allow_downgrade=True))
    monkeypatch.setattr(main, "_read_target", lambda: "3.13.2")
    monkeypatch.setattr(main, "_own_release", lambda: "3.14.0")
    _verify_to_digest(monkeypatch)
    backend = _FakeBackend(
        running="docker.io/assailai/ares-agent:3.14.0", me=_owner(f"{_UPDATER}:3.14.0")
    )

    main._tick(backend)

    assert backend.plan == UpdatePlan(agent=f"docker.io/assailai/ares-agent@sha256:3.13.2")
    assert backend.plan.updater is None


def test_the_rollback_guard_does_not_skip_removing_a_predecessor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # the guard sits after _settle_role: a leftover ares-updater-old must not be stranded on the
    # host just because the standing target is bogus
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.13.2")
    monkeypatch.setattr(main, "_own_release", lambda: "3.14.0")
    backend = _FakeBackend(
        running="docker.io/assailai/ares-agent:3.14.0", me=_owner(f"{_UPDATER}:3.14.0")
    )

    main._tick(backend)

    assert backend.plan is None
    assert backend.predecessor_removals == 1


def test_tick_backs_off_after_an_update_that_did_not_stick(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given a target whose image verifies but does not survive the move (a crash-looping build, or
    # a k8s rollout that was rolled back). Without a memo this repeats every poll_seconds forever:
    # pull, create, wait ten seconds, delete, and a cosign subprocess each time.
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.15.0")
    seen = _verify_to_digest(monkeypatch)
    clock = types.SimpleNamespace(now=1000.0)
    monkeypatch.setattr(main.time, "monotonic", lambda: clock.now)
    backend = _FakeBackend(running="docker.io/assailai/ares-agent:3.14.0", apply_result=False)

    # when it ticks, is told the agent did not move, and ticks again
    main._tick(backend)
    assert backend.plan is not None and len(seen) == 1
    backend.plan = None
    main._tick(backend)

    # then nothing was attempted and cosign was not asked a second time
    assert backend.plan is None
    assert len(seen) == 1

    # and once the wait is over it tries again, verifying afresh rather than reusing the digest
    clock.now += main._APPLY_RETRY_SECONDS + 1
    main._tick(backend)
    assert backend.plan is not None
    assert len(seen) == 2


def test_tick_forgets_a_digest_whose_move_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    # the cache maps a target to "the digest cosign attested for it". Keeping that across a failed
    # move would let a retry apply an attestation that may since have been revoked.
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.15.0")
    _verify_to_digest(monkeypatch)
    backend = _FakeBackend(running="docker.io/assailai/ares-agent:3.14.0", apply_result=False)

    main._tick(backend)

    assert "3.15.0" not in main._verified


def test_tick_does_not_back_the_agent_off_when_only_the_handoff_returned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # the two memos answer different questions, and conflating them would let a failed updater
    # handoff freeze the agent's updates for half an hour
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.15.0")
    _verify_to_digest(monkeypatch)
    backend = _FakeBackend(
        running="docker.io/assailai/ares-agent:3.15.0", me=_owner(f"{_UPDATER}:3.14.0")
    )

    main._tick(backend)

    assert backend.plan == UpdatePlan(updater=f"{_UPDATER}@sha256:3.15.0")
    assert "3.15.0" in main._self_retry_after
    assert "3.15.0" not in main._apply_retry_after


def test_the_owner_removes_its_predecessor_once(monkeypatch: pytest.MonkeyPatch) -> None:
    # given an updater that holds its name, with nothing to update
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "3.14.0")
    backend = _FakeBackend(
        running="docker.io/assailai/ares-agent:3.14.0", me=_owner(f"{_UPDATER}:3.14.0")
    )

    # when it ticks twice
    main._tick(backend)
    main._tick(backend)

    # then it looked for a predecessor once, not on every poll
    assert backend.predecessor_removals == 1


# --- CA trust: cosign is a subprocess, so SSL_CERT_FILE is the only lever that reaches it -------


def _prepare_ca_dirs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    host_ca, extra = tmp_path / "host-ca", tmp_path / "certs"
    image_bundle = tmp_path / "image-bundle.crt"
    image_bundle.write_text("PUBLIC ROOTS\n")
    monkeypatch.setattr(tlsconf, "HOST_CA_DIR", host_ca)
    monkeypatch.setattr(tlsconf, "EXTRA_CA_DIR", extra)
    monkeypatch.setattr(tlsconf, "IMAGE_BUNDLE", image_bundle)
    monkeypatch.setattr(tlsconf, "MERGED_BUNDLE", tmp_path / "merged.pem")
    # install_ca_bundle writes straight to os.environ (that is the point: children inherit it), so
    # register the variable with monkeypatch first or whatever it sets leaks into later tests.
    # setenv records the pre-test state; the delenv leaves the code seeing it as unset.
    monkeypatch.setenv("SSL_CERT_FILE", "")
    monkeypatch.delenv("SSL_CERT_FILE")
    return host_ca, extra


def test_no_mounted_cas_leaves_ssl_cert_file_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the common case: nothing mounted, so the image's own store is already the whole truth and
    # we must not narrow it by pointing SSL_CERT_FILE at a bundle of our own.
    _prepare_ca_dirs(tmp_path, monkeypatch)

    assert tlsconf.install_ca_bundle() is None
    assert "SSL_CERT_FILE" not in os.environ


def test_mounted_cas_are_merged_with_the_image_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # union, never replacement: dropping the public roots would break the registry pull itself.
    host_ca, extra = _prepare_ca_dirs(tmp_path, monkeypatch)
    host_ca.mkdir()
    (host_ca / "corp-root.crt").write_text("CORP ROOT\n")
    extra.mkdir()
    (extra / "internal.pem").write_text("INTERNAL ROOT\n")

    bundle = tlsconf.install_ca_bundle()

    assert bundle is not None
    body = bundle.read_text()
    assert "PUBLIC ROOTS" in body and "CORP ROOT" in body and "INTERNAL ROOT" in body
    # cosign is a Go binary we shell out to; it reads this variable and nothing else we control.
    assert os.environ["SSL_CERT_FILE"] == str(bundle)


def test_dangling_symlinks_are_ignored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # a mounted /etc/ssl/certs is mostly symlinks into a directory that was not mounted.
    host_ca, _ = _prepare_ca_dirs(tmp_path, monkeypatch)
    host_ca.mkdir()
    (host_ca / "dangling.pem").symlink_to("/usr/share/ca-certificates/nowhere.crt")

    assert tlsconf.install_ca_bundle() is None
    assert "SSL_CERT_FILE" not in os.environ


def test_an_operator_set_ssl_cert_file_wins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # someone who pointed it somewhere deliberately gets to keep their answer.
    host_ca, _ = _prepare_ca_dirs(tmp_path, monkeypatch)
    host_ca.mkdir()
    (host_ca / "corp-root.crt").write_text("CORP ROOT\n")
    monkeypatch.setenv("SSL_CERT_FILE", "/operators/own.pem")

    assert tlsconf.install_ca_bundle() is None
    assert os.environ["SSL_CERT_FILE"] == "/operators/own.pem"


def test_an_unreadable_image_bundle_leaves_the_default_trust_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # SSL_CERT_FILE *replaces* the default trust, so writing a bundle of only the mounted roots
    # would narrow the updater to the corporate CA and break public TLS. Fail toward the image's
    # own store instead.
    host_ca, _ = _prepare_ca_dirs(tmp_path, monkeypatch)
    host_ca.mkdir()
    (host_ca / "corp-root.crt").write_text("CORP ROOT\n")
    monkeypatch.setattr(tlsconf, "IMAGE_BUNDLE", tmp_path / "does-not-exist.crt")

    assert tlsconf.install_ca_bundle() is None
    assert "SSL_CERT_FILE" not in os.environ


def test_the_non_tls_extracts_are_left_out_of_the_merged_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # SSL_CERT_FILE is what cosign reads, so a root the host trusts only for e-mail or code
    # signing would otherwise become a valid issuer for the registry and the Sigstore log. The
    # mount is the RHEL extract directory, which holds one bundle per purpose.
    host_ca, _ = _prepare_ca_dirs(tmp_path, monkeypatch)
    host_ca.mkdir()
    (host_ca / "tls-ca-bundle.pem").write_text("TLS ROOTS\n")
    (host_ca / "email-ca-bundle.pem").write_text("EMAIL ROOT\n")
    (host_ca / "objsign-ca-bundle.pem").write_text("OBJSIGN ROOT\n")

    bundle = tlsconf.install_ca_bundle()

    assert bundle is not None
    body = bundle.read_text()
    assert "PUBLIC ROOTS" in body and "TLS ROOTS" in body
    assert "EMAIL ROOT" not in body
    assert "OBJSIGN ROOT" not in body
    assert os.environ["SSL_CERT_FILE"] == str(bundle)


def test_only_non_tls_extracts_leave_ssl_cert_file_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Nothing eligible once the rule has run. SSL_CERT_FILE *replaces* the default trust, so the
    # choice is only ever "widen or leave alone", and the image's own store is the answer.
    host_ca, _ = _prepare_ca_dirs(tmp_path, monkeypatch)
    host_ca.mkdir()
    (host_ca / "email-ca-bundle.pem").write_text("EMAIL ROOT\n")

    assert tlsconf.install_ca_bundle() is None
    assert "SSL_CERT_FILE" not in os.environ


def test_the_skipped_extracts_are_named_in_the_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # said before the early return, or "I mounted a directory and the updater did nothing" has no
    # explanation anywhere - and unlike the agent, the updater has no startup summary line.
    host_ca, _ = _prepare_ca_dirs(tmp_path, monkeypatch)
    host_ca.mkdir()
    (host_ca / "email-ca-bundle.pem").write_text("EMAIL ROOT\n")

    with caplog.at_level(logging.INFO, logger="ares.updater.tls"):
        tlsconf.install_ca_bundle()

    assert "email-ca-bundle.pem" in caplog.text


@pytest.mark.parametrize(
    "layout",
    [
        {"tls-ca-bundle.pem": "TLS", "email-ca-bundle.pem": "MAIL", "objsign-ca-bundle.pem": "OBJ"},
        {"ca-certificates.crt": "DEBIAN"},
        {"email-ca-bundle.pem": "MAIL", "corp-root.crt": "CORP"},
        {"corp-root.crt": "CORP", "internal.pem": "INTERNAL"},
    ],
    ids=["rhel-extracts", "debian-bundle", "a-stray-email-extract", "an-ordinary-drop-in"],
)
def test_the_updater_selects_the_same_host_ca_files_as_the_agent(
    tmp_path: Path, layout: dict[str, str]
) -> None:
    # The two _server_auth_only are the same text on purpose: the updater image ships updater/
    # only, so it cannot import agent.tlsconf. Compare behaviour rather than source, so a
    # reformat does not fail and a logic change on one side cannot pass.
    from agent import tlsconf as agent_tlsconf

    directory = tmp_path / "host-ca"
    directory.mkdir()
    for name, body in layout.items():
        (directory / name).write_text(f"{body}\n")

    assert tlsconf._server_auth_only(tlsconf._pems_in(directory)) == agent_tlsconf._server_auth_only(
        agent_tlsconf._pems_in(directory)
    )
    assert tlsconf._PEM_SUFFIXES == agent_tlsconf._PEM_SUFFIXES
    assert tlsconf._TLS_BUNDLE_NAME == agent_tlsconf._TLS_BUNDLE_NAME
    assert tlsconf._NON_TLS_BUNDLE_PREFIXES == agent_tlsconf._NON_TLS_BUNDLE_PREFIXES


def test_unreadable_mounted_files_leave_the_default_trust_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Nothing mounted actually loaded, so there is nothing to add and no reason to point
    # SSL_CERT_FILE at a copy of what the image already trusts.
    host_ca, _ = _prepare_ca_dirs(tmp_path, monkeypatch)
    host_ca.mkdir()
    unreadable = host_ca / "corp-root.crt"
    unreadable.write_text("CORP ROOT\n")
    unreadable.chmod(0o000)

    try:
        assert tlsconf.install_ca_bundle() is None
        assert "SSL_CERT_FILE" not in os.environ
    finally:
        unreadable.chmod(0o644)
