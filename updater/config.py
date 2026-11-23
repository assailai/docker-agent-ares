"""Companion-updater configuration (env-driven, ``ARES_UPDATE_`` prefix)."""

from __future__ import annotations

from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class UpdaterSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ARES_UPDATE_", extra="ignore")

    # the agent container (docker) / Deployment + container (k8s) this updater keeps current.
    # the alias accepts the documented ARES_UPDATE_CONTAINER as well as ARES_UPDATE_CONTAINER_NAME.
    container_name: str = Field(
        default="ares-agent",
        validation_alias=AliasChoices("ARES_UPDATE_CONTAINER", "ARES_UPDATE_CONTAINER_NAME"),
    )
    # optional override for the registry/repo; empty means derive it from the running agent's
    # image so the updater can never pull from a different repo than the agent was deployed from.
    image_repo: str = ""
    # shared with the agent: the agent writes the desired version here, the updater reads it.
    target_file: Path = Field(default=Path("/data/update-target.json"))
    poll_seconds: float = 30.0

    # the updater's own container (docker) / its sidecar in the agent Deployment (k8s). Once the
    # agent is on the target release, the updater moves itself there too (ARES-2049); every install
    # path (scripts/bootstrap.sh, docker-compose.yml, deploy/k8s) gives it this name.
    self_container_name: str = "ares-updater"
    # off for a host whose updater is managed some other way (GitOps, change control): the agent
    # still updates, the updater stays on what was installed.
    self_update: bool = True
    # The updater refuses to move the AGENT to a release older than its own, or to a target that is
    # no release at all. A signed-but-old image is still a downgrade attack: the signature is
    # genuine, and the version handoff is not. Set this only for a deliberate, operator-driven
    # rollback on a host you control. It never lets the updater move ITSELF backwards - that guard
    # has no override, because an updater taken below 3.14.0 could never update itself again.
    allow_downgrade: bool = False
    # never set by hand. An updater stamps it onto the successor it starts, so that while both run
    # during a handoff each can tell which container is its own (dockerd.inspect_self).
    instance: str = ""

    # fail-closed: refuse to apply an image whose signature we cannot verify. Turn this OFF
    # (ARES_UPDATE_REQUIRE_SIGNATURE=false) only for local/dev; CI signs published images.
    require_signature: bool = True
    # cosign keyless verification (preferred): the expected signer identity, an ANCHORED regexp
    # (cosign's -regexp flags are substring matches, so anchor with ^...$ and escape dots) matched
    # against the certificate Fulcio issued to the signing job. Plus the OIDC issuer below.
    #
    # Two things decide what that identity actually says, and both are easy to get wrong:
    #   * the workflow FILE is the one holding the `cosign sign` step (docker-build.yml), because
    #     Fulcio takes the SAN from the OIDC job_workflow_ref claim - NOT the entrypoint workflow
    #     that calls it. Naming the caller (docker-publish.yml) is a regexp that can never match.
    #   * the REF is the caller's ref, since docker-build.yml is invoked as a local reusable
    #     workflow. The release path (auto-tag.yml, on a version-bump merge) therefore signs at
    #     refs/heads/main, which is the protected branch: a merge there has been reviewed.
    # refs/tags/v* used to be accepted too, and must not be. Any account with push access can
    # create a tag - and no ruleset can stop that without also stopping auto-tag.yml, since
    # GitHub will not accept the Actions app as a bypass actor here (ARES-2351) - and
    # docker-publish.yml built and signed on one, so an attacker who could not merge to main
    # could still publish an image under release tags with the identity the whole fleet trusts.
    # docker-publish.yml no longer triggers on tags, docker-build.yml refuses to push from any
    # other ref, and auto-tag.yml fails the release when a v<version> tag does not name the
    # reviewed commit that cut it. What this identity should name is the ref that gets REVIEWED,
    # and that is a branch.
    # So the boundary this enforces is "built and signed from this repo's protected branch by its
    # build workflow, via GitHub OIDC" - branch / latest / sha images on main satisfy it too. The
    # updater only ever pulls <repo>:<target-version> as named by the control plane, and _tick
    # refuses a target that is not a release version, so it cannot drift onto one of those; it
    # applies the exact digest cosign attested rather than re-resolving.
    #
    # Defaulted to this image's own publishing workflow so every deploy shape (docker run, compose,
    # k8s) verifies out of the box without spelling the regexp out in each install command; override
    # only when self-hosting the images under a different signer.
    cosign_identity: str = (
        r"^https://github\.com/assailai/docker-agent-ares/"
        r"\.github/workflows/docker-build\.yml@"
        r"refs/heads/main$"
    )
    cosign_issuer: str = "https://token.actions.githubusercontent.com"
    # cosign key-based verification (alternative): path to a cosign public key.
    cosign_key: str = ""

    # k8s namespace override; defaults to the pod's own namespace (service-account file).
    k8s_namespace: str = ""
    log_level: str = "INFO"


def _split_ref(image_ref: str) -> tuple[str, str]:
    """Split an image ref into (repo, tag). A digest ref (``repo@sha256:...``) has no tag. A
    trailing ``:`` is a tag only when what follows has no ``/`` (otherwise it is a registry
    port, e.g. ``reg:5000/img``)."""
    repo, at, _digest = image_ref.partition("@")
    if at:
        return (repo, "")
    head, sep, tail = image_ref.rpartition(":")
    return (head, tail) if (sep and "/" not in tail) else (image_ref, "")


def tag_of(image_ref: str) -> str:
    """``assailai/ares-agent:2.5.0`` -> ``2.5.0``; empty string when there is no tag."""
    return _split_ref(image_ref)[1]


def repo_of(image_ref: str) -> str:
    """``assailai/ares-agent:2.5.0`` -> ``assailai/ares-agent`` (drops the tag if present)."""
    return _split_ref(image_ref)[0]


settings = UpdaterSettings()
