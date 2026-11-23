"""The install paths, where they make decisions the agent then depends on.

Four files, because the decisions are shared between them: ``scripts/bootstrap.sh``,
``scripts/verify-images.sh``, ``docker-compose.yml`` and ``deploy/k8s/ares-agent.yaml``. The
release every path pins, the images each one names, and the cosign block the two scripts both
carry are things that have to agree ACROSS the files, so the tests for them live together rather
than one file per script.

Only the CA detection is pinned here, and deliberately: the same candidate list is written a
second time in the other repo, in the install command the dashboard hands operators
(``apps/web/src/lib/agent-install.ts``, ``caDetection``). Two copies of one list across two
repositories is a drift trap, and nothing can fail the build in *both* of them, so each side pins
its own copy. That does not detect cross-repo drift, but it does mean neither list can change by
accident: whoever edits one gets a failure telling them the other exists. The parity tests between
the two shell scripts are here for the same reason, one level down: neither can source the other,
so the duplicated cosign block is unavoidable and these tests are what fail when it diverges.
"""

from __future__ import annotations

import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import NamedTuple

import pytest

_REPO = Path(__file__).resolve().parents[1]
BOOTSTRAP = _REPO / "scripts" / "bootstrap.sh"
VERIFY = _REPO / "scripts" / "verify-images.sh"
README = _REPO / "README.md"
COMPOSE = _REPO / "docker-compose.yml"
K8S = _REPO / "deploy" / "k8s" / "ares-agent.yaml"
VERSION_FILE = _REPO / "agent" / "__version__.py"

# The order matters as much as the membership. /etc/ssl/certs is a symlink into /etc/pki on RHEL,
# so checking it first and resolving with `readlink -f` lands on the real bundle on every distro;
# checking the pki path first would work too, but only by accident on Debian.
EXPECTED_CA_CANDIDATES = [
    "/etc/ssl/certs/ca-certificates.crt",  # Debian, Ubuntu, Alpine, SUSE
    "/etc/pki/tls/certs/ca-bundle.crt",  # RHEL, Fedora, Amazon Linux
]


def _candidates() -> list[str]:
    match = re.search(r"for bundle in (.+?); do", BOOTSTRAP.read_text())
    assert match, "host_ca_dir no longer loops over a list of candidate bundles"
    return match.group(1).split()


def test_the_ca_candidates_match_the_dashboard_install_command() -> None:
    assert _candidates() == EXPECTED_CA_CANDIDATES, (
        "The host CA candidate list changed. The dashboard's install command carries the same "
        "list in ares-v2 (apps/web/src/lib/agent-install.ts, caDetection), and the two must stay "
        "identical or the same host gets diagnosed differently depending on how it was installed."
    )


def test_the_host_ca_mount_is_read_only_and_never_exposes_private_keys() -> None:
    body = BOOTSTRAP.read_text()

    assert ":/host-ca:ro" in body, "the host CA mount must be read-only"
    assert "/host-ca:rw" not in body
    # /etc/ssl/private sits beside the certificate directory on Debian and holds host private
    # keys. Mounting the parent, or that path, would hand them to a container that has no use
    # for them.
    assert "/etc/ssl/private" not in body
    assert '-v "/etc/ssl:' not in body


def test_the_kept_identity_marker_is_matched_before_agent_online() -> None:
    # Ordering, not membership, is the bug here. On a re-install that could not re-enroll, BOTH
    # strings are in the log by the time wait_until_online reads it: the agent really is online,
    # just as the agent it already was. Matching "Agent online" first is precisely how a failed
    # re-enrollment used to be reported as a successful install.
    body = BOOTSTRAP.read_text()

    kept = body.find('*"Keeping the existing agent identity"*)')
    online = body.find('*"Agent online"*)')

    assert kept != -1, "wait_until_online no longer detects a re-install that kept its identity"
    assert online != -1, "wait_until_online no longer detects the agent coming online"
    assert kept < online, (
        "the kept-identity case must be matched before 'Agent online', which is also in the log "
        "by then; otherwise a re-install that failed to re-enroll exits 0 as a success."
    )


def test_the_reset_flag_removes_both_containers_before_the_volume() -> None:
    # The engine refuses to remove a volume any container still references, and ares-updater
    # mounts this one read-only. Removing the agent alone would leave `volume rm` failing, which
    # (before the guard below) meant starting the agent on the very identity ARES_RESET was asked
    # to discard.
    body = BOOTSTRAP.read_text()
    reset = body[body.index("reset_state() {") : body.index("# Echo this host's CA directory")]

    rm_containers = reset.index('rm -f "$CONTAINER_NAME" "$UPDATER_CONTAINER_NAME"')
    rm_volume = reset.index('volume rm "$VOLUME_NAME"')

    assert rm_containers < rm_volume, "both containers must be removed before the volume"
    # And a volume that will not go away has to stop the install rather than be shrugged off.
    assert "exit 1" in reset, "a failed volume removal must abort instead of enrolling anyway"


def test_the_reset_is_opt_in() -> None:
    # The data volume is deliberately kept across a re-install: it is what lets an agent survive
    # being recreated, and the agent re-enrolls on its own when handed a token it was not minted
    # from. Discarding it by default would turn every upgrade into a brand-new agent.
    body = BOOTSTRAP.read_text()

    assert '[ -n "${ARES_RESET:-}" ] || return 0' in body, (
        "reset_state must return early unless ARES_RESET is set"
    )


# ── The updater's engine socket (ARES-1725) ─────────────────────────────────────────────────────
#
# A rootful Podman host has no /var/run/docker.sock, and the installer used to hand the updater
# that path anyway. Podman refused the mount, the installer printed one warning and then "Done",
# and the agent stayed on its install version for good. Three customer hosts sat on 3.6.0 through
# four releases that way.

BASH = shutil.which("bash") or "/bin/bash"


def _function(name: str, script: Path = BOOTSTRAP) -> str:
    match = re.search(
        rf"^{name}\(\) \{{\n.*?^\}}\n", script.read_text(), re.DOTALL | re.MULTILINE
    )
    assert match, f"{script.name} no longer defines {name}"
    return match.group(0)


@pytest.fixture
def short_tmp() -> Iterator[Path]:
    """A short /tmp directory: a Unix socket path is capped at ~104 bytes on macOS, which a pytest
    tmp_path can exceed."""
    workdir = Path(tempfile.mkdtemp(prefix="ab", dir="/tmp"))
    yield workdir
    shutil.rmtree(workdir, ignore_errors=True)


class _SocketRun(NamedTuple):
    engine_sock: str
    systemctl_calls: list[str]
    output: str


def _setup_podman(
    workdir: Path,
    *,
    is_podman: bool,
    uid: int,
    systemctl_succeeds: bool,
    disable_autoupdate: bool = False,
    socket_already_there: bool = False,
) -> _SocketRun:
    """Run setup_rootful_podman in bash with `id` and `systemctl` stubbed. The stubbed
    `enable --now podman.socket` creates a real Unix socket, as socket activation would."""
    sock = workdir / "podman.sock"
    calls = workdir / "calls"
    calls.touch()
    bind = (
        f"{shlex.quote(sys.executable)} -c "
        "'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])'"
    )
    if socket_already_there:
        subprocess.run(f"{bind} {shlex.quote(str(sock))}", shell=True, check=True)
    script = f"""
set -euo pipefail
id() {{ echo {uid}; }}
systemctl() {{
    echo "$*" >> {shlex.quote(str(calls))}
    if [ {int(systemctl_succeeds)} -ne 1 ]; then
        echo "Failed to connect to bus: No such file or directory"
        return 1
    fi
    if [ "$*" = "enable --now podman.socket" ] && [ ! -S {shlex.quote(str(sock))} ]; then
        {bind} {shlex.quote(str(sock))}
    fi
}}
step() {{ :; }}
info() {{ echo "INFO $1"; }}
warn() {{ echo "WARN $1"; }}
IS_PODMAN={"true" if is_podman else "false"}
ENGINE_SOCK=/var/run/docker.sock
PODMAN_ROOTFUL_SOCK={shlex.quote(str(sock))}
{_function("first_error_line")}
{_function("setup_rootful_podman")}
setup_rootful_podman
echo "ENGINE_SOCK=$ENGINE_SOCK"
"""
    env = {"PATH": "/usr/bin:/bin"}
    if disable_autoupdate:
        env["ARES_DISABLE_AUTOUPDATE"] = "1"
    done = subprocess.run(
        [BASH, "-c", script], capture_output=True, text=True, env=env, check=True, timeout=30
    )
    engine_sock = done.stdout.strip().splitlines()[-1].removeprefix("ENGINE_SOCK=")
    return _SocketRun(
        engine_sock=engine_sock.replace(str(sock), "<podman.sock>"),
        systemctl_calls=calls.read_text().splitlines(),
        output=done.stdout,
    )


def test_rootful_podman_enables_its_api_socket_and_hands_that_to_the_updater(
    short_tmp: Path,
) -> None:
    # given a rootful Podman host where podman.socket is not yet enabled (a stock RHEL host)
    # when the installer sets up the runtime
    run = _setup_podman(short_tmp, is_podman=True, uid=0, systemctl_succeeds=True)

    # then it enables podman.socket and uses Podman's own socket, not /var/run/docker.sock
    assert "enable --now podman.socket" in run.systemctl_calls
    assert run.engine_sock == "<podman.sock>"
    assert "INFO Enabled podman.socket" in run.output


def test_a_socket_file_left_behind_does_not_stand_in_for_enabling_the_service(
    short_tmp: Path,
) -> None:
    # given a socket file already at Podman's path, as systemd leaves it once the unit is stopped
    # when the installer sets up the runtime
    run = _setup_podman(
        short_tmp, is_podman=True, uid=0, systemctl_succeeds=True, socket_already_there=True
    )

    # then it still enables the service, which is what makes the socket answer, and keep answering
    # after a reboot
    assert "enable --now podman.socket" in run.systemctl_calls


def test_rootful_podman_restarts_the_agent_after_a_reboot(short_tmp: Path) -> None:
    # given rootful Podman, which has no daemon to honour --restart=always across a reboot
    # when the installer sets up the runtime, with or without auto-update
    run = _setup_podman(short_tmp, is_podman=True, uid=0, systemctl_succeeds=True)
    (short_tmp / "calls").unlink()
    no_update = _setup_podman(
        short_tmp, is_podman=True, uid=0, systemctl_succeeds=True, disable_autoupdate=True
    )

    # then podman-restart is enabled either way: it is about the agent, not the updater
    assert "enable podman-restart.service" in run.systemctl_calls
    assert no_update.systemctl_calls == ["enable podman-restart.service"]


def test_rootful_podman_that_cannot_enable_the_socket_says_why(short_tmp: Path) -> None:
    # given a rootful Podman host where podman.socket cannot be enabled (no systemd, or a policy)
    # when the installer sets up the runtime
    run = _setup_podman(short_tmp, is_podman=True, uid=0, systemctl_succeeds=False)

    # then it still points at Podman's socket, so the updater fails on the real reason, and the
    # warning carries systemctl's own reason rather than discarding it
    assert run.engine_sock == "<podman.sock>"
    assert (
        "WARN Could not enable podman.socket, which the auto-update companion needs: "
        "Failed to connect to bus: No such file or directory"
    ) in run.output


def test_docker_and_rootless_podman_keep_the_socket_they_already_had(short_tmp: Path) -> None:
    # given Docker, or rootless Podman (whose socket setup_persistence already chose)
    # when the installer sets up the runtime
    docker = _setup_podman(short_tmp, is_podman=False, uid=0, systemctl_succeeds=True)
    rootless = _setup_podman(short_tmp, is_podman=True, uid=1000, systemctl_succeeds=True)

    # then nothing changes and no system service is touched
    assert docker.engine_sock == "/var/run/docker.sock"
    assert rootless.engine_sock == "/var/run/docker.sock"
    assert docker.systemctl_calls == rootless.systemctl_calls == []


# ── Telling the operator when the updater cannot work ────────────────────────────────────────────


class _UpdaterRun(NamedTuple):
    status: int
    output: str
    calls: list[str]  # each engine call's subcommand
    argv: list[str]  # and its whole argument list


def _start_updater(
    workdir: Path,
    *,
    run_rc: int = 0,
    run_out: str = "",
    inspect: str = "true 0",
    exec_rc: int = 0,
    exec_out: str = "",
    logs: str = "",
    is_podman: bool = False,
    uid: int = 0,
) -> _UpdaterRun:
    """Run start_updater then report_autoupdate_failure, against a stub container engine whose
    `run`, `inspect`, `exec` and `logs` answer as given. Exit status and output are what an
    operator, or the automation running the installer, would see."""
    calls = workdir / "engine-calls"
    calls.touch()
    argv = workdir / "engine-argv"
    argv.touch()
    script = f"""
set -euo pipefail
id() {{ echo {uid}; }}
step() {{ :; }}
info() {{ echo "INFO $1"; }}
warn() {{ echo "WARN $1"; }}
error() {{ echo "ERROR $1"; }}
host_ca_dir() {{ :; }}
replace_existing() {{ :; }}
sleep() {{ :; }}
engine() {{
    echo "$1" >> {shlex.quote(str(calls))}
    echo "$*" >> {shlex.quote(str(argv))}
    case "$1" in
        run) printf '%s' "$RUN_OUT"; return "$RUN_RC" ;;
        inspect) printf '%s' "$INSPECT" ;;
        exec) printf '%s' "$EXEC_OUT"; return "$EXEC_RC" ;;
        logs) printf '%s' "$LOGS" ;;
    esac
}}
RUNTIME=engine
IS_PODMAN={"true" if is_podman else "false"}
ENGINE_SOCK=/var/run/docker.sock
CONTAINER_NAME=ares-agent
UPDATER_CONTAINER_NAME=ares-updater
VOLUME_NAME=ares-agent-data
UPDATER_IMAGE=docker.io/assailai/ares-updater:3.12.0
UPDATER_SETTLE_SECONDS=0
AUTOUPDATE_FAILED=false
AUTOUPDATE_REASON=""
AUTOUPDATE_ADVICE=""
EXIT_NO_AUTOUPDATE=3
ENGINE_PING=ping
{_function("first_error_line")}
{_function("socket_advice")}
{_function("autoupdate_failed")}
{_function("start_updater")}
{_function("report_autoupdate_failure")}
start_updater
report_autoupdate_failure
echo "NOTHING TO REPORT"
"""
    env = {
        "PATH": "/usr/bin:/bin",
        "RUN_RC": str(run_rc),
        "RUN_OUT": run_out,
        "INSPECT": inspect,
        "EXEC_RC": str(exec_rc),
        "EXEC_OUT": exec_out,
        "LOGS": logs,
    }
    done = subprocess.run([BASH, "-c", script], capture_output=True, text=True, env=env, timeout=30)
    return _UpdaterRun(
        status=done.returncode,
        output=done.stdout + done.stderr,
        calls=calls.read_text().splitlines(),
        argv=argv.read_text().splitlines(),
    )


def _error_lines(run: _UpdaterRun) -> list[str]:
    return [line for line in run.output.splitlines() if line.startswith("ERROR ")]


def test_a_working_updater_is_reported_as_started(short_tmp: Path) -> None:
    # given an engine that starts the updater, keeps it up, and answers its ping
    # when the installer starts the updater
    run = _start_updater(short_tmp)

    # then it says so, exits 0, and only after the ping went through the updater's own socket
    assert run.status == 0
    assert "INFO Auto-update companion started." in run.output
    assert "NOTHING TO REPORT" in run.output
    assert run.calls == ["rm", "run", "inspect", "exec"]


def test_an_install_removes_what_an_interrupted_updater_handoff_left(short_tmp: Path) -> None:
    # given an install that may land while an updater is handing itself over (ARES-2049), when the
    # installer starts the updater
    run = _start_updater(short_tmp)

    # then before starting one it removes the successor and the stepped-aside updater a handoff
    # runs, so neither is left idling beside the updater it starts
    assert run.argv[0] == "rm -f ares-updater-next ares-updater-old"


def test_a_failed_docker_run_reports_the_engine_error_not_the_help_line(short_tmp: Path) -> None:
    # given Docker refusing a socket that is not there; its output ends with a --help line
    run_out = (
        'docker: Error response from daemon: invalid mount config for type "bind": bind source '
        "path does not exist: /var/run/docker.sock\n\nRun 'docker run --help' for more information"
    )
    # when the installer starts the updater
    run = _start_updater(short_tmp, run_rc=125, run_out=run_out)

    # then the failure names Docker's own reason, says what to check, and exits 3
    errors = _error_lines(run)
    assert run.status == 3
    assert any("bind source path does not exist: /var/run/docker.sock" in e for e in errors)
    assert not any("--help" in e for e in errors)
    advice = "Check that /var/run/docker.sock is the running engine's socket"
    assert any(advice in e for e in errors), errors


def test_rootful_podman_without_a_socket_is_told_to_enable_podman_socket(short_tmp: Path) -> None:
    # given the podman-docker shim's banner, then Podman refusing the missing socket (ARES-1725)
    run_out = (
        "Emulate Docker CLI using podman. Create /etc/containers/nodocker to quiet msg.\n"
        "Error: statfs /run/podman/podman.sock: no such file or directory"
    )
    # when the installer starts the updater as root
    run = _start_updater(short_tmp, run_rc=125, run_out=run_out, is_podman=True, uid=0)

    # then the reason is Podman's, not the banner, and the fix is the one that applies
    errors = _error_lines(run)
    assert run.status == 3
    assert any("statfs /run/podman/podman.sock: no such file or directory" in e for e in errors)
    assert not any("Emulate Docker CLI" in e for e in errors)
    assert any("'systemctl enable --now podman.socket'" in e for e in errors)


def test_an_image_that_cannot_be_pulled_gets_pull_advice_not_socket_advice(short_tmp: Path) -> None:
    run_out = (
        "Error: initializing source docker://docker.io/assailai/ares-updater:3.12.0: reading manifest "
        "3.12.0 in docker.io/assailai/ares-updater: toomanyrequests: too many requests"
    )
    run = _start_updater(short_tmp, run_rc=125, run_out=run_out, is_podman=True, uid=0)

    errors = _error_lines(run)
    assert run.status == 3
    assert any("pull docker.io/assailai/ares-updater:3.12.0" in e for e in errors)
    assert not any("podman.socket" in e for e in errors)


def test_podman_retry_warnings_give_way_to_its_final_error(short_tmp: Path) -> None:
    # given Podman's output for a pull it retried and then gave up on (seen on a real host)
    retry = (
        'time="2026-10-13T08:07:58Z" level=warning msg="Failed, retrying in 1s ... (1/3). Error: '
        'initializing source docker://assailai/ares-updater:3.9.1: pinging container registry"'
    )
    final = (
        "Error: initializing source docker://assailai/ares-updater:3.9.1: pinging container "
        'registry registry-1.docker.io: Get "https://registry-1.docker.io/v2/": i/o timeout'
    )
    run_out = f"{retry}\n{retry}\n{final}"
    run = _start_updater(short_tmp, run_rc=125, run_out=run_out, is_podman=True)

    # then the reason shown is the conclusive error, not the first retry
    errors = _error_lines(run)
    assert any(e == f"ERROR   {final}" for e in errors), errors
    assert not any("retrying" in e for e in errors)


def test_an_engine_that_fails_silently_is_still_a_failure(short_tmp: Path) -> None:
    # given a run that fails with no output at all
    run = _start_updater(short_tmp, run_rc=1, run_out="")

    # then it is still reported, rather than an empty reason reading as success
    assert run.status == 3
    assert "NOTHING TO REPORT" not in run.output
    assert any("no further detail from the engine" in e for e in _error_lines(run))


def test_an_updater_that_crashes_on_start_is_caught(short_tmp: Path) -> None:
    # given an updater that is already being restarted when the installer looks
    run = _start_updater(
        short_tmp,
        inspect="true 2",
        logs="2026-10-13 ERROR ares.updater no Docker socket and not running in Kubernetes",
    )

    errors = _error_lines(run)
    assert run.status == 3
    assert any("no Docker socket and not running in Kubernetes" in e for e in errors)
    assert "exec" not in run.calls


def test_an_updater_that_runs_but_cannot_use_the_socket_is_caught(short_tmp: Path) -> None:
    # given an updater that starts and stays up, but whose socket the engine refuses (SELinux): the
    # case a "still running" check alone passed, because the updater only uses the socket once an
    # update is queued and logs, rather than exits, when it cannot
    run = _start_updater(
        short_tmp,
        exec_rc=1,
        exec_out="ConnectError: [Errno 13] Permission denied",
        is_podman=True,
        uid=0,
    )

    errors = _error_lines(run)
    assert run.status == 3
    assert any(
        "cannot use the container engine through /var/run/docker.sock: "
        "ConnectError: [Errno 13] Permission denied" in e
        for e in errors
    )
    assert "INFO Auto-update companion started." not in run.output


def test_the_socket_is_resolved_before_the_updater_starts_and_a_failure_is_reported_last() -> None:
    body = BOOTSTRAP.read_text()
    main = body[body.index("main() {") :]

    order = [
        main.index("setup_persistence"),
        main.index("setup_rootful_podman"),
        main.index("start_updater"),
        main.index("print_summary"),
        main.index("report_autoupdate_failure"),
    ]
    assert order == sorted(order), (
        "the rootful socket has to be resolved after setup_persistence (which owns the rootless "
        "one) and before the updater starts; a failed updater is reported after the summary, so "
        "it is the last thing the operator reads rather than a warning above 'Done'"
    )


def test_the_updater_may_use_the_engine_socket_under_selinux() -> None:
    # SELinux (enforcing by default on RHEL and Fedora) stops a container connecting to the engine
    # socket, so an updater without this starts fine and then fails every check.
    assert "updater_args+=(--security-opt label=disable)" in _function("start_updater")
    assert "      - label=disable" in COMPOSE.read_text()


def test_every_install_path_names_its_images_fully_qualified() -> None:
    # RHEL's Podman (and OpenShift's CRI-O) enforce short-name resolution: "assailai/ares-agent"
    # stops at an interactive registry prompt and, with no terminal, fails the install outright.
    for path in (BOOTSTRAP, VERIFY, COMPOSE, K8S):
        # an image reference is followed by its tag; the GitHub script URLs are followed by "/"
        refs = re.findall(r"(?:docker\.io/)?assailai/ares-(?:agent|updater)(?=:)", path.read_text())
        assert refs, f"{path.name} names no agent image"
        assert all(ref.startswith("docker.io/") for ref in refs), f"{path.name}: {refs}"


def test_every_install_path_pins_the_release_being_cut() -> None:
    # 3.10.0 and 3.11.0 were cut without moving these, so the installer fetched from the v3.11.0
    # tag installed 3.9.0 and left the catch-up to the updater, which is the one part that may not
    # be running.
    version = re.search(r'__version__ = "(.+?)"', VERSION_FILE.read_text())
    assert version
    expected = version.group(1)

    image_pin = r"ares-(?:agent|updater):(\d+\.\d+\.\d+)"
    pins = {
        "scripts/bootstrap.sh": re.findall(r":-(\d+\.\d+\.\d+)\}", BOOTSTRAP.read_text()),
        "scripts/verify-images.sh": re.findall(r":-(\d+\.\d+\.\d+)\}", VERIFY.read_text()),
        "docker-compose.yml": re.findall(image_pin, COMPOSE.read_text()),
        "deploy/k8s/ares-agent.yaml": re.findall(image_pin, K8S.read_text()),
    }
    for path, found in pins.items():
        assert len(found) == 2, f"{path}: expected an agent and an updater pin, found {found}"
        assert set(found) == {expected}, (
            f"{path} pins {found}, but agent/__version__.py is {expected}"
        )


# --- install-time verification: the updater gets the engine socket, so it is checked first ------


def test_the_installer_verifies_both_images_before_anything_starts() -> None:
    # The updater is handed the engine socket, which is the host. Before ARES-2327 the installer
    # pulled it by a mutable tag with no check at all, so write access to the Docker Hub
    # repositories was write access to the next host that installed - and the substituted updater
    # then decided every later verification.
    script = BOOTSTRAP.read_text()
    order = [script.find(name) for name in ("verify_images", "start_container", "start_updater")]
    assert -1 not in order, "the installer no longer verifies the images"
    # the calls in main(), not the definitions and not the comments around them
    main_body = script[script.rindex("\nmain() {") :]
    steps = [
        line.strip()
        for line in main_body.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    calls = [steps.index(name) for name in ("verify_images", "start_container", "start_updater")]
    assert calls == sorted(calls), "verification does not run before the containers start"


def test_nothing_is_destroyed_before_the_images_are_verified() -> None:
    # Verification is fail-closed and reaches ghcr.io, Fulcio and Rekor, so it is now a step that
    # can fail on a healthy host behind a strict proxy. reset_state deletes the data volume this
    # host's agent identity lives in. In that order a blocked install would take the identity with
    # it and leave nothing running to go back to (ARES-2327 review).
    main_body = BOOTSTRAP.read_text()
    main_body = main_body[main_body.rindex("\nmain() {") :]
    steps = [
        line.strip()
        for line in main_body.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert steps.index("verify_images") < steps.index("reset_state")


def test_the_installer_runs_the_digest_it_verified() -> None:
    # Verifying a tag and then running that tag is a TOCTOU: the registry can repoint it in
    # between. verify_image prints the digest reference and verify_images writes it back over
    # $IMAGE / $UPDATER_IMAGE, so what starts is the artifact that was checked.
    script = BOOTSTRAP.read_text()
    assert 'digest="${repo}@${sha}"' in script, "verify_image does not build a digest reference"
    assert "printf -v \"$which\" '%s' \"$verified\"" in script, (
        "the verified digest is not written back over the image reference"
    )


def test_the_installer_does_not_let_the_updater_vouch_for_itself() -> None:
    # cosign comes from Sigstore, pinned by digest - not from the ares-updater image, which is one
    # of the two things being checked. A substituted updater must not supply its own auditor.
    script = BOOTSTRAP.read_text()
    cosign = re.search(r'^COSIGN_IMAGE="\$\{ARES_COSIGN_IMAGE:-(\S+?)\}"', script, re.M)
    assert cosign, "no cosign image pinned for install-time verification"
    assert re.search(r"@sha256:[0-9a-f]{64}$", cosign.group(1)), cosign.group(1)
    assert "ares-updater" not in cosign.group(1)


def test_the_installer_has_no_way_to_skip_verification() -> None:
    # Fail-closed on purpose. An override would be read by exactly the install this protects: an
    # automated one, on a host where nobody sees the warning. ARES_COSIGN_IMAGE changes WHICH
    # cosign runs (an internal mirror), never whether one does.
    script = BOOTSTRAP.read_text()
    assert not re.search(r"ARES_(SKIP|NO|DISABLE)_(IMAGE_)?VERIF", script), (
        "the installer has a flag that skips signature verification"
    )


def test_the_installer_checks_the_same_signer_the_updater_does() -> None:
    # Two copies of one regexp, in a shell script and in Python. They must agree, or an install
    # accepts something the running updater would later refuse (or the other way round).
    from updater.config import UpdaterSettings

    script = BOOTSTRAP.read_text()
    identity = re.search(r"^COSIGN_IDENTITY='(.+)'$", script, re.M)
    issuer = re.search(r'^COSIGN_ISSUER="(.+)"$', script, re.M)
    assert identity and issuer, "the installer does not pin a signer identity and issuer"

    settings = UpdaterSettings()
    assert identity.group(1) == settings.cosign_identity
    assert issuer.group(1) == settings.cosign_issuer


def test_the_installer_gives_cosign_the_host_cas_without_narrowing_its_trust() -> None:
    # cosign has to reach the registry, Fulcio and Rekor through the same inspecting proxy as
    # everything else. Go reads SSL_CERT_FILE and SSL_CERT_DIR, and naming only the host's file
    # would REPLACE the image's public roots - which would break the Sigstore endpoints and fail
    # every install behind a proxy, fail-closed, with a signature error that is not one.
    script = BOOTSTRAP.read_text()
    helper = script[script.index("cosign_ca_args() {") : script.index("# Pull an image,")]
    assert "/host-ca:ro" in helper
    assert "SSL_CERT_DIR=/etc/ssl/certs" in helper, "the image's own roots are dropped"
    # and the same purpose rule the agent and updater use: only the TLS extract on RHEL
    assert "tls-ca-bundle.pem" in helper


# --- the standalone verifier: the compose and Kubernetes paths' half of the same job ------------
#
# bootstrap.sh establishes the digest-pinning defence for the `docker run` install. The compose and
# Kubernetes paths named the host-privileged updater by mutable tag and started it unchecked, so
# write access to the Docker Hub repositories was still write access to the next host that
# installed that way (ARES-2351). scripts/verify-images.sh is what closes that, and because it is
# fetched standalone it carries its own copy of the installer's cosign block.

_SHARED_WITH_THE_INSTALLER = [
    "detect_platform",
    "check_runtime",
    "host_ca_dir",
    "repo_of",
    "cosign_ca_args",
    "verify_image",
]


@pytest.mark.parametrize("name", _SHARED_WITH_THE_INSTALLER)
def test_the_verifier_checks_an_image_exactly_as_the_installer_does(name: str) -> None:
    # given one of the functions both scripts need

    # then the two copies are identical, character for character. Neither script can source the
    # other: both are fetched on their own through `bash <(curl ...)`, so there is no shared file
    # to put this in. A second copy of security-critical logic is a drift trap - the same one
    # agent/tlsconf.py and updater/tlsconf.py live with - and this is the only thing that fails
    # when the two answers start to differ.
    assert _function(name, VERIFY) == _function(name, BOOTSTRAP), (
        f"{name} has drifted between bootstrap.sh and verify-images.sh"
    )


def test_the_verifier_trusts_the_same_signer_and_the_same_cosign() -> None:
    # given the constants that decide what counts as genuine
    wanted = re.findall(
        r"^(COSIGN_(?:IMAGE|IDENTITY|ISSUER)=.*)$", BOOTSTRAP.read_text(), re.M
    )
    found = re.findall(r"^(COSIGN_(?:IMAGE|IDENTITY|ISSUER)=.*)$", VERIFY.read_text(), re.M)

    # then both scripts pin the same signer, the same OIDC issuer and the same cosign build. A
    # verifier that accepted something the installer refuses (or the reverse) would mean the
    # install path you happened to pick decided whether an image was acceptable.
    assert len(wanted) == 3, f"bootstrap.sh no longer pins three cosign constants: {wanted}"
    assert found == wanted, "verify-images.sh pins a different signer, issuer or cosign"


def test_the_verifier_pins_the_digest_it_checked_rather_than_the_tag() -> None:
    # given the script
    script = VERIFY.read_text()

    # then what it writes out is verify_image's answer, never the reference it was asked about.
    # Verifying a tag and then recording that tag is a TOCTOU: the registry can repoint it in
    # between, which is the whole attack.
    assert 'agent="$(verify_image "$IMAGE")"' in script
    assert 'updater="$(verify_image "$UPDATER_IMAGE")"' in script
    assert 'write_env ".env" "$agent" "$updater"' in script
    assert 'pinned="${ref%@*}@${verified##*@}"' in script, (
        "the manifest is not rewritten to the digest that was verified"
    )


def test_the_verifier_has_no_way_to_skip_verification() -> None:
    # Fail-closed, for the same reason the installer is: an override would be read by exactly the
    # install this protects - an automated one, on a host where nobody reads the warning.
    assert not re.search(r"ARES_(SKIP|NO|DISABLE)_(IMAGE_)?VERIF", VERIFY.read_text()), (
        "verify-images.sh has a flag that skips signature verification"
    )


@pytest.mark.parametrize("name", ["pin_manifest", "write_env"])
def test_an_empty_grep_result_does_not_end_the_verifier_silently(name: str) -> None:
    # This one is here because it actually happened. The script runs under `set -o pipefail` and
    # grep exits 1 when it matches nothing, so `refs="$(grep ... | sort -u)"` inherited that 1 and
    # `set -e` killed the script - in between the step heading and the error that explains what to
    # do about it. Pointing it at a file naming no Ares image printed a heading, then stopped.

    # given one of the functions that scans a file
    greps = [line.strip() for line in _function(name, VERIFY).splitlines() if "grep -" in line]

    # then each grep says what an empty result means, rather than leaving pipefail to decide
    assert greps, f"{name} no longer greps"
    assert all("|| true" in line for line in greps), (
        f"{name} has a grep whose empty result pipefail turns into a silent exit: {greps}"
    )


def test_the_verifier_leaves_a_manifest_alone_when_an_image_does_not_verify() -> None:
    # given the manifest-rewriting half
    body = _function("pin_manifest", VERIFY)

    # then it edits a copy and moves it over the original only at the end. Rewriting in place
    # would leave a half-pinned manifest behind when the second image fails to verify - and a
    # half-pinned manifest still applies, which is the worst of both.
    assert 'tmp="$(mktemp "${file}.XXXXXX")"' in body
    assert body.index('cat "$file" > "$tmp"') < body.index('verified="$(verify_image "$ref")"')
    assert body.index('verified="$(verify_image "$ref")"') < body.index('cat "$tmp" > "$file"')


def test_compose_cannot_start_an_image_that_was_never_verified() -> None:
    # given the compose file's image references
    images = re.findall(r"^\s+image:\s*(.+)$", COMPOSE.read_text(), re.M)

    # then neither names an image directly: both read a variable with no default, so `docker
    # compose up` stops with the message below until verify-images.sh has written .env. This is
    # the one install path where the check can actually be ENFORCED rather than documented -
    # kubectl has no substitution, so the manifest can only be pinned by rewriting it.
    assert len(images) == 2, f"expected an agent and an updater image, found {images}"
    for image in images:
        assert image.startswith("${ARES_") and ":?" in image, (
            f"compose would start {image} without checking it"
        )
        assert "verify-images.sh" in image, (
            f"the error an operator sees does not say what to run: {image}"
        )


def test_the_release_a_bare_compose_up_would_have_used_is_still_named() -> None:
    # given the messages compose prints when the variables are unset
    messages = re.findall(r"^\s+image: \$\{ARES_\w+:\?(.+)\}$", COMPOSE.read_text(), re.M)

    # then each still names the fully qualified, version-pinned reference it is about to verify.
    # An operator reading docker-compose.yml has to be able to see WHICH release this file
    # installs, and test_every_install_path_pins_the_release_being_cut reads it from here.
    assert len(messages) == 2, f"expected two required-variable messages, found {messages}"
    for message in messages:
        assert re.search(r"docker\.io/assailai/ares-(agent|updater):\d+\.\d+\.\d+", message), (
            f"the message does not say which image is being pinned: {message}"
        )


@pytest.mark.parametrize(
    ("ref", "expected"),
    [
        ("docker.io/assailai/ares-agent", "docker.io/assailai/ares-agent"),
        ("docker.io/assailai/ares-agent:3.15.0", "docker.io/assailai/ares-agent"),
        ("docker.io/assailai/ares-agent@sha256:ab", "docker.io/assailai/ares-agent"),
        # the form verify-images.sh writes into a manifest, and a legal ARES_IMAGE override. Until
        # ARES-2351 repo_of stopped at the digest and returned the tag glued on, so verify_image
        # then hunted for a RepoDigest beginning "...ares-agent:3.15.0@sha256:" - which no engine
        # ever reports, and the install failed with "could not resolve a digest".
        ("docker.io/assailai/ares-agent:3.15.0@sha256:ab", "docker.io/assailai/ares-agent"),
        # a registry:port is all repository, and must not be mistaken for a tag
        ("localhost:5000/team/agent", "localhost:5000/team/agent"),
        ("localhost:5000/team/agent:1.2", "localhost:5000/team/agent"),
    ],
)
def test_repo_of_finds_the_repository_in_every_reference_form(ref: str, expected: str) -> None:
    # given the installer's own repo_of, executed rather than read
    done = subprocess.run(
        [BASH, "-c", f'{_function("repo_of")}\nrepo_of "$1"', "_", ref],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )

    # then it strips the tag and the digest, both together and apart
    assert done.stdout == expected, f"repo_of({ref!r}) = {done.stdout!r}"


@pytest.mark.parametrize(
    ("option", "apply_command"),
    [
        ("### Option B: Docker Compose", "docker compose up -d"),
        ("### Option D: Kubernetes", "kubectl apply -f ares-agent.yaml"),
    ],
    ids=["compose", "kubernetes"],
)
def test_the_documented_install_verifies_before_it_starts_anything(
    option: str, apply_command: str
) -> None:
    # given the install option's own section of the README
    readme = README.read_text()
    start = readme.index(option)
    end = readme.index("\n### ", start + len(option))
    section = readme[start:end]

    # then the verify step is in it, and it comes BEFORE the command that starts the containers.
    # On Kubernetes this ordering is the whole control - kubectl applies a bare tag quite happily -
    # so a README that lost the step, or printed it afterwards, would leave the k8s path exactly
    # where ARES-2351 found it.
    assert "verify-images.sh" in section, f"{option} no longer tells the operator to verify"
    assert apply_command in section, f"{option} no longer shows {apply_command!r}"
    assert section.index("verify-images.sh") < section.index(apply_command), (
        f"{option} starts the containers before verifying them"
    )
