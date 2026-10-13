"""The bootstrap installer, where it makes decisions the agent then depends on.

Only the CA detection is pinned here, and deliberately: the same candidate list is written a
second time in the other repo, in the install command the dashboard hands operators
(``apps/web/src/lib/agent-install.ts``, ``caDetection``). Two copies of one list across two
repositories is a drift trap, and nothing can fail the build in *both* of them, so each side pins
its own copy. That does not detect cross-repo drift, but it does mean neither list can change by
accident: whoever edits one gets a failure telling them the other exists.
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


def _function(name: str) -> str:
    match = re.search(
        rf"^{name}\(\) \{{\n.*?^\}}\n", BOOTSTRAP.read_text(), re.DOTALL | re.MULTILINE
    )
    assert match, f"bootstrap.sh no longer defines {name}"
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
    calls: list[str]


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
    assert run.calls == ["run", "inspect", "exec"]


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
    for path in (BOOTSTRAP, COMPOSE, K8S):
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
        "docker-compose.yml": re.findall(image_pin, COMPOSE.read_text()),
        "deploy/k8s/ares-agent.yaml": re.findall(image_pin, K8S.read_text()),
    }
    for path, found in pins.items():
        assert len(found) == 2, f"{path}: expected an agent and an updater pin, found {found}"
        assert set(found) == {expected}, (
            f"{path} pins {found}, but agent/__version__.py is {expected}"
        )


# ── A refused registration ──────────────────────────────────────────────────────────────────────
#
# Ares answering a 4xx used to read as "Cannot reach Ares" in the agent's log, and the installer
# waited out its whole timeout on it. A prod agent with ARES_NETWORKS set to docker network names
# did exactly that, while Ares was perfectly reachable.

_REFUSED = (
    "ERROR Ares refused the registration (HTTP 422: internal_networks: Value error, none of"
    " internal_networks is a CIDR / IP network). internal_networks is ARES_NETWORKS: set it to"
    " CIDRs such as 10.0.0.0/24. Retrying in 10s."
)


def _wait_until_online(logs: str) -> subprocess.CompletedProcess[str]:
    """Run wait_until_online against a stub engine whose running container has logged ``logs``."""
    script = f"""
set -euo pipefail
step() {{ :; }}
info() {{ echo "INFO $1"; }}
warn() {{ echo "WARN $1"; }}
error() {{ echo "ERROR $1"; }}
sleep() {{ :; }}
engine() {{
    case "$1" in
        inspect) echo running ;;
        logs) printf '%s\\n' "$LOGS" ;;
    esac
}}
RUNTIME=engine
CONTAINER_NAME=ares-agent
ONLINE_TIMEOUT=2
ONLINE_INTERVAL=1
{_function("wait_until_online")}
wait_until_online
echo "RETURNED"
"""
    env = {"PATH": "/usr/bin:/bin", "LOGS": logs}
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True, env=env, timeout=30)


def test_a_refused_registration_fails_the_install_with_the_reason() -> None:
    # given an agent whose registration Ares refused; when the installer waits for it
    done = _wait_until_online(f"Registering with https://ares.example (networks=x)\n{_REFUSED}")

    # then it stops at once, non-zero, and shows the agent's own line, which names what to fix
    assert done.returncode == 1, done.stdout
    assert "RETURNED" not in done.stdout
    assert "Ares refused the registration (HTTP 422: internal_networks" in done.stdout
    assert "re-run this installer with the same token" in done.stdout


def test_a_refusal_that_cleared_before_the_agent_came_online_is_a_success() -> None:
    # a refusal fixed on the Ares side mid-install leaves both lines in the log; the agent is online
    done = _wait_until_online(f"{_REFUSED}\nAgent online as agent-1")

    assert done.returncode == 0, done.stdout
    assert "INFO The agent is online." in done.stdout


def test_the_installer_greps_the_words_the_agent_logs() -> None:
    # two files, one phrase: a reworded log line would silently turn the fail-fast back off
    assert '"Ares refused the registration (%s).' in (_REPO / "agent" / "main.py").read_text()
