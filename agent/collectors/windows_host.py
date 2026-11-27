"""Normalize a Windows server's read-only WinRM posture into executable-control facts (the credentialed
Windows host tier).

A step beyond the SSH host tier (:mod:`linux_host`), which is Linux-only: Windows servers expose their
configuration over WinRM, not SSH. This tier opens ONE read-only WinRM session with a ``winrm_login``
credential from the agent's local vault, runs a SINGLE FIXED PowerShell gather script (no arbitrary
command, no caller input interpolated, the WinRM analogue of the db-query tier's one fixed catalog
query), and parses the JSON it returns into the Windows ``server.*`` fields. Like every collector it
ABSTAINS rather than invents: an unreachable host, a failed auth, or a field the script could not read
leaves the control UNAVAILABLE / the field out, so it stays NOT_ASSESSED.

Read-only by construction: the gather script only ever reads (registry queries, ``Get-*`` cmdlets); it
never writes, installs, or runs anything the caller supplies. NTLM auth (pure-python, via pyspnego)
over WinRM; the NTLM message layer seals the payload even on the plaintext 5985 transport, and 5986
(HTTPS) is used when the port says so, with the host's self-signed certificate not verified (the agent
has no store for it, exactly as the kube / storage tiers).

This pass serves the unambiguous Windows controls. The `server.audit.security_logging_disabled` read is
deferred (its honest form needs a locale-independent audit-policy read, not the locale-sensitive
`auditpol` text), and the definition-gated Windows controls (`patch.critical_missing`, `edr.unhealthy`,
`credential.insecure_storage`) are out of scope until their meaning is settled.

The parse functions are PURE (the gather script's JSON in, typed value out); the networked WinRM run is
a separate coroutine so the handler is testable by monkeypatching the fetch.
"""

from __future__ import annotations

import asyncio
import json

import winrm

# The Windows host controls this collector reads, all from the one posture document the gather script
# returns. The factual-absolute posture controls:
POSTURE_CONTROLS = frozenset(
    {
        "server.remote.rdp_nla_disabled",
        "server.service.smbv1_enabled",
        "server.share.smb_signing_not_required",
        "server.boot.disk_unencrypted",
        "server.firewall.enabled",
        "server.firewall.permissive",
    }
)
# A BASELINE-COMPARISON control: the agent sends the RAW observed Windows local-Administrators set and
# leaves the `policy_approved` gate for the control plane, which diffs it against the tenant's approved
# baseline. Emits the SAME wire key as the Linux host tier (`observed_local_admins`), so Windows and
# Linux admins feed one control with no control-plane change; the per-host asset key keeps their
# baselines separate.
BASELINE_CONTROLS = frozenset({"server.localadmin.unapproved"})
SERVES = POSTURE_CONTROLS | BASELINE_CONTROLS

# The standard WinRM ports. 5985 is HTTP (the NTLM message layer still seals the payload); 5986 is
# HTTPS. The collect target is the Windows host; the port decides the scheme.
_WINRM_HTTP_PORT = 5985
_WINRM_HTTPS_PORT = 5986

# Bound the admin read so a huge group cannot make one collection unbounded (build-for-scale). A larger
# group still yields a lower-bound observed set, which only ever UNDER-reports a gt-0 finding.
_MAX_ADMINS = 10_000

# The ONE fixed, read-only PowerShell gather script. It interpolates NOTHING from the caller; it reads
# the registry and Get-* cmdlets and emits a single compact JSON object. `SilentlyContinue` means a
# cmdlet the host cannot answer (e.g. BitLocker feature absent) yields a null field, which the parser
# reads as abstain rather than a false posture.
_GATHER_SCRIPT = r"""
$ErrorActionPreference='SilentlyContinue'
$rdp=(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication).UserAuthentication
$smb=Get-SmbServerConfiguration
$bl=Get-BitLockerVolume -MountPoint $env:SystemDrive
$admins=@(Get-LocalGroupMember -Group 'Administrators' | ForEach-Object { "$($_.Name)" })
$active=(Get-NetConnectionProfile | Select-Object -ExpandProperty NetworkCategory -First 1)
$fwAll=Get-NetFirewallProfile
$fw=$null
if($active){ $fw=$fwAll | Where-Object { $_.Name -eq $active } | Select-Object -First 1 }
[pscustomobject]@{
  rdp_user_authentication = $rdp
  smb1_enabled = $smb.EnableSMB1Protocol
  smb_signing_required = $smb.RequireSecuritySignature
  bitlocker_protection = if($bl){[int]$bl.ProtectionStatus}else{$null}
  local_admins = $admins
  firewall_enabled = if($fw){[bool]$fw.Enabled}else{$null}
  firewall_default_inbound = if($fw){"$($fw.DefaultInboundAction)"}else{$null}
} | ConvertTo-Json -Compress
""".strip()


def serves(control_id: str) -> bool:
    """Whether this collector reads ``control_id`` from a Windows host over WinRM."""
    return control_id in SERVES


def _bool(value: object) -> bool | None:
    """A strict boolean, or ``None`` to abstain (PowerShell's ConvertTo-Json renders booleans as JSON
    true/false, so a non-bool here means the field was absent or malformed)."""
    return value if isinstance(value, bool) else None


def parse_rdp_nla_enforced(posture: object) -> bool | None:
    """Whether RDP Network Level Authentication is enforced (the registry ``UserAuthentication`` value
    is exactly 1), or ``None`` to abstain when it was not read. The field is the enforced sense, so a
    ``False`` reading is the finding (RDP without NLA)."""
    if not isinstance(posture, dict):
        return None
    value = posture.get("rdp_user_authentication")
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value == 1


def parse_smbv1_enabled(posture: object) -> bool | None:
    """Whether the SMBv1 protocol is enabled on the server (``EnableSMB1Protocol``), or ``None`` to
    abstain. ``True`` is the finding (legacy, exploitable protocol enabled)."""
    return _bool(posture.get("smb1_enabled")) if isinstance(posture, dict) else None


def parse_smb_signing_required(posture: object) -> bool | None:
    """Whether the server requires SMB signing (``RequireSecuritySignature``), or ``None`` to abstain.
    ``False`` is the finding (SMB signing not required)."""
    return _bool(posture.get("smb_signing_required")) if isinstance(posture, dict) else None


def parse_full_disk_encryption_enabled(posture: object) -> bool | None:
    """Whether the system drive is BitLocker-protected (``ProtectionStatus`` == On, which is 1), or
    ``None`` to abstain when BitLocker could not be read (feature absent). ``False`` is the finding
    (system drive unencrypted)."""
    if not isinstance(posture, dict):
        return None
    value = posture.get("bitlocker_protection")
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value == 1


def parse_firewall_enabled(posture: object) -> bool | None:
    """Whether the Windows Firewall is enabled for the active network profile (Domain / Private /
    Public), or ``None`` to abstain when no active profile could be resolved (honest: "which profile is
    active" is unknowable then, not a finding). ``False`` is the finding (firewall off on the active
    profile)."""
    return _bool(posture.get("firewall_enabled")) if isinstance(posture, dict) else None


def parse_firewall_permissive_default(posture: object) -> bool | None:
    """Whether the active profile's default inbound action is Allow (a permissive default), or ``None``
    to abstain when it was not read. ``True`` is the finding (firewall default-allows inbound)."""
    if not isinstance(posture, dict):
        return None
    value = posture.get("firewall_default_inbound")
    if not isinstance(value, str) or not value:
        return None
    return value.strip().lower() == "allow"


def parse_local_admins(posture: object) -> list[str] | None:
    """The Windows local-Administrators members, as a sorted, de-duplicated list of their
    ``DOMAIN\\account`` / ``MACHINE\\account`` identifiers, or ``None`` to abstain when the set was not
    read. This is the RAW OBSERVED SET: the agent does NOT judge which are "unapproved" (it has no
    baseline); the control plane diffs it against the tenant's approved baseline. Bounded so a huge
    group cannot make one collection unbounded."""
    if not isinstance(posture, dict):
        return None
    members = posture.get("local_admins")
    if not isinstance(members, list):
        return None
    out: set[str] = set()
    for member in members:
        if isinstance(member, str) and member.strip():
            out.add(member.strip())
        if len(out) >= _MAX_ADMINS:
            break
    return sorted(out)


def rdp_nla_field(posture: object) -> dict[str, object] | None:
    """The ``server.remote.rdp_nla_disabled`` field dict, or ``None`` to abstain."""
    value = parse_rdp_nla_enforced(posture)
    return None if value is None else {"rdp_network_level_auth_enforced": value}


def smbv1_field(posture: object) -> dict[str, object] | None:
    """The ``server.service.smbv1_enabled`` field dict, or ``None`` to abstain."""
    value = parse_smbv1_enabled(posture)
    return None if value is None else {"smbv1_enabled": value}


def smb_signing_field(posture: object) -> dict[str, object] | None:
    """The ``server.share.smb_signing_not_required`` field dict, or ``None`` to abstain."""
    value = parse_smb_signing_required(posture)
    return None if value is None else {"smb_signing_required": value}


def disk_encryption_field(posture: object) -> dict[str, object] | None:
    """The ``server.boot.disk_unencrypted`` field dict, or ``None`` to abstain."""
    value = parse_full_disk_encryption_enabled(posture)
    return None if value is None else {"full_disk_encryption_enabled": value}


def firewall_enabled_field(posture: object) -> dict[str, object] | None:
    """The ``server.firewall.enabled`` field dict, or ``None`` to abstain."""
    value = parse_firewall_enabled(posture)
    return None if value is None else {"active_profile_enabled": value}


def firewall_permissive_field(posture: object) -> dict[str, object] | None:
    """The ``server.firewall.permissive`` field dict, or ``None`` to abstain."""
    value = parse_firewall_permissive_default(posture)
    return None if value is None else {"firewall_permissive_default": value}


def local_admins_field(posture: object) -> dict[str, object] | None:
    """The observed-set field the agent sends for ``server.localadmin.unapproved``: the raw Windows
    local-Administrators members, under the SAME wire key the Linux tier uses so the control-plane
    baseline normalizer needs no change (``observed_local_admins``). Abstains (``None``) when the set
    was not read."""
    members = parse_local_admins(posture)
    return None if members is None else {"observed_local_admins": members}


def _run_gather(endpoint: str, username: str, password: str, *, verify: bool) -> str:
    """Open a WinRM session and run the ONE fixed gather script, returning its stdout (synchronous;
    pywinrm has no async API, so the caller runs this in a thread, exactly as the db-query tier runs
    pg8000). NTLM transport; the host's self-signed certificate is not verified on HTTPS (``verify``
    False), the same inverse-trust the kube / storage tiers use. Raises on connect / auth / non-zero
    exit, which the caller records as honest UNAVAILABLE."""
    session = winrm.Session(
        endpoint,
        auth=(username, password),
        transport="ntlm",
        server_cert_validation="validate" if verify else "ignore",
    )
    result = session.run_ps(_GATHER_SCRIPT)
    if result.status_code != 0:
        stderr = result.std_err.decode("utf-8", "replace")[:300] if result.std_err else ""
        raise RuntimeError(f"winrm gather exited {result.status_code}: {stderr}")
    return result.std_out.decode("utf-8", "replace")


async def fetch_posture(
    target: str,
    credential,
    *,
    timeout: float,  # pywinrm manages its own transport timeout; kept for parity with the other tiers
    port: int = _WINRM_HTTP_PORT,
    verify: bool = False,
) -> dict:
    """Run the read-only WinRM gather against the Windows host and return its parsed posture document,
    or ``{}`` when the host returned nothing parseable. 5985 is HTTP, anything else (5986) is HTTPS.
    Raises on connect / auth / run failure (UNAVAILABLE)."""
    scheme = "http" if port == _WINRM_HTTP_PORT else "https"
    endpoint = f"{scheme}://{target}:{port}/wsman"
    raw = await asyncio.to_thread(
        _run_gather, endpoint, credential.username, credential.secret, verify=verify
    )
    try:
        body = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    return body if isinstance(body, dict) else {}
