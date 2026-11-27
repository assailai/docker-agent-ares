"""Normalize a Windows server's read-only WinRM posture into executable-control facts.

The Linux host tier reads config over SSH; Windows servers expose theirs over WinRM. This tier opens
one WinRM session with a ``winrm_login`` vault credential and runs a single fixed PowerShell gather
(read-only ``Get-*`` cmdlets and registry queries, no caller input interpolated, the WinRM analogue of
the db-query tier's one fixed catalog query), then parses the JSON into the ``server.*`` fields. It
ABSTAINS rather than invents: an unreachable host, a failed auth, or a field the script could not read
leaves the control NOT_ASSESSED. NTLM over WinRM (the message layer seals the payload even on the
plaintext 5985 transport); the host's self-signed cert is not verified, as in the kube / storage tiers.

Only the controls that read reliably over a WinRM network logon are served here. ``boot.disk_unencrypted``
is out: BitLocker status (Get-BitLockerVolume and the Win32_EncryptableVolume CIM class alike) is not
readable from a network-logon token, so it needs CredSSP or a local-agent read. ``audit.security_logging_disabled``
needs a locale-independent read rather than ``auditpol`` text, and ``patch.critical_missing`` /
``edr.unhealthy`` / ``credential.insecure_storage`` wait on a product definition.

The parse functions are pure (JSON in, typed value out); the networked run is a separate coroutine so
the handler is testable by monkeypatching the fetch.
"""

from __future__ import annotations

import asyncio
import json

import winrm

# the Windows host controls this collector reads, all from the one posture document the gather script
# returns. The factual-absolute posture controls:
POSTURE_CONTROLS = frozenset(
    {
        "server.remote.rdp_nla_disabled",
        "server.service.smbv1_enabled",
        "server.share.smb_signing_not_required",
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

# the standard WinRM HTTP port; the NTLM message layer still seals the payload over it. A caller that
# passes any other port (e.g. 5986) gets HTTPS instead. The collect target is the Windows host.
_WINRM_HTTP_PORT = 5985

# bound the admin read so a huge group cannot make one collection unbounded (build-for-scale). A larger
# group still yields a lower-bound observed set, which only ever UNDER-reports a gt-0 finding.
_MAX_ADMINS = 10_000

# how far the WS-Man read timeout sits above the operation timeout, so the client still polls once more
# after the server's operation window closes rather than dropping the connection mid-gather.
_READ_TIMEOUT_BUFFER_SEC = 5

# the ONE fixed, read-only PowerShell gather script. It interpolates NOTHING from the caller; it reads
# the registry and Get-* cmdlets and emits a single compact JSON object. `SilentlyContinue` means a
# cmdlet the host cannot answer (e.g. BitLocker feature absent) yields a null field, which the parser
# reads as abstain rather than a false posture.
_GATHER_SCRIPT = r"""
$ErrorActionPreference='SilentlyContinue'
$rdp=(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication).UserAuthentication
$smb=Get-SmbServerConfiguration
$admins=@(Get-LocalGroupMember -Group 'Administrators' | ForEach-Object { "$($_.Name)" })
# firewall across all profiles via Get-NetFirewallProfile (reliable over WinRM, unlike
# Get-NetConnectionProfile, which returns nothing from a network logon). The active profile cannot be
# singled out remotely, so a server is read across all three: enabled only if every profile is on,
# permissive if any default-allows inbound. Compute into variables first, since PowerShell 5.1 does
# not evaluate an inline if/else in a hashtable value position.
$fwAll=@(Get-NetFirewallProfile)
$fwEn=$null; $fwIn=$null
if($fwAll.Count -gt 0){
  $allEnabled=$true; $anyPermissive=$false
  foreach($f in $fwAll){
    if("$($f.Enabled)" -ne 'True'){ $allEnabled=$false }
    if("$($f.DefaultInboundAction)" -eq 'Allow'){ $anyPermissive=$true }
  }
  $fwEn=$allEnabled
  if($anyPermissive){ $fwIn='Allow' }else{ $fwIn='Block' }
}
[pscustomobject]@{
  rdp_user_authentication = $rdp
  smb1_enabled = $smb.EnableSMB1Protocol
  smb_signing_required = $smb.RequireSecuritySignature
  local_admins = $admins
  firewall_enabled = $fwEn
  firewall_default_inbound = $fwIn
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


def parse_firewall_enabled(posture: object) -> bool | None:
    """Whether the Windows Firewall is enabled across the host's profiles, or ``None`` to abstain when
    no firewall profile could be read. Read from the registry across Domain / Private / Public (the
    active profile is not reliably resolvable over a WinRM network logon), so the value is True only
    when every profile is enabled; ``False`` (any profile off) is the finding."""
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


def _run_gather(endpoint: str, username: str, password: str, *, verify: bool, timeout: float) -> str:
    """Open a WinRM session and run the ONE fixed gather script, returning its stdout (synchronous;
    pywinrm has no async API, so the caller runs this in a thread, exactly as the db-query tier runs
    pg8000). NTLM transport; the host's self-signed certificate is not verified on HTTPS (``verify``
    False), the same inverse-trust the kube / storage tiers use. ``timeout`` bounds the read so an
    unresponsive host cannot hang the collection; the WS-Man operation timeout sits just under it.
    Raises on connect / auth / non-zero exit, which the caller records as honest UNAVAILABLE."""
    session = winrm.Session(
        endpoint,
        auth=(username, password),
        transport="ntlm",
        server_cert_validation="validate" if verify else "ignore",
        read_timeout_sec=int(timeout) + _READ_TIMEOUT_BUFFER_SEC,
        operation_timeout_sec=int(timeout),
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
    timeout: float,
    port: int = _WINRM_HTTP_PORT,
    verify: bool = False,
) -> dict:
    """Run the read-only WinRM gather against the Windows host and return its parsed posture document,
    or ``{}`` when the host returned nothing parseable. The default port (5985) is HTTP; any other port
    is HTTPS. Raises on connect / auth / run failure (UNAVAILABLE)."""
    scheme = "http" if port == _WINRM_HTTP_PORT else "https"
    endpoint = f"{scheme}://{target}:{port}/wsman"
    raw = await asyncio.to_thread(
        _run_gather,
        endpoint=endpoint,
        username=credential.username,
        password=credential.secret,
        verify=verify,
        timeout=timeout,
    )
    try:
        body = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    return body if isinstance(body, dict) else {}
