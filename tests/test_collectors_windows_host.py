"""The Windows host collector normalises the one read-only WinRM posture document into the Windows
`server.*` fields, and sends the RAW local-Administrators set for the baseline control under the SAME
wire key as the Linux tier. Every parser ABSTAINS (returns ``None``) when its field was not read, so an
unreachable or unauthorized host leaves the control NOT_ASSESSED rather than inventing a posture."""

from __future__ import annotations

from agent.collectors import windows_host


def _posture(
    *,
    rdp_ua: int = 1,
    smb1: bool = False,
    smb_signing: bool = True,
    bitlocker: int = 1,
    firewall_enabled: bool = True,
    firewall_inbound: str = "Block",
    admins: list[str] | None = None,
) -> dict:
    """A full posture document. Defaults are the HARDENED host (no finding on any control); a test
    flips one field to the insecure value to assert that control's finding polarity."""
    return {
        "rdp_user_authentication": rdp_ua,
        "smb1_enabled": smb1,
        "smb_signing_required": smb_signing,
        "bitlocker_protection": bitlocker,
        "firewall_enabled": firewall_enabled,
        "firewall_default_inbound": firewall_inbound,
        "local_admins": ["BUILTIN\\Administrator"] if admins is None else admins,
    }


# ── RDP NLA (eq-False-is-finding, read from an integer registry value) ────────────────────────────
def test_rdp_nla_enforced_only_when_value_is_exactly_one() -> None:
    assert windows_host.parse_rdp_nla_enforced(_posture(rdp_ua=1)) is True
    assert windows_host.parse_rdp_nla_enforced(_posture(rdp_ua=0)) is False  # the finding
    # a bool must not read as the int 1 (True == 1 in Python), and a missing value abstains
    assert windows_host.parse_rdp_nla_enforced({"rdp_user_authentication": True}) is None
    assert windows_host.parse_rdp_nla_enforced({}) is None


def test_smbv1_and_signing_booleans() -> None:
    assert windows_host.parse_smbv1_enabled(_posture(smb1=True)) is True  # finding
    assert windows_host.parse_smbv1_enabled(_posture(smb1=False)) is False
    assert windows_host.parse_smb_signing_required(_posture(smb_signing=False)) is False  # finding
    assert windows_host.parse_smb_signing_required(_posture(smb_signing=True)) is True
    assert windows_host.parse_smbv1_enabled({"smb1_enabled": "no"}) is None


def test_bitlocker_protection_status() -> None:
    assert windows_host.parse_full_disk_encryption_enabled(_posture(bitlocker=1)) is True
    assert windows_host.parse_full_disk_encryption_enabled(_posture(bitlocker=0)) is False  # finding
    # BitLocker feature absent -> null -> abstain (not a false "unencrypted")
    assert windows_host.parse_full_disk_encryption_enabled({"bitlocker_protection": None}) is None
    assert windows_host.parse_full_disk_encryption_enabled({"bitlocker_protection": True}) is None


def test_firewall_enabled_and_permissive() -> None:
    assert windows_host.parse_firewall_enabled(_posture(firewall_enabled=True)) is True
    assert windows_host.parse_firewall_enabled(_posture(firewall_enabled=False)) is False  # finding
    # no active profile resolved -> null -> abstain
    assert windows_host.parse_firewall_enabled({"firewall_enabled": None}) is None
    # permissive default: Allow is the finding, Block is clean, case-insensitive
    assert windows_host.parse_firewall_permissive_default(_posture(firewall_inbound="Allow")) is True
    assert windows_host.parse_firewall_permissive_default(_posture(firewall_inbound="Block")) is False
    assert windows_host.parse_firewall_permissive_default(_posture(firewall_inbound="allow")) is True
    assert windows_host.parse_firewall_permissive_default({"firewall_default_inbound": None}) is None


def test_posture_field_dicts_and_abstain() -> None:
    p = _posture(rdp_ua=0, smb1=True, smb_signing=False, bitlocker=0, firewall_enabled=False, firewall_inbound="Allow")
    assert windows_host.rdp_nla_field(p) == {"rdp_network_level_auth_enforced": False}
    assert windows_host.smbv1_field(p) == {"smbv1_enabled": True}
    assert windows_host.smb_signing_field(p) == {"smb_signing_required": False}
    assert windows_host.disk_encryption_field(p) == {"full_disk_encryption_enabled": False}
    assert windows_host.firewall_enabled_field(p) == {"active_profile_enabled": False}
    assert windows_host.firewall_permissive_field(p) == {"firewall_permissive_default": True}
    assert windows_host.rdp_nla_field({}) is None
    assert windows_host.disk_encryption_field({"bitlocker_protection": None}) is None


# ── local Administrators (the baseline control, SAME wire key as Linux) ────────────────────────────
def test_local_admins_sorted_deduped_and_trimmed() -> None:
    doc = {"local_admins": ["WINHOST\\rogueadmin", "BUILTIN\\Administrator", " WINHOST\\rogueadmin ", "", "  "]}
    assert windows_host.parse_local_admins(doc) == ["BUILTIN\\Administrator", "WINHOST\\rogueadmin"]


def test_local_admins_abstains_on_non_list() -> None:
    assert windows_host.parse_local_admins({}) is None
    assert windows_host.parse_local_admins({"local_admins": "nope"}) is None
    assert windows_host.parse_local_admins("nope") is None


def test_local_admins_field_uses_the_linux_wire_key() -> None:
    assert windows_host.local_admins_field(_posture(admins=["BUILTIN\\Administrator", "WINHOST\\rogue"])) == {
        "observed_local_admins": ["BUILTIN\\Administrator", "WINHOST\\rogue"]
    }
    assert windows_host.local_admins_field({"local_admins": "nope"}) is None


# ── serves() routing ──────────────────────────────────────────────────────────────────────────────
def test_serves_the_windows_controls_only() -> None:
    for control in (
        "server.remote.rdp_nla_disabled",
        "server.service.smbv1_enabled",
        "server.share.smb_signing_not_required",
        "server.boot.disk_unencrypted",
        "server.firewall.enabled",
        "server.firewall.permissive",
        "server.localadmin.unapproved",
    ):
        assert windows_host.serves(control) is True
    # the Linux-only SSH controls are not this tier
    assert windows_host.serves("server.ssh.password") is False
    assert windows_host.serves("server.sysctl.ip_forwarding") is False
    assert windows_host.serves("storage.snapshot.unprotected") is False


def test_localadmin_is_the_only_baseline_member() -> None:
    assert windows_host.BASELINE_CONTROLS == frozenset({"server.localadmin.unapproved"})
    assert "server.localadmin.unapproved" not in windows_host.POSTURE_CONTROLS


def test_the_gather_script_is_read_only() -> None:
    # The gather script is a fixed constant (no caller interpolation) and uses only read verbs; it is
    # the WinRM analogue of the db-query tier's one fixed catalog query.
    lowered = windows_host._GATHER_SCRIPT.lower()
    for write_verb in (
        "set-", "remove-", "new-", "stop-", "start-", "restart-", "disable-", "enable-", "invoke-",
    ):
        assert write_verb not in lowered, f"gather script contains a write verb: {write_verb}"
