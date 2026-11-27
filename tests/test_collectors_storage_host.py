"""The storage host collector normalizes an NFS server's export table (``/etc/exports``) into the
``storage.nfs.wildcard_rw`` fact, flagging an export open read-write to every host and abstaining when
the host has no exports at all (never guessing a clean result)."""

from __future__ import annotations

from pathlib import Path

from agent.collectors import storage_host

_FIX = Path(__file__).with_name("fixtures")


def test_wildcard_read_write_export_is_flagged() -> None:
    exports = (_FIX / "exports_wildcard_rw.txt").read_text()
    assert storage_host.parse_nfs_wildcard_rw_export(exports) is True


def test_restricted_or_read_only_exports_pass() -> None:
    # A host-restricted rw export plus a world-readable RO export: neither is wildcard read-write.
    exports = (_FIX / "exports_restricted.txt").read_text()
    assert storage_host.parse_nfs_wildcard_rw_export(exports) is False


def test_all_addresses_cidr_client_counts_as_wildcard() -> None:
    assert storage_host.parse_nfs_wildcard_rw_export("/data 0.0.0.0/0(rw,sync)\n") is True
    assert storage_host.parse_nfs_wildcard_rw_export("/data ::/0(rw)\n") is True


def test_domain_wildcard_is_not_treated_as_all_hosts() -> None:
    # `*.corp.example` restricts to a domain; flagging it would be a false positive.
    assert storage_host.parse_nfs_wildcard_rw_export("/data *.corp.example(rw)\n") is False


def test_wildcard_but_read_only_passes() -> None:
    assert storage_host.parse_nfs_wildcard_rw_export("/data *(ro,sync)\n") is False


def test_no_exports_abstains_never_false_positives() -> None:
    # Not an NFS server (empty read), or a file of only comments: abstain rather than assert "clean".
    assert storage_host.parse_nfs_wildcard_rw_export("") is None
    assert storage_host.parse_nfs_wildcard_rw_export("# only a comment\n\n") is None
    assert storage_host.parse_nfs_wildcard_rw_export("cat: /etc/exports: No such file\n") is None


def test_routing_and_collection() -> None:
    assert storage_host.serves("storage.nfs.wildcard_rw") is True
    assert storage_host.serves("server.ssh.password") is False
    assert storage_host.source_for("storage.nfs.wildcard_rw") == storage_host.SOURCE_NFS_EXPORTS
    sources = {storage_host.SOURCE_NFS_EXPORTS: "/data *(rw)\n"}
    assert storage_host.collect_control_fields(sources, "storage.nfs.wildcard_rw") == {
        "wildcard_read_write_export": True
    }
    assert storage_host.collect_control_fields(sources, "net.management.telnet") is None
