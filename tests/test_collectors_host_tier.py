"""The host tier aggregates the host collector families (server hardening, storage, ...) behind one
interface the dispatcher routes through: each control is owned by exactly one family, the evidence
sources are merged loss-free, and a control no host family serves falls through to the device tier."""

from __future__ import annotations

from agent.collectors import (
    database_host,
    host_tier,
    linux_host,
    mail_host,
    storage_host,
    web_host,
)

_FAMILIES = (linux_host, storage_host, database_host, mail_host, web_host)


def test_each_control_routes_to_its_owning_family() -> None:
    assert host_tier.serves("server.ssh.password") is True
    assert host_tier.serves("server.audit.security_logging_disabled") is True
    assert host_tier.serves("storage.nfs.wildcard_rw") is True
    assert host_tier.serves("database.client.tls") is True
    assert host_tier.serves("mail.auth.legacy") is True
    # A device control (read from the running-config) is NOT a host control: it falls through.
    assert host_tier.serves("net.management.telnet") is False


def test_source_for_delegates_to_the_owning_family() -> None:
    assert host_tier.source_for("server.ssh.password") == linux_host.SOURCE_SSHD
    assert host_tier.source_for("storage.nfs.wildcard_rw") == storage_host.SOURCE_NFS_EXPORTS
    assert host_tier.source_for("database.client.tls") == database_host.SOURCE_PG_HBA
    assert host_tier.source_for("net.management.telnet") is None


def test_source_readers_merge_every_family_loss_free() -> None:
    # Every family's sources are present, and the merge preserves each family's reader name.
    total = 0
    for family in _FAMILIES:
        for source, reader in family.SOURCE_READERS.items():
            assert host_tier.SOURCE_READERS[source] == reader
            total += 1
    # Sources are globally unique, so no family's source was clobbered by the merge.
    assert len(host_tier.SOURCE_READERS) == total


def test_sources_for_collects_each_needed_source_once() -> None:
    needed = host_tier.sources_for(
        ["server.ssh.password", "server.ssh.root_login", "storage.nfs.wildcard_rw"]
    )
    # Two ssh.* controls share the sshd source (read once); storage adds its own.
    assert needed == {linux_host.SOURCE_SSHD, storage_host.SOURCE_NFS_EXPORTS}


def test_collect_control_fields_delegates_and_abstains() -> None:
    sources = {storage_host.SOURCE_NFS_EXPORTS: "/data *(rw)\n"}
    assert host_tier.collect_control_fields(sources, "storage.nfs.wildcard_rw") == {
        "wildcard_read_write_export": True
    }
    assert host_tier.collect_control_fields(sources, "net.management.telnet") is None
