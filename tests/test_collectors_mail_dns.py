"""The mail-DNS collector derives the mail domain from Postfix main.cf and reads the domain's SPF /
DMARC enforcement from its TXT records. The networked resolve is exercised live in the accuracy lab;
these tests pin the domain derivation and the pure parsing."""

from __future__ import annotations

from agent.collectors import mail_dns


def test_domain_from_postfix_mydomain_then_myhostname() -> None:
    assert mail_dns.domain_from_postfix("mydomain = lab.local\nmyhostname = mail.lab.local") == "lab.local"
    # no mydomain -> parent of myhostname
    assert mail_dns.domain_from_postfix("myhostname = mail.corp.example") == "corp.example"
    assert mail_dns.domain_from_postfix("# nothing here") is None
    assert mail_dns.domain_from_postfix("myhostname = standalone") is None


def test_spf_enforced_only_on_hard_fail() -> None:
    assert mail_dns.parse_spf_enforced(["v=spf1 mx -all"]) is True
    assert mail_dns.parse_spf_enforced(["v=spf1 mx ~all"]) is False
    assert mail_dns.parse_spf_enforced(["v=spf1 ?all"]) is False
    assert mail_dns.parse_spf_enforced(["v=spf1 +all"]) is False
    assert mail_dns.parse_spf_enforced(["some other txt"]) is False  # no SPF published
    assert mail_dns.parse_spf_enforced([]) is False
    assert mail_dns.parse_spf_enforced("nope") is None


def test_dmarc_enforced_on_quarantine_or_reject() -> None:
    assert mail_dns.parse_dmarc_enforced(["v=DMARC1; p=reject"]) is True
    assert mail_dns.parse_dmarc_enforced(["v=DMARC1; p=quarantine; rua=mailto:x@y"]) is True
    assert mail_dns.parse_dmarc_enforced(["v=DMARC1; p=none"]) is False
    assert mail_dns.parse_dmarc_enforced(["unrelated"]) is False  # no DMARC published
    assert mail_dns.parse_dmarc_enforced([]) is False
    assert mail_dns.parse_dmarc_enforced(None) is None


def test_serves_and_fields() -> None:
    assert mail_dns.serves("mail.spf.not_enforced") is True
    assert mail_dns.serves("mail.dmarc.not_enforced") is True
    assert mail_dns.serves("mail.auth.legacy") is False
    assert mail_dns.spf_field(["v=spf1 ~all"]) == {"spf_enforced": False}
    assert mail_dns.dmarc_field(["v=DMARC1; p=none"]) == {"dmarc_policy_enforced": False}
    assert mail_dns.spf_field("x") is None


def test_mtasts_enforced_only_when_published_and_mode_enforce() -> None:
    assert mail_dns.parse_mtasts_published(["v=STSv1; id=20260101"]) is True
    assert mail_dns.parse_mtasts_published(["unrelated"]) is False
    assert mail_dns.parse_mtasts_published([]) is False
    assert mail_dns.parse_mtasts_published("x") is None
    assert mail_dns.parse_mtasts_mode("version: STSv1\nmode: enforce\nmx: m.lab\nmax_age: 86400") == "enforce"
    assert mail_dns.parse_mtasts_mode("mode: testing") == "testing"
    assert mail_dns.parse_mtasts_mode("no mode here") is None
    # enforced only when BOTH published and mode enforce
    assert mail_dns.parse_mtasts_enforce_enabled(True, "enforce") is True
    assert mail_dns.parse_mtasts_enforce_enabled(True, "testing") is False
    assert mail_dns.parse_mtasts_enforce_enabled(False, None) is False
    # not published (the common real finding) -> not enforced
    assert mail_dns.mtasts_field(False, None) == {"mta_sts_enforce_mode_enabled": False}
    assert mail_dns.mtasts_field(True, "enforce") == {"mta_sts_enforce_mode_enabled": True}
    assert mail_dns.serves("mail.mtasts.not_enforced") is True
