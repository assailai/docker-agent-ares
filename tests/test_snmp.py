"""The bounded SNMPv2c default-community probe (PR-08, the UDP specialist).

Two kinds of seam are pinned: the request encoding is byte-for-byte, because the control plane and a
real device both have to accept the exact datagram; and the response parser is driven with hostile
and malformed input, because a UDP reply comes from the target and a parser that raised, over-read,
or read a random datagram as an accepted community would be a correctness and a safety bug at once.
"""

from __future__ import annotations

from agent.snmp import (
    _TAG_GET_RESPONSE,
    _TAG_NULL,
    _TAG_OCTET_STRING,
    _TAG_SEQUENCE,
    SYS_DESCR_OID,
    _encode_int,
    _encode_oid,
    _tlv,
    build_snmp_get,
    parse_snmp_response,
)


def _response(
    *,
    community: str = "public",
    request_id: int = 1,
    error_status: int = 0,
    sys_descr: str | None = "Arista Networks EOS",
) -> bytes:
    """Craft a GetResponse datagram the way a device would, for the parser to read back."""
    value = (
        _tlv(_TAG_OCTET_STRING, sys_descr.encode("utf-8"))
        if sys_descr is not None
        else _tlv(_TAG_NULL, b"")
    )
    varbind = _tlv(_TAG_SEQUENCE, _encode_oid(SYS_DESCR_OID) + value)
    varbind_list = _tlv(_TAG_SEQUENCE, varbind)
    pdu = _tlv(
        _TAG_GET_RESPONSE,
        _encode_int(request_id) + _encode_int(error_status) + _encode_int(0) + varbind_list,
    )
    return _tlv(
        _TAG_SEQUENCE,
        _encode_int(1) + _tlv(_TAG_OCTET_STRING, community.encode("utf-8")) + pdu,
    )


# ── encoding is byte-exact ────────────────────────────────────────────────────


def test_build_snmp_get_is_byte_for_byte() -> None:
    expected = bytes.fromhex(
        "302602010104067075626c6963a019020101020100020100300e300c06082b060102010101000500"
    )
    assert build_snmp_get(community="public", request_id=1) == expected


def test_a_request_id_with_the_high_bit_set_is_padded_not_negative() -> None:
    # 0x80 as a BER integer would read as negative without a leading zero byte.
    assert _encode_int(0x80) == bytes.fromhex("02020080")
    assert _encode_int(0) == bytes.fromhex("020100")
    assert _encode_int(1) == bytes.fromhex("020101")


def test_sysdescr_oid_encodes_to_the_well_known_bytes() -> None:
    assert _encode_oid(SYS_DESCR_OID) == bytes.fromhex("06082b06010201010100")


# ── parsing a genuine response ────────────────────────────────────────────────


def test_a_valid_getresponse_is_accepted_with_its_description() -> None:
    result = parse_snmp_response(_response(request_id=1), expected_request_id=1)
    assert result is not None
    assert result.accepted is True
    assert result.community == "public"
    assert result.request_id == 1
    assert result.sys_descr == "Arista Networks EOS"


def test_an_error_status_is_parsed_but_not_accepted() -> None:
    result = parse_snmp_response(_response(error_status=5))
    assert result is not None
    assert result.error_status == 5
    assert result.accepted is False


def test_a_response_without_a_value_still_parses() -> None:
    result = parse_snmp_response(_response(sys_descr=None))
    assert result is not None
    assert result.accepted is True
    assert result.sys_descr is None


# ── the parser refuses everything that is not our response ────────────────────


def test_a_request_id_mismatch_is_refused_as_spoofing_guard() -> None:
    assert parse_snmp_response(_response(request_id=1), expected_request_id=999) is None


def test_a_get_request_is_not_a_response() -> None:
    # The device echoing our own GET tag back must not read as a response it accepted.
    assert parse_snmp_response(build_snmp_get(community="public", request_id=1)) is None


def test_random_bytes_are_not_snmp() -> None:
    assert parse_snmp_response(b"\x00\x01\x02\x03nothing here") is None
    assert parse_snmp_response(b"") is None
    assert parse_snmp_response(b"\x30") is None


def test_a_truncated_length_is_refused_not_over_read() -> None:
    # A SEQUENCE claiming 100 content bytes in a 3-byte datagram must yield None, never an index
    # error or a read past the buffer.
    assert parse_snmp_response(b"\x30\x64\x00") is None


def test_an_oversized_datagram_is_refused() -> None:
    assert parse_snmp_response(b"\x30" + b"\x00" * 5000) is None


def test_a_non_utf8_community_is_refused() -> None:
    # A community field that is not valid UTF-8 must be refused by the decode guard, not raise.
    empty_pdu = _encode_int(1) + _encode_int(0) + _encode_int(0) + _tlv(_TAG_SEQUENCE, b"")
    message = _tlv(
        _TAG_SEQUENCE,
        _encode_int(1)
        + _tlv(_TAG_OCTET_STRING, b"\xff\xfe")
        + _tlv(_TAG_GET_RESPONSE, empty_pdu),
    )
    assert parse_snmp_response(message) is None
