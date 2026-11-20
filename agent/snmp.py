"""A minimal, bounded SNMPv2c GET for default-community discovery (PR-08, the UDP specialist).

The agent identifies SNMP the only honest way a passive sweep cannot: by sending one bounded
GET-request for ``sysDescr.0`` with a well-known default community and seeing whether the device
answers. A valid GetResponse to community ``public`` IS the finding (the device accepts a guessable
community), so this module both identifies the protocol and establishes the weakness in one probe.
That is exactly what the control-plane ``net.snmp.default_community`` discovery rule consumes.

It is deliberately a hand-rolled, single-purpose SNMPv2c codec rather than a dependency: the surface
is one GET and one response parse, and a security-sensitive agent image is better without a general
SNMP stack. ``build_snmp_get`` is pure (parameters in, exact bytes out); ``parse_snmp_response`` is
pure and defensive (hostile bytes in, a typed response or ``None`` out, never a raise and never an
over-read), because a UDP reply comes from the target and is untrusted. The socket that carries
these bytes lives in the discover handler, so this stays trivially testable from fixtures.
"""

from __future__ import annotations

from dataclasses import dataclass

# sysDescr.0 (1.3.6.1.2.1.1.1.0): the system description, present on every SNMP agent, so a GET for
# it is the least intrusive proof that the agent answered our community.
SYS_DESCR_OID: tuple[int, ...] = (1, 3, 6, 1, 2, 1, 1, 1, 0)

# The guessable communities worth testing. Identification is the finding, so the list is exactly the
# well-known defaults, never a dictionary attack: this is discovery, not credential brute force.
DEFAULT_COMMUNITIES: tuple[str, ...] = ("public", "private")

_VERSION_V2C = 1  # SNMP version field: 0 is v1, 1 is v2c

# BER tags.
_TAG_INTEGER = 0x02
_TAG_OCTET_STRING = 0x04
_TAG_NULL = 0x05
_TAG_OID = 0x06
_TAG_SEQUENCE = 0x30
_TAG_GET_REQUEST = 0xA0  # context-specific [0], constructed
_TAG_GET_RESPONSE = 0xA2  # context-specific [2], constructed

# A single UDP datagram we are willing to parse. A response larger than this is not something a
# bounded sysDescr GET should elicit, so it is refused rather than walked.
_MAX_RESPONSE = 4096


@dataclass(frozen=True, slots=True)
class SnmpGetResponse:
    """A parsed SNMPv2c GetResponse. ``accepted`` is the honest verdict: the device returned a
    well-formed response with a non-error status to the community we sent, i.e. it accepted it.
    ``sys_descr`` is the returned description when it was an octet string, carried as evidence."""

    community: str
    request_id: int
    error_status: int
    sys_descr: str | None

    @property
    def accepted(self) -> bool:
        return self.error_status == 0


# ── encoding ──────────────────────────────────────────────────────────────────


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes((length,))
    body = b""
    while length:
        body = bytes((length & 0xFF,)) + body
        length >>= 8
    return bytes((0x80 | len(body),)) + body


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes((tag,)) + _encode_length(len(content)) + content


def _encode_int(value: int) -> bytes:
    if value == 0:
        return _tlv(_TAG_INTEGER, b"\x00")
    body = b""
    n = value
    while n:
        body = bytes((n & 0xFF,)) + body
        n >>= 8
    # BER integers are signed: a leading byte with its high bit set would read as negative, so pad.
    if body[0] & 0x80:
        body = b"\x00" + body
    return _tlv(_TAG_INTEGER, body)


def _encode_oid(parts: tuple[int, ...]) -> bytes:
    if len(parts) < 2:
        raise ValueError("an OID needs at least two arcs")
    first = parts[0] * 40 + parts[1]
    body = bytes((first,))
    for arc in parts[2:]:
        if arc < 0x80:
            body += bytes((arc,))
            continue
        chunk = bytes((arc & 0x7F,))
        arc >>= 7
        while arc:
            chunk = bytes((0x80 | (arc & 0x7F),)) + chunk
            arc >>= 7
        body += chunk
    return _tlv(_TAG_OID, body)


def build_snmp_get(
    *,
    community: str,
    request_id: int,
    oid: tuple[int, ...] = SYS_DESCR_OID,
) -> bytes:
    """The exact bytes of an SNMPv2c GET-request for ``oid`` under ``community``.

    Deterministic: the same arguments always produce the same datagram, so the encoding is pinned by
    a byte-for-byte fixture test rather than trusted."""

    varbind = _tlv(_TAG_SEQUENCE, _encode_oid(oid) + _tlv(_TAG_NULL, b""))
    varbind_list = _tlv(_TAG_SEQUENCE, varbind)
    pdu = _tlv(
        _TAG_GET_REQUEST,
        _encode_int(request_id)
        + _encode_int(0)  # error-status
        + _encode_int(0)  # error-index
        + varbind_list,
    )
    message = _tlv(
        _TAG_SEQUENCE,
        _encode_int(_VERSION_V2C) + _tlv(_TAG_OCTET_STRING, community.encode("utf-8")) + pdu,
    )
    return message


# ── decoding (defensive: untrusted bytes in) ──────────────────────────────────


@dataclass(frozen=True, slots=True)
class _Field:
    tag: int
    content: bytes
    end: int  # index in the buffer just past this field


def _read_field(data: bytes, offset: int) -> _Field | None:
    """Read one TLV starting at ``offset``, or ``None`` on any malformation or over-read. Never
    raises and never reads past ``len(data)``, so a hostile datagram yields a clean ``None``."""

    if offset + 2 > len(data):
        return None
    tag = data[offset]
    length_byte = data[offset + 1]
    cursor = offset + 2
    if length_byte < 0x80:
        length = length_byte
    else:
        num = length_byte & 0x7F
        if num == 0 or num > 4 or cursor + num > len(data):
            return None
        length = 0
        for i in range(num):
            length = (length << 8) | data[cursor + i]
        cursor += num
    end = cursor + length
    if end > len(data):
        return None
    return _Field(tag=tag, content=data[cursor:end], end=end)


def _read_int(data: bytes, offset: int) -> tuple[int, int] | None:
    field = _read_field(data, offset)
    if field is None or field.tag != _TAG_INTEGER or not field.content:
        return None
    return int.from_bytes(field.content, "big", signed=True), field.end


def parse_snmp_response(
    data: bytes,
    *,
    expected_request_id: int | None = None,
) -> SnmpGetResponse | None:
    """Parse an SNMPv2c GetResponse, or ``None`` if ``data`` is not one.

    ``None`` is returned for anything that is not a well-formed GetResponse: a random UDP reply, an
    ICMP body, a truncated or oversized datagram, or (when ``expected_request_id`` is given) a
    response whose request-id does not match the GET we sent. That last check is a cheap spoofing
    guard: an off-path answer that did not see our request-id is rejected rather than read as the
    device accepting our community.
    """

    if not data or len(data) > _MAX_RESPONSE:
        return None
    message = _read_field(data, 0)
    if message is None or message.tag != _TAG_SEQUENCE:
        return None
    body = message.content

    version = _read_int(body, 0)
    if version is None:
        return None
    _, cursor = version

    community_field = _read_field(body, cursor)
    if community_field is None or community_field.tag != _TAG_OCTET_STRING:
        return None
    try:
        community = community_field.content.decode("utf-8")
    except UnicodeDecodeError:
        return None

    pdu = _read_field(body, community_field.end)
    if pdu is None or pdu.tag != _TAG_GET_RESPONSE:
        return None
    pdu_body = pdu.content

    request = _read_int(pdu_body, 0)
    if request is None:
        return None
    request_id, cursor = request
    if expected_request_id is not None and request_id != expected_request_id:
        return None

    error = _read_int(pdu_body, cursor)
    if error is None:
        return None
    error_status, cursor = error

    error_index = _read_int(pdu_body, cursor)
    if error_index is None:
        return None
    _, cursor = error_index

    sys_descr = _first_octet_string_value(pdu_body, cursor)
    return SnmpGetResponse(
        community=community,
        request_id=request_id,
        error_status=error_status,
        sys_descr=sys_descr,
    )


def _first_octet_string_value(pdu_body: bytes, offset: int) -> str | None:
    """The first varbind value that is a readable octet string, or ``None``. Used only to carry
    sysDescr as evidence; the verdict (accepted) never depends on it, so an unreadable or absent
    value is simply no evidence, not a parse failure."""

    varbind_list = _read_field(pdu_body, offset)
    if varbind_list is None or varbind_list.tag != _TAG_SEQUENCE:
        return None
    varbind = _read_field(varbind_list.content, 0)
    if varbind is None or varbind.tag != _TAG_SEQUENCE:
        return None
    oid_field = _read_field(varbind.content, 0)
    if oid_field is None:
        return None
    value = _read_field(varbind.content, oid_field.end)
    if value is None or value.tag != _TAG_OCTET_STRING:
        return None
    try:
        return value.content.decode("utf-8", "replace")
    except (UnicodeDecodeError, ValueError):
        return None
