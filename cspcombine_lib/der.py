"""Small dependency-free ASN.1/DER helpers used by cspcombine.

Only the subset that occurs in ViPNet and CryptoPro key containers is
implemented: definite lengths, SEQUENCE, INTEGER, OCTET STRING, BIT STRING,
OBJECT IDENTIFIER, context-specific tags and GeneralizedTime.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field


class DerError(ValueError):
    pass


def der_length(length: int) -> bytes:
    if length < 0:
        raise DerError("negative DER length")
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def der(tag: int, body: bytes = b"") -> bytes:
    return bytes([tag]) + der_length(len(body)) + body


def der_item(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    """Read one DER TLV and return ``(tag, body, next_offset)``."""
    if offset + 2 > len(data):
        raise DerError("truncated DER item")
    tag = data[offset]
    length_byte = data[offset + 1]
    position = offset + 2
    if length_byte & 0x80:
        count = length_byte & 0x7F
        if count == 0:
            raise DerError("indefinite DER lengths are not supported")
        if position + count > len(data):
            raise DerError("truncated DER length")
        length = int.from_bytes(data[position:position + count], "big")
        position += count
    else:
        length = length_byte
    end = position + length
    if end > len(data):
        raise DerError("truncated DER value")
    return tag, data[position:end], end


def der_children(data: bytes) -> list[tuple[int, bytes]]:
    result: list[tuple[int, bytes]] = []
    position = 0
    while position < len(data):
        tag, body, position = der_item(data, position)
        result.append((tag, body))
    return result


def der_oid(value: str) -> bytes:
    numbers = [int(part) for part in value.split(".")]
    if len(numbers) < 2:
        raise DerError(f"invalid OID: {value}")
    out = bytearray([40 * numbers[0] + numbers[1]])
    for number in numbers[2:]:
        if number < 0:
            raise DerError(f"invalid OID component: {number}")
        parts = [number & 0x7F]
        number >>= 7
        while number:
            parts.append(0x80 | (number & 0x7F))
            number >>= 7
        out.extend(reversed(parts))
    return der(0x06, bytes(out))


def oid_text(value: bytes) -> str:
    if not value:
        raise DerError("empty OBJECT IDENTIFIER")
    first = value[0]
    parts = [min(2, first // 40), first - min(2, first // 40) * 40]
    number = 0
    for byte in value[1:]:
        number = (number << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(number)
            number = 0
    return ".".join(map(str, parts))


def der_integer(value: int) -> bytes:
    if value < 0:
        # Two's-complement, minimal representation for a negative INTEGER.
        bits = value.bit_length() + 1
        length = max(1, (bits + 7) // 8)
        return der(0x02, value.to_bytes(length, "big", signed=True))
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\0" + raw
    return der(0x02, raw)


def der_octet(value: bytes) -> bytes:
    return der(0x04, value)


def der_bit_string(value: bytes, unused: int = 0) -> bytes:
    if not 0 <= unused <= 7:
        raise DerError("invalid number of unused bits")
    return der(0x03, bytes([unused]) + value)


def der_sequence(*items: bytes) -> bytes:
    return der(0x30, b"".join(items))


def der_generalized_time(text: str) -> bytes:
    encoded = text.encode("ascii")
    if len(encoded) != 15 or not encoded.endswith(b"Z"):
        raise DerError(f"invalid GeneralizedTime: {text}")
    return der(0x18, encoded)


def implicit_tag(number: int, body: bytes, constructed: bool = False) -> bytes:
    return der((0xA0 if constructed else 0x80) | number, body)


@dataclass
class Der:
    """Parsed DER node, convenient for the CryptoPro header layout."""

    tag: int
    value: bytes
    children: list["Der"] = field(default_factory=list)

    def oid(self) -> str:
        if self.tag != 0x06:
            raise DerError("expected OBJECT IDENTIFIER")
        return oid_text(self.value)


def der_read(data: bytes, offset: int = 0) -> tuple[Der, int]:
    tag, value, end = der_item(data, offset)
    children: list[Der] = []
    if tag in (0x30, 0x31):
        position = 0
        while position < len(value):
            child, position = der_read(value, position)
            children.append(child)
        if position != len(value):
            raise DerError("invalid ASN.1 contents")
    return Der(tag, value, children), end


def pem_encode(label: str, data: bytes) -> bytes:
    body = base64.b64encode(data)
    lines = b"\n".join(body[i:i + 64] for i in range(0, len(body), 64))
    return b"-----BEGIN " + label.encode("ascii") + b"-----\n" + lines + b"\n-----END " + label.encode("ascii") + b"-----\n"


def pem_decode(text: str) -> tuple[str, bytes]:
    lines = [line.strip() for line in text.strip().splitlines()]
    if not lines or not lines[0].startswith("-----BEGIN ") or not lines[0].endswith("-----"):
        raise DerError("not a PEM block")
    label = lines[0][len("-----BEGIN "):-5]
    body = "".join(line for line in lines[1:] if not line.startswith("-----"))
    return label, base64.b64decode(body)
