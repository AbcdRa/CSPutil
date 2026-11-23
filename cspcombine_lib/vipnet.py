"""Read, extract from and build single-file ViPNet (ITCS/PKEY) containers."""

from __future__ import annotations

import secrets
import struct
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .curves import CURVES, DIGEST_OIDS, curve_by_oid
from .der import (DerError, der, der_children, der_integer, der_item,
                  der_octet, der_oid, der_sequence, oid_text)
from .gost import (gost_cfb_decrypt, gost_cfb_encrypt, gost_mac,
                   hmac_streebog256, pbkdf2_streebog256)
from .keys import generalized_time, parse_generalized_time, private_key_pem
from .schema import Spec

MAGICS = (b"ITCS", b"PKEY", b"_CCK", b"_LCK")
PBKDF2_OID = "1.2.840.113549.1.5.12"
HMAC_STREEBOG_512_OID = "1.2.643.7.1.1.4.2"


@dataclass
class Entry:
    key_info_raw: bytes
    key_class: int
    key_type: int
    algorithm: str | None
    parameters: list[str]
    key_algorithm: str | None
    key_parameters: list[str]
    salt: bytes | None
    iterations: int | None
    key_block: bytes
    public_key: bytes | None
    source: bytes
    key_block_offset: int
    entry_size_offset: int
    key_size_offset: int
    serial: bytes | None = None
    validity: tuple[datetime | None, datetime | None] = (None, None)
    key_uid: bytes | None = None
    flags: int | None = None

    @property
    def curve_oid(self) -> str | None:
        for value in self.key_parameters:
            if value in CURVES:
                return value
        for value in self.key_parameters:
            try:
                curve_by_oid(value)
                return value
            except ValueError:
                continue
        return None


def _algorithm_fields(value: bytes) -> tuple[str | None, list[str], bytes | None, int | None]:
    sequence = der_children(value)
    if not sequence or sequence[0][0] != 0x30:
        raise ValueError("некорректный AlgorithmIdentifier")
    fields = der_children(sequence[0][1])
    if not fields or fields[0][0] != 0x06:
        raise ValueError("AlgorithmIdentifier без OID")
    identifier = oid_text(fields[0][1])
    oids: list[str] = []
    salt = None
    iterations = None
    if len(fields) > 1 and fields[1][0] == 0x30:
        params = der_children(fields[1][1])
        oids = [oid_text(item[1]) for item in params if item[0] == 0x06]
        salt = next((item[1] for item in params if item[0] == 0x04), None)
        iterations = next((int.from_bytes(item[1], "big") for item in params
                           if item[0] == 0x02), None)
    return identifier, oids, salt, iterations


def _key_algorithm_fields(value: bytes) -> tuple[str | None, list[str]]:
    sequence = der_children(value)
    if not sequence or sequence[0][0] != 0x30:
        raise ValueError("некорректный keyAlgorithm")
    fields = der_children(sequence[0][1])
    if not fields or fields[0][0] != 0x06:
        raise ValueError("keyAlgorithm без OID")
    identifier = oid_text(fields[0][1])
    params: list[str] = []
    if len(fields) > 1 and fields[1][0] == 0x30:
        params = [oid_text(item[1]) for item in der_children(fields[1][1])
                  if item[0] == 0x06]
    return identifier, params


def read_container(source: Path | str | bytes) -> Entry:
    data = source if isinstance(source, (bytes, bytearray)) else Path(source).read_bytes()
    data = bytes(data)
    if data[:4] not in MAGICS:
        raise ValueError("неподдерживаемый тип контейнера ViPNet")
    header_size = struct.unpack_from("<i", data, 8)[0]
    position = 12 + max(header_size, 0)
    if position > len(data):
        raise ValueError("повреждённый заголовок контейнера")
    entry_size = struct.unpack_from("<i", data, position)[0]
    position += 4
    entry_start = position
    tag, body, position = der_item(data, position)
    if tag != 0x30:
        raise ValueError("запись контейнера не является ASN.1 SEQUENCE")
    sequence = der_children(body)
    if len(sequence) < 3 or sequence[1][0] != 0x30 or sequence[2][0] != 0x30:
        raise ValueError("некорректная структура записи контейнера")
    key_info = der(0x30, sequence[1][1])
    key_fields = der_children(sequence[1][1])
    defence_fields = der_children(sequence[2][1])
    if len(key_fields) < 2:
        raise ValueError("keyInfo не содержит типа ключа")

    algorithm = None
    parameters: list[str] = []
    key_algorithm = None
    key_parameters: list[str] = []
    serial = None
    validity: tuple[datetime | None, datetime | None] = (None, None)
    flags = None

    for item_tag, value in key_fields[2:]:
        if item_tag == 0xA0:
            key_algorithm, key_parameters = _key_algorithm_fields(value)
        elif item_tag == 0xA1:
            inner_tag, inner_body, _ = der_item(value)
            if inner_tag == 0x04:
                serial = inner_body
        elif item_tag == 0xA6:
            try:
                fields = der_children(value)
                if fields and fields[0][0] == 0x30:
                    fields = der_children(fields[0][1])
            except DerError:
                fields = []
            not_before = next((body for tag, body in fields if tag == 0x80), None)
            not_after = next((body for tag, body in fields if tag == 0x81), None)
            validity = (parse_generalized_time(not_before) if not_before else None,
                        parse_generalized_time(not_after) if not_after else None)
        elif item_tag == 0xAA:
            inner_tag, inner_body, _ = der_item(value)
            if inner_tag == 0x02:
                flags = int.from_bytes(inner_body, "big", signed=True)

    salt = None
    iterations = None
    key_uid = None
    for item_tag, value in defence_fields[2:]:
        if item_tag == 0xA0:
            try:
                algorithm, parameters, salt, iterations = _algorithm_fields(value)
            except (DerError, ValueError):
                pass
        elif item_tag == 0xA7:
            inner_tag, inner_body, _ = der_item(value)
            if inner_tag == 0x03 and inner_body and inner_body[0] == 0:
                key_uid = inner_body[1:]

    key_size = struct.unpack_from("<i", data, position)[0]
    position += 4
    key_block = data[position:position + key_size]
    if position + key_size - entry_start != entry_size:
        raise ValueError("некорректный размер блока ключа")
    public_key = next((value for tag, value in sequence[3:] if tag == 0xA1), None)

    return Entry(
        key_info_raw=key_info,
        key_class=int.from_bytes(key_fields[0][1], "big", signed=True),
        key_type=int.from_bytes(key_fields[1][1], "big", signed=True),
        algorithm=algorithm,
        parameters=parameters,
        key_algorithm=key_algorithm,
        key_parameters=key_parameters,
        salt=salt,
        iterations=iterations,
        key_block=key_block,
        public_key=public_key,
        source=data,
        key_block_offset=position,
        entry_size_offset=12 + max(header_size, 0),
        key_size_offset=position - 4,
        serial=serial,
        validity=validity,
        key_uid=key_uid,
        flags=flags,
    )


def _pin_key(entry: Entry, pin: str) -> bytes:
    try:
        password = pin.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("ПИН должен содержать ASCII-текст") from error
    if entry.algorithm == PBKDF2_OID:
        if entry.salt is None or entry.iterations is None:
            raise ValueError("не удалось прочитать параметры PBKDF2")
        return pbkdf2_streebog256(password, entry.salt, entry.iterations, 32)
    from .gost import Gost3411_94
    digest = Gost3411_94()
    digest.update(password)
    pin_hash = digest.digest()
    digest = Gost3411_94()
    digest.update(password + pin_hash)
    unwrap = digest.digest()
    return b"".join(
        struct.pack(
            "<I",
            (int.from_bytes(pin_hash[i:i + 4], "little", signed=True)
             - int.from_bytes(unwrap[i:i + 4], "little", signed=True)) & 0xFFFFFFFF,
        )
        for i in range(0, 32, 4)
    )


def extract(entry: Entry, pin: str) -> bytes:
    cek = entry.key_block[:-12]
    expected_mac = entry.key_block[-12:-8]
    iv = entry.key_block[-8:]
    pin_key = _pin_key(entry, pin)
    if not secrets.compare_digest(gost_mac(cek + entry.key_info_raw, pin_key), expected_mac):
        raise ValueError("неверный ПИН-код")
    masked = gost_cfb_decrypt(cek, pin_key, iv)
    curve = None
    if entry.curve_oid:
        try:
            curve = curve_by_oid(entry.curve_oid)
        except ValueError:
            curve = None
    order = curve.q if curve else int(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893", 16)
    width = curve.width if curve else 32
    half = len(masked) // 2
    if entry.key_class & 3 == 0:
        private_bytes = gost_cfb_decrypt(masked[:half], masked[half:], b"\0" * 8)
        private = int.from_bytes(private_bytes, "big")
        if private == 0:
            raise ValueError("получен нулевой закрытый ключ")
        return private.to_bytes(width, "big")
    # CryptoPro-A parameters: ViPNet stores x*d and y*d^-1; their product is
    # the private scalar.
    x = int.from_bytes(masked[:half][::-1], "big")
    y = int.from_bytes(masked[half:][::-1], "big")
    private = (x * y) % order
    if private == 0:
        raise ValueError("получен нулевой закрытый ключ")
    return private.to_bytes(width, "big")


def export_pem(entry: Entry, pin: str) -> bytes:
    private = extract(entry, pin)
    scalar = int.from_bytes(private, "big")
    curve_oid = entry.curve_oid
    if curve_oid is None:
        raise ValueError("контейнер не содержит идентификатор кривой")
    digest_oid = next((item for item in entry.key_parameters if item not in CURVES), None)
    if digest_oid is None:
        digest_oid = DIGEST_OIDS.get(curve_by_oid(curve_oid).kind,
                                     DIGEST_OIDS["2012-256"])
    algorithm = entry.key_algorithm or "1.2.643.7.1.1.1.1"
    return private_key_pem(scalar, curve_oid, digest_oid, algorithm)


def _serial_bytes(value: str, native_profile: bool) -> bytes:
    if value in ("", "auto"):
        if native_profile:
            filetime = int((time.time() + 11644473600) * 10_000_000)
            return secrets.token_bytes(4) + b"\0" * 4 + filetime.to_bytes(8, "little")
        return secrets.token_bytes(16)
    cleaned = value.replace(":", "").replace(" ", "").replace("-", "")
    serial = bytes.fromhex(cleaned)
    if len(serial) != 16:
        raise ValueError("serial_number должен содержать 16 байт")
    return serial


def build_container(spec: Spec) -> bytes:
    container_type = str(spec.raw.get("container", {}).get("type", "ITCS"))
    if container_type != "ITCS":
        raise ValueError("поддерживается только тип контейнера ITCS")
    curve = spec.curve
    if curve is None:
        raise ValueError("кривая не задана")
    public = spec.public
    if public is None:
        raise ValueError("не удалось вычислить открытый ключ")
    public_bytes = public.x.to_bytes(curve.width, "big")[::-1] + \
        public.y.to_bytes(curve.width, "big")[::-1]

    key_algorithm = der_sequence(
        der_oid(spec.key_algorithm_oid),
        der_sequence(der_oid(curve.oid), der_oid(spec.digest_oid)),
    )
    validity = der_sequence(
        der(0x80, generalized_time(spec.valid_from).encode("ascii")),
        der(0x81, generalized_time(spec.valid_until).encode("ascii")),
    )
    key_info_fields = [
        der_integer(spec.key_class),
        der_integer(spec.key_type),
        der(0xA0, key_algorithm),
        der(0xA1, der_octet(_serial_bytes(spec.serial_number, spec.native_profile))),
        der(0xA6, validity),
    ]
    if spec.native_profile:
        key_info_fields.append(der(0xA7, der(0x03, b"\0" + public_bytes[:8])))
    key_info_fields.append(der(0xAA, der_integer(spec.flags)))
    key_info = der_sequence(*key_info_fields)

    try:
        password = spec.pin.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("ПИН должен содержать ASCII-текст") from error

    salt = secrets.token_bytes(8) if spec.salt == "auto" else bytes.fromhex(
        spec.salt.replace(":", "").replace(" ", ""))
    if len(salt) != 8:
        raise ValueError("salt должен содержать 8 байт")
    iv = secrets.token_bytes(8) if spec.iv == "auto" else bytes.fromhex(
        spec.iv.replace(":", "").replace(" ", ""))
    if len(iv) != 8:
        raise ValueError("iv должен содержать 8 байт")
    if spec.iterations < 1:
        raise ValueError("iterations должен быть положительным")
    if spec.key_length != 32:
        raise ValueError("key_length должен быть равен 32")

    pin_key = pbkdf2_streebog256(password, salt, spec.iterations, spec.key_length)
    if spec.key_uid == "auto":
        key_uid = hmac_streebog256(pin_key, password)
    else:
        key_uid = bytes.fromhex(spec.key_uid.replace(":", "").replace(" ", ""))
    if len(key_uid) != 32:
        raise ValueError("key_uid должен содержать 32 байта")

    pbkdf_params = der_sequence(
        der_octet(salt),
        der_integer(spec.iterations),
        der_integer(spec.key_length),
        der_sequence(der_oid(HMAC_STREEBOG_512_OID), der(0x05, b"")),
    )
    defence_algorithm = der_sequence(der_oid(PBKDF2_OID), pbkdf_params)
    defence_info = der_sequence(
        der_integer(spec.defence_key_class),
        der_integer(spec.defence_key_type),
        der(0xA0, defence_algorithm),
        der(0xA7, der(0x03, b"\0" + key_uid)),
        der(0xAA, der_integer(spec.defence_flags)),
    )
    entry_body = (der(0x02, bytes([spec.entry_version & 0xFF])) + key_info +
                  defence_info + der(0xA1, der_octet(public_bytes)))
    entry_asn1 = der(0x30, entry_body)

    width = curve.width
    if spec.key_class & 3 == 0:
        # Plain masked private key: [encrypted scalar] || [one-time key].
        if width != 32:
            raise ValueError("key_class 0 поддерживается только для 256-битных ключей")
        ephemeral = secrets.token_bytes(width)
        private_bytes = spec.scalar.to_bytes(width, "big")
        masked = gost_cfb_encrypt(private_bytes, ephemeral, b"\0" * 8) + ephemeral
    else:
        # CryptoPro-A parameters: store x*d and y*d^-1; their product is the
        # private scalar after extraction.
        mask_x = secrets.randbelow(curve.q - 1) + 1
        mask_y = (spec.scalar * pow(mask_x, -1, curve.q)) % curve.q
        masked = mask_x.to_bytes(width, "big")[::-1] + \
            mask_y.to_bytes(width, "big")[::-1]
    encrypted = gost_cfb_encrypt(masked, pin_key, iv)
    key_block = encrypted + gost_mac(encrypted + key_info, pin_key) + iv

    header = bytes.fromhex(spec.header.replace(":", "").replace(" ", ""))
    entry_size = len(entry_asn1) + 4 + len(key_block)
    return (b"ITCS" + struct.pack("<I", spec.version & 0xFFFFFFFF) +
            struct.pack("<i", len(header)) + header +
            struct.pack("<i", entry_size) + entry_asn1 +
            struct.pack("<i", len(key_block)) + key_block)
