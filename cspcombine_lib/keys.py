"""Private-key input/output helpers.

The user may pass a PKCS#8 PEM (as produced by ``cspcombine export``), a path
to such a file, or a bare hexadecimal scalar.  When a key is not supplied the
caller generates one on the selected curve.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .curves import Curve, DIGEST_OIDS, SIGN_OIDS, curve_by_oid, normalize_kind
from .der import (DerError, der_integer, der_octet, der_oid, der_read,
                  der_sequence, pem_decode, pem_encode)


@dataclass
class KeyMaterial:
    scalar: int
    curve_oid: str | None = None
    digest_oid: str | None = None
    algorithm_oid: str | None = None

    def validate(self, curve: Curve) -> None:
        if not 1 <= self.scalar < curve.q:
            raise ValueError("закрытый ключ вне диапазона кривой")


def _scalar_from_pkcs8(data: bytes) -> KeyMaterial:
    root, end = der_read(data)
    if end != len(data) or root.tag != 0x30 or len(root.children) < 3:
        raise ValueError("не удалось разобрать PKCS#8")
    algorithm = root.children[1]
    if algorithm.tag != 0x30 or not algorithm.children:
        raise ValueError("PKCS#8 без AlgorithmIdentifier")
    algorithm_oid = algorithm.children[0].oid()
    curve_oid = None
    digest_oid = None
    if len(algorithm.children) > 1 and algorithm.children[1].tag == 0x30:
        params = algorithm.children[1].children
        if params and params[0].tag == 0x06:
            curve_oid = params[0].oid()
        if len(params) > 1 and params[1].tag == 0x06:
            digest_oid = params[1].oid()
    private_octets = root.children[2]
    if private_octets.tag != 0x04:
        raise ValueError("PKCS#8 не содержит OCTET STRING закрытого ключа")
    inner, end = der_read(private_octets.value)
    if inner.tag == 0x02:
        # Some older extractors wrote the raw scalar as an INTEGER without
        # the canonical leading zero for values whose top bit is set.  A
        # private scalar is always positive, so read it unsigned.
        scalar = int.from_bytes(inner.value, "big")
    elif inner.tag == 0x30:
        scalar = None
        for child in inner.children:
            if child.tag == 0x04:
                scalar = int.from_bytes(child.value, "big")
                break
            if child.tag == 0x02 and scalar is None and len(child.value) > 1:
                # ECPrivateKey starts with version INTEGER 1; ignore it.
                continue
        if scalar is None:
            raise ValueError("ECPrivateKey не содержит приватный скаляр")
        for child in inner.children:
            if child.tag == 0xA0:
                try:
                    params, _ = der_read(child.value)
                    if params.tag == 0x06:
                        if curve_oid is None:
                            curve_oid = params.oid()
                    elif params.tag == 0x30:
                        oids = [item.oid() for item in params.children if item.tag == 0x06]
                        if oids and curve_oid is None:
                            curve_oid = oids[0]
                        if len(oids) > 1 and digest_oid is None:
                            digest_oid = oids[1]
                except (DerError, ValueError):
                    pass
    else:
        raise ValueError("неизвестный формат закрытого ключа в PKCS#8")
    return KeyMaterial(scalar, curve_oid, digest_oid, algorithm_oid)


def parse_private_key(value: str) -> KeyMaterial:
    """Parse a PEM block, a path to a PEM file, or a hexadecimal scalar."""
    text = value.strip()
    path = Path(text)
    if "BEGIN" not in text and len(text) < 4096 and path.is_file():
        text = path.read_text(encoding="ascii")
    if "BEGIN" in text:
        label, data = pem_decode(text)
        if label not in ("PRIVATE KEY", "EC PRIVATE KEY"):
            raise ValueError(f"неподдерживаемый PEM-блок: {label}")
        if label == "EC PRIVATE KEY":
            inner, end = der_read(data)
            if end != len(data) or inner.tag != 0x30:
                raise ValueError("не удалось разобрать EC PRIVATE KEY")
            scalar = next((int.from_bytes(c.value, "big") for c in inner.children
                           if c.tag == 0x04), None)
            if scalar is None:
                raise ValueError("EC PRIVATE KEY не содержит скаляр")
            curve_oid = None
            for child in inner.children:
                if child.tag == 0xA0:
                    try:
                        params, _ = der_read(child.value)
                        if params.tag == 0x06:
                            curve_oid = params.oid()
                        elif params.tag == 0x30:
                            oids = [item.oid() for item in params.children
                                    if item.tag == 0x06]
                            if oids:
                                curve_oid = oids[0]
                    except (DerError, ValueError):
                        pass
            return KeyMaterial(scalar, curve_oid)
        return _scalar_from_pkcs8(data)
    cleaned = re.sub(r"[\s:_-]", "", text)
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if not cleaned or not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        raise ValueError("закрытый ключ должен быть PEM, путём к PEM или hex-скаляром")
    return KeyMaterial(int(cleaned, 16))


def private_key_pem(scalar: int, curve_oid: str, digest_oid: str,
                    algorithm_oid: str | None = None) -> bytes:
    curve = curve_by_oid(curve_oid)
    kind = curve.kind
    algorithm_oid = algorithm_oid or SIGN_OIDS[kind]
    scalar_bytes = scalar.to_bytes(max(1, (scalar.bit_length() + 7) // 8), "big")
    parameters = der_sequence(der_oid(curve_oid), der_oid(digest_oid))
    algorithm = der_sequence(der_oid(algorithm_oid), parameters)
    ec_private_key = der_sequence(der_integer(1), der_octet(scalar_bytes))
    body = der_sequence(der_integer(0), algorithm, der_octet(ec_private_key))
    return pem_encode("PRIVATE KEY", body)


def parse_datetime(value: str | None, default: datetime,
                   end_of_day: bool = False) -> datetime:
    if value is None or value == "" or str(value).strip().lower() == "auto":
        return default
    text = str(value).strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        base = datetime.fromisoformat(text).replace(tzinfo=timezone.utc)
        if end_of_day:
            return base.replace(hour=23, minute=59, second=59)
        return base
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def generalized_time(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y%m%d%H%M%SZ")


def parse_generalized_time(value: bytes) -> datetime | None:
    try:
        return datetime.strptime(value.decode("ascii"), "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
    except (UnicodeDecodeError, ValueError):
        return None


def default_validity(valid_from: str | None = None,
                     valid_until: str | None = None) -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    start = parse_datetime(valid_from, now)
    end = parse_datetime(valid_until, start + timedelta(days=365), end_of_day=True)
    if end < start:
        raise ValueError("дата окончания действия раньше даты начала")
    return start, end


def kind_from_material(material: KeyMaterial, fallback: str = "2012-256") -> str:
    if material.curve_oid:
        try:
            return curve_by_oid(material.curve_oid).kind
        except ValueError:
            pass
    return normalize_kind(fallback)
