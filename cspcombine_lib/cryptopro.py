"""Read, extract from and build CryptoPro file containers."""

from __future__ import annotations

import base64
import io
import re
import secrets
import tarfile
import zipfile
from datetime import datetime
from pathlib import Path

from .curves import AGREEMENT_OIDS, DIGEST_OIDS, SIGN_OIDS, curve_by_oid
from .der import (Der, der, der_bit_string, der_octet, der_oid,
                  der_read, der_sequence, pem_encode)
from .gost import (Gost3411_94, SBOX_A, SBOX_Z, gost_ecb, gost_mac,
                   sbox_for_kind, streebog256)
from .keys import generalized_time, private_key_pem
from .schema import Spec

DENEF = b"DENEFH028.760246785.IUEFHWUIO.EF"
OID_DH_2001 = "1.2.643.2.2.98"
OID_DH_2012_256 = "1.2.643.7.1.1.6.1"
OID_DH_2012_512 = "1.2.643.7.1.1.6.2"
OID_SIGN_2001 = "1.2.643.2.2.19"
OID_SIGN_2012_256 = "1.2.643.7.1.1.1.1"
OID_SIGN_2012_512 = "1.2.643.7.1.1.1.2"
KNOWN_FILES = ("header.key", "primary.key", "masks.key", "masks2.key",
               "primary2.key", "name.key")


def _octets(value: Der) -> bytes:
    if value.tag != 0x04:
        raise ValueError("ожидался ASN.1 OCTET STRING")
    return value.value


def _decode_children(value: bytes) -> list[Der]:
    result: list[Der] = []
    position = 0
    while position < len(value):
        child, position = der_read(value, position)
        result.append(child)
    return result


def _load_sequence(data: bytes, name: str) -> Der:
    value, rest = der_read(data)
    if rest != len(data) or value.tag != 0x30:
        raise ValueError(f"некорректный {name}")
    return value


def is_container_dir(path: Path) -> bool:
    return path.is_dir() and (path / "header.key").is_file() and \
        (path / "primary.key").is_file() and (path / "masks.key").is_file()


def read_container_source(path: Path) -> dict[str, bytes]:
    if is_container_dir(path):
        files = {}
        for name in KNOWN_FILES:
            candidate = path / name
            if candidate.is_file():
                files[name] = candidate.read_bytes()
        return files
    if path.is_file():
        data = path.read_bytes()
        if data.startswith(b"PK\x03\x04"):
            try:
                return _read_zip(data)
            except (zipfile.BadZipFile, OSError) as error:
                raise ValueError(f"повреждённый zip-архив: {error}") from error
        try:
            return _read_tar(data)
        except (tarfile.TarError, OSError, ValueError):
            pass
    raise ValueError("не найден контейнер CryptoPro (каталог с header.key "
                     "или tar/zip-архив)")


def _collect_archive_members(members) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for name, data in members:
        base = Path(name).name
        if base in KNOWN_FILES and base not in files:
            files[base] = data
    if not {"header.key", "primary.key", "masks.key"} <= files.keys():
        raise ValueError("архив не содержит файлов контейнера CryptoPro")
    return files


def _read_tar(data: bytes) -> dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        members = []
        for member in archive.getmembers():
            if member.isfile():
                extracted = archive.extractfile(member)
                if extracted is not None:
                    members.append((member.name, extracted.read()))
    return _collect_archive_members(members)


def _read_zip(data: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = [(info.filename, archive.read(info))
                   for info in archive.infolist() if not info.is_dir()]
    return _collect_archive_members(members)


def pack_tar(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name in KNOWN_FILES:
            if name not in files:
                continue
            info = tarfile.TarInfo(name)
            info.size = len(files[name])
            info.mode = 0o600
            info.mtime = 0
            archive.addfile(info, io.BytesIO(files[name]))
    return buffer.getvalue()


def pack_zip(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in KNOWN_FILES:
            if name in files:
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.external_attr = 0o600 << 16
                archive.writestr(info, files[name])
    return buffer.getvalue()


class Container:
    """A CryptoPro file container loaded into memory."""

    def __init__(self, files: dict[str, bytes], pin: str = ""):
        self.files = files
        self.pin = pin or ""
        self.header = self._read_sequence("header.key")
        self.primary = self._read_sequence("primary.key")
        self.masks = self._read_sequence("masks.key")
        if not self.header.children or self.header.children[0].tag != 0x30:
            raise ValueError("некорректный header.key")
        header0 = self.header.children[0]
        self.public_x = None
        self.certificate = None
        self.hmac_password = None
        self.container_attributes = None
        for item in header0.children:
            tag = item.tag & 31
            if tag in (5, 6):
                # CryptoPro stores the certificate as the contents of an
                # implicitly tagged field (the bytes begin with SEQUENCE).
                if self.certificate is None:
                    self.certificate = item.value
            elif tag == 2:
                self.hmac_password = item.value
            elif tag == 3:
                self.container_attributes = item.value
            elif tag == 10:
                self.public_x = item.value

        params = next((x for x in header0.children if x.tag == 0x30), None)
        if params is None or not params.children:
            raise ValueError("header.key не содержит параметров ключа")
        algorithm_field = next((x for x in params.children if x.tag == 0xA0), None)
        if algorithm_field is None:
            raise ValueError("header.key не содержит AlgorithmIdentifier")
        algorithm = Der(0x30, algorithm_field.value,
                        _decode_children(algorithm_field.value))
        if not algorithm.children:
            raise ValueError("пустой AlgorithmIdentifier")
        alg_oid = algorithm.children[0].oid()
        self.algorithm_oid = alg_oid
        if len(algorithm.children) < 2:
            raise ValueError("AlgorithmIdentifier без параметров")
        algorithm_params = algorithm.children[1]
        if not algorithm_params.children and algorithm_params.tag == 0x30:
            algorithm_params = Der(0x30, algorithm_params.value,
                                   _decode_children(algorithm_params.value))
        if len(algorithm_params.children) < 2:
            raise ValueError("AlgorithmIdentifier без параметров кривой")
        self.param_set = algorithm_params.children[0].oid()
        self.digest_set = algorithm_params.children[1].oid()
        if alg_oid in (OID_DH_2001, OID_SIGN_2001):
            self.kind = "2001"
            self.sign_oid = OID_SIGN_2001
            self.agreement_oid = OID_DH_2001
        elif alg_oid in (OID_DH_2012_256, OID_SIGN_2012_256):
            self.kind = "2012-256"
            self.sign_oid = OID_SIGN_2012_256
            self.agreement_oid = OID_DH_2012_256
        elif alg_oid in (OID_DH_2012_512, OID_SIGN_2012_512):
            self.kind = "2012-512"
            self.sign_oid = OID_SIGN_2012_512
            self.agreement_oid = OID_DH_2012_512
        else:
            raise ValueError(f"неподдерживаемый алгоритм CryptoPro: {alg_oid}")
        self.curve = curve_by_oid(self.param_set)
        self._private_key_cache: int | None = None
        self.name = None
        if "name.key" in files:
            try:
                name_root, _ = der_read(files["name.key"])
                if name_root.children and name_root.children[0].tag in (0x16, 0x0C):
                    raw_name = name_root.children[0].value
                    try:
                        self.name = raw_name.decode("utf-8")
                    except UnicodeDecodeError:
                        self.name = raw_name.decode("cp1251", "replace")
            except ValueError:
                pass

    @property
    def password_protected(self) -> bool:
        return bool(self.hmac_password and self.hmac_password != b"\0" * 4)

    @property
    def usage(self) -> str:
        return "exchange" if self.algorithm_oid in (
            OID_DH_2001, OID_DH_2012_256, OID_DH_2012_512) else "sign"

    def _read_sequence(self, name: str) -> Der:
        if name not in self.files:
            raise ValueError(f"в контейнере отсутствует {name}")
        return _load_sequence(self.files[name], name)

    def _digest(self, data: bytes) -> bytes:
        if self.kind == "2001":
            return _gost94(data)
        return streebog256(data)

    def _decode_key(self) -> bytes:
        salt = _octets(self.masks.children[1])
        pin = self.pin.encode("ascii")
        pin4 = b"".join(bytes((byte, 0, 0, 0)) for byte in pin)
        result = self._digest(salt + pin4)
        width = 32 if self.kind == "2001" else 64
        current = bytearray(width)
        current[:32] = DENEF
        for _ in range(2000 if pin else 2):
            a = bytes(x ^ 0x36 for x in current)
            b = bytes(x ^ 0x5C for x in current)
            digest = self._digest(a + result + b + result)
            current[:len(digest)] = digest
        a = bytes(x ^ 0x36 for x in current)
        b = bytes(x ^ 0x5C for x in current)
        final = self._digest(a[:32] + salt + b[:32] + pin4)
        return self._digest(final[:32])

    def private_key(self) -> int:
        if self._private_key_cache is not None:
            return self._private_key_cache
        decode_key = self._decode_key()
        encrypted = _octets(self.primary.children[0])
        plain = gost_ecb(encrypted, decode_key, sbox_for_kind(self.kind), decrypt=True)
        primary_value = int.from_bytes(plain, "little")
        mask_value = int.from_bytes(_octets(self.masks.children[0])[::-1], "big")
        if mask_value == 0:
            raise ValueError("нулевая маска ключа")
        value = (primary_value * pow(mask_value, -1, self.curve.q)) % self.curve.q
        self._private_key_cache = value
        return value

    def private_pem(self) -> bytes:
        key = self.private_key()
        return private_key_pem(key, self.param_set, self.digest_set, self.sign_oid)

    def certificate_pem(self) -> bytes:
        if self.certificate is None:
            raise ValueError("в контейнере нет сертификата")
        return pem_encode("CERTIFICATE", self.certificate)

    def public_key_points(self):
        from .gost import point_mul
        return point_mul(self.private_key(), self.curve)

    def certificate_public_key(self) -> bytes | None:
        """Return the certificate's public key as x||y in little-endian."""
        return _certificate_public_key(self.certificate, self.curve)

    def verify_key(self) -> bool | None:
        """Compare the decrypted key with the certificate, when present.

        CryptoPro containers do not expose a simple check value that is
        understood by this tool, so the certificate is the best available
        PIN oracle.  ``None`` means "cannot verify".
        """
        expected = self.certificate_public_key()
        if expected is None:
            return None
        from .gost import point_mul
        public = point_mul(self.private_key(), self.curve)
        if public is None:
            return False
        little = public.x.to_bytes(self.curve.width, "little") + \
            public.y.to_bytes(self.curve.width, "little")
        big = public.x.to_bytes(self.curve.width, "big") + \
            public.y.to_bytes(self.curve.width, "big")
        return expected in (little, big)

    def verify_password(self) -> bool | None:
        """Check the container's password verifier (header field [2]).

        The verifier is MAC_16(zeros) under the password key derived with the
        public-key fingerprint as salt.  ``None`` means the container does not
        contain a usable verifier.
        """
        if not self.public_x:
            return None
        stored = self.hmac_password
        if stored is None:
            return None
        if not self.pin:
            return stored == b"\0" * 4
        if stored == b"\0" * 4:
            return False
        digest = _gost94 if self.kind == "2001" else streebog256
        sbox = SBOX_A if self.kind == "2001" else SBOX_Z
        derived = _kdf_key(self.pin, self.public_x, self.kind, digest)
        expected = gost_mac(b"\0" * 16, derived, sbox)
        return secrets.compare_digest(expected, stored)


def _gost94(data: bytes) -> bytes:
    digest = Gost3411_94()
    digest.update(data)
    return digest.digest()


def _parse_certificate(value: str) -> bytes:
    if not value:
        return b""
    try:
        path = Path(value)
        if "BEGIN" not in value and path.is_file():
            value = path.read_text(encoding="ascii")
    except OSError:
        pass
    if "BEGIN" in value:
        match = re.search(r"-----BEGIN [^-]+-----(.*?)-----END [^-]+-----",
                          value, re.S)
        if match is None:
            raise ValueError("некорректный PEM-сертификат")
        return base64.b64decode("".join(match.group(1).split()))
    cleaned = re.sub(r"[^0-9a-fA-F]", "", value)
    return bytes.fromhex(cleaned) if cleaned else b""


def _certificate_public_key(certificate: bytes | None, curve) -> bytes | None:
    """Extract the GOST public key (x||y, little-endian) from a certificate."""
    if certificate is None:
        return None
    try:
        root, _ = der_read(certificate)
        tbs = root.children[0]
    except (ValueError, IndexError):
        return None
    for node in tbs.children:
        if node.tag != 0x30 or len(node.children) < 2:
            continue
        algorithm = node.children[0]
        bits = node.children[-1]
        if algorithm.tag != 0x30 or bits.tag != 0x03 or not algorithm.children:
            continue
        try:
            oid = algorithm.children[0].oid()
        except ValueError:
            continue
        if not oid.startswith("1.2.643.") or not bits.value:
            continue
        payload = bits.value[1:]  # skip the unused-bits byte
        expected = curve.width * 2
        if len(payload) >= expected:
            return payload[-expected:]
    return None


def certificate_public_key(cert_value: str, curve) -> bytes | None:
    """Parse a certificate given as PEM/hex/path and return its public key."""
    return _certificate_public_key(_parse_certificate(cert_value), curve)


def certificate_matches_key(cert_value: str, curve, scalar: int) -> bool | None:
    expected = certificate_public_key(cert_value, curve)
    if expected is None:
        return None
    from .gost import point_mul
    public = point_mul(scalar, curve)
    if public is None:
        return False
    little = public.x.to_bytes(curve.width, "little") + \
        public.y.to_bytes(curve.width, "little")
    big = public.x.to_bytes(curve.width, "big") + \
        public.y.to_bytes(curve.width, "big")
    return expected in (little, big)


def _extension(oid: str, moment: datetime) -> bytes:
    when = generalized_time(moment).encode("ascii")
    time_sequence = der_sequence(der(0x81, when))
    return der_sequence(der_oid(oid), der_octet(time_sequence))


def _kdf_key(pin: str, salt: bytes, kind: str, digest) -> bytes:
    pin_bytes = pin.encode("ascii")
    pin4 = b"".join(bytes((byte, 0, 0, 0)) for byte in pin_bytes)
    result = digest(salt + pin4)
    width = 32 if kind == "2001" else 64
    current = bytearray(width)
    current[:32] = DENEF
    for _ in range(2000 if pin_bytes else 2):
        a = bytes(x ^ 0x36 for x in current)
        b = bytes(x ^ 0x5C for x in current)
        value = digest(a + result + b + result)
        current[:len(value)] = value
    a = bytes(x ^ 0x36 for x in current)
    b = bytes(x ^ 0x5C for x in current)
    final = digest(a[:32] + salt + b[:32] + pin4)
    return digest(final[:32])


def build_container(spec: Spec) -> dict[str, bytes]:
    curve = spec.curve
    if curve is None:
        raise ValueError("кривая не задана")
    # CryptoPro selects the KDF from the signature algorithm OID, not from the
    # curve.  Real CSP containers may pair a 2001 curve with a 2012-256
    # signature OID, so keep the requested algorithm and only make the OIDs
    # consistent with it.
    kind = spec.kind
    expected_digest = DIGEST_OIDS[kind]
    expected_sign = SIGN_OIDS[kind]
    digest_oid = spec.digest_oid if spec.digest_oid == expected_digest else expected_digest
    sign_oid = spec.key_algorithm_oid if spec.key_algorithm_oid == expected_sign else expected_sign
    usage = spec.key_usage.strip().lower()
    if usage in ("both", "all", "sign+exchange"):
        raise ValueError("совмещённый контейнер (sign+exchange) не поддерживается; "
                         "создайте отдельные контейнеры для подписи и обмена")
    is_exchange = usage in ("exchange", "exc", "обмен")
    algorithm_oid = AGREEMENT_OIDS[kind] if is_exchange else sign_oid
    key_attributes = (der_bit_string(b"\x20", unused=5) if is_exchange
                      else der_bit_string(b""))
    default_extension = ("1.2.643.2.2.37.3.10" if is_exchange
                         else "1.2.643.2.2.37.3.9")
    public = spec.public
    if public is None:
        raise ValueError("не удалось вычислить открытый ключ")
    width = curve.width
    x, y = public.x, public.y
    public_le = x.to_bytes(width, "big")[::-1]

    cert = _parse_certificate(spec.certificate_der)
    digest_func = _gost94 if kind == "2001" else streebog256
    sbox_mac = SBOX_A if kind == "2001" else SBOX_Z
    public_fp = public_le[:8]

    # Inner header sequence (the first SEQUENCE in header.key).
    algorithm_body = der_oid(algorithm_oid) + der_sequence(
        der_oid(curve.oid), der_oid(digest_oid))
    key_parameters = der_sequence(
        key_attributes,
        der(0xA0, algorithm_body),
    )
    flags = b"\xc0" if spec.pin else b"\x40"
    if spec.pin:
        # Password verifier: MAC of 16 zero bytes under the password key
        # derived with the public-key fingerprint as salt (8 bytes).
        fp_key = _kdf_key(spec.pin, public_fp, kind, digest_func)
        hmac_password = gost_mac(b"\0" * 16, fp_key, sbox_mac)
    else:
        hmac_password = b"\0" * 4
    header_fields = [
        der(0xA0, der_oid(spec.container_type_oid)),
        der_bit_string(flags, unused=6),
        key_parameters,
        der(0x82, hmac_password),
    ]
    if cert:
        header_fields.append(der(0x85, cert))
    header_fields.append(der(0x8A, public_fp))

    extension_oids = ([spec.extension_oid] if spec.extension_oid
                      else [default_extension])
    extensions = b"".join(_extension(oid, spec.valid_until)
                          for oid in extension_oids)
    header_fields.append(der(0xAC, extensions))
    # hmacKeyContainerContent: GOST 28147 MAC over the DER-encoded
    # KeyContainerContent with a 32-byte zero key.
    header_inner = der_sequence(*header_fields)
    container_mac = gost_mac(header_inner, b"\0" * 32, sbox_mac)
    header_outer = der_sequence(header_inner, der_octet(container_mac))

    # masks.key / primary.key and the optional backup pair.
    salt = secrets.token_bytes(12)
    mask_int = secrets.randbelow(curve.q - 1) + 1
    mask_stored = mask_int.to_bytes(width, "little")
    key = _kdf_key(spec.pin, salt, kind, digest_func)
    masked = (spec.scalar * mask_int) % curve.q
    plain = masked.to_bytes(width, "little")
    encrypted = gost_ecb(plain, key, sbox_for_kind(kind))
    mac = gost_mac(salt, mask_stored, sbox_mac)
    masks = der_sequence(der_octet(mask_stored), der_octet(salt),
                         der_octet(mac))
    primary = der_sequence(der_octet(encrypted))

    files = {"header.key": header_outer, "masks.key": masks,
             "primary.key": primary}
    if spec.backup_key:
        salt2 = secrets.token_bytes(12)
        mask2_int = secrets.randbelow(curve.q - 1) + 1
        mask2_stored = mask2_int.to_bytes(width, "little")
        key2 = _kdf_key(spec.pin, salt2, kind, digest_func)
        masked2 = (spec.scalar * mask2_int) % curve.q
        plain2 = masked2.to_bytes(width, "little")
        encrypted2 = gost_ecb(plain2, key2, sbox_for_kind(kind))
        mac2 = gost_mac(salt2, mask2_stored, sbox_mac)
        files["masks2.key"] = der_sequence(
            der_octet(mask2_stored), der_octet(salt2),
            der_octet(mac2))
        files["primary2.key"] = der_sequence(der_octet(encrypted2))

    name = spec.container_name.encode("utf-8")
    name_tag = 0x16 if spec.container_name.isascii() else 0x0C
    files["name.key"] = der_sequence(der(name_tag, name))
    return files


def write_container(files: dict[str, bytes], directory: Path) -> None:
    if directory.exists() and not directory.is_dir():
        raise ValueError(f"путь существует и не является каталогом: {directory}")
    directory.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        path = directory / name
        path.write_bytes(data)
        try:
            path.chmod(0o600)
        except OSError:
            pass
