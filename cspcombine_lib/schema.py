"""JSON specification normalisation and defaults for ``cspcombine create``."""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .curves import (DIGEST_OIDS, SIGN_OIDS, Curve, curve_by_oid,
                     default_curve, normalize_kind)
from .keys import KeyMaterial, default_validity, parse_private_key
from .gost import generate_private_scalar


def cfg_get(spec: dict[str, Any], *paths: str, default: Any = None) -> Any:
    for path in paths:
        current: Any = spec
        found = True
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                found = False
                break
        if found and current is not None:
            return current
    return default


def has_path(spec: dict[str, Any], *paths: str) -> bool:
    for path in paths:
        current: Any = spec
        found = True
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                found = False
                break
        if found:
            return True
    return False


PROVIDER_ALIASES = {
    "vipnet": "vipnet",
    "viper": "vipnet",
    "infotecs": "vipnet",
    "випнет": "vipnet",
    "cryptopro": "cryptopro",
    "crypto-pro": "cryptopro",
    "crypto_pro": "cryptopro",
    "csp": "cryptopro",
    "криптопро": "cryptopro",
    "gost": "cryptopro",
}


def resolve_provider(spec: dict[str, Any], override: str | None = None) -> str:
    if override:
        value = override
    else:
        value = cfg_get(spec, "provider", "crypto_provider", "csp",
                        "container.provider", default=None)
    if value is None:
        # Guess from the shape of the specification.
        container_type = str(cfg_get(spec, "container.type", default="")).upper()
        if container_type in ("ITCS", "PKEY", "_CCK", "_LCK"):
            return "vipnet"
        if any(key in spec for key in ("key_algorithm", "curve_oid",
                                       "certificate_der", "container_name",
                                       "key_usage", "extension_oid")):
            return "cryptopro"
        return "vipnet"
    text = str(value).strip().lower()
    if text in PROVIDER_ALIASES:
        return PROVIDER_ALIASES[text]
    if text in ("auto", "any"):
        return "vipnet"
    raise ValueError(f"неизвестный криптопровайдер: {value}")


def _is_oid(value: Any) -> bool:
    text = str(value)
    return text.count(".") >= 3 and all(part.isdigit() for part in text.split("."))


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on", "да")
    return bool(value)


@dataclass
class Spec:
    provider: str
    raw: dict[str, Any] = field(default_factory=dict)
    base_dir: Path = field(default_factory=Path.cwd)
    pin: str = ""
    pin_generated: bool = False
    material: KeyMaterial | None = None
    key_generated: bool = False
    kind: str = "2012-256"
    curve: Curve | None = None
    digest_oid: str = DIGEST_OIDS["2012-256"]
    key_algorithm_oid: str = SIGN_OIDS["2012-256"]
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    container_name: str = "cspcombine"

    # ViPNet-specific values.
    iterations: int = 2000
    key_length: int = 32
    salt: str = "auto"
    iv: str = "auto"
    version: int = 16
    entry_version: int = 3
    header: str = ""
    serial_number: str = "auto"
    key_uid: str = "auto"
    native_profile: bool = False
    key_class: int = 1
    key_type: int = 43590
    flags: int = 1
    defence_key_class: int = 1024
    defence_key_type: int = 32826
    defence_flags: int = 0

    # CryptoPro-specific values.
    certificate_der: str = ""
    key_usage: str = "sign"
    extension_oid: str | None = None
    container_type_oid: str = "1.2.643.2.2.37.2.1"
    backup_key: bool = True

    @property
    def scalar(self) -> int:
        if self.material is None:
            raise ValueError("закрытый ключ не задан")
        return self.material.scalar

    @property
    def public(self):
        from .gost import point_mul
        return point_mul(self.scalar, self.curve)

    def describe_key_source(self) -> str:
        if self.key_generated:
            return "сгенерирован"
        return "из спецификации"


def _resolve_curve(spec: dict[str, Any], material: KeyMaterial | None,
                   provider: str, explicit_kind: str | None) -> Curve:
    curve_value = cfg_get(spec, "curve", "curve_oid", "key.curve",
                          "key.curve_oid", default=None)
    if curve_value:
        if _is_oid(curve_value):
            return curve_by_oid(str(curve_value))
        return default_curve(normalize_kind(curve_value), provider)
    if material is not None and material.curve_oid:
        try:
            return curve_by_oid(material.curve_oid)
        except ValueError:
            pass
    material_kind = None
    if material is not None and material.algorithm_oid:
        for known_kind, oid in SIGN_OIDS.items():
            if material.algorithm_oid == oid:
                material_kind = known_kind
                break
    if provider == "vipnet" and explicit_kind is None and material_kind is None:
        from .curves import CRYPTOPRO_XCHA
        return CRYPTOPRO_XCHA
    return default_curve(explicit_kind or material_kind or "2012-256", provider)


def _resolve_kind(spec: dict[str, Any], material: KeyMaterial | None,
                  curve: Curve, provider: str,
                  explicit_kind: str | None) -> str:
    if explicit_kind:
        return explicit_kind
    if material is not None and material.algorithm_oid:
        algorithm = material.algorithm_oid
        if algorithm == SIGN_OIDS["2001"]:
            return "2001"
        if algorithm == SIGN_OIDS["2012-512"]:
            return "2012-512"
        if algorithm == SIGN_OIDS["2012-256"]:
            return "2012-256"
    if provider == "vipnet" and explicit_kind is None:
        # The original ViPNet builder uses the 2012-256 signature OID with
        # the CryptoPro-XchA curve.  A raw scalar or a key without algorithm
        # parameters therefore gets the same default profile.
        return "2012-256"
    return curve.kind


def _parse_pin(spec: dict[str, Any], provider: str) -> tuple[str, bool]:
    present = has_path(spec, "pin", "protection.pin", "key.pin", "password")
    value = cfg_get(spec, "pin", "protection.pin", "key.pin", "password",
                    default=None)
    if present:
        if value is None or value == "":
            return "", False
        if str(value).strip().lower() in ("auto", "generate"):
            return _random_pin(), True
        return str(value), False
    return _random_pin(), True


def _random_pin() -> str:
    return f"{secrets.randbelow(100_000_000):08d}"


def load_spec(path: Path, pin_override: str | None = None,
              provider_override: str | None = None) -> Spec:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("JSON-спецификация должна быть объектом")
    provider = resolve_provider(data, provider_override)
    spec = Spec(provider=provider, raw=data, base_dir=path.parent)

    key_value = cfg_get(data, "private_key", "private_key_file",
                        "key.private_key", "key.file",
                        "key_path", "key.private_key_path", default=None)
    material = None
    if key_value not in (None, "", "auto", "generate", "random"):
        if isinstance(key_value, dict):
            key_value = json.dumps(key_value)
        key_text = str(key_value)
        if "BEGIN" not in key_text:
            key_path = Path(key_text).expanduser()
            if not key_path.is_absolute():
                relative_to_spec = path.parent / key_path
                if relative_to_spec.is_file():
                    key_text = str(relative_to_spec)
            elif key_path.is_file():
                key_text = str(key_path)
        try:
            material = parse_private_key(key_text)
        except OSError:
            raise
        except Exception as error:
            raise ValueError(f"не удалось прочитать закрытый ключ: {error}") from error
    spec.material = material

    algorithm_value = cfg_get(data, "algorithm", "key_algorithm",
                              "key.algorithm", "key.kind", default=None)
    explicit_kind = None
    if algorithm_value:
        text = str(algorithm_value)
        explicit_kind = normalize_kind(text)

    curve = _resolve_curve(data, material, provider, explicit_kind)
    kind = _resolve_kind(data, material, curve, provider, explicit_kind)
    if kind == "2001" and curve.kind != "2001":
        raise ValueError("алгоритм 2001 не соответствует выбранной кривой")
    if kind == "2012-512" and curve.kind != "2012-512":
        raise ValueError("алгоритм 2012-512 требует 512-битную кривую")
    if kind == "2012-256" and curve.kind == "2012-512":
        raise ValueError("алгоритм 2012-256 не соответствует 512-битной кривой")
    spec.kind = kind
    spec.curve = curve

    digest_value = cfg_get(data, "digest", "digest_oid", "key.digest",
                           "key.digest_oid", default=None)
    if digest_value:
        if _is_oid(digest_value):
            spec.digest_oid = str(digest_value)
        else:
            spec.digest_oid = DIGEST_OIDS[normalize_kind(str(digest_value))]
    elif material is not None and material.digest_oid:
        spec.digest_oid = material.digest_oid
    else:
        spec.digest_oid = DIGEST_OIDS[kind]

    sign_value = cfg_get(data, "key_algorithm_oid", "sign_oid",
                         "key.sign_oid", "key.key_algorithm_oid", default=None)
    if sign_value and _is_oid(sign_value):
        spec.key_algorithm_oid = str(sign_value)
    elif material is not None and material.algorithm_oid and _is_oid(material.algorithm_oid):
        spec.key_algorithm_oid = material.algorithm_oid
    else:
        spec.key_algorithm_oid = SIGN_OIDS[kind]

    if material is not None:
        material.validate(curve)
    else:
        spec.material = KeyMaterial(generate_private_scalar(curve), curve.oid,
                                    spec.digest_oid, spec.key_algorithm_oid)
        spec.key_generated = True

    if pin_override is not None:
        spec.pin, spec.pin_generated = pin_override, False
    else:
        spec.pin, spec.pin_generated = _parse_pin(data, provider)

    spec.valid_from, spec.valid_until = default_validity(
        cfg_get(data, "valid_from", "not_before", "key.validity.not_before",
                "validity.not_before", default=None),
        cfg_get(data, "valid_until", "valid_to", "not_after", "expires",
                "key.validity.not_after", "validity.not_after",
                default=None),
    )

    spec.container_name = str(cfg_get(
        data, "container_name", "container.name", "name", "key.name",
        default="cspcombine"))

    spec.iterations = int(cfg_get(data, "iterations", "protection.iterations",
                                  "key.iterations", default=2000))
    spec.key_length = int(cfg_get(data, "key_length", "protection.key_length",
                                  default=32))
    spec.salt = str(cfg_get(data, "salt", "protection.salt", default="auto"))
    spec.iv = str(cfg_get(data, "iv", "protection.iv", default="auto"))
    spec.version = int(cfg_get(data, "container.version", "version", default=16))
    spec.entry_version = int(cfg_get(data, "entry_version",
                                     "container.entry_version", default=3))
    spec.header = str(cfg_get(data, "container.header", "header", default=""))
    spec.serial_number = str(cfg_get(data, "serial_number", "serial",
                                     "key.serial_number", default="auto"))
    spec.key_uid = str(cfg_get(data, "key_uid", "key.key_uid", default="auto"))
    spec.native_profile = _as_bool(cfg_get(data, "native_profile", "key.native_profile",
                                          default=False))
    spec.key_class = int(cfg_get(data, "key_class", "key.key_class", default=1))
    spec.key_type = int(cfg_get(data, "key_type", "key.key_type", default=43590))
    spec.flags = int(cfg_get(data, "flags", "key.flags", default=1))
    spec.defence_key_class = int(cfg_get(data, "defence.key_class",
                                         "defence_key_class", default=1024))
    spec.defence_key_type = int(cfg_get(data, "defence.key_type",
                                        "defence_key_type", default=32826))
    spec.defence_flags = int(cfg_get(data, "defence.flags",
                                     "defence_flags", default=0))

    spec.certificate_der = str(cfg_get(data, "certificate_der",
                                       "certificate", default=""))
    if spec.certificate_der and "BEGIN" not in spec.certificate_der:
        cert_path = Path(spec.certificate_der).expanduser()
        if not cert_path.is_absolute():
            cert_path = path.parent / cert_path
        if cert_path.is_file():
            spec.certificate_der = str(cert_path)
    spec.key_usage = str(cfg_get(data, "key_usage", "usage",
                                 default="sign")).lower()
    extension_oid = cfg_get(data, "extension_oid", "key.extension_oid",
                            default=None)
    spec.extension_oid = str(extension_oid) if extension_oid else None
    spec.container_type_oid = str(cfg_get(data, "container_type_oid",
                                          "container.type_oid",
                                          default="1.2.643.2.2.37.2.1"))
    spec.backup_key = _as_bool(cfg_get(data, "backup_key", default=True), True)
    return spec
