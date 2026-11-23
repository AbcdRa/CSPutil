"""Command-line interface for cspcombine."""

from __future__ import annotations

import argparse
import getpass
import json
import struct
import sys
import tempfile
from pathlib import Path

from . import __version__
from .cryptopro import (Container as CryptoProContainer,
                        build_container as build_cryptopro,
                        certificate_matches_key, is_container_dir, pack_tar,
                        pack_zip, read_container_source, write_container)
from .der import DerError
from .keys import private_key_pem
from .schema import Spec, load_spec, resolve_provider
from .vipnet import (MAGICS, build_container as build_vipnet,
                     export_pem, extract as extract_vipnet, read_container)


class CliError(Exception):
    pass


def _detect_provider(path: Path, override: str | None) -> str:
    if override and override != "auto":
        return resolve_provider({}, override)
    if path.is_dir():
        if is_container_dir(path):
            return "cryptopro"
        raise CliError(f"каталог не похож на контейнер CryptoPro: {path}")
    if path.is_file():
        head = path.read_bytes()[:4]
        if head in MAGICS:
            return "vipnet"
        data = path.read_bytes()
        if data.startswith(b"PK\x03\x04"):
            try:
                read_container_source(path)
                return "cryptopro"
            except ValueError:
                pass
        try:
            read_container_source(path)
            return "cryptopro"
        except ValueError:
            pass
        raise CliError(f"не удалось определить формат контейнера: {path}")
    raise CliError(f"контейнер не найден: {path}")


def _read_text_output(data: bytes, output: Path | None) -> None:
    if output is None or str(output) == "-":
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    else:
        output.write_bytes(data)


def command_export(args: argparse.Namespace) -> int:
    container_path = Path(args.container).expanduser()
    provider = _detect_provider(container_path, args.provider)
    pin = args.pin
    if pin is None:
        if provider == "vipnet" and sys.stdin.isatty():
            pin = getpass.getpass("ПИН-код: ")
        else:
            pin = ""

    if provider == "vipnet":
        entry = read_container(container_path)
        if args.cert:
            raise CliError("ViPNet-контейнер не содержит отдельного сертификата")
        pem = export_pem(entry, pin)
    else:
        files = read_container_source(container_path)
        container = CryptoProContainer(files, pin)
        if args.cert:
            pem = container.certificate_pem()
        else:
            pem = container.private_pem()
            if not args.no_verify:
                verified = container.verify_key()
                if verified is None:
                    verified = container.verify_password()
                if verified is False:
                    raise CliError("неверный ПИН-код")
                if verified is None:
                    print("Предупреждение: контейнер не содержит средства "
                          "проверки PIN, правильность PIN не проверена",
                          file=sys.stderr)

    _read_text_output(pem, Path(args.output).expanduser() if args.output else None)
    return 0


def _emit_vipnet(data: bytes, output: Path | None, fmt: str) -> None:
    if fmt not in ("auto", "raw"):
        raise CliError("для ViPNet-контейнера поддерживается только формат raw")
    _read_text_output(data, output)


def _emit_cryptopro(files: dict[str, bytes], output: Path | None, fmt: str) -> None:
    if fmt == "auto":
        if output is None or str(output) == "-":
            fmt = "tar"
        elif output.is_dir():
            fmt = "folder"
        else:
            suffix = output.suffix.lower()
            if suffix == ".zip":
                fmt = "zip"
            elif suffix in (".tar", ".tgz", ".tar.gz"):
                fmt = "tar"
            elif suffix == "":
                fmt = "folder"
            else:
                fmt = "tar"
    if fmt == "folder":
        if output is None or str(output) == "-":
            raise CliError("для формата folder укажите -o КАТАЛОГ")
        write_container(files, output)
        return
    if fmt == "zip":
        _read_text_output(pack_zip(files), output)
        return
    if fmt == "tar":
        _read_text_output(pack_tar(files), output)
        return
    raise CliError(f"неизвестный формат вывода: {fmt}")


def _print_create_info(spec: Spec, output: Path | None, fmt: str) -> None:
    print(f"Криптопровайдер: {spec.provider}", file=sys.stderr)
    print(f"Кривая: {spec.curve.oid} ({spec.curve.name})", file=sys.stderr)
    print(f"Алгоритм: {spec.kind}", file=sys.stderr)
    print(f"Действителен до: {spec.valid_until.isoformat()}", file=sys.stderr)
    if spec.key_generated:
        print("Закрытый ключ: сгенерирован", file=sys.stderr)
    if spec.pin_generated:
        print(f"ПИН-код (сгенерирован): {spec.pin}", file=sys.stderr)
    if spec.provider == "cryptopro" and fmt == "tar" and (
            output is None or str(output) == "-"):
        print("Вывод: tar-архив с файлами CryptoPro (header.key, primary.key, ...)",
              file=sys.stderr)
    elif spec.provider == "cryptopro" and fmt == "folder":
        print(f"Каталог контейнера: {output}", file=sys.stderr)


def command_create(args: argparse.Namespace) -> int:
    spec_path = Path(args.spec).expanduser()
    if not spec_path.is_file():
        raise CliError(f"JSON-спецификация не найдена: {spec_path}")
    spec = load_spec(spec_path, pin_override=args.pin, provider_override=args.provider)

    if spec.provider == "cryptopro" and spec.certificate_der:
        matches = certificate_matches_key(spec.certificate_der, spec.curve,
                                          spec.scalar)
        if matches is False:
            raise CliError("сертификат не соответствует закрытому ключу "
                           "(укажите правильный private_key)")
        if matches is None:
            print("Предупреждение: не удалось извлечь ГОСТ-ключ из "
                  "сертификата; соответствие не проверено", file=sys.stderr)

    output = Path(args.output).expanduser() if args.output else None
    fmt = args.format
    if output is None and sys.stdout.isatty() and fmt == "auto":
        raise CliError("укажите -o ФАЙЛ/КАТАЛОГ или перенаправьте stdout "
                       "(> container) — иначе двоичный контейнер попадёт в терминал")
    if spec.key_generated and not args.key_out:
        print("Ключ сгенерирован; при необходимости сохраните его через --key-out",
              file=sys.stderr)
    if spec.provider == "vipnet":
        if fmt == "auto":
            fmt = "raw"
        data = build_vipnet(spec)
        _emit_vipnet(data, output, fmt)
    else:
        files = build_cryptopro(spec)
        effective_fmt = fmt
        _emit_cryptopro(files, output, effective_fmt)
        if fmt == "auto":
            if output is None or str(output) == "-":
                effective_fmt = "tar"
            elif output.is_dir():
                effective_fmt = "folder"
            else:
                suffix = output.suffix.lower()
                effective_fmt = "zip" if suffix == ".zip" else (
                    "folder" if suffix == "" else "tar")
        fmt = effective_fmt

    if args.key_out:
        pem = private_key_pem(spec.scalar, spec.curve.oid, spec.digest_oid,
                              spec.key_algorithm_oid)
        key_out = Path(args.key_out).expanduser()
        key_out.write_bytes(pem)
        try:
            key_out.chmod(0o600)
        except OSError:
            pass
        print(f"Закрытый ключ сохранён в {key_out}", file=sys.stderr)
    _print_create_info(spec, output, fmt)
    return 0


def command_inspect(args: argparse.Namespace) -> int:
    path = Path(args.container).expanduser()
    provider = _detect_provider(path, args.provider)
    if provider == "vipnet":
        entry = read_container(path)
        info = {
            "provider": "vipnet",
            "key_algorithm": entry.key_algorithm,
            "curve": entry.curve_oid,
            "parameters": entry.key_parameters,
            "key_class": entry.key_class,
            "key_type": entry.key_type,
            "valid_from": entry.validity[0].isoformat() if entry.validity[0] else None,
            "valid_to": entry.validity[1].isoformat() if entry.validity[1] else None,
            "serial": entry.serial.hex() if entry.serial else None,
            "salt": entry.salt.hex() if entry.salt else None,
            "iterations": entry.iterations,
            "key_uid": entry.key_uid.hex() if entry.key_uid else None,
            "flags": entry.flags,
        }
    else:
        files = read_container_source(path)
        container = CryptoProContainer(files, args.pin or "")
        info = {
            "provider": "cryptopro",
            "container_name": container.name,
            "usage": container.usage,
            "kind": container.kind,
            "curve": container.param_set,
            "digest": container.digest_set,
            "sign_algorithm": container.sign_oid,
            "agreement_algorithm": container.agreement_oid,
            "password_protected": container.password_protected,
            "certificate": container.certificate is not None,
            "public_x": container.public_x.hex() if container.public_x else None,
            "files": sorted(files),
        }
    if args.json:
        print(json.dumps(info, ensure_ascii=False, indent=2))
    else:
        labels = {
            "provider": "Провайдер",
            "container_name": "Имя контейнера",
            "usage": "Назначение ключа",
            "password_protected": "Защищён PIN-кодом",
            "kind": "Тип ключа",
            "curve": "Кривая",
            "digest": "Хэш",
            "sign_algorithm": "Алгоритм подписи",
            "agreement_algorithm": "Алгоритм согласования",
            "key_algorithm": "Алгоритм ключа",
            "parameters": "Параметры",
            "key_class": "Класс ключа",
            "key_type": "Тип ключа (число)",
            "valid_from": "Действителен с",
            "valid_to": "Действителен до",
            "serial": "Серийный номер",
            "salt": "Salt",
            "iterations": "Итераций",
            "key_uid": "KeyUID",
            "flags": "Флаги",
            "certificate": "Сертификат",
            "public_x": "Открытый ключ (фрагмент)",
            "files": "Файлы",
        }
        for key, value in info.items():
            print(f"{labels.get(key, key)}: {value}")
    return 0


def command_selftest(args: argparse.Namespace) -> int:
    from .gost import streebog256, streebog512

    expected_empty = "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb"
    if streebog256(b"").hex() != expected_empty:
        raise CliError("самопроверка Streebog-256 не пройдена")
    if streebog512(b"").hex()[:32] != "8e945da209aa869f0455928529bcae46":
        raise CliError("самопроверка Streebog-512 не пройдена")

    with tempfile.TemporaryDirectory(prefix="cspcombine-selftest-") as temp:
        root = Path(temp)
        for provider in ("vipnet", "cryptopro"):
            spec = {"provider": provider, "pin": "12345678",
                    "container_name": "selftest",
                    "valid_until": "2030-01-01"}
            spec_path = root / f"{provider}.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            loaded = load_spec(spec_path)
            if provider == "vipnet":
                data = build_vipnet(loaded)
                entry = read_container(data)
                got = int.from_bytes(extract_vipnet(entry, "12345678"), "big")
            else:
                files = build_cryptopro(loaded)
                from .der import der_children, der_item, der_sequence
                from .gost import SBOX_Z, gost_mac
                _, header_body, _ = der_item(files["header.key"])
                parts = der_children(header_body)
                if gost_mac(der_sequence(parts[0][1]), b"\0" * 32,
                            SBOX_Z) != parts[1][1]:
                    raise CliError("самопроверка MAC заголовка не пройдена")
                container = CryptoProContainer(files, "12345678")
                got = container.private_key()
                if not container.verify_password():
                    raise CliError("самопроверка пароля CryptoPro не пройдена")
            if got != loaded.scalar:
                raise CliError(f"самопроверка {provider} не пройдена")
            print(f"{provider}: OK", file=sys.stderr)
    print("Все самопроверки пройдены", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cspcombine",
        description="Единая утилита для контейнеров ViPNet и КриптоПро.",
    )
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    export = subparsers.add_parser(
        "export", help="извлечь закрытый ключ (PEM) из контейнера")
    export.add_argument("-container", "--container", "-c", required=True,
                        help="файл ViPNet, каталог CryptoPro или tar/zip")
    export.add_argument("-pin", "--pin", "-p", default=None,
                        help="ПИН-код (пустая строка означает отсутствие PIN)")
    export.add_argument("-o", "--output", default=None,
                        help="файл вывода (по умолчанию stdout)")
    export.add_argument("--provider", choices=("auto", "vipnet", "cryptopro"),
                        default="auto")
    export.add_argument("--cert", action="store_true",
                        help="извлечь сертификат вместо ключа (CryptoPro)")
    export.add_argument("--no-verify", action="store_true",
                        help="не сверять ключ с сертификатом CryptoPro")
    export.set_defaults(function=command_export)

    create = subparsers.add_parser(
        "create", help="создать контейнер по JSON-спецификации")
    create.add_argument("spec", help="JSON-файл спецификации")
    create.add_argument("-o", "--output", default=None,
                        help="файл/каталог вывода (по умолчанию stdout)")
    create.add_argument("-pin", "--pin", "-p", default=None,
                        help="переопределить ПИН-код из спецификации")
    create.add_argument("--provider", choices=("vipnet", "cryptopro"),
                        default=None)
    create.add_argument("--format", choices=("auto", "raw", "tar", "zip", "folder"),
                        default="auto")
    create.add_argument("--key-out", default=None,
                        help="дополнительно сохранить закрытый ключ в PEM")
    create.set_defaults(function=command_create)

    inspect = subparsers.add_parser(
        "inspect", help="показать параметры контейнера")
    inspect.add_argument("-container", "--container", "-c", required=True)
    inspect.add_argument("-pin", "--pin", "-p", default=None)
    inspect.add_argument("--provider", choices=("auto", "vipnet", "cryptopro"),
                         default="auto")
    inspect.add_argument("--json", action="store_true")
    inspect.set_defaults(function=command_inspect)

    selftest = subparsers.add_parser("selftest", help="проверить алгоритмы и round-trip")
    selftest.set_defaults(function=command_selftest)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.function(args)
    except (CliError, ValueError, OSError, DerError, struct.error, IndexError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Прервано", file=sys.stderr)
        return 130
