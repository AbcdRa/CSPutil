from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cspcombine_lib.cryptopro import (  # noqa: E402
    Container as CryptoProContainer,
    build_container as build_cryptopro,
    pack_tar,
    pack_zip,
    read_container_source,
)
from cspcombine_lib.cli import _path_arg  # noqa: E402
from cspcombine_lib.keys import parse_private_key, private_key_pem  # noqa: E402
from cspcombine_lib.schema import _load_json, load_spec  # noqa: E402
from cspcombine_lib.vipnet import (  # noqa: E402
    build_container as build_vipnet,
    extract as extract_vipnet,
    read_container as read_vipnet,
)


class AlgorithmTests(unittest.TestCase):
    def test_streebog_empty(self):
        from cspcombine_lib.gost import streebog256, streebog512
        self.assertEqual(
            streebog256(b"").hex(),
            "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb",
        )
        self.assertTrue(streebog512(b"").hex().startswith(
            "8e945da209aa869f0455928529bcae46"))

    def test_pem_roundtrip(self):
        from cspcombine_lib.curves import TC26_256_A
        scalar = 0x1234567890ABCDEF
        pem = private_key_pem(scalar, TC26_256_A.oid,
                              "1.2.643.7.1.1.2.2", "1.2.643.7.1.1.1.1")
        parsed = parse_private_key(pem.decode())
        self.assertEqual(parsed.scalar, scalar)
        self.assertEqual(parsed.curve_oid, TC26_256_A.oid)


class SpecTests(unittest.TestCase):
    def _spec(self, root: Path, data: dict):
        path = root / "spec.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return load_spec(path)

    def test_defaults(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            spec = self._spec(root, {"provider": "vipnet"})
            self.assertEqual(spec.curve.oid, "1.2.643.2.2.36.0")
            self.assertEqual(len(spec.pin), 8)
            self.assertIsNotNone(spec.valid_until)
            self.assertGreater(spec.scalar, 0)

    def test_relative_key_path(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            spec = self._spec(root, {"provider": "cryptopro", "pin": ""})
            (root / "key.pem").write_bytes(
                private_key_pem(spec.scalar, spec.curve.oid,
                                spec.digest_oid, spec.key_algorithm_oid))
            new_spec = self._spec(root, {
                "provider": "cryptopro",
                "pin": "",
                "private_key": "key.pem",
            })
            self.assertEqual(new_spec.scalar, spec.scalar)

    def test_windows_paths_in_json(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "spec.json"
            cases = {
                r'{"private_key":"C:\\Users\\mihail\\key.pem"}':
                    r"C:\Users\mihail\key.pem",
                r'{"private_key":"C:\Users\mihail\key.pem"}':
                    r"C:\Users\mihail\key.pem",
                r'{"private_key":"C:\temp\key.pem"}':
                    r"C:\temp\key.pem",
                r'{"private_key":"C:\users\mihail\key.pem"}':
                    r"C:\users\mihail\key.pem",
                r'{"private_key":"D:\vm\DLL\key.pem"}':
                    r"D:\vm\DLL\key.pem",
            }
            for document, expected in cases.items():
                path.write_text(document, encoding="utf-8")
                self.assertEqual(_load_json(path)["private_key"], expected)

    def test_windows_cli_path_with_trailing_quote(self):
        self.assertEqual(str(_path_arg('D:\\vm\\DLL\\test"')),
                         "D:\\vm\\DLL\\test")
        self.assertEqual(str(_path_arg('"D:\\vm\\DLL\\test"')),
                         "D:\\vm\\DLL\\test")


class ContainerTests(unittest.TestCase):
    def _vipnet_spec(self, root: Path, **extra):
        data = {
            "provider": "vipnet",
            "pin": "12345678",
            "iterations": 10,
            "valid_from": "2025-01-01",
            "valid_until": "2030-06-30",
            "container_name": "test",
        }
        data.update(extra)
        path = root / "vipnet.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return load_spec(path)

    def _cryptopro_spec(self, root: Path, **extra):
        data = {
            "provider": "cryptopro",
            "pin": "",
            "valid_until": "2030-06-30",
            "container_name": "test",
            "backup_key": False,
        }
        data.update(extra)
        path = root / "cryptopro.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return load_spec(path)

    def test_vipnet_roundtrip(self):
        with tempfile.TemporaryDirectory() as temp:
            spec = self._vipnet_spec(Path(temp))
            data = build_vipnet(spec)
            entry = read_vipnet(data)
            got = int.from_bytes(extract_vipnet(entry, "12345678"), "big")
            self.assertEqual(got, spec.scalar)
            self.assertEqual(entry.validity[0].year, 2025)
            self.assertEqual(entry.validity[1].strftime("%Y-%m-%d"), "2030-06-30")

    def test_vipnet_key_class_zero(self):
        with tempfile.TemporaryDirectory() as temp:
            spec = self._vipnet_spec(Path(temp), key_class=0)
            data = build_vipnet(spec)
            entry = read_vipnet(data)
            got = int.from_bytes(extract_vipnet(entry, "12345678"), "big")
            self.assertEqual(got, spec.scalar)

    def test_vipnet_512(self):
        with tempfile.TemporaryDirectory() as temp:
            spec = self._vipnet_spec(Path(temp), algorithm="2012-512",
                                     curve="1.2.643.7.1.2.1.2.1")
            data = build_vipnet(spec)
            got = int.from_bytes(extract_vipnet(read_vipnet(data), "12345678"), "big")
            self.assertEqual(got, spec.scalar)

    def test_cryptopro_roundtrip(self):
        with tempfile.TemporaryDirectory() as temp:
            spec = self._cryptopro_spec(Path(temp))
            files = build_cryptopro(spec)
            container = CryptoProContainer(files, "")
            self.assertEqual(container.private_key(), spec.scalar)
            self.assertEqual(set(files), {"header.key", "masks.key",
                                          "primary.key", "name.key"})

    def test_cryptopro_pin_roundtrip(self):
        with tempfile.TemporaryDirectory() as temp:
            spec = self._cryptopro_spec(Path(temp), pin="12345678")
            files = build_cryptopro(spec)
            container = CryptoProContainer(files, "12345678")
            self.assertEqual(container.private_key(), spec.scalar)
            self.assertTrue(container.verify_password())

    def test_cryptopro_container_macs(self):
        from cspcombine_lib.der import der_children, der_item, der_sequence
        from cspcombine_lib.gost import SBOX_Z, gost_mac
        with tempfile.TemporaryDirectory() as temp:
            spec = self._cryptopro_spec(Path(temp))
            files = build_cryptopro(spec)
            tag, body, _ = der_item(files["header.key"]) 
            parts = der_children(body)
            inner = der_sequence(parts[0][1])
            self.assertEqual(gost_mac(inner, b"\0" * 32, SBOX_Z), parts[1][1])
            tag, body, _ = der_item(files["masks.key"])
            mask, salt, mac = [value for tag, value in der_children(body)]
            self.assertEqual(gost_mac(salt, mask, SBOX_Z), mac)

    def test_cryptopro_key_attributes(self):
        from cspcombine_lib.der import der_children, der_item
        cases = [
            ({}, b"\x00"),                              # no attributes
            ({"exportable": True}, b"\x07\x80"),        # pkaExportable
            ({"key_usage": "exchange"}, b"\x05\x20"),   # pkaExchange
            ({"exportable": True, "key_usage": "exchange"},
             b"\x05\xa0"),                              # exportable exchange
        ]
        with tempfile.TemporaryDirectory() as temp:
            for extra, expected in cases:
                spec = self._cryptopro_spec(Path(temp), **extra)
                files = build_cryptopro(spec)
                _, header_body, _ = der_item(files["header.key"])
                outer = dict(der_children(header_body))
                inner = dict(der_children(outer[0x30]))
                attributes = dict(der_children(inner[0x30]))[0x03]
                self.assertEqual(attributes, expected)
                container = CryptoProContainer(files, "")
                self.assertEqual(container.exportable,
                                 bool(extra.get("exportable", False)))

    def test_cryptopro_2001_roundtrip(self):
        with tempfile.TemporaryDirectory() as temp:
            spec = self._cryptopro_spec(Path(temp), algorithm="2001",
                                        curve="1.2.643.2.2.35.1")
            files = build_cryptopro(spec)
            container = CryptoProContainer(files, "")
            self.assertEqual(container.kind, "2001")
            self.assertEqual(container.private_key(), spec.scalar)

    def test_cryptopro_512_roundtrip(self):
        with tempfile.TemporaryDirectory() as temp:
            spec = self._cryptopro_spec(Path(temp), algorithm="2012-512",
                                        curve="1.2.643.7.1.2.1.2.1")
            files = build_cryptopro(spec)
            container = CryptoProContainer(files, "")
            self.assertEqual(container.private_key(), spec.scalar)

    def test_archives(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            spec = self._cryptopro_spec(root)
            files = build_cryptopro(spec)
            for suffix, packed in ((".tar", pack_tar(files)), (".zip", pack_zip(files))):
                path = root / f"container{suffix}"
                path.write_bytes(packed)
                container = CryptoProContainer(read_container_source(path), "")
                self.assertEqual(container.private_key(), spec.scalar)


class RealContainerTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("CSPCOMBINE_REAL_TESTS"),
                         "set CSPCOMBINE_REAL_TESTS=1 to run real-container tests")
    def test_real_vipnet(self):
        configured = os.environ.get("CSPCOMBINE_REAL_VIPNET")
        if not configured:
            self.skipTest("set CSPCOMBINE_REAL_VIPNET to a sample container")
        path = Path(configured)
        if not path.exists():
            self.skipTest("sample ViPNet container is absent")
        pin = os.environ.get("CSPCOMBINE_REAL_VIPNET_PIN", "12345678")
        entry = read_vipnet(path)
        self.assertGreater(int.from_bytes(extract_vipnet(entry, pin), "big"), 0)

    @unittest.skipUnless(os.environ.get("CSPCOMBINE_REAL_TESTS"),
                         "set CSPCOMBINE_REAL_TESTS=1 to run real-container tests")
    def test_real_cryptopro_certificate(self):
        configured = os.environ.get("CSPCOMBINE_REAL_CRYPTOPRO")
        if not configured:
            self.skipTest("set CSPCOMBINE_REAL_CRYPTOPRO to a sample container")
        path = Path(configured)
        if not path.exists():
            self.skipTest("sample CryptoPro container is absent")
        pin = os.environ.get("CSPCOMBINE_REAL_CRYPTOPRO_PIN", "12345678")
        container = CryptoProContainer(read_container_source(path), pin)
        self.assertTrue(container.verify_key())


if __name__ == "__main__":
    unittest.main()
