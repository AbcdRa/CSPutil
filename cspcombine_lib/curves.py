"""GOST elliptic curves and their identifiers.

The parameters mirror the named curves used by CryptoPro CSP and ViPNet.
Only the curves that are understood by the bundled container readers/writers
are listed; unknown curves are rejected instead of silently guessed.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Curve:
    oid: str
    name: str
    kind: str          # "2001", "2012-256" or "2012-512"
    p: int
    a: int
    b: int
    q: int             # order of the generator
    gx: int
    gy: int
    width: int         # size of a field element in bytes

    def point(self):  # pragma: no cover - tiny convenience helper
        return self.gx, self.gy


def _int(hex_text: str) -> int:
    return int(hex_text.replace(" ", ""), 16)


CRYPTOPRO_A = Curve(
    oid="1.2.643.2.2.35.1",
    name="CryptoPro-A (GOST R 34.10-2001)",
    kind="2001",
    p=_int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97"),
    a=_int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94"),
    b=_int("A6"),
    q=_int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893"),
    gx=1,
    gy=_int("8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14"),
    width=32,
)

CRYPTOPRO_XCHA = Curve(
    oid="1.2.643.2.2.36.0",
    name="CryptoPro-XchA (GOST R 34.10-2001)",
    kind="2001",
    p=CRYPTOPRO_A.p,
    a=CRYPTOPRO_A.a,
    b=CRYPTOPRO_A.b,
    q=CRYPTOPRO_A.q,
    gx=CRYPTOPRO_A.gx,
    gy=CRYPTOPRO_A.gy,
    width=32,
)

TC26_256_A = Curve(
    oid="1.2.643.7.1.2.1.1.1",
    name="TC26-256-A (GOST R 34.10-2012)",
    kind="2012-256",
    p=CRYPTOPRO_A.p,
    a=_int("C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335"),
    b=_int("295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513"),
    q=_int("400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67"),
    gx=_int("91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28"),
    gy=_int("32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C"),
    width=32,
)

TC26_512_A = Curve(
    oid="1.2.643.7.1.2.1.2.1",
    name="TC26-512-A (GOST R 34.10-2012)",
    kind="2012-512",
    p=_int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7"),
    a=_int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4"),
    b=_int("E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265"
           "EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760"),
    q=_int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
           "27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275"),
    gx=3,
    gy=_int("7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921"
            "DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4"),
    width=64,
)

CURVES: dict[str, Curve] = {
    curve.oid: curve
    for curve in (CRYPTOPRO_A, CRYPTOPRO_XCHA, TC26_256_A, TC26_512_A)
}

# Some containers carry the curve OID in a slightly different place.  These
# aliases let the builders keep the user-supplied OID while resolving crypto.
CURVES["1.2.643.2.2.36.0"] = CRYPTOPRO_XCHA


SIGN_OIDS = {
    "2001": "1.2.643.2.2.19",
    "2012-256": "1.2.643.7.1.1.1.1",
    "2012-512": "1.2.643.7.1.1.1.2",
}

AGREEMENT_OIDS = {
    "2001": "1.2.643.2.2.98",
    "2012-256": "1.2.643.7.1.1.6.1",
    "2012-512": "1.2.643.7.1.1.6.2",
}

DIGEST_OIDS = {
    "2001": "1.2.643.2.2.30.1",
    "2012-256": "1.2.643.7.1.1.2.2",
    "2012-512": "1.2.643.7.1.1.2.3",
}

KIND_ALIASES = {
    "2001": "2001",
    "gost2001": "2001",
    "gost-2001": "2001",
    "gost3410-2001": "2001",
    "34.10-2001": "2001",
    "гост2001": "2001",
    "гост-2001": "2001",
    "2012-256": "2012-256",
    "2012_256": "2012-256",
    "gost2012-256": "2012-256",
    "gost2012_256": "2012-256",
    "gost-2012-256": "2012-256",
    "gost3410-2012-256": "2012-256",
    "34.10-2012-256": "2012-256",
    "гост2012-256": "2012-256",
    "гост-2012-256": "2012-256",
    "256": "2012-256",
    "2012-512": "2012-512",
    "2012_512": "2012-512",
    "gost2012-512": "2012-512",
    "gost2012_512": "2012-512",
    "gost-2012-512": "2012-512",
    "gost3410-2012-512": "2012-512",
    "34.10-2012-512": "2012-512",
    "гост2012-512": "2012-512",
    "гост-2012-512": "2012-512",
    "512": "2012-512",
}


def curve_by_oid(oid: str) -> Curve:
    try:
        return CURVES[oid]
    except KeyError as error:
        raise ValueError(f"неподдерживаемая кривая: {oid}") from error


def default_curve(kind: str, provider: str = "cryptopro") -> Curve:
    kind = normalize_kind(kind)
    if provider == "vipnet":
        # This is the profile used by the original ViPNet builder and tested
        # against the CSP container parser.
        if kind == "2001":
            return CRYPTOPRO_XCHA
        if kind == "2012-256":
            return CRYPTOPRO_XCHA
    if kind == "2001":
        return CRYPTOPRO_A
    if kind == "2012-512":
        return TC26_512_A
    return TC26_256_A


def normalize_kind(value: str | None) -> str:
    if not value:
        return "2012-256"
    text = str(value).strip().lower().replace(" ", "")
    if text in KIND_ALIASES:
        return KIND_ALIASES[text]
    if text.startswith("1.2.643.2.2.35") or text.startswith("1.2.643.2.2.36"):
        return "2001"
    if text.startswith("1.2.643.7.1.2.1.2") or text == "1.2.643.7.1.1.1.2":
        return "2012-512"
    if text.startswith("1.2.643.7.1.2.1.1") or text == "1.2.643.7.1.1.1.1":
        return "2012-256"
    return "2012-256"


def kind_for_curve(curve: Curve) -> str:
    return curve.kind
