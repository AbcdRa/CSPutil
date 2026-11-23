"""Pure-Python GOST primitives used by both supported providers.

Everything here is implemented locally so the command has no third-party
dependencies.  The algorithms follow the same conventions as the reference
Bouncy Castle code used by the original extractors.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from .curves import Curve
from .streebog_tables import T as STREEBOG_T, C as STREEBOG_C

MASK32 = 0xFFFFFFFF

# GOST 28147-89 S-boxes, 8 rows of 16 nibbles.  Row i substitutes nibble i.
SBOX_A = bytes([
    9, 6, 3, 2, 8, 11, 1, 7, 10, 4, 14, 15, 12, 0, 13, 5,
    3, 7, 14, 9, 8, 10, 15, 0, 5, 2, 6, 12, 11, 4, 13, 1,
    14, 4, 6, 2, 11, 3, 13, 8, 12, 15, 5, 10, 0, 7, 1, 9,
    14, 7, 10, 12, 13, 1, 3, 9, 0, 2, 11, 4, 15, 8, 5, 6,
    11, 5, 1, 9, 8, 13, 15, 0, 14, 4, 2, 3, 12, 7, 10, 6,
    3, 10, 13, 12, 1, 2, 0, 11, 7, 5, 9, 4, 8, 15, 14, 6,
    1, 13, 2, 9, 7, 10, 6, 0, 8, 12, 4, 5, 15, 3, 11, 14,
    11, 10, 15, 5, 0, 12, 14, 8, 6, 2, 3, 9, 1, 7, 13, 4,
])

SBOX_D = bytes([
    10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15,
    5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8,
    7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13,
    4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3,
    7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5,
    7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3,
    13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11,
    1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12,
])

# TC26 parameter set Z (used by GOST R 34.10-2012 containers).
SBOX_Z = bytes([
    12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1,
    6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15,
    11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0,
    12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11,
    7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12,
    5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0,
    8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7,
    1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2,
])


def _u32(data: bytes) -> int:
    return int.from_bytes(data, "little")


def _p32(value: int) -> bytes:
    return (value & MASK32).to_bytes(4, "little")


def _build_step_tables(sbox: bytes):
    """Combine the S-box substitution with its nibble shift.

    The GOST round substitutes eight nibbles and shifts each by four bits.
    Pre-computing two nibbles per byte turns the hot loop into four table
    lookups instead of eight lookups plus shifts.
    """
    tables = []
    for byte_index in range(4):
        table = [0] * 256
        for byte in range(256):
            low = sbox[16 * (2 * byte_index) + (byte & 15)]
            high = sbox[16 * (2 * byte_index + 1) + (byte >> 4)]
            table[byte] = (low << (8 * byte_index)) | (high << (8 * byte_index + 4))
        tables.append(table)
    return tuple(tables)


_STEP_TABLES = {
    SBOX_A: _build_step_tables(SBOX_A),
    SBOX_D: _build_step_tables(SBOX_D),
    SBOX_Z: _build_step_tables(SBOX_Z),
}


def gost_step(left: int, key: int, sbox: bytes = SBOX_A) -> int:
    value = (left + key) & MASK32
    t0, t1, t2, t3 = _STEP_TABLES[sbox]
    substituted = (t0[value & 0xFF] | t1[(value >> 8) & 0xFF] |
                   t2[(value >> 16) & 0xFF] | t3[value >> 24])
    return ((substituted << 11) | (substituted >> 21)) & MASK32


def gost_block(block: bytes, key: bytes, sbox: bytes = SBOX_A,
               decrypt: bool = False) -> bytes:
    """One GOST 28147-89 ECB block (8 bytes in, 8 bytes out)."""
    words = [_u32(key[i:i + 4]) for i in range(0, 32, 4)]
    left, right = _u32(block[:4]), _u32(block[4:])
    if decrypt:
        rounds = (words + list(reversed(words)) * 3)[:31]
    else:
        rounds = (words * 3 + words[7:0:-1])[:31]
    for round_key in rounds:
        left, right = right ^ gost_step(left, round_key, sbox), left
    right ^= gost_step(left, words[0], sbox)
    return _p32(left) + _p32(right)


def gost_ecb(data: bytes, key: bytes, sbox: bytes, decrypt: bool = False) -> bytes:
    if len(data) % 8:
        raise ValueError("длина данных должна быть кратна 8")
    return b"".join(
        gost_block(data[i:i + 8], key, sbox, decrypt)
        for i in range(0, len(data), 8)
    )


def gost_cfb_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    result, shift = bytearray(), bytearray(iv)
    for position in range(0, len(data), 8):
        chunk = data[position:position + 8]
        stream = gost_block(bytes(shift), key)
        encrypted = bytes(a ^ b for a, b in zip(chunk, stream))
        result.extend(encrypted)
        shift = bytearray(encrypted)
    return bytes(result)


def gost_cfb_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    result, shift = bytearray(), bytearray(iv)
    for position in range(0, len(data), 8):
        chunk = data[position:position + 8]
        stream = gost_block(bytes(shift), key)
        plain = bytes(a ^ b for a, b in zip(chunk, stream))
        result.extend(plain)
        shift = bytearray(chunk)
    return bytes(result)


def gost_mac(data: bytes, key: bytes, sbox: bytes = SBOX_A) -> bytes:
    """Four-byte GOST 28147-89 MAC (16 rounds, optional S-box)."""
    state = bytearray(8)
    words = [_u32(key[i:i + 4]) for i in range(0, 32, 4)]

    def mac_block(block: bytes) -> None:
        nonlocal state
        left, right = _u32(block[:4]), _u32(block[4:])
        for round_key in words * 2:
            left, right = right ^ gost_step(left, round_key, sbox), left
        state[:] = _p32(left) + _p32(right)

    if not data:
        mac_block(b"\0" * 8)
    else:
        full_blocks = len(data) // 8
        last_full_is_final = len(data) % 8 == 0
        process_count = full_blocks - (1 if last_full_is_final else 0)
        for index in range(process_count):
            block = data[index * 8:index * 8 + 8]
            if index:
                block = bytes(a ^ b for a, b in zip(block, state))
            mac_block(block)
        tail = data[process_count * 8:].ljust(8, b"\0")
        if process_count:
            tail = bytes(a ^ b for a, b in zip(tail, state))
        mac_block(tail)
    return bytes(state[:4])


GOST94_C2 = bytes([
    0, 255, 0, 255, 0, 255, 0, 255,
    255, 0, 255, 0, 255, 0, 255, 0,
    0, 255, 255, 0, 255, 0, 0, 255,
    255, 0, 0, 0, 255, 255, 0, 255,
])
_GOST94_C2_INT = int.from_bytes(GOST94_C2, "little")
_MASK64 = (1 << 64) - 1
_MASK256 = (1 << 256) - 1


def _gost94_a(value: int) -> int:
    low = value & _MASK64
    following = (value >> 64) & _MASK64
    return (value >> 64) | ((low ^ following) << 192)


def _gost94_fw(value: int, count: int = 1) -> int:
    for _ in range(count):
        feedback = ((value & 0xFFFF) ^ ((value >> 16) & 0xFFFF) ^
                    ((value >> 32) & 0xFFFF) ^ ((value >> 48) & 0xFFFF) ^
                    ((value >> 192) & 0xFFFF) ^ ((value >> 240) & 0xFFFF))
        value = (value >> 16) | (feedback << 240)
    return value


class Gost3411_94:
    """GOST R 34.11-94 with the CryptoPro/D-A parameters."""

    def __init__(self) -> None:
        self.h = bytearray(32)
        self.total = 0
        self.sum = bytearray(32)
        self.buffer = bytearray()

    def _block(self, message: bytes) -> None:
        h = self.h
        u = bytearray(h)
        v = bytearray(message)
        u_int = int.from_bytes(u, "little")
        v_int = int.from_bytes(v, "little")
        s = bytearray()
        for index in range(4):
            w = bytes(a ^ b for a, b in zip(u, v))
            permuted = b"".join(w[k:k + 1] + w[8 + k:9 + k] +
                                  w[16 + k:17 + k] + w[24 + k:25 + k]
                                  for k in range(8))
            s += gost_block(h[index * 8:(index + 1) * 8], permuted, SBOX_D)
            if index != 3:
                u_int = _gost94_a(u_int)
                # C[1] and C[3] are zero; only the middle step uses C2.
                if index == 1:
                    u_int ^= _GOST94_C2_INT
                v_int = _gost94_a(_gost94_a(v_int))
                u[:] = u_int.to_bytes(32, "little")
                v[:] = v_int.to_bytes(32, "little")
        x = _gost94_fw(int.from_bytes(s, "little"), 12)
        s = bytearray(x.to_bytes(32, "little"))
        s = bytearray(a ^ b for a, b in zip(s, message))
        s = bytearray(_gost94_fw(int.from_bytes(s, "little"), 1).to_bytes(32, "little"))
        s = bytearray(a ^ b for a, b in zip(s, h))
        self.h[:] = _gost94_fw(int.from_bytes(s, "little"), 61).to_bytes(32, "little")

    def update(self, data: bytes) -> None:
        self.total += len(data)
        self.buffer += data
        while len(self.buffer) > 32:
            block = bytes(self.buffer[:32])
            self.sum[:] = ((int.from_bytes(self.sum, "little") +
                            int.from_bytes(block, "little")) & _MASK256).to_bytes(32, "little")
            self._block(block)
            del self.buffer[:32]

    @staticmethod
    def _add(a: bytes, b: bytes) -> bytes:
        return ((int.from_bytes(a, "little") + int.from_bytes(b, "little")) &
                _MASK256).to_bytes(32, "little")

    def digest(self) -> bytes:
        block = bytes(self.buffer).ljust(32, b"\0")
        if self.buffer or self.total:
            self.sum[:] = self._add(self.sum, block)
            self._block(block)
        self._block((self.total * 8).to_bytes(32, "little"))
        self._block(bytes(self.sum))
        return bytes(self.h)


def gost3411_94(data: bytes) -> bytes:
    digest = Gost3411_94()
    digest.update(data)
    return digest.digest()


_T0, _T1, _T2, _T3, _T4, _T5, _T6, _T7 = STREEBOG_T
_STREEBOG_C = [bytes(item) for item in STREEBOG_C]
_MASK512 = (1 << 512) - 1
_FROM_BYTES = int.from_bytes


def _streebog_transform(value: bytearray) -> None:
    t0, t1, t2, t3, t4, t5, t6, t7 = _T0, _T1, _T2, _T3, _T4, _T5, _T6, _T7
    out = [0] * 64
    for i in range(8):
        base = 56 + i
        word = (t0[value[base]] ^ t1[value[base - 8]] ^
                t2[value[base - 16]] ^ t3[value[base - 24]] ^
                t4[value[base - 32]] ^ t5[value[base - 40]] ^
                t6[value[base - 48]] ^ t7[value[base - 56]])
        offset = 8 * i
        out[offset] = word & 0xFF
        out[offset + 1] = (word >> 8) & 0xFF
        out[offset + 2] = (word >> 16) & 0xFF
        out[offset + 3] = (word >> 24) & 0xFF
        out[offset + 4] = (word >> 32) & 0xFF
        out[offset + 5] = (word >> 40) & 0xFF
        out[offset + 6] = (word >> 48) & 0xFF
        out[offset + 7] = (word >> 56) & 0xFF
    value[:] = out


def _streebog_xor(left, right) -> bytes:
    return (_FROM_BYTES(left, "little") ^
            _FROM_BYTES(right, "little")).to_bytes(64, "little")


def _streebog_g(hh: bytearray, nn: bytes, mm: bytes) -> None:
    saved = bytes(hh)
    hh[:] = _streebog_xor(hh, nn)
    _streebog_transform(hh)
    key = bytes(hh)
    ki = bytes(hh)
    key = bytearray(_streebog_xor(key, mm))
    _streebog_transform(key)
    for round_no in range(11):
        ki = bytearray(_streebog_xor(ki, _STREEBOG_C[round_no]))
        _streebog_transform(ki)
        key = bytearray(_streebog_xor(key, ki))
        _streebog_transform(key)
    ki = bytearray(_streebog_xor(ki, _STREEBOG_C[11]))
    _streebog_transform(ki)
    key = _streebog_xor(key, ki)
    hh[:] = _streebog_xor(_streebog_xor(saved, key), mm)


def streebog(data: bytes, bits: int = 256) -> bytes:
    """GOST R 34.11-2012 (Streebog), 256- or 512-bit variant."""
    h = bytearray(b"\x01" * 64 if bits == 256 else b"\0" * 64)
    n = bytearray(64)
    sigma = bytearray(64)
    zero = bytes(64)

    def add(a: bytearray, b: bytes) -> None:
        a[:] = ((_FROM_BYTES(a, "big") + _FROM_BYTES(b, "big")) &
                _MASK512).to_bytes(64, "big")

    def add_bits(a: bytearray, bits_count: int) -> None:
        a[:] = ((_FROM_BYTES(a, "big") + bits_count) &
                _MASK512).to_bytes(64, "big")

    position = 0
    while len(data) - position >= 64:
        block = bytearray(data[position:position + 64][::-1])
        position += 64
        _streebog_g(h, n, block)
        add_bits(n, 512)
        add(sigma, block)
    tail = data[position:][::-1]
    block = bytearray(64)
    block[64 - len(tail):] = tail
    block[63 - len(tail)] = 1
    _streebog_g(h, n, block)
    add_bits(n, len(tail) * 8)
    add(sigma, block)
    _streebog_g(h, zero, n)
    _streebog_g(h, zero, sigma)
    result = bytes(h[::-1])
    return result[32:] if bits == 256 else result


def streebog256(data: bytes) -> bytes:
    return streebog(data, 256)


def streebog512(data: bytes) -> bytes:
    return streebog(data, 512)


def pbkdf2_streebog256(password: bytes, salt: bytes, iterations: int,
                       length: int) -> bytes:
    """PBKDF2-HMAC-Streebog-512 truncated/named as used by ViPNet."""
    def hmac_streebog(key: bytes, message: bytes) -> bytes:
        if len(key) > 64:
            key = streebog512(key)
        key = key.ljust(64, b"\0")
        inner = streebog512(bytes(a ^ 0x36 for a in key) + message)
        return streebog512(bytes(a ^ 0x5C for a in key) + inner)

    if iterations < 1:
        raise ValueError("iterations must be at least 1")
    output = bytearray()
    for block_number in range(1, (length + 31) // 32 + 1):
        u = hmac_streebog(password, salt + block_number.to_bytes(4, "big"))
        result = bytearray(u)
        for _ in range(1, iterations):
            u = hmac_streebog(password, u)
            result = bytearray(a ^ b for a, b in zip(result, u))
        output.extend(result)
    return bytes(output[:length])


def hmac_streebog256(key: bytes, message: bytes) -> bytes:
    block_key = streebog256(key) if len(key) > 64 else key
    block_key = block_key.ljust(64, b"\0")
    inner = streebog256(bytes(b ^ 0x36 for b in block_key) + message)
    return streebog256(bytes(b ^ 0x5C for b in block_key) + inner)


# ---------------------------------------------------------------------------
# Elliptic-curve arithmetic for GOST curves (short Weierstrass form).
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PublicKey:
    x: int
    y: int

    def little_endian(self, width: int) -> bytes:
        return self.x.to_bytes(width, "big")[::-1] + self.y.to_bytes(width, "big")[::-1]


def point_add(left: PublicKey | None, right: PublicKey | None,
              curve: Curve) -> PublicKey | None:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left.x, left.y
    x2, y2 = right.x, right.y
    if x1 == x2 and (y1 + y2) % curve.p == 0:
        return None
    if left == right:
        if y1 == 0:
            return None
        slope = ((3 * x1 * x1 + curve.a) * pow(2 * y1, -1, curve.p)) % curve.p
    else:
        slope = ((y2 - y1) * pow(x2 - x1, -1, curve.p)) % curve.p
    x3 = (slope * slope - x1 - x2) % curve.p
    return PublicKey(x3, (slope * (x1 - x3) - y1) % curve.p)


def point_mul(number: int, curve: Curve, point: PublicKey | None = None) -> PublicKey | None:
    if point is None:
        point = PublicKey(curve.gx, curve.gy)
    result: PublicKey | None = None
    addend: PublicKey | None = point
    while number:
        if number & 1:
            result = point_add(result, addend, curve)
        addend = point_add(addend, addend, curve)
        number >>= 1
    return result


def generate_private_scalar(curve: Curve) -> int:
    if curve.q <= 2:
        raise ValueError("invalid curve order")
    return secrets.randbelow(curve.q - 1) + 1


def sbox_for_kind(kind: str) -> bytes:
    return SBOX_A if kind == "2001" else SBOX_Z
