"""Beaver triples from OT-based (Gilboa / Du-Atallah) multiplication.

Two servers ``S0`` and ``S1`` hold additive shares over ``Z_{2^bits}``.  A Beaver
triple ``(a, b, c)`` with ``c = a*b`` is generated offline; the online
multiplication then opens ``d = x - a`` and ``e = y - b`` (both uniformly random
because ``a, b`` are random masks) and computes
``z = c + d*b + e*a + d*e``.

Offline triple generation uses OT-based multiplication of the cross terms: for
each bit ``i`` of the receiver's value the sender offers ``(r_i, r_i + a*2^i)``;
the receiver selects with its bit and sums; the sender's share is ``-sum r_i``.
"""

from __future__ import annotations

import secrets

from ..crypto.ot import ot_1of2


def _enc(x: int) -> bytes:
    return x.to_bytes(8, "big")


def _dec(b: bytes) -> int:
    return int.from_bytes(b, "big")


def gilboa_mult(a: int, b: int, bits: int = 32) -> tuple[int, int]:
    """OT multiplication: sender holds ``a``, receiver holds ``b``.

    Returns ``(u, v)`` with ``u + v == a*b (mod 2^bits)``; ``u`` goes to the
    sender, ``v`` to the receiver.
    """
    mod = 1 << bits
    b_bits = [(b >> i) & 1 for i in range(bits)]
    r = [secrets.randbelow(mod) for _ in range(bits)]
    v = 0
    for i in range(bits):
        m0 = r[i] % mod
        m1 = (r[i] + a * (1 << i)) % mod
        chosen = ot_1of2(_enc(m0), _enc(m1), b_bits[i])
        v = (v + _dec(chosen)) % mod
    u = (-sum(r)) % mod
    return u, v


class Triple:
    """A Beaver triple held in additive shares by two servers."""

    def __init__(self, bits: int = 32):
        self.bits = bits
        mod = 1 << bits
        a0, b0 = secrets.randbelow(mod), secrets.randbelow(mod)
        a1, b1 = secrets.randbelow(mod), secrets.randbelow(mod)
        # cross terms via OT multiplication
        u01, v01 = gilboa_mult(a0, b1, bits)  # S0 sender, S1 receiver
        u10, v10 = gilboa_mult(a1, b0, bits)  # S1 sender, S0 receiver
        c0 = (a0 * b0 + u01 + v10) % mod
        c1 = (a1 * b1 + v01 + u10) % mod
        self.s0 = (a0, b0, c0)
        self.s1 = (a1, b1, c1)

    def reconstruct(self) -> tuple[int, int, int]:
        mod = 1 << self.bits
        a = (self.s0[0] + self.s1[0]) % mod
        b = (self.s0[1] + self.s1[1]) % mod
        c = (self.s0[2] + self.s1[2]) % mod
        return a, b, c


def beaver_mul(x: tuple[int, int], y: tuple[int, int], triple: Triple,
               bits: int = 32, channel=None) -> tuple[int, int]:
    """Online multiplication of additively-shared ``x`` and ``y``."""
    mod = 1 << bits
    a0, b0, c0 = triple.s0
    a1, b1, c1 = triple.s1
    d0, d1 = (x[0] - a0) % mod, (x[1] - a1) % mod
    e0, e1 = (y[0] - b0) % mod, (y[1] - b1) % mod
    if channel is not None:
        channel.send("S0", "S1", "open d0", d0)
        channel.send("S1", "S0", "open d1", d1)
        channel.send("S0", "S1", "open e0", e0)
        channel.send("S1", "S0", "open e1", e1)
    d = (d0 + d1) % mod
    e = (e0 + e1) % mod
    z0 = (c0 + d * b0 + e * a0 + d * e) % mod  # party 0 adds d*e
    z1 = (c1 + d * b1 + e * a1) % mod
    return z0, z1
