"""Secret sharing.

* :class:`AdditiveZ2k` -- additive shares over ``Z_{2^k}`` (default 32-bit) used
  for the MPC arithmetic in Module B.  Addition of shares is local (no
  communication), which is the whole point of the "sums over banks are free"
  argument on the slides.
* :func:`split_zq` / :func:`combine_zq` -- additive shares over ``Z_q`` used by
  the read-only DORAM one-hot vectors and the ZKP side.
* :class:`Replicated3` -- 2-out-of-3 replicated shares with PRG-derived zero
  sharing, the machinery reused by MPC-in-the-head (Module D3).
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from .group import GROUP


# --------------------------------------------------------------------------
# Additive sharing over Z_{2^k}
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class AdditiveZ2k:
    bits: int = 32

    @property
    def modulus(self) -> int:
        return 1 << self.bits

    def share(self, value: int, n: int = 2) -> list[int]:
        m = self.modulus
        shares = [secrets.randbelow(m) for _ in range(n - 1)]
        last = (value - sum(shares)) % m
        shares.append(last)
        return shares

    def reconstruct(self, shares: list[int]) -> int:
        return sum(shares) % self.modulus

    def add(self, a: list[int], b: list[int]) -> list[int]:
        m = self.modulus
        return [(x + y) % m for x, y in zip(a, b)]

    def add_const(self, shares: list[int], c: int, party: int = 0) -> list[int]:
        out = list(shares)
        out[party] = (out[party] + c) % self.modulus
        return out


# --------------------------------------------------------------------------
# Additive sharing over Z_q
# --------------------------------------------------------------------------
def split_zq(value: int, n: int = 2) -> list[int]:
    shares = [GROUP.rand_scalar() for _ in range(n - 1)]
    last = (value - sum(shares)) % GROUP.q
    shares.append(last)
    return shares


def combine_zq(shares: list[int]) -> int:
    return sum(shares) % GROUP.q


# --------------------------------------------------------------------------
# Replicated 2-out-of-3 sharing with PRG zero-sharing (for MPC-in-the-head)
# --------------------------------------------------------------------------
def prg(seed: bytes, label: bytes, modulus: int) -> int:
    """Deterministic pseudo-random value in ``[0, modulus)`` from a seed."""
    out = b""
    counter = 0
    need = (modulus.bit_length() + 7) // 8 + 16
    while len(out) < need:
        out += hashlib.sha256(seed + label + counter.to_bytes(4, "big")).digest()
        counter += 1
    return int.from_bytes(out[:need], "big") % modulus


@dataclass
class Replicated3:
    """3-party replicated additive sharing over ``Z_{2^k}``.

    Party ``i`` holds shares ``(x_i, x_{i+1})`` so any two parties can
    reconstruct, but one alone learns nothing.  Zero-shares used to re-randomise
    products are derived from pairwise PRG seeds (slides 19-23).
    """

    bits: int = 1

    @property
    def modulus(self) -> int:
        return 1 << self.bits

    def share(self, value: int) -> list[tuple[int, int]]:
        m = self.modulus
        x0 = secrets.randbelow(m)
        x1 = secrets.randbelow(m)
        x2 = (value - x0 - x1) % m
        xs = [x0, x1, x2]
        # party i holds (x_i, x_{i+1})
        return [(xs[i], xs[(i + 1) % 3]) for i in range(3)]

    def reconstruct(self, parties: list[tuple[int, int]]) -> int:
        # x0 from party0[0], x1 from party1[0], x2 from party2[0]
        x0 = parties[0][0]
        x1 = parties[1][0]
        x2 = parties[2][0]
        return (x0 + x1 + x2) % self.modulus
