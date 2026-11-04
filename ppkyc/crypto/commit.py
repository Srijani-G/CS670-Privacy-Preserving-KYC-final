"""Commitments: Pedersen (for the ZKP side) and hash (for MPC-in-the-head).

Pedersen commitment ``C = g^m * h^r`` is perfectly hiding and computationally
binding; ``h`` is :data:`PEDERSEN_H` whose discrete log base ``g`` is unknown.
The hash commitment ``H(m || r)`` is used to commit to party views in the
MPC-in-the-head proof (binding from collision resistance, hiding from the
random ``r``).
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from .group import GROUP, PEDERSEN_H


@dataclass(frozen=True)
class Pedersen:
    """Pedersen commitment scheme ``C = g^m h^r`` in the shared group."""

    g: int = GROUP.g
    h: int = PEDERSEN_H

    def commit(self, m: int, r: int | None = None) -> tuple[int, int]:
        """Return ``(C, r)`` committing to message ``m`` with randomness ``r``."""
        if r is None:
            r = GROUP.rand_scalar()
        c = GROUP.mul(GROUP.exp(self.g, m), GROUP.exp(self.h, r))
        return c, r

    def open(self, c: int, m: int, r: int) -> bool:
        expected = GROUP.mul(GROUP.exp(self.g, m), GROUP.exp(self.h, r))
        return c == expected

    def add(self, c1: int, c2: int) -> int:
        """Homomorphic add: commits to ``m1+m2`` with randomness ``r1+r2``."""
        return GROUP.mul(c1, c2)


PEDERSEN = Pedersen()


def hash_commit(*parts: bytes, r: bytes | None = None) -> tuple[bytes, bytes]:
    """Hash commitment ``H(parts || r)``; returns ``(commitment, r)``."""
    if r is None:
        r = secrets.token_bytes(32)
    h = hashlib.sha256()
    for p in parts:
        h.update(len(p).to_bytes(8, "big"))
        h.update(p)
    h.update(r)
    return h.digest(), r


def hash_open(commitment: bytes, *parts: bytes, r: bytes) -> bool:
    expected, _ = hash_commit(*parts, r=r)
    return commitment == expected
