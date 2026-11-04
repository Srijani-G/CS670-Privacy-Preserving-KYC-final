"""Secure dot product ``<w, x>`` on additive shares (Module B scoring).

The Regulator's model weights ``w`` and the (combined) feature vector ``x`` are
additively shared between ``S0`` and ``S1``.  Each coordinate product uses one
Beaver triple; the sums are local.  The result is an additive sharing of the
risk score, which is then fed to the garbled-circuit threshold comparison.
"""

from __future__ import annotations

from .beaver import Triple, beaver_mul


def secure_dotprod(w_shares: list[tuple[int, int]],
                   x_shares: list[tuple[int, int]],
                   bits: int = 32, channel=None) -> tuple[int, int]:
    """Return additive shares of ``sum_i w_i * x_i`` over ``Z_{2^bits}``."""
    assert len(w_shares) == len(x_shares)
    mod = 1 << bits
    acc0, acc1 = 0, 0
    for wi, xi in zip(w_shares, x_shares):
        triple = Triple(bits)  # one offline triple per multiplication
        z0, z1 = beaver_mul(wi, xi, triple, bits, channel)
        acc0 = (acc0 + z0) % mod
        acc1 = (acc1 + z1) % mod
    return acc0, acc1


def share_value(value: int, bits: int = 32) -> tuple[int, int]:
    """Additively split a value between S0 and S1."""
    import secrets
    mod = 1 << bits
    s0 = secrets.randbelow(mod)
    return s0, (value - s0) % mod
