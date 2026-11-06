"""Schnorr group (prime-order subgroup of Z_p^*).

The whole project works in a multiplicative group modulo a prime ``p`` whose
order is a large prime ``q`` (``q | p-1``).  This matches how the course slides
analyse the sigma protocols (exponentiation modulo a prime, slide "group theory
refresher").  Every verifier is expected to call :meth:`Group.is_member` on
every received element -- skipping that check can leak secret bits via small
subgroups.

The constants below are a freshly generated 2048-bit ``p`` with a 256-bit prime
subgroup order ``q`` (same shape as RFC 5114 group 2.3).  They were produced and
verified with Miller-Rabin so that ``pow(g, q, p) == 1`` and both ``p`` and ``q``
are prime; a module-level self check re-verifies the subgroup relation on import.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Group parameters (2048-bit p, 256-bit q).  Generated once and embedded so the
# library needs no multi-second prime search at import time.
# ---------------------------------------------------------------------------
_P = int(
    "8b611bff139bdc66b59342a7ad26b770feae17e22bd0e5b9ac1285cf181dc90a"
    "2890ad6ab2010ca7052f0a99ddd614f959cf95249cf6c1f5fec9fee355ed0302"
    "b2571d20113fc175483d84f4885262d52611d766d69929eabec375e279186295"
    "d0c8232b74f91bb0f1f3fe80ad100c913f2403f35e2cc94047adc6b7f064d2e80"
    "8222610f428c57b9845864feebca43a920c78706378086415de3ef5ee75d95f5b"
    "e5571eb39ffbd09b5499d48f05ab6f8d6f4b5ce50dc0a7a5a23d93da5be495da5"
    "d99f8c26f38b467f76808a51eaa2fecaef9d4a70e56bb7f1a4b76c31007bf8445"
    "4e9d82612bb34cabe0eed521670e10ac512c507b88d9e771703c7151311d",
    16,
)
_Q = int(
    "fae40ee8731022abfb51812789e03922bf6e1df0fa447c837e35378c91aafdd1", 16
)
_G = int(
    "70b0001d5c705cdf1d5e7b1bab5bb8d7398cdfc2929e535850c740a739ccd9e7"
    "4b2bcd5968f340b8df4e813feef5948a67d7a46c152f3e1c53f60f615e32bb260"
    "716e984a325b13c1b4d63c03f6ec36481f3acbd7f7836cd1bb9b8db6e307b2b7f"
    "d7fff254c5870a73aa48e5fb97ae65d65db07f25dabe346d88f8ece0ebb4f4c9e"
    "260ab8c5abf56c4bdbc218b19ca16f867e2b22ff35ab949d665436eb733306015"
    "cf0870a74ddd4855937810093d6ba92b4aeaa5c1af8dacf36e52b45bc51b55c35"
    "d6e40a8464d779cb50e4809cd7aa854811a6915525c57912291bf8f602266a0c7"
    "01fe6c4d481e87fb1895d6f993219832256aba8cd49f4e99bb5808c47b",
    16,
)


class GroupError(ValueError):
    """Raised when an element fails the subgroup-membership check."""


@dataclass(frozen=True)
class Group:
    """A Schnorr group with generator ``g`` of prime order ``q`` modulo ``p``.

    All arithmetic is plain Python big-integer modular arithmetic.  Elements are
    ``int`` in the range ``[1, p)``; scalars (exponents) live in ``Z_q``.
    """

    p: int = _P
    q: int = _Q
    g: int = _G

    # -- scalar helpers ----------------------------------------------------
    def rand_scalar(self) -> int:
        """Uniform non-zero scalar in ``Z_q`` (an exponent / witness)."""
        return 1 + secrets.randbelow(self.q - 1)

    def rand_element(self) -> int:
        """Uniform element of the order-``q`` subgroup."""
        return self.exp(self.g, self.rand_scalar())

    # -- group operations --------------------------------------------------
    def exp(self, base: int, e: int) -> int:
        return pow(base, e % self.q, self.p)

    def mul(self, a: int, b: int) -> int:
        return (a * b) % self.p

    def inv(self, a: int) -> int:
        return pow(a, self.p - 2, self.p)

    def div(self, a: int, b: int) -> int:
        return self.mul(a, self.inv(b))

    # -- membership (small-subgroup defence) -------------------------------
    def is_member(self, h: int) -> bool:
        """True iff ``h`` is a genuine element of the order-``q`` subgroup.

        Requires ``1 < h < p`` and ``h^q == 1 (mod p)``.  Every verifier calls
        this on every received group element; skipping it (invalid-group input)
        can leak secret bits via small subgroups.
        """
        if not (1 < h < self.p):
            return False
        return pow(h, self.q, self.p) == 1

    def check_member(self, h: int, what: str = "element") -> int:
        if not self.is_member(h):
            raise GroupError(f"{what} is not in the order-q subgroup")
        return h

    # -- hashing into the group -------------------------------------------
    def hash_to_group(self, *parts: bytes) -> int:
        """Deterministically hash bytes to a subgroup element.

        Expand with SHA-256 to roughly the length of ``p``, reduce mod ``p``,
        then raise to the cofactor ``(p-1)/q`` to land in the order-``q``
        subgroup (reject the identity).  Using a genuine hash-*to-group* -- as
        opposed to hashing identifiers to plain integers -- is what blocks the
        ratio-leak in DH-PSI.
        """
        cofactor = (self.p - 1) // self.q
        nbytes = (self.p.bit_length() + 7) // 8
        counter = 0
        while True:
            buf = b""
            i = 0
            seed = b"\x00".join(parts) + b"|" + counter.to_bytes(4, "big")
            while len(buf) < nbytes + 16:
                buf += hashlib.sha256(seed + i.to_bytes(4, "big")).digest()
                i += 1
            x = int.from_bytes(buf[: nbytes + 16], "big") % self.p
            if x <= 1:
                counter += 1
                continue
            h = pow(x, cofactor, self.p)
            if h > 1:
                return h
            counter += 1


# A single shared group instance for the whole library.
GROUP = Group()

# Second Pedersen generator: nobody knows log_g(H) because it comes from a hash.
PEDERSEN_H = GROUP.hash_to_group(b"ppkyc-pedersen-h")

# Import-time self check: catch any corrupted constant immediately.
assert pow(GROUP.g, GROUP.q, GROUP.p) == 1, "generator is not of order q"
assert GROUP.is_member(PEDERSEN_H), "Pedersen H not in subgroup"
