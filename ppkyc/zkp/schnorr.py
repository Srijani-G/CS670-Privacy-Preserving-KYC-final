"""Schnorr proof of knowledge and Pedersen-opening proof.

Each sigma protocol ships in interactive and Fiat-Shamir form, with a
**simulator** (pick ``z, e`` then set ``a = g^z h^{-e}``) and an **extractor**
(recover the witness from two accepting transcripts that share the first message
``a`` but use different challenges).  Together these demonstrate completeness,
special soundness and special honest-verifier zero-knowledge (slides 18-22).

Schnorr statement:   know ``w`` with ``h = g^w``.
    a = g^r ;  challenge e ;  z = r + e*w mod q ;  verify  g^z == a * h^e

Pedersen opening:   know ``(m, s)`` with ``C = g^m h^s``.
    two-witness variant with responses ``z_m, z_s``.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..crypto.group import GROUP
from ..crypto.commit import PEDERSEN
from ..crypto.fiat_shamir import Transcript


# --------------------------------------------------------------------------
# Schnorr: know w s.t. h = g^w
# --------------------------------------------------------------------------
@dataclass
class SchnorrProof:
    a: int
    z: int
    e: int | None = None  # bound for the non-interactive form


def schnorr_commit(w: int) -> tuple[int, int]:
    """First message: pick nonce r, send a = g^r. Returns (r, a)."""
    r = GROUP.rand_scalar()
    return r, GROUP.exp(GROUP.g, r)


def schnorr_respond(r: int, w: int, e: int) -> int:
    return (r + e * w) % GROUP.q


def schnorr_verify(h: int, a: int, e: int, z: int) -> bool:
    if not GROUP.is_member(h) or not GROUP.is_member(a):
        return False
    return GROUP.exp(GROUP.g, z) == GROUP.mul(a, GROUP.exp(h, e))


def schnorr_prove_fs(w: int, h: int, domain: str = "schnorr") -> SchnorrProof:
    r, a = schnorr_commit(w)
    t = Transcript(domain).append_group("h", h).append_group("a", a)
    e = t.challenge()
    z = schnorr_respond(r, w, e)
    return SchnorrProof(a=a, z=z, e=e)


def schnorr_verify_fs(h: int, proof: SchnorrProof, domain: str = "schnorr") -> bool:
    if not GROUP.is_member(h) or not GROUP.is_member(proof.a):
        return False
    t = Transcript(domain).append_group("h", h).append_group("a", proof.a)
    e = t.challenge()
    if proof.e is not None and proof.e != e:
        return False
    return schnorr_verify(h, proof.a, e, proof.z)


def schnorr_simulate(h: int, e: int | None = None) -> SchnorrProof:
    """SHVZK simulator: pick z, e, set a = g^z * h^{-e} (no witness used)."""
    if e is None:
        e = GROUP.rand_scalar()
    z = GROUP.rand_scalar()
    a = GROUP.mul(GROUP.exp(GROUP.g, z), GROUP.exp(h, (-e) % GROUP.q))
    return SchnorrProof(a=a, z=z, e=e)


def schnorr_extract(a: int, e1: int, z1: int, e2: int, z2: int) -> int:
    """Special-soundness extractor: w = (z1 - z2)/(e1 - e2) mod q.

    This is the nonce-reuse pitfall turned into a tool: two accepting transcripts that reuse
    the nonce ``r`` (same ``a``) reveal the secret key.
    """
    assert e1 != e2, "challenges must differ"
    num = (z1 - z2) % GROUP.q
    den = pow((e1 - e2) % GROUP.q, GROUP.q - 2, GROUP.q)
    return (num * den) % GROUP.q


# --------------------------------------------------------------------------
# Pedersen opening: know (m, s) s.t. C = g^m h^s
# --------------------------------------------------------------------------
@dataclass
class OpeningProof:
    a: int
    zm: int
    zs: int
    e: int | None = None


def opening_prove_fs(m: int, s: int, C: int, domain: str = "pedersen-open") -> OpeningProof:
    rm = GROUP.rand_scalar()
    rs = GROUP.rand_scalar()
    a = GROUP.mul(GROUP.exp(PEDERSEN.g, rm), GROUP.exp(PEDERSEN.h, rs))
    t = Transcript(domain).append_group("C", C).append_group("a", a)
    e = t.challenge()
    zm = (rm + e * m) % GROUP.q
    zs = (rs + e * s) % GROUP.q
    return OpeningProof(a=a, zm=zm, zs=zs, e=e)


def opening_verify_fs(C: int, proof: OpeningProof, domain: str = "pedersen-open") -> bool:
    if not GROUP.is_member(C) or not GROUP.is_member(proof.a):
        return False
    t = Transcript(domain).append_group("C", C).append_group("a", proof.a)
    e = t.challenge()
    if proof.e is not None and proof.e != e:
        return False
    lhs = GROUP.mul(GROUP.exp(PEDERSEN.g, proof.zm), GROUP.exp(PEDERSEN.h, proof.zs))
    rhs = GROUP.mul(proof.a, GROUP.exp(C, e))
    return lhs == rhs


def opening_simulate(C: int, e: int | None = None) -> OpeningProof:
    if e is None:
        e = GROUP.rand_scalar()
    zm = GROUP.rand_scalar()
    zs = GROUP.rand_scalar()
    # a = g^zm h^zs C^{-e}
    a = GROUP.mul(
        GROUP.mul(GROUP.exp(PEDERSEN.g, zm), GROUP.exp(PEDERSEN.h, zs)),
        GROUP.exp(C, (-e) % GROUP.q),
    )
    return OpeningProof(a=a, zm=zm, zs=zs, e=e)
