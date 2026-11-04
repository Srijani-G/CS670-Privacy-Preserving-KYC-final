"""DLEQ (Chaum-Pedersen): equality of two discrete logs.

Statement: know ``w`` such that ``A = g^w`` and ``B = u^w`` for public bases
``g, u``.  Used for the **scoped nullifier**: the nullifier is ``nu = H2G(rp)^sk``
and a DLEQ proof ties the ``sk`` committed inside ``C_sk`` to the exponent of
``nu``, so the same user at the same RP always yields the same ``nu`` (sybil
resistance), while different RPs get unlinkable nullifiers under DDH.

    a1 = g^r ; a2 = u^r ; e = H(...) ; z = r + e*w
    verify  g^z == a1 * A^e   and   u^z == a2 * B^e
"""

from __future__ import annotations

from dataclasses import dataclass

from ..crypto.group import GROUP
from ..crypto.fiat_shamir import Transcript


@dataclass
class DLEQProof:
    a1: int
    a2: int
    z: int
    e: int | None = None


def dleq_prove_fs(w: int, g: int, u: int, A: int, B: int,
                  domain: str = "dleq") -> DLEQProof:
    r = GROUP.rand_scalar()
    a1 = GROUP.exp(g, r)
    a2 = GROUP.exp(u, r)
    t = (Transcript(domain)
         .append_group("g", g).append_group("u", u)
         .append_group("A", A).append_group("B", B)
         .append_group("a1", a1).append_group("a2", a2))
    e = t.challenge()
    z = (r + e * w) % GROUP.q
    return DLEQProof(a1=a1, a2=a2, z=z, e=e)


def dleq_verify_fs(g: int, u: int, A: int, B: int, proof: DLEQProof,
                   domain: str = "dleq") -> bool:
    for elem in (g, u, A, B, proof.a1, proof.a2):
        if not GROUP.is_member(elem):
            return False
    t = (Transcript(domain)
         .append_group("g", g).append_group("u", u)
         .append_group("A", A).append_group("B", B)
         .append_group("a1", proof.a1).append_group("a2", proof.a2))
    e = t.challenge()
    if proof.e is not None and proof.e != e:
        return False
    ok1 = GROUP.exp(g, proof.z) == GROUP.mul(proof.a1, GROUP.exp(A, e))
    ok2 = GROUP.exp(u, proof.z) == GROUP.mul(proof.a2, GROUP.exp(B, e))
    return ok1 and ok2


def dleq_simulate(g: int, u: int, A: int, B: int, e: int | None = None) -> DLEQProof:
    if e is None:
        e = GROUP.rand_scalar()
    z = GROUP.rand_scalar()
    a1 = GROUP.mul(GROUP.exp(g, z), GROUP.exp(A, (-e) % GROUP.q))
    a2 = GROUP.mul(GROUP.exp(u, z), GROUP.exp(B, (-e) % GROUP.q))
    return DLEQProof(a1=a1, a2=a2, z=z, e=e)
