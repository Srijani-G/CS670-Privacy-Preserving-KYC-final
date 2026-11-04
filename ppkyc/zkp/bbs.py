"""BBS+ signatures over BLS12-381 (pairing-based anonymous credentials).

This module is the **stronger implementation** that fixes two Tier-1 limitations
of the sigma-only credential in :mod:`ppkyc.zkp.credential`:

* **#1 Multi-show unlinkability** -- a BBS+ signature is *re-randomised* on every
  presentation, so two showings of the same credential are unlinkable even to
  colluding verifiers (the sigma credential reused static commitments, which
  acted as a serial number).
* **#2 Blind issuance** -- the holder commits to its secret key ``sk`` and the
  issuer signs the *committed* message, so the issuer never learns ``sk`` and
  cannot link an issued credential to a later presentation.

Unlike the rest of the project, this needs a **bilinear pairing**, which is not
in the Python standard library; it uses ``py_ecc``'s pure-Python BLS12-381.
This is the one deliberate departure from the "no external crypto library" rule,
made to reach genuine multi-show unlinkability (CL / BBS+ in the literature
survey, section 3.1).  Correctness of every algebraic relation below was checked
empirically against the pairing before this module was written.

Scheme (type-3 pairing ``e: G1 x G2 -> GT``, prime order ``p``)
-----------------------------------------------------------------
Params:  ``g1`` in G1, ``g2`` in G2, and message generators ``h0, h1..hL`` in G1
whose discrete logs are unknown (derived by hash-to-curve).

Key:     ``x`` (secret) with public key ``w = x*g2`` in G2.

Sign(m1..mL):   pick ``e, s``; ``B = g1 + s*h0 + sum mi*hi``;  ``A = (1/(e+x))*B``;
                signature ``(A, e, s)``.
Verify:         ``e(A, w + e*g2) == e(B, g2)``.

Presentation is a Fiat-Shamir proof of knowledge of a signature that
re-randomises ``A`` and proves the hidden messages in zero knowledge, optionally
disclosing a subset, and binds a per-verifier **nullifier** ``nu = m1*U`` with
``U = hash_to_G1(rp_id)`` (consistent per RP for sybil detection, unlinkable
across RPs because ``U`` has an unknown discrete log).
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field

from py_ecc.optimized_bls12_381 import (
    G1, G2, multiply, add, neg, pairing, curve_order as P, Z1, eq, normalize,
)
from py_ecc.bls.hash_to_curve import hash_to_G1

_H2G1_DST = b"ppkyc-bbs-h2g1-v1"


# --------------------------------------------------------------------------
# scalar / group helpers (all scalars live in Z_p, p = curve order)
# --------------------------------------------------------------------------
def rand_scalar() -> int:
    """Uniform non-zero scalar in ``Z_p``."""
    return 1 + secrets.randbelow(P - 1)


def _inv(x: int) -> int:
    return pow(x % P, P - 2, P)


def _mul(pt, s: int):
    """Scalar multiplication ``s*pt`` in G1 (or G2)."""
    return multiply(pt, s % P)


def _sum(points):
    acc = Z1
    for pt in points:
        acc = add(acc, pt)
    return acc


def hash_to_g1(msg: bytes):
    """Hash bytes to a G1 point with unknown discrete log (for generators/nullifier)."""
    return hash_to_G1(msg, _H2G1_DST, hashlib.sha256)


def _ser(pt) -> bytes:
    """Canonical byte encoding of a G1 point (affine x || y), for transcripts."""
    x, y = normalize(pt)
    return x.n.to_bytes(48, "big") + y.n.to_bytes(48, "big")


# --------------------------------------------------------------------------
# parameters and keys
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class BBSParams:
    """Public parameters for an ``L``-message BBS+ signature."""

    L: int
    g1: object
    g2: object
    h0: object
    h: tuple  # length L: message generators h[i] for message i (0-indexed)

    @staticmethod
    def create(L: int) -> "BBSParams":
        h0 = hash_to_g1(b"h0")
        h = tuple(hash_to_g1(b"h%d" % (i + 1)) for i in range(L))
        return BBSParams(L=L, g1=G1, g2=G2, h0=h0, h=h)


@dataclass
class BBSKey:
    sk: int                      # x
    pk: object                   # w = x*g2 in G2

    @staticmethod
    def generate(params: BBSParams) -> "BBSKey":
        x = rand_scalar()
        return BBSKey(sk=x, pk=_mul(params.g2, x))


@dataclass
class Signature:
    A: object
    e: int
    s: int


# --------------------------------------------------------------------------
# plain sign / verify
# --------------------------------------------------------------------------
def _B(params: BBSParams, msgs: list[int], s: int):
    terms = [params.g1, _mul(params.h0, s)]
    terms += [_mul(params.h[i], msgs[i]) for i in range(params.L)]
    return _sum(terms)


def sign(params: BBSParams, key: BBSKey, msgs: list[int]) -> Signature:
    assert len(msgs) == params.L
    e, s = rand_scalar(), rand_scalar()
    B = _B(params, msgs, s)
    A = _mul(B, _inv((e + key.sk) % P))
    return Signature(A=A, e=e, s=s)


def verify(params: BBSParams, pk, msgs: list[int], sig: Signature) -> bool:
    if len(msgs) != params.L:
        return False
    B = _B(params, msgs, sig.s)
    lhs = pairing(add(pk, _mul(params.g2, sig.e)), sig.A)  # e(A, w + e*g2)
    rhs = pairing(params.g2, B)                            # e(B, g2)
    return lhs == rhs


# --------------------------------------------------------------------------
# blind issuance (fixes #2): issuer signs msg index 0 (sk) without learning it
# --------------------------------------------------------------------------
@dataclass
class BlindRequest:
    commitment: object          # C = sk*h[0] + s_user*h0
    # Schnorr PoK that the holder knows (sk, s_user) opening C
    challenge: int
    z_sk: int
    z_s: int


def blind_request(params: BBSParams, sk: int) -> tuple[BlindRequest, int]:
    """Holder side: commit to ``sk`` and prove knowledge of the opening.

    Returns ``(request, s_user)``; keep ``s_user`` to unblind the signature.
    """
    s_user = rand_scalar()
    C = add(_mul(params.h[0], sk), _mul(params.h0, s_user))
    # Schnorr PoK of (sk, s_user): T = a*h[0] + b*h0
    a, b = rand_scalar(), rand_scalar()
    T = add(_mul(params.h[0], a), _mul(params.h0, b))
    c = int.from_bytes(
        hashlib.sha256(b"blind|" + _ser(C) + _ser(T)).digest(), "big") % P
    z_sk = (a + c * sk) % P
    z_s = (b + c * s_user) % P
    return BlindRequest(commitment=C, challenge=c, z_sk=z_sk, z_s=z_s), s_user


def blind_request_valid(params: BBSParams, req: BlindRequest) -> bool:
    """Issuer side: check the holder really knows the committed opening."""
    # T == z_sk*h[0] + z_s*h0 - c*C
    T = add(add(_mul(params.h[0], req.z_sk), _mul(params.h0, req.z_s)),
            neg(_mul(req.commitment, req.challenge)))
    c = int.from_bytes(
        hashlib.sha256(b"blind|" + _ser(req.commitment) + _ser(T)).digest(),
        "big") % P
    return c == req.challenge


def blind_sign(params: BBSParams, key: BBSKey, req: BlindRequest,
               known_msgs: dict[int, int]) -> Signature:
    """Issuer side: sign the committed ``sk`` plus the attributes it verified.

    ``known_msgs`` maps message index (>=1) to the value the issuer learned at
    KYC time (e.g. dob, nationality, level).  Index 0 (sk) stays blinded in ``C``.
    """
    if not blind_request_valid(params, req):
        raise ValueError("blind-request opening proof invalid")
    e, s_iss = rand_scalar(), rand_scalar()
    terms = [params.g1, req.commitment, _mul(params.h0, s_iss)]
    terms += [_mul(params.h[i], known_msgs[i]) for i in range(1, params.L)]
    B = _sum(terms)
    A = _mul(B, _inv((e + key.sk) % P))
    return Signature(A=A, e=e, s=s_iss)


def unblind(sig: Signature, s_user: int) -> Signature:
    """Holder side: fold the user blinding into ``s`` to get the final signature."""
    return Signature(A=sig.A, e=sig.e, s=(sig.s + s_user) % P)


# --------------------------------------------------------------------------
# unlinkable presentation (fixes #1) with selective disclosure + nullifier
# --------------------------------------------------------------------------
@dataclass
class Presentation:
    Ap: object
    Abar: object
    d: object
    nu: object                  # nullifier nu = sk * U(rp_id)
    challenge: int
    z_e: int
    z_r2: int
    z_r3: int
    z_s: int
    z_m: dict                   # hidden message index -> response
    disclosed: dict             # disclosed index -> value


def _nullifier_base(rp_id: bytes):
    return hash_to_g1(b"null|" + rp_id)


def present(params: BBSParams, msgs: list[int], sig: Signature,
            disclose_idx: list[int], rp_id: bytes) -> Presentation:
    """Holder side: re-randomise the signature and prove it in zero knowledge.

    Hidden messages are proved without revealing them; ``disclose_idx`` lists the
    message indices to reveal.  A nullifier on message 0 (``sk``) is bound to
    ``rp_id`` for sybil detection.
    """
    A, e, s = sig.A, sig.e, sig.s
    B = _B(params, msgs, s)
    r1, r2 = rand_scalar(), rand_scalar()
    r3 = _inv(r1)
    Ap = _mul(A, r1)
    Abar = add(_mul(B, r1), neg(_mul(Ap, e)))      # = x*A'
    d = add(_mul(B, r1), neg(_mul(params.h0, r2)))
    s_pr = (s - r2 * r3) % P                        # s'
    U = _nullifier_base(rp_id)
    nu = _mul(U, msgs[0])
    hidden = [i for i in range(params.L) if i not in disclose_idx]

    # targets
    Y1 = add(Abar, neg(d))                          # = e*(-A') + r2*h0
    Y2 = add(params.g1, _sum([_mul(params.h[i], msgs[i]) for i in disclose_idx]))

    # blindings + commitments (Schnorr over shared witnesses; m[0] shared Y2/Y3)
    be, br2, br3, bs = (rand_scalar(), rand_scalar(), rand_scalar(), rand_scalar())
    bm = {i: rand_scalar() for i in hidden}
    T1 = add(_mul(neg(Ap), be), _mul(params.h0, br2))
    T2 = add(_mul(d, br3), add(_mul(neg(params.h0), bs),
             _sum([_mul(neg(params.h[i]), bm[i]) for i in hidden])))
    T3 = _mul(U, bm[0]) if 0 in hidden else Z1

    c = _challenge(Ap, Abar, d, nu, U, Y1, Y2, T1, T2, T3)
    z_e = (be + c * e) % P
    z_r2 = (br2 + c * r2) % P
    z_r3 = (br3 + c * r3) % P
    z_s = (bs + c * s_pr) % P
    z_m = {i: (bm[i] + c * msgs[i]) % P for i in hidden}
    disclosed = {i: msgs[i] for i in disclose_idx}
    return Presentation(Ap=Ap, Abar=Abar, d=d, nu=nu, challenge=c, z_e=z_e,
                        z_r2=z_r2, z_r3=z_r3, z_s=z_s, z_m=z_m, disclosed=disclosed)


def _challenge(Ap, Abar, d, nu, U, Y1, Y2, T1, T2, T3) -> int:
    blob = b"".join(_ser(pt) for pt in (Ap, Abar, d, nu, U, Y1, Y2, T1, T2, T3))
    return int.from_bytes(hashlib.sha256(blob).digest(), "big") % P


def verify_present(params: BBSParams, pk, pres: Presentation,
                   rp_id: bytes) -> bool:
    """Verifier side: check the presentation proof and the signature relation."""
    Ap, Abar, d, nu = pres.Ap, pres.Abar, pres.d, pres.nu
    if eq(Ap, Z1):
        return False
    # signature relation: e(A', w) == e(Abar, g2)  (proves Abar = x*A')
    if pairing(pk, Ap) != pairing(params.g2, Abar):
        return False
    U = _nullifier_base(rp_id)
    hidden = list(pres.z_m.keys())
    Y1 = add(Abar, neg(d))
    Y2 = add(params.g1,
             _sum([_mul(params.h[i], v) for i, v in pres.disclosed.items()]))
    c = pres.challenge
    # recompute commitments:  T == sum(z*base) - c*Y
    T1 = add(add(_mul(neg(Ap), pres.z_e), _mul(params.h0, pres.z_r2)),
             neg(_mul(Y1, c)))
    T2 = add(add(_mul(d, pres.z_r3),
                 add(_mul(neg(params.h0), pres.z_s),
                     _sum([_mul(neg(params.h[i]), pres.z_m[i]) for i in hidden]))),
             neg(_mul(Y2, c)))
    T3 = add(_mul(U, pres.z_m[0]), neg(_mul(nu, c))) if 0 in hidden else Z1
    return _challenge(Ap, Abar, d, nu, U, Y1, Y2, T1, T2, T3) == c
