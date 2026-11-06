"""Verifiable KYC credentials (Module D), built only from sigma + Fiat-Shamir.

Issuance
--------
After offline verification the wallet picks a secret key ``sk`` and commits to
every attribute, including ``sk`` itself: ``C_sk, C_dob, C_nat, C_level``.  The
issuer learns the attribute values (it did the KYC) but **not** ``sk`` -- the
wallet proves knowledge of the ``C_sk`` opening in zero knowledge.  The issuer
then produces a plain Schnorr signature over
``H(commitments || expiry || issuer_id)``.

Presentation
------------
The RP sends ``(rp_id, nonce, timestamp, predicates)``.  The wallet returns the
credential and a single combined proof under **one** challenge

    e = H( params || ctx || commitments || signature || all first-messages )

covering:

* ``age >= min_age``  -- range proof on ``g^{cutoff} C_dob^{-1}``;
* ``kyc_level >= min_level`` -- range proof on ``C_level g^{-min_level}``;
* ``nationality in allowed_set`` -- OR-proof over the set;
* scoped nullifier ``nu = H2G(rp_id)^sk`` with a DLEQ-style proof tying ``sk``
  inside ``C_sk`` to the exponent of ``nu``.

Binding the proof to ``(rp_id, nonce, timestamp)`` defeats replay (attack #5);
tying ``sk`` inside ``C_sk`` gives holder binding (attack #6); the nullifier
gives per-RP sybil resistance (attack #7) while staying unlinkable across RPs.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field

from ..crypto.group import GROUP
from ..crypto.commit import PEDERSEN
from ..crypto.fiat_shamir import Transcript
from .schnorr import opening_prove_fs, opening_verify_fs, OpeningProof
from .orproof import ORProof, ORCommitState, or_commit, or_respond, or_check
from . import range as rng

AGE_BITS = 24   # covers date-difference values (YYYYMMDD) up to ~16M
LEVEL_BITS = 4  # kyc level difference 0..15


# --------------------------------------------------------------------------
# Issuer: Schnorr signature keypair
# --------------------------------------------------------------------------
@dataclass
class Signature:
    R: int
    s: int


@dataclass
class Issuer:
    issuer_id: str
    isk: int = field(default_factory=lambda: GROUP.rand_scalar())

    @property
    def ipk(self) -> int:
        return GROUP.exp(GROUP.g, self.isk)

    def sign(self, msg: bytes) -> Signature:
        k = GROUP.rand_scalar()
        R = GROUP.exp(GROUP.g, k)
        e = _sig_challenge(R, self.ipk, msg)
        s = (k + e * self.isk) % GROUP.q
        return Signature(R=R, s=s)


def _sig_challenge(R: int, ipk: int, msg: bytes) -> int:
    t = Transcript("schnorr-sig").append_group("R", R).append_group("ipk", ipk)
    t.append_bytes("msg", msg)
    return t.challenge()


def signature_verify(ipk: int, msg: bytes, sig: Signature) -> bool:
    if not GROUP.is_member(ipk) or not GROUP.is_member(sig.R):
        return False
    e = _sig_challenge(sig.R, ipk, msg)
    return GROUP.exp(GROUP.g, sig.s) == GROUP.mul(sig.R, GROUP.exp(ipk, e))


# --------------------------------------------------------------------------
# Credential
# --------------------------------------------------------------------------
@dataclass
class Credential:
    C_sk: int
    C_dob: int
    C_nat: int
    C_level: int
    expiry: int          # YYYYMMDD
    issuer_id: str
    signature: Signature


def _credential_msg(C_sk, C_dob, C_nat, C_level, expiry, issuer_id) -> bytes:
    h = hashlib.sha256()
    for c in (C_sk, C_dob, C_nat, C_level):
        b = c.to_bytes(256, "big")
        h.update(b)
    h.update(expiry.to_bytes(8, "big"))
    h.update(issuer_id.encode())
    return h.digest()


# --------------------------------------------------------------------------
# Wallet
# --------------------------------------------------------------------------
@dataclass
class Wallet:
    """Holds the attribute secrets; attributes never leave the wallet."""

    dob: int            # date of birth as YYYYMMDD
    nationality: int    # numeric country code
    kyc_level: int
    sk: int = field(default_factory=lambda: GROUP.rand_scalar())
    r_sk: int = field(default_factory=lambda: GROUP.rand_scalar())
    r_dob: int = field(default_factory=lambda: GROUP.rand_scalar())
    r_nat: int = field(default_factory=lambda: GROUP.rand_scalar())
    r_level: int = field(default_factory=lambda: GROUP.rand_scalar())
    credential: Credential | None = None

    # commitments -----------------------------------------------------------
    def commitments(self) -> dict:
        C_sk, _ = PEDERSEN.commit(self.sk, self.r_sk)
        C_dob, _ = PEDERSEN.commit(self.dob, self.r_dob)
        C_nat, _ = PEDERSEN.commit(self.nationality, self.r_nat)
        C_level, _ = PEDERSEN.commit(self.kyc_level, self.r_level)
        return {"C_sk": C_sk, "C_dob": C_dob, "C_nat": C_nat, "C_level": C_level}

    # issuance request ------------------------------------------------------
    def issuance_request(self) -> dict:
        """What the wallet sends the issuer: commitments, revealed attribute
        openings (the issuer already knows these values from offline KYC), and a
        ZK opening proof for ``C_sk`` so the issuer never learns ``sk``."""
        c = self.commitments()
        sk_proof = opening_prove_fs(self.sk, self.r_sk, c["C_sk"],
                                    domain="issue-sk")
        return {
            "commitments": c,
            "openings": {
                "dob": (self.dob, self.r_dob),
                "nat": (self.nationality, self.r_nat),
                "level": (self.kyc_level, self.r_level),
            },
            "sk_proof": sk_proof,
        }

    def store_credential(self, cred: Credential) -> None:
        self.credential = cred


def issue(issuer: Issuer, request: dict, expiry: int,
          expected: dict | None = None) -> Credential:
    """Issuer side: verify the openings, then sign the commitments.

    ``expected`` optionally pins the attribute values the issuer verified
    offline (dob/nat/level); the openings must match them.
    """
    c = request["commitments"]
    op = request["openings"]
    # check revealed openings
    for key, cname in (("dob", "C_dob"), ("nat", "C_nat"), ("level", "C_level")):
        val, r = op[key]
        if not PEDERSEN.open(c[cname], val, r):
            raise ValueError(f"opening for {key} does not match commitment")
        if expected is not None and expected.get(key) is not None and expected[key] != val:
            raise ValueError(f"attribute {key} does not match offline KYC record")
    # check sk opening proof (zero knowledge; issuer never sees sk)
    if not opening_verify_fs(c["C_sk"], request["sk_proof"], domain="issue-sk"):
        raise ValueError("C_sk opening proof invalid")
    msg = _credential_msg(c["C_sk"], c["C_dob"], c["C_nat"], c["C_level"],
                          expiry, issuer.issuer_id)
    sig = issuer.sign(msg)
    return Credential(c["C_sk"], c["C_dob"], c["C_nat"], c["C_level"],
                      expiry, issuer.issuer_id, sig)


# --------------------------------------------------------------------------
# Presentation
# --------------------------------------------------------------------------
@dataclass
class Predicates:
    min_age: int | None = None
    allowed_nats: list[int] | None = None
    min_level: int | None = None


@dataclass
class PresentationRequest:
    rp_id: str
    nonce: bytes
    timestamp: int
    today: int               # YYYYMMDD, used for the age cutoff
    predicates: Predicates


@dataclass
class NullifierProof:
    nu: int
    a1: int
    a2: int
    z_sk: int
    z_s: int


@dataclass
class Presentation:
    credential: Credential
    age_proof: rng.RangeProof | None
    level_proof: rng.RangeProof | None
    nat_proof: ORProof | None
    nullifier: NullifierProof
    challenge: int


def _cutoff(today: int, min_age: int) -> int:
    """YYYYMMDD cutoff: born on/before this date => age >= min_age."""
    year = today // 10000
    rest = today % 10000
    return (year - min_age) * 10000 + rest


def _ctx_bytes(req: PresentationRequest) -> bytes:
    return (req.rp_id.encode() + b"|" + req.nonce + b"|"
            + req.timestamp.to_bytes(8, "big") + b"|"
            + req.today.to_bytes(8, "big"))


def _presentation_transcript(cred: Credential, req: PresentationRequest,
                             first_msgs: list[int]) -> Transcript:
    t = Transcript("kyc-presentation")
    t.append_context(req.rp_id, req.nonce, req.timestamp)
    t.append_int("today", req.today)
    for name, c in (("C_sk", cred.C_sk), ("C_dob", cred.C_dob),
                    ("C_nat", cred.C_nat), ("C_level", cred.C_level)):
        t.append_group(name, c)
    t.append_group("sigR", cred.signature.R)
    t.append_int("sigs", cred.signature.s)
    for m in first_msgs:
        t.append_group("fm", m)
    return t


def present(wallet: Wallet, req: PresentationRequest) -> Presentation:
    cred = wallet.credential
    if cred is None:
        raise ValueError("wallet has no credential")
    preds = req.predicates
    u = GROUP.hash_to_group(b"nullifier-scope|" + req.rp_id.encode())

    # ---- commit phase: build every first message -------------------------
    first_msgs: list[int] = []

    age_state = None
    if preds.min_age is not None:
        cutoff = _cutoff(req.today, preds.min_age)
        v = cutoff - wallet.dob
        if v < 0:
            raise ValueError("wallet does not satisfy age predicate")
        # C_v = g^cutoff C_dob^{-1} commits to (cutoff - dob) with rand -r_dob
        age_state = rng.range_commit(v, (-wallet.r_dob) % GROUP.q, AGE_BITS)
        first_msgs.extend(rng.range_first_messages(age_state))

    level_state = None
    if preds.min_level is not None:
        v = wallet.kyc_level - preds.min_level
        if v < 0:
            raise ValueError("wallet does not satisfy level predicate")
        level_state = rng.range_commit(v, wallet.r_level, LEVEL_BITS)
        first_msgs.extend(rng.range_first_messages(level_state))

    nat_state: ORCommitState | None = None
    if preds.allowed_nats is not None:
        if wallet.nationality not in preds.allowed_nats:
            raise ValueError("wallet does not satisfy nationality predicate")
        bases = [PEDERSEN.h] * len(preds.allowed_nats)
        targets = [GROUP.div(cred.C_nat, GROUP.exp(GROUP.g, a % GROUP.q))
                   for a in preds.allowed_nats]
        true_idx = preds.allowed_nats.index(wallet.nationality)
        nat_state = or_commit(bases, targets, true_idx, wallet.r_nat)
        first_msgs.extend(nat_state.a)

    # nullifier commit
    nu = GROUP.exp(u, wallet.sk)
    t_sk = GROUP.rand_scalar()
    t_s = GROUP.rand_scalar()
    a1 = GROUP.mul(GROUP.exp(GROUP.g, t_sk), GROUP.exp(PEDERSEN.h, t_s))
    a2 = GROUP.exp(u, t_sk)
    first_msgs.extend([nu, a1, a2])

    # ---- single challenge ------------------------------------------------
    e = _presentation_transcript(cred, req, first_msgs).challenge()

    # ---- respond phase ---------------------------------------------------
    age_proof = rng.range_respond(age_state, e) if age_state else None
    level_proof = rng.range_respond(level_state, e) if level_state else None
    nat_proof = or_respond(nat_state, e) if nat_state else None
    z_sk = (t_sk + e * wallet.sk) % GROUP.q
    z_s = (t_s + e * wallet.r_sk) % GROUP.q
    nullifier = NullifierProof(nu=nu, a1=a1, a2=a2, z_sk=z_sk, z_s=z_s)

    return Presentation(cred, age_proof, level_proof, nat_proof, nullifier, e)


# --------------------------------------------------------------------------
# Verifier (Relying Party)
# --------------------------------------------------------------------------
def verify_presentation(pres: Presentation, req: PresentationRequest,
                        issuer_pk: int) -> bool:
    cred = pres.credential
    preds = req.predicates

    # 0. credential signature under the *pinned* issuer key (attack #: rogue issuer)
    for elem in (cred.C_sk, cred.C_dob, cred.C_nat, cred.C_level):
        if not GROUP.is_member(elem):
            return False
    msg = _credential_msg(cred.C_sk, cred.C_dob, cred.C_nat, cred.C_level,
                          cred.expiry, cred.issuer_id)
    if not signature_verify(issuer_pk, msg, cred.signature):
        return False
    if cred.expiry < req.today:
        return False  # expired

    u = GROUP.hash_to_group(b"nullifier-scope|" + req.rp_id.encode())

    # 1. rebuild first messages from the proof (same order as the prover)
    first_msgs: list[int] = []
    if preds.min_age is not None:
        if pres.age_proof is None:
            return False
        first_msgs.extend(list(pres.age_proof.bit_commitments))
        for bp in pres.age_proof.bit_proofs:
            first_msgs.extend(bp.a)
    if preds.min_level is not None:
        if pres.level_proof is None:
            return False
        first_msgs.extend(list(pres.level_proof.bit_commitments))
        for bp in pres.level_proof.bit_proofs:
            first_msgs.extend(bp.a)
    if preds.allowed_nats is not None:
        if pres.nat_proof is None:
            return False
        first_msgs.extend(pres.nat_proof.a)
    first_msgs.extend([pres.nullifier.nu, pres.nullifier.a1, pres.nullifier.a2])

    # 2. recompute the single challenge and bind it (defeats replay)
    e = _presentation_transcript(cred, req, first_msgs).challenge()
    if e != pres.challenge:
        return False

    # 3. age predicate
    if preds.min_age is not None:
        cutoff = _cutoff(req.today, preds.min_age)
        C_v = rng.le_commitment(cred.C_dob, cutoff)
        if not rng.range_check(C_v, pres.age_proof, e):
            return False
    # 4. level predicate
    if preds.min_level is not None:
        C_v = rng.ge_commitment(cred.C_level, preds.min_level)
        if not rng.range_check(C_v, pres.level_proof, e):
            return False
    # 5. nationality predicate
    if preds.allowed_nats is not None:
        bases = [PEDERSEN.h] * len(preds.allowed_nats)
        targets = [GROUP.div(cred.C_nat, GROUP.exp(GROUP.g, a % GROUP.q))
                   for a in preds.allowed_nats]
        if not or_check(bases, targets, pres.nat_proof, e):
            return False
    # 6. nullifier: sk inside C_sk is the exponent of nu
    nf = pres.nullifier
    if not GROUP.is_member(nf.nu):
        return False
    lhs1 = GROUP.mul(GROUP.exp(GROUP.g, nf.z_sk), GROUP.exp(PEDERSEN.h, nf.z_s))
    rhs1 = GROUP.mul(nf.a1, GROUP.exp(cred.C_sk, e))
    lhs2 = GROUP.exp(u, nf.z_sk)
    rhs2 = GROUP.mul(nf.a2, GROUP.exp(nf.nu, e))
    if lhs1 != rhs1 or lhs2 != rhs2:
        return False
    return True


class RelyingParty:
    """Stateful RP that pins an issuer key and rejects duplicate nullifiers."""

    def __init__(self, rp_id: str, issuer_pk: int):
        self.rp_id = rp_id
        self.issuer_pk = issuer_pk
        self.seen_nullifiers: set[int] = set()

    def verify(self, pres: Presentation, req: PresentationRequest,
               enforce_unique: bool = True) -> bool:
        if req.rp_id != self.rp_id:
            return False
        if not verify_presentation(pres, req, self.issuer_pk):
            return False
        nu = pres.nullifier.nu
        if enforce_unique and nu in self.seen_nullifiers:
            return False  # sybil / double presentation
        self.seen_nullifiers.add(nu)
        return True
