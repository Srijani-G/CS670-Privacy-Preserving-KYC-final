"""KYC credentials on BBS+ (the unlinkable, blindly-issued upgrade).

This is the Module-D credential flow rebuilt on :mod:`ppkyc.zkp.bbs` to fix the
two Tier-1 limitations of the sigma credential in :mod:`ppkyc.zkp.credential`:

* **#1 multi-show unlinkability** -- each presentation re-randomises the
  signature, so two showings cannot be linked (the sigma credential leaked a
  static serial number);
* **#2 blind issuance** -- the issuer signs a commitment to ``sk`` and never
  learns it, so it cannot link issuance to any later presentation.

It keeps the sybil-resistant **per-RP nullifier** (``nu = sk * U(rp_id)``) and
adds **selective disclosure** of chosen attributes.

Scope note (honest): this module delivers the unlinkability + blind-issuance
fix.  *Threshold predicates* ("age >= 18", "level >= 2") over hidden attributes
need range proofs in the pairing group -- that is a separate limitation
(Bulletproofs, issue #5) and is **not** solved here; the demo discloses the
attributes an RP checks directly.  The original :mod:`ppkyc.zkp.credential`
still provides the range/OR predicate privacy, at the cost of linkability.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import bbs

# message layout (indices into the BBS+ message vector)
SK, DOB, NAT, LEVEL = 0, 1, 2, 3
N_MESSAGES = 4

# one shared parameter set for the whole KYC deployment
PARAMS = bbs.BBSParams.create(N_MESSAGES)


@dataclass
class Issuer:
    issuer_id: str
    key: bbs.BBSKey = field(default_factory=lambda: bbs.BBSKey.generate(PARAMS))

    @property
    def pk(self):
        return self.key.pk


@dataclass
class Credential:
    """The BBS+ signature over (sk, dob, nat, level); attributes stay in wallet."""
    signature: bbs.Signature
    issuer_id: str


@dataclass
class Wallet:
    dob: int
    nationality: int
    kyc_level: int
    sk: int = field(default_factory=bbs.rand_scalar)
    credential: Credential | None = None

    def _msgs(self) -> list[int]:
        return [self.sk, self.dob, self.nationality, self.kyc_level]

    # -- issuance (blind in sk) -------------------------------------------
    def issuance_request(self):
        """Commit to ``sk`` (blinded) with a proof of knowledge of the opening.

        Returns ``(request, secret_blinding)``; the issuer learns dob/nat/level
        (it did the KYC) but never ``sk``.
        """
        return bbs.blind_request(PARAMS, self.sk)

    def store(self, cred: Credential) -> None:
        self.credential = cred


def issue(issuer: Issuer, wallet: Wallet, expected: dict | None = None) -> Credential:
    """Issuer side: blind-sign the committed ``sk`` plus the verified attributes.

    ``expected`` optionally pins the dob/nat/level the issuer verified offline.
    """
    req, s_user = wallet.issuance_request()
    known = {DOB: wallet.dob, NAT: wallet.nationality, LEVEL: wallet.kyc_level}
    if expected is not None:
        for name, idx in (("dob", DOB), ("nat", NAT), ("level", LEVEL)):
            if expected.get(name) is not None and expected[name] != known[idx]:
                raise ValueError(f"attribute {name} does not match offline KYC record")
    blinded = bbs.blind_sign(PARAMS, issuer.key, req, known)
    full = bbs.unblind(blinded, s_user)
    cred = Credential(signature=full, issuer_id=issuer.issuer_id)
    wallet.store(cred)
    return cred


@dataclass
class PresentationRequest:
    rp_id: str
    disclose: tuple = ()   # attribute indices to reveal (e.g. (NAT,))


def present(wallet: Wallet, req: PresentationRequest) -> bbs.Presentation:
    if wallet.credential is None:
        raise ValueError("wallet has no credential")
    return bbs.present(PARAMS, wallet._msgs(), wallet.credential.signature,
                       list(req.disclose), req.rp_id.encode())


class RelyingParty:
    """Verifies presentations under a pinned issuer key, rejecting re-use."""

    def __init__(self, rp_id: str, issuer_pk, allowed_nats: list[int] | None = None):
        self.rp_id = rp_id
        self.issuer_pk = issuer_pk
        self.allowed_nats = allowed_nats
        self.seen_nullifiers: set = set()

    def verify(self, pres: bbs.Presentation, enforce_unique: bool = True) -> bool:
        if not bbs.verify_present(PARAMS, self.issuer_pk, pres, self.rp_id.encode()):
            return False
        # optional policy on a disclosed attribute
        if self.allowed_nats is not None:
            nat = pres.disclosed.get(NAT)
            if nat is None or nat not in self.allowed_nats:
                return False
        # sybil / double-presentation check via the per-RP nullifier
        key = bbs._ser(pres.nu)
        if enforce_unique and key in self.seen_nullifiers:
            return False
        self.seen_nullifiers.add(key)
        return True
