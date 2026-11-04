"""CDS OR-proof over discrete-log statements.

A single proof shows: *for some index i*, ``target_i = base_i ^ w_i`` -- without
revealing which ``i``.  The false branches are simulated (pick ``z_i, e_i``,
set ``a_i = base_i^{z_i} target_i^{-e_i}``) and the challenge is split so
``sum(e_i) == e`` (Cramer-Damgard-Schoenmakers, slides on OR-proofs).

Used for:

* **bit proofs** in the range proof -- statement 0 is "``C = h^r``" (bit 0) and
  statement 1 is "``C/g = h^r``" (bit 1).
* **set membership** for nationality -- one branch per allowed country value,
  "``C_nat / g^{country} = h^r``".
"""

from __future__ import annotations

from dataclasses import dataclass

from ..crypto.group import GROUP
from ..crypto.fiat_shamir import Transcript


@dataclass
class ORProof:
    a: list[int]
    e: list[int]
    z: list[int]


def _transcript(domain: str, bases: list[int], targets: list[int],
                a_list: list[int], ctx: bytes) -> Transcript:
    t = Transcript(domain)
    t.append_bytes("ctx", ctx)
    for i, (b, y, a) in enumerate(zip(bases, targets, a_list)):
        t.append_group(f"base{i}", b).append_group(f"target{i}", y).append_group(f"a{i}", a)
    return t


def or_prove_fs(bases: list[int], targets: list[int], true_idx: int, w: int,
                ctx: bytes = b"", domain: str = "or") -> ORProof:
    state = or_commit(bases, targets, true_idx, w)
    chal = _transcript(domain, bases, targets, state.a, ctx).challenge()
    return or_respond(state, chal)


@dataclass
class ORCommitState:
    bases: list[int]
    targets: list[int]
    true_idx: int
    w: int
    r: int
    a: list[int]
    e: list[int]  # pre-chosen challenges for the simulated branches
    z: list[int]  # pre-chosen responses for the simulated branches


def or_commit(bases: list[int], targets: list[int], true_idx: int,
              w: int) -> ORCommitState:
    """First phase: simulate false branches, commit the real branch."""
    n = len(bases)
    assert len(targets) == n and 0 <= true_idx < n
    a = [0] * n
    e = [0] * n
    z = [0] * n
    for i in range(n):
        if i == true_idx:
            continue
        e[i] = GROUP.rand_scalar()
        z[i] = GROUP.rand_scalar()
        a[i] = GROUP.mul(GROUP.exp(bases[i], z[i]),
                         GROUP.exp(targets[i], (-e[i]) % GROUP.q))
    r = GROUP.rand_scalar()
    a[true_idx] = GROUP.exp(bases[true_idx], r)
    return ORCommitState(bases, targets, true_idx, w, r, a, e, z)


def or_respond(state: ORCommitState, challenge: int) -> ORProof:
    """Second phase: split an externally-supplied challenge."""
    n = len(state.bases)
    e = list(state.e)
    z = list(state.z)
    e[state.true_idx] = (challenge - sum(e[i] for i in range(n)
                                         if i != state.true_idx)) % GROUP.q
    z[state.true_idx] = (state.r + e[state.true_idx] * state.w) % GROUP.q
    return ORProof(a=list(state.a), e=e, z=z)


def or_check(bases: list[int], targets: list[int], proof: ORProof,
             challenge: int) -> bool:
    """Verify equations against an externally-supplied challenge."""
    n = len(bases)
    if not (len(targets) == n == len(proof.a) == len(proof.e) == len(proof.z)):
        return False
    for elem in bases + targets + proof.a:
        if not GROUP.is_member(elem):
            return False
    if sum(proof.e) % GROUP.q != challenge % GROUP.q:
        return False
    for i in range(n):
        lhs = GROUP.exp(bases[i], proof.z[i])
        rhs = GROUP.mul(proof.a[i], GROUP.exp(targets[i], proof.e[i]))
        if lhs != rhs:
            return False
    return True


def or_verify_fs(bases: list[int], targets: list[int], proof: ORProof,
                 ctx: bytes = b"", domain: str = "or") -> bool:
    n = len(bases)
    if not (len(targets) == n == len(proof.a) == len(proof.e) == len(proof.z)):
        return False
    for elem in bases + targets + proof.a:
        if not GROUP.is_member(elem):
            return False
    chal = _transcript(domain, bases, targets, proof.a, ctx).challenge()
    if sum(proof.e) % GROUP.q != chal:
        return False
    for i in range(n):
        lhs = GROUP.exp(bases[i], proof.z[i])
        rhs = GROUP.mul(proof.a[i], GROUP.exp(targets[i], proof.e[i]))
        if lhs != rhs:
            return False
    return True
