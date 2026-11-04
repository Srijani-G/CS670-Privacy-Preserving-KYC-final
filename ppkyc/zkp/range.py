"""Range proof: a committed value lies in ``[0, 2^k)``.

Given a Pedersen commitment ``C = g^v h^r`` the prover shows ``v in [0, 2^k)``:

* commit to each bit ``C_i = g^{b_i} h^{r_i}`` (the randomness of the top bit is
  chosen so that ``prod C_i^{2^i} == C`` exactly);
* an OR-proof per bit that ``C_i`` opens to 0 or 1;
* the verifier recomputes ``prod C_i^{2^i}`` and checks it equals ``C``.

The proof is linear in ``k`` (tens of KB) -- the natural place to note why
Bulletproofs exist (future work).  Both a self-contained Fiat-Shamir form and a
commit/respond form (for one combined challenge in the credential presentation)
are provided.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..crypto.group import GROUP
from ..crypto.commit import PEDERSEN
from ..crypto.fiat_shamir import Transcript
from .orproof import ORProof, ORCommitState, or_commit, or_respond, or_check


@dataclass
class RangeProof:
    bit_commitments: list[int]
    bit_proofs: list[ORProof]
    k: int


@dataclass
class RangeCommitState:
    bit_commitments: list[int]
    or_states: list[ORCommitState]
    k: int


def _bit_statement(ci: int) -> tuple[list[int], list[int]]:
    """Bases/targets for the OR-proof that ``ci`` opens to 0 or 1."""
    # branch 0: ci = h^{r}   -> target = ci           (bit 0)
    # branch 1: ci/g = h^{r} -> target = ci * g^{-1}  (bit 1)
    h = PEDERSEN.h
    return [h, h], [ci, GROUP.div(ci, PEDERSEN.g)]


def range_commit(v: int, r: int, k: int) -> RangeCommitState:
    assert 0 <= v < (1 << k), "value out of declared range"
    bits = [(v >> i) & 1 for i in range(k)]
    r_bits = [GROUP.rand_scalar() for _ in range(k - 1)]
    partial = sum((1 << i) * r_bits[i] for i in range(k - 1)) % GROUP.q
    inv_top = pow(1 << (k - 1), GROUP.q - 2, GROUP.q)
    r_bits.append(((r - partial) * inv_top) % GROUP.q)

    commitments, states = [], []
    for i in range(k):
        ci, _ = PEDERSEN.commit(bits[i], r_bits[i])
        commitments.append(ci)
        bases, targets = _bit_statement(ci)
        states.append(or_commit(bases, targets, bits[i], r_bits[i]))
    return RangeCommitState(commitments, states, k)


def range_first_messages(state: RangeCommitState) -> list[int]:
    """Everything the challenge must bind: bit commitments and OR a-values."""
    out = list(state.bit_commitments)
    for s in state.or_states:
        out.extend(s.a)
    return out


def range_respond(state: RangeCommitState, challenge: int) -> RangeProof:
    proofs = [or_respond(s, challenge) for s in state.or_states]
    return RangeProof(state.bit_commitments, proofs, state.k)


def range_check(C: int, proof: RangeProof, challenge: int) -> bool:
    if proof.k != len(proof.bit_commitments) or proof.k != len(proof.bit_proofs):
        return False
    if not GROUP.is_member(C):
        return False
    for ci, bp in zip(proof.bit_commitments, proof.bit_proofs):
        if not GROUP.is_member(ci):
            return False
        bases, targets = _bit_statement(ci)
        if not or_check(bases, targets, bp, challenge):
            return False
    acc = 1
    for i, ci in enumerate(proof.bit_commitments):
        acc = GROUP.mul(acc, GROUP.exp(ci, (1 << i) % GROUP.q))
    return acc == C


# -- self-contained Fiat-Shamir form ---------------------------------------
def range_prove(C: int, v: int, r: int, k: int, ctx: bytes = b"",
                domain: str = "range") -> RangeProof:
    state = range_commit(v, r, k)
    t = Transcript(domain).append_bytes("ctx", ctx).append_group("C", C)
    for m in range_first_messages(state):
        t.append_group("fm", m)
    return range_respond(state, t.challenge())


def range_verify(C: int, proof: RangeProof, ctx: bytes = b"",
                 domain: str = "range") -> bool:
    if not GROUP.is_member(C):
        return False
    t = Transcript(domain).append_bytes("ctx", ctx).append_group("C", C)
    fm = list(proof.bit_commitments)
    for bp in proof.bit_proofs:
        fm.extend(bp.a)
    for m in fm:
        t.append_group("fm", m)
    return range_check(C, proof, t.challenge())


# -- helpers for "attribute vs threshold" claims ---------------------------
def le_commitment(C_attr: int, cutoff: int) -> int:
    """``C_v = g^{cutoff} * C_attr^{-1}`` commits to ``cutoff - attr``.

    Proving ``C_v in [0,2^k)`` proves ``attr <= cutoff`` (e.g. dob <= cutoff
    year, i.e. age >= threshold).  Randomness of ``C_v`` is ``-r_attr``.
    """
    return GROUP.mul(GROUP.exp(GROUP.g, cutoff % GROUP.q), GROUP.inv(C_attr))


def ge_commitment(C_attr: int, threshold: int) -> int:
    """``C_v = C_attr * g^{-threshold}`` commits to ``attr - threshold``.

    Proving ``C_v in [0,2^k)`` proves ``attr >= threshold`` (e.g. KYC level).
    Randomness of ``C_v`` is ``r_attr``.
    """
    return GROUP.mul(C_attr, GROUP.exp(GROUP.g, (-threshold) % GROUP.q))
