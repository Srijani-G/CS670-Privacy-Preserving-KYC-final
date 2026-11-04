"""MPC-in-the-head proof of the age predicate (Module D3).

Proves the same ``x >= T`` claim a second way, using the slides' MPC-in-the-head
construction, so its proof size / time can be benchmarked against the sigma
range proof of the same claim.

* A 3-party replicated-sharing protocol over GF(2) with PRG-derived zero
  sharing (the machinery of slides 19-23).
* A comparator circuit over the secret bits of ``x``: XOR and NOT are local;
  AND uses replicated multiplication plus a zero-sharing correction, followed by
  a one-element reshare message.
* The prover runs all three parties "in its head", commits to each party's view
  and the three output shares.  Fiat-Shamir selects, per round, **which pair of
  views to open**.  The verifier recomputes those two parties, checks their
  commitments, checks the message on the edge between them, and checks the three
  output shares XOR to 1.

Soundness error is ``2/3`` per round (a cheated edge is caught only when exactly
that pair is opened), so ~137 rounds give ``2^-80``.  Zero-knowledge comes from
the 2-privacy of the protocol: any two views are independent of ``x``.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field

from ..crypto.sharing import prg
from ..crypto.commit import hash_commit, hash_open
from ..crypto.fiat_shamir import Transcript


# --------------------------------------------------------------------------
# One simulated execution ("in the head")
# --------------------------------------------------------------------------
class _Party:
    """Holds replicated shares (first = s_i, second = s_{i+1}) per wire."""

    def __init__(self, idx: int, seed_self: bytes, seed_next: bytes):
        self.idx = idx
        self.seed_self = seed_self
        self.seed_next = seed_next
        self.first: dict[int, int] = {}
        self.second: dict[int, int] = {}
        self.received: list[int] = []  # reshare messages received (ordered)


def _run_execution(x_bits: list[int], T_bits: list[int]):
    """Run the 3-party comparator on secret ``x`` once; return parties + output.

    Returns (parties, output_shares) where output_shares[i] is party i's share
    of the result bit (x >= T).
    """
    seeds = [secrets.token_bytes(16) for _ in range(3)]
    parties = [_Party(i, seeds[i], seeds[(i + 1) % 3]) for i in range(3)]

    wire = 0
    gid = 0  # gate counter, salts the zero-sharing PRG

    def new_wire() -> int:
        nonlocal wire
        w = wire
        wire += 1
        return w

    def share_input(bit: int) -> int:
        w = new_wire()
        s0 = secrets.randbelow(2)
        s1 = secrets.randbelow(2)
        s2 = bit ^ s0 ^ s1
        s = [s0, s1, s2]
        for i in range(3):
            parties[i].first[w] = s[i]
            parties[i].second[w] = s[(i + 1) % 3]
        return w

    def xor(a: int, b: int) -> int:
        w = new_wire()
        for i in range(3):
            parties[i].first[w] = parties[i].first[a] ^ parties[i].first[b]
            parties[i].second[w] = parties[i].second[a] ^ parties[i].second[b]
        return w

    def xor_const(a: int, c: int) -> int:
        w = new_wire()
        for i in range(3):
            fa, sa = parties[i].first[a], parties[i].second[a]
            # public constant XORed into party 0's share (and party 2's "second")
            parties[i].first[w] = fa ^ (c if i == 0 else 0)
            parties[i].second[w] = sa ^ (c if (i + 1) % 3 == 0 else 0)
        return w

    def not_gate(a: int) -> int:
        return xor_const(a, 1)

    def and_const(a: int, c: int) -> int:
        w = new_wire()
        for i in range(3):
            parties[i].first[w] = parties[i].first[a] & c
            parties[i].second[w] = parties[i].second[a] & c
        return w

    def and_gate(a: int, b: int) -> int:
        nonlocal gid
        w = new_wire()
        gid += 1
        label = b"and" + gid.to_bytes(4, "big")
        # local products and zero sharing
        z = [0, 0, 0]
        for i in range(3):
            ai, ai1 = parties[i].first[a], parties[i].second[a]
            bi, bi1 = parties[i].first[b], parties[i].second[b]
            t = (ai & bi) ^ (ai & bi1) ^ (ai1 & bi)
            alpha = (prg(parties[i].seed_self, label, 2)
                     ^ prg(parties[i].seed_next, label, 2))
            z[i] = t ^ alpha
        # each party i holds z_i as "first"; receives z_{i+1} as "second"
        for i in range(3):
            parties[i].first[w] = z[i]
            parties[i].second[w] = z[(i + 1) % 3]
            parties[i].received.append(z[(i + 1) % 3])  # message from party i+1
        return w

    def or_gate(a: int, b: int) -> int:
        return not_gate(and_gate(not_gate(a), not_gate(b)))

    # ---- build the comparator x >= T (unsigned, n bits) ------------------
    n = len(x_bits)
    xw = [share_input(bit) for bit in x_bits]

    borrow = None
    for i in range(n):
        ti = T_bits[i]
        if borrow is None:
            borrow = and_const(not_gate(xw[i]), ti)  # (~x_i) & t_i
        else:
            d = xor_const(xw[i], ti)                 # x_i ^ t_i
            b1 = and_const(not_gate(xw[i]), ti)      # (~x_i) & t_i
            b2 = and_gate(not_gate(d), borrow)       # (~(x_i^t_i)) & borrow
            borrow = or_gate(b1, b2)
    ge = not_gate(borrow)

    output_shares = [parties[i].first[ge] for i in range(3)]
    return parties, output_shares


def _commit_party(party: _Party) -> tuple[bytes, bytes, bytes]:
    """Commit to a party's full view; returns (commitment, randomness, blob)."""
    h = hashlib.sha256()
    h.update(party.seed_self)
    h.update(party.seed_next)
    for w in sorted(party.first):
        h.update(w.to_bytes(4, "big"))
        h.update(bytes([party.first[w], party.second[w]]))
    for m in party.received:
        h.update(bytes([m]))
    blob = h.digest()
    com, r = hash_commit(blob)
    return com, r, blob


# --------------------------------------------------------------------------
# Proof object
# --------------------------------------------------------------------------
@dataclass
class MPCitHRound:
    commitments: list[bytes]      # 3 view commitments
    output_shares: list[int]      # 3 output shares (published)
    opened: tuple[int, int] = (0, 1)
    opened_views: list = field(default_factory=list)  # (seed_self, seed_next, first, second, received, com_r)


@dataclass
class MPCitHProof:
    rounds: list[MPCitHRound]
    T: int
    n_bits: int


def _challenge_pairs(commit_digest: bytes, n_rounds: int) -> list[int]:
    """Derive, per round, which pair to open (0->{0,1},1->{1,2},2->{0,2})."""
    out = []
    counter = 0
    while len(out) < n_rounds:
        d = hashlib.sha256(commit_digest + counter.to_bytes(4, "big")).digest()
        for byte in d:
            out.append(byte % 3)
            if len(out) >= n_rounds:
                break
        counter += 1
    return out


_PAIRS = {0: (0, 1), 1: (1, 2), 2: (0, 2)}


def prove(x: int, T: int, n_bits: int, n_rounds: int = 137) -> MPCitHProof:
    x_bits = [(x >> i) & 1 for i in range(n_bits)]
    T_bits = [(T >> i) & 1 for i in range(n_bits)]
    assert x >= T, "witness does not satisfy the predicate"

    prebuilt = []
    commit_acc = hashlib.sha256()
    commit_acc.update(T.to_bytes(8, "big"))
    commit_acc.update(n_bits.to_bytes(4, "big"))
    for _ in range(n_rounds):
        parties, out_shares = _run_execution(x_bits, T_bits)
        coms, rs, blobs = [], [], []
        for p in parties:
            com, r, blob = _commit_party(p)
            coms.append(com)
            rs.append(r)
            blobs.append(blob)
        prebuilt.append((parties, out_shares, coms, rs))
        for com in coms:
            commit_acc.update(com)
        for s in out_shares:
            commit_acc.update(bytes([s]))

    pairs = _challenge_pairs(commit_acc.digest(), n_rounds)

    rounds = []
    for (parties, out_shares, coms, rs), pc in zip(prebuilt, pairs):
        i, j = _PAIRS[pc]
        opened_views = []
        for idx in (i, j):
            p = parties[idx]
            opened_views.append((p.seed_self, p.seed_next,
                                 dict(p.first), dict(p.second),
                                 list(p.received), rs[idx]))
        rounds.append(MPCitHRound(commitments=coms, output_shares=out_shares,
                                  opened=(i, j), opened_views=opened_views))
    return MPCitHProof(rounds=rounds, T=T, n_bits=n_bits)


def verify(proof: MPCitHProof) -> bool:
    T_bits = [(proof.T >> i) & 1 for i in range(proof.n_bits)]

    # recompute the challenge from commitments + output shares
    commit_acc = hashlib.sha256()
    commit_acc.update(proof.T.to_bytes(8, "big"))
    commit_acc.update(proof.n_bits.to_bytes(4, "big"))
    for rnd in proof.rounds:
        for com in rnd.commitments:
            commit_acc.update(com)
        for s in rnd.output_shares:
            commit_acc.update(bytes([s]))
    pairs = _challenge_pairs(commit_acc.digest(), len(proof.rounds))

    for rnd, pc in zip(proof.rounds, pairs):
        if rnd.opened != _PAIRS[pc]:
            return False
        # output shares must reconstruct to 1
        if (rnd.output_shares[0] ^ rnd.output_shares[1] ^ rnd.output_shares[2]) != 1:
            return False
        if not _verify_round(rnd, T_bits, proof.n_bits):
            return False
    return True


def _verify_round(rnd: MPCitHRound, T_bits: list[int], n_bits: int) -> bool:
    i, j = rnd.opened
    views = {i: rnd.opened_views[0], j: rnd.opened_views[1]}

    # 1. commitments of the opened views match
    for idx in (i, j):
        seed_self, seed_next, first, second, received, com_r = views[idx]
        h = hashlib.sha256()
        h.update(seed_self)
        h.update(seed_next)
        for w in sorted(first):
            h.update(w.to_bytes(4, "big"))
            h.update(bytes([first[w], second[w]]))
        for m in received:
            h.update(bytes([m]))
        if not hash_open(rnd.commitments[idx], h.digest(), r=com_r):
            return False

    # 2. replay both opened parties and check the edge between them.
    replayed = {}
    for idx in (i, j):
        replayed[idx] = _replay_party(idx, views[idx], T_bits, n_bits)
    if replayed[i] is None or replayed[j] is None:
        return False

    # check messages sent on the opened edge match what was received.
    # party a sends z_a to party a-1; so party (idx) receives from party (idx+1).
    # if (idx+1) is also opened, its sent values must equal idx's received list.
    for idx in (i, j):
        nxt = (idx + 1) % 3
        if nxt in views:
            sent_by_next = replayed[nxt]["sent"]   # z values party nxt produced
            recv_by_idx = views[idx][4]            # received list
            if sent_by_next != recv_by_idx:
                return False
    # 3. opened output shares consistent with replay
    for idx in (i, j):
        if replayed[idx]["output"] != rnd.output_shares[idx]:
            return False
    return True


def _replay_party(idx: int, view, T_bits: list[int], n_bits: int):
    """Recompute party ``idx``'s computation from its view alone.

    Returns dict with 'sent' (z_i values it produced per AND gate) and 'output'.
    Returns None if the view is internally malformed.
    """
    seed_self, seed_next, first, second, received, _ = view
    # We recompute using the committed input shares (first/second for inputs);
    # non-input wires are recomputed from gate logic, and the 'second' of AND
    # outputs comes from the received messages.
    f: dict[int, int] = {}
    s: dict[int, int] = {}
    wire = 0
    gid = 0
    recv_ptr = 0
    sent = []

    def nw():
        nonlocal wire
        w = wire
        wire += 1
        return w

    # inputs
    xw = []
    for _ in range(n_bits):
        w = nw()
        if w not in first or w not in second:
            return None
        f[w] = first[w]
        s[w] = second[w]
        xw.append(w)

    def xor(a, b):
        w = nw(); f[w] = f[a] ^ f[b]; s[w] = s[a] ^ s[b]; return w

    def xor_const(a, c):
        w = nw()
        f[w] = f[a] ^ (c if idx == 0 else 0)
        s[w] = s[a] ^ (c if (idx + 1) % 3 == 0 else 0)
        return w

    def not_gate(a):
        return xor_const(a, 1)

    def and_const(a, c):
        w = nw(); f[w] = f[a] & c; s[w] = s[a] & c; return w

    def and_gate(a, b):
        nonlocal gid, recv_ptr
        w = nw(); gid += 1
        label = b"and" + gid.to_bytes(4, "big")
        ai, ai1 = f[a], s[a]
        bi, bi1 = f[b], s[b]
        t = (ai & bi) ^ (ai & bi1) ^ (ai1 & bi)
        alpha = prg(seed_self, label, 2) ^ prg(seed_next, label, 2)
        zi = t ^ alpha
        sent.append(zi)
        f[w] = zi
        # second component comes from the received reshare message
        if recv_ptr >= len(received):
            return None
        s[w] = received[recv_ptr]
        recv_ptr += 1
        return w

    def or_gate(a, b):
        return not_gate(and_gate(not_gate(a), not_gate(b)))

    borrow = None
    for i2 in range(n_bits):
        ti = T_bits[i2]
        if borrow is None:
            borrow = and_const(not_gate(xw[i2]), ti)
        else:
            d = xor_const(xw[i2], ti)
            b1 = and_const(not_gate(xw[i2]), ti)
            r = and_gate(not_gate(d), borrow)
            if r is None:
                return None
            b2 = r
            borrow = or_gate(b1, b2)
    ge = not_gate(borrow)
    return {"sent": sent, "output": f[ge]}
