# Threat model and limitations

## Adversary

The private system **v1** is analysed in the **semi-honest (honest-but-curious)**
model, matching how the course protocols are analysed: each party follows the
protocol but tries to learn more than it should from its own *view* (the messages
it sends and receives). The `Channel` class records every message so each party's
view is available for the leakage checks and simulator sketches.

Malicious behaviour is addressed in the implementation but is not demonstrated
as separate attack-lab scenarios:

- a malicious OT receiver is stopped by the Naor-Pinkas constraint;
- a cheating ZK prover is stopped by full-length challenges, fresh nonces and
  subgroup-membership checks.

## What each module leaks (claimed leakage)

| Module | Party | Learns |
|---|---|---|
| A (PSI) | Bank | which of *its own* customers matched, and `|W|` |
| A (PSI) | Regulator | `|Q|` |
| B (MPC) | S0 / S1 | only uniform random shares; the final flag |
| C (DORAM) | S0 / S1 | the number of queries and `n`; never the index |
| D (ZKP) | Relying party | pass/fail and a per-RP nullifier; never the attributes |

## Simulator sketches (slides 69-70)

Each module admits a PPT simulator that reproduces a corrupted party's view from
that party's **input and output only**:

- **PSI** — the bank's view is `{H(q)^a}`, `{H(q)^{ab}}` and a shuffled
  `{H(w)^b}`; a simulator given the match set and `|W|` samples uniform group
  elements for the non-matching positions (DDH), so the view carries nothing
  beyond the claimed leakage.
- **MPC (Beaver)** — the opened values `d = x-a`, `e = y-b` are uniformly random
  because `a, b` are uniform masks; the simulator samples them uniformly.
- **DORAM** — each server sees one uniformly random share of a one-hot vector;
  the simulator samples a uniform vector.
- **ZKP** — every sigma protocol ships a simulator (`pick z, e; set
  a = g^z h^{-e}`); the combined presentation is simulated branch by branch.

## Out of scope

Network and side-channel attacks; real identity proofing at issuance; fuzzy name
matching; UI trust; key management.

## Honest limitations (prototype, not production)

- **Linkable credential reuse** *(addressed in the BBS+ upgrade)* — the sigma
  credential's Schnorr-signed commitment is a static value, so two RPs *could*
  link a reused credential. This is now fixed in `ppkyc/zkp/bbs.py`: a BBS+
  signature is re-randomised on every presentation, giving genuine multi-show
  unlinkability even against colluding RPs, while the per-RP nullifier still
  makes same-RP re-use detectable.
- **Non-blind issuance** *(addressed in the BBS+ upgrade)* — in the sigma
  credential the issuer could link issuance to all usage. The BBS+ flow uses
  **blind issuance**: the holder commits to `sk` (proving knowledge of the
  opening) and the issuer signs the commitment, so it never learns `sk` and
  cannot link an issued credential to any later presentation. BBS+ needs a
  bilinear pairing (`py_ecc` BLS12-381), the one exception to the pure-stdlib
  rule; full CL and re-randomisable signatures remain the production reference.
- **PSI enumeration** — a malicious bank can submit the whole
  identifier space to learn the watchlist; PSI cannot prevent this
  cryptographically. v1 only *mitigates* it with authenticated queries, a cap on
  `|Q|` per window and an audit log.
- **Range-proof size** — the sigma range proof is linear in the bit-width (tens
  of KB); Bulletproofs would shrink it (future work).
- **DORAM cost** — the read-only DORAM is `O(n)` per read; a distributed point
  function would cut queries to `O(log n)` (future work).
- **Group size / performance** — a 2048-bit group is used for clarity, not speed;
  a prime-order elliptic curve would be far faster in production.
