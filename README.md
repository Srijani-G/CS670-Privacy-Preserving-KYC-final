# Privacy-Preserving KYC/AML

**CS670: Cryptographic Techniques for Privacy Preservation**

A working prototype showing that **secure multiparty computation**, **oblivious
memory access** and **zero-knowledge proofs** deliver cross-institution KYC/AML
compliance *while raw customer data never leaves its owner*. It builds a
deliberately flawed naive system (**v0**) next to the private system (**v1**),
runs the same attacks on both, and names the course property that blocks each
one.

The core protocol implementations are written in **Python 3** and primarily
use standard-library primitives such as `hashlib` and `secrets`. The optional
BBS+ credential upgrade uses `py_ecc` for BLS12-381 pairing operations; the
local web demo additionally uses FastAPI and Uvicorn.

## Quick start

```bash
# Install the optional BBS+ and frontend API dependencies.
python -m pip install -r requirements.txt
python run_tests.py        # full test suite (completeness, soundness, correctness, leakage)
python -m demo.demo        # end-to-end demo of all four modules + the attack lab
python -m attacks.run_attacks   # just the v0-vs-v1 attack table
```

The core modules use only the standard library. The **BBS+ credential upgrade**
(see *Stronger credentials* below) requires `py_ecc`; the local web demo uses
FastAPI and Uvicorn.

```bash
python -m demo.demo_bbs    # unlinkable, blindly-issued credentials (fixes linkability + non-blind issuance)
```

## Local web demo

The static frontend calls a FastAPI backend that runs the existing protocol code.
Each protocol page includes an interactive algorithm walkthrough and editable
demo inputs. The attack lab lets you choose one of the 7 implemented scenarios, inspect its
steps, edit supported attacker inputs, and run it against v0, v1, or both. Its
outcomes describe whether an attack succeeded; they are not test-pass indicators.
It is a local educational demo only; do not enter real customer information.

1. Install dependencies with `python -m pip install -r requirements.txt`.
2. In one PowerShell window, start the API from the repository root:

   ```powershell
   python -m uvicorn backend.app:app --host 127.0.0.1 --port 8001 --reload
   ```

3. In a second PowerShell window, start the static frontend from the repository root:

   ```powershell
   python -m http.server 8000 --bind 127.0.0.1 --directory frontend
   ```

4. Open <http://127.0.0.1:8000> in your browser. The backend health endpoint is
   <http://127.0.0.1:8001/api/health>, and its interactive API docs are at
   <http://127.0.0.1:8001/docs>.

Press `Ctrl+C` in each terminal to stop its server. The Attack Lab runs all 7
scenarios and may take a few seconds.

The private-registry page accepts 1–2,048 status records per DORAM query.
Use **Load 2,048-record sample** to populate a demo registry and read its final
record. The API schema boundary is tested separately from the DORAM protocol:
2,048 records are accepted, while empty and 2,049-record requests are rejected.

## Large-data comparisons

The opt-in [`large_tests/`](large_tests) suite generates synthetic CSV datasets
with thousands of rows and compares naive and privacy-preserving outputs for all
four modules. See [`large_tests/README.md`](large_tests/README.md) for generation
and run commands. MPC and credential runs can be slow at the full 1,000-case
size, so the runner defaults to 10 cases per module.

## The four modules

| Module | KYC task | Course tools | Code |
|---|---|---|---|
| **A. Sanctions screening** | Bank checks customers against the regulator's watchlist; list stays hidden, bank learns only its own matches. | DH-based PSI, hash-to-group, group-membership checks | [`ppkyc/psi/`](ppkyc/psi) |
| **B. Cross-bank AML analytics** | Is combined deposits above a threshold / what is the risk score, without revealing per-bank amounts or the model. | Additive shares, Du-Atallah/Beaver triples, OT, garbled circuits | [`ppkyc/mpc/`](ppkyc/mpc) |
| **C. Private registry & documents** | Outsourced encrypted KYC docs; query a shared KYC-status registry without revealing which record. | Linear & square-root ORAM, 2-server read-only DORAM via one-hot dot products | [`ppkyc/oram/`](ppkyc/oram) |
| **D. Verifiable claims** | Customer proves `age ≥ 18`, `nationality ∈ set`, `kyc_level ≥ 2` about issuer-signed committed attributes without showing documents. | Pedersen commitments, Schnorr, DLEQ, OR-proofs, Fiat-Shamir, MPC-in-the-head | [`ppkyc/zkp/`](ppkyc/zkp) |
 
### Module C registry configuration

The Module C read-only DORAM demo and correctness test use **1,024 synthetic
customer records**. The fixture is generated deterministically (seed `670`) at
runtime, so it is reproducible and does not require a database server or a
persistent SQLite file. Each fictional record includes a customer ID, name,
date of birth, nationality, KYC status, risk category, and last-review date.

DORAM currently operates on an indexed integer array of KYC-status codes
(`0` pending, `1` verified, `2` rejected, `3` under review), derived from those
records. Both non-colluding servers receive identical copies of this 1,024-entry
array. The richer synthetic metadata remains in the local fixture and is not
sent as part of the DORAM query. The API and frontend use the same status-code
mapping: `0` pending, `1` verified, `2` rejected, and `3` under review. This is
an in-memory educational simulation, not a persistent customer database.

`generate_synthetic_registry()` and `encode_registry_statuses()` in
`ppkyc/oram/doram_ro.py` define the fixture and its DORAM representation.

## Repository layout

```
ppkyc/
  crypto/     group.py  fiat_shamir.py  commit.py  sharing.py  ot.py  gc.py
  zkp/        schnorr.py  dleq.py  orproof.py  range.py  credential.py  mpcith.py
  psi/        dh_psi.py
  mpc/        beaver.py  dotprod.py  gc_compare.py  pipeline.py
  oram/       linear.py  sqrt.py  doram_ro.py
  kyc_naive/  v0.py                 # the deliberately-flawed baseline
  channel.py                        # view-recording channel (for leakage/simulator checks)
attacks/      harness.py  attacks.py  run_attacks.py     # the attack lab
tests/        test_crypto_core.py  test_zkp.py  test_modules.py  test_api.py
demo/         demo.py
docs/         threat_model.md  paper_to_module.md
```

## Shared cryptographic core

- **Group** — a 2048-bit Schnorr group with a 256-bit prime-order subgroup.
  `is_member` is enforced on every received element (skipping it can leak secret
  bits via small subgroups); `hash_to_group` clears the cofactor so PSI leaks no
  integer ratios.
- **Fiat-Shamir** — a strong transcript binding group params, statement and
  verifier context (rp_id, nonce, timestamp); a deliberately *weak* variant
  exists for illustrative weak-Fiat-Shamir tests.
- **Commitments** — Pedersen (`g^m h^r`, perfectly hiding) and hash commitments
  (for MPC-in-the-head views).
- **Secret sharing** — additive over `Z_{2^32}` and `Z_q`, plus 3-party
  replicated shares with PRG zero-sharing (for MPC-in-the-head).
- **OT** — Naor-Pinkas 1-out-of-2 (the "tie Bob's hands" fix); a malicious
  receiver cannot learn both messages.
- **Garbled circuits** — point-and-permute + free-XOR + GRR3; adder and
  comparator, checked against plaintext evaluation.

## Module D in one paragraph

The wallet picks a secret key `sk` and commits to every attribute
(`C_sk, C_dob, C_nat, C_level`). The issuer checks the openings (in zero
knowledge for `sk`) and Schnorr-signs `H(commitments ‖ expiry ‖ issuer_id)`. To
present, the wallet returns the credential plus a **single combined proof under
one challenge** `e = H(params ‖ ctx ‖ commitments ‖ signature ‖ all
first-messages)` covering: a **range proof** for `age ≥ 18`, a range proof for
`kyc_level ≥ 2`, an **OR-proof** for nationality, and a scoped **nullifier**
`ν = H2G(rp_id)^sk` with a DLEQ-style proof tying `sk` inside `C_sk` to `ν`.
Binding to `(rp_id, nonce, timestamp)` defeats replay; tying `sk` gives holder
binding; the nullifier gives per-RP sybil resistance while staying unlinkable
across RPs. The same age claim is also proved a second way with
**MPC-in-the-head** (`mpcith.py`) for a size/time comparison.

## Attack lab

`python -m attacks.run_attacks` runs all 7 privacy attacks against v0 and v1:

| # | Attack | v1 defence |
|---|---|---|
| 1 | PII breach | MPC/ZK — no party holds full data |
| 2 | Hash dictionary | DH-PSI secret exponents |
| 3 | Amount snooping | additive shares + GC |
| 4 | Access-pattern inference | ORAM / DORAM |
| 5 | Replay | nonce + RP id in the FS hash |
| 6 | Credential lending | `sk` bound inside `C_sk` |
| 7 | Sybil accounts | scoped nullifier |

## Stronger credentials (BBS+ upgrade)

The sigma credential above has two honest limitations: it is **linkable** (the
signed commitments are a static serial number, so two RPs can tell the same
credential was shown twice) and **non-blindly issued** (the issuer can link
issuance to every later use). Both are fixed in [`ppkyc/zkp/bbs.py`](ppkyc/zkp/bbs.py)
and [`ppkyc/zkp/credential_bbs.py`](ppkyc/zkp/credential_bbs.py) with **BBS+
signatures** (literature survey §3.1, CL/BBS+):

- **multi-show unlinkability** — each presentation re-randomises the signature,
  so showings are unlinkable even to colluding verifiers;
- **blind issuance** — the holder commits to its secret key `sk` and the issuer
  signs the *commitment*, never learning `sk`;
- the sybil-resistant **per-RP nullifier** `ν = sk·H2G(rp_id)` is kept.

BBS+ needs a bilinear pairing, which the standard library lacks, so this one
module uses `py_ecc`'s pure-Python BLS12-381 — the single, deliberate exception
to the no-crypto-library rule. Scope: this delivers the unlinkability and
blind-issuance fix; *threshold predicates* (`age ≥ 18`) over hidden attributes
would need pairing-group range proofs (Bulletproofs, future work) and are not
ported here, so the BBS+ demo discloses the attributes an RP checks.

## Threat model & limitations

See [`docs/threat_model.md`](docs/threat_model.md). In short: the core is
**semi-honest** (as most course protocols are analysed); malicious behaviour is
shown only in the attack lab; this is a **prototype, not production** —
credential reuse is linkable, issuance is non-blind, PSI enumeration is only
mitigated, and key management / real identity proofing are out of scope.
Production answers (BBS+/CL credentials, Bulletproofs, zk-SNARKs, DPF-based
DORAM) are noted as future work.

The research-foundation / paper-to-module table is in
[`docs/paper_to_module.md`](docs/paper_to_module.md).
