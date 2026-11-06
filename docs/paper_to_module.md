# Paper-to-module table

The sources below were named from the course plan **from memory** and must have
their exact titles, authors and years verified before they appear in the written
report. This table maps each one to where it is used in the code and notes the
deviations made in this prototype.

| Module | Source (verify before citing) | Where in the code | Deviation in this prototype |
|---|---|---|---|
| Core | Course slides (CS670): MPC, Secure Memory Access, ZKP | whole repo | — |
| A: PSI | Huberman et al. (DH-style PSI); Meadows (early PSI); Pinkas-Schneider-Zohner (OT-based PSI) | `ppkyc/psi/dh_psi.py` | DH-PSI only; OT-PSI left as future work |
| B: MPC | Yao (garbled circuits); Beaver (multiplication triples); Du-Atallah (secure dot product); free-XOR & GRR3 garbling; GMW; IKNP (OT extension) | `ppkyc/mpc/*`, `ppkyc/crypto/gc.py`, `ppkyc/crypto/ot.py` | 2-party semi-honest; GRR3 + free-XOR; triples via Gilboa OT (no IKNP extension) |
| C: ORAM | Goldreich-Ostrovsky (square-root ORAM); Stefanov et al. (Path ORAM); Shi et al. (tree ORAM); Doerner-shelat (DORAM); Boyle-Gilboa-Ishai (DPF) | `ppkyc/oram/*` | linear + square-root ORAM + read-only 2-server DORAM; tree ORAM and DPF are future work |
| D: ZKP | Schnorr; Fiat-Shamir; Cramer-Damgard-Schoenmakers (OR-proofs); Chaum-Pedersen (DLEQ); Pedersen (commitments); Ishai-Kushilevitz-Ostrovsky-Sahai (MPC-in-the-head) | `ppkyc/zkp/*` | credential = sigma + Fiat-Shamir over Pedersen commitments; MPCitH is the 3-party 2-of-3-opening variant |
| D+: BBS+ upgrade | Camenisch-Lysyanskaya (CL); Au-Susilo-Mu / BBS+; Boneh-Boyen (survey §3.1) | `ppkyc/zkp/bbs.py`, `ppkyc/zkp/credential_bbs.py` | BBS+ over BLS12-381 (`py_ecc`); fixes credential linkability (multi-show unlinkable) and non-blind issuance; pairing is the one non-stdlib dependency; threshold predicates over hidden attributes still future work (Bulletproofs) |
| Attacks | Dao-Miller-Wright-Grubbs ("Frozen Heart"); Howgrave-Graham & Smart (lattice attacks on biased nonces); Bernhard-Pereira-Warinschi (weak Fiat-Shamir) | `attacks/attacks.py` | the trimmed lab keeps the seven privacy attacks; weak-Fiat-Shamir / biased-nonce demonstrations were removed and remain optional future work |
| Context | zkKYC (Pauwels et al.); Chaum (blind signatures); Aadhaar offline e-KYC / DigiLocker | `docs/`, report | motivation only |
| Future work | Coconut; Bulletproofs; Groth16 (all out of syllabus). Camenisch-Lysyanskaya / BBS+ is now **implemented** (see the D+ row). | — | Bulletproofs/Groth16/Coconut documented as design-only future work |

## Build order (from the plan) and status

| Step | Deliverable | Status |
|---|---|---|
| 1 | Core library (group, FS, commitments, sharing, OT, GC) with tests | ✅ done |
| 2 | v0 and attacks 1, 2, 4 | ✅ done |
| 3 | Module D (sigma toolkit, credentials, range proofs) and attacks 7-11, 13 | ✅ done |
| 4 | Module A (DH-PSI) and attacks 3, 12 | ✅ done |
| 5 | Module B (Beaver, GC comparison) and attack 6 | ✅ done |
| 6 | Module C1 (linear, square-root ORAM) + attack 5, then C2 (read-only DORAM) | ✅ done |
| 7 | MPC-in-the-head, benchmarks, demo | ✅ done |
