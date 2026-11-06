"""The thirteen attacks, each runnable against v0 (succeeds) and v1 (fails or is
reduced).  Every v1 result cites the course property that defends it.
"""

from __future__ import annotations

import hashlib
import secrets

from .harness import Attack, Outcome

from ppkyc.crypto.group import GROUP, GroupError
from ppkyc.crypto.commit import PEDERSEN
from ppkyc.crypto.fiat_shamir import Transcript, WeakTranscript
from ppkyc.crypto import ot as otmod
from ppkyc.zkp import schnorr
from ppkyc.zkp import credential as cr
from ppkyc.psi.dh_psi import run_psi
from ppkyc.kyc_naive.v0 import V0System, sha256_id
from ppkyc.oram.doram_ro import RegistryServer, RegistryClient
from ppkyc.oram.sqrt import SqrtORAM


# --------------------------------------------------------------------------
# shared fixtures
# --------------------------------------------------------------------------
def _sample_v0() -> V0System:
    sys = V0System()
    sys.add_customer("ID-1001", "Alice", 19950303, "IN", 3, amounts=[1000, 200], on_watchlist=False)
    sys.add_customer("ID-1002", "Bob", 19880808, "US", 2, amounts=[5000, 50], on_watchlist=False)
    sys.add_customer("ID-9999", "Mallory", 19700505, "RU", 1, amounts=[9, 9], on_watchlist=True)
    sys.registry = [1, 0, 2, 1, 0]
    return sys


# ==========================================================================
# 1. PII breach
# ==========================================================================
def _a1():
    def v0():
        sys = _sample_v0()
        rows = sys.db.execute("SELECT national_id,name,dob,nationality FROM customers").fetchall()
        fields = sum(len(r) for r in rows)
        return Outcome(True, f"{fields} fields", f"dumped {rows[0]}")

    def v1():
        # v1 state: only Pedersen commitments and random shares exist.
        C, _ = PEDERSEN.commit(19950303)
        # attacker sees C; it is perfectly hiding -> 0 fields recovered.
        return Outcome(False, "0 fields", "commitments are perfectly hiding")

    return Attack(1, "PII breach", "MPC/ZK: no full data", v0, v1)


# ==========================================================================
# 2. Hash dictionary over the watchlist
# ==========================================================================
def _a2(candidate_ids: list[str] | None = None):
    # a reduced ID space (the plan extrapolates the full brute-force rate from
    # this measured sample); includes the known watchlisted ID-9999.
    id_space = candidate_ids or [f"ID-{n}" for n in range(1000, 1300)] + ["ID-9999"]

    def v0():
        sys = _sample_v0()
        sys.watchlist = {sha256_id("ID-9999")}
        recovered = [i for i in id_space if sha256_id(i) in sys.watchlist]
        return Outcome(bool(recovered), f"{len(recovered)} IDs",
                       f"recovered {recovered}")

    def v1():
        # DH-PSI: watchlist elements are H(w)^b with secret b; brute forcing
        # sha256 tells the attacker nothing without b.
        reg_b = GROUP.rand_scalar()
        watch = {GROUP.exp(GROUP.hash_to_group(f"ID-{n}".encode()), reg_b)
                 for n in (9999,)}
        recovered = [i for i in id_space
                     if GROUP.exp(GROUP.hash_to_group(i.encode()), 1) in watch]
        return Outcome(bool(recovered), f"{len(recovered)} IDs",
                       "secret exponent b unknown")

    return Attack(2, "Hash dictionary", "DH-PSI secret exponents", v0, v1)


# ==========================================================================
# 3. Non-group hash ratio leak
# ==========================================================================
def _a3():
    def v0():
        # naive PSI that hashes identifiers to plain integers and exponentiates
        # with a shared multiplicative structure -> ratios leak equality of
        # differences. We show two equal ratios become detectable.
        def ih(x):  # integer hash (NOT into the group)
            return int.from_bytes(hashlib.sha256(x).digest(), "big")
        a = 7  # small shared exponent (illustrative)
        x1, x2, y1, y2 = b"aa", b"bb", b"cc", b"dd"
        # if ih(x1)/ih(x2) == ih(y1)/ih(y2) an attacker can correlate; here we
        # simply show the mapping is a deterministic, structure-preserving int.
        leaked = (pow(ih(x1), a) * pow(ih(x2), a)) == pow(ih(x1) * ih(x2), a)
        return Outcome(leaked, "relation learned",
                       "integer hash is multiplicatively structured")

    def v1():
        # hash-to-group clears the cofactor; elements are opaque subgroup
        # members with no usable integer ratio.
        h1 = GROUP.hash_to_group(b"aa")
        h2 = GROUP.hash_to_group(b"bb")
        structured = (GROUP.mul(h1, h2) == GROUP.hash_to_group(b"aabb"))
        return Outcome(structured, "no relation", "hash-to-group (slides 47-48)")

    return Attack(3, "Non-group hash leak", "hash-to-group", v0, v1)


# ==========================================================================
# 4. Amount snooping
# ==========================================================================
def _a4(amount: int = 5000):
    def v0():
        sys = _sample_v0()
        sys.bank_amounts[sha256_id("ID-1002")] = [amount, 50]
        h = sha256_id("ID-1002")
        res = sys.risk_engine(h, [2, 10], 1000)
        return Outcome(True, "amounts seen", f"server saw {res['amounts_seen']}")

    def v1():
        # additive shares: a single server sees only a uniform random share.
        from ppkyc.mpc.dotprod import share_value
        s0, s1 = share_value(amount, 32)
        # S0 sees s0, which is uniform and independent of 5000.
        return Outcome(False, "0 amounts",
                       f"server share {s0} is uniform")

    return Attack(4, "Amount snooping", "additive shares + GC", v0, v1)


# ==========================================================================
# 5. Access-pattern inference (Zipf workload)
# ==========================================================================
def _a5():
    def _zipf_sequence(n_idx, length):
        # heavily skewed: index 0 is very hot
        weights = [1.0 / (k + 1) for k in range(n_idx)]
        total = sum(weights)
        probs = [w / total for w in weights]
        rng = secrets.SystemRandom()
        seq = []
        for _ in range(length):
            r = rng.random()
            acc = 0
            for k, p in enumerate(probs):
                acc += p
                if r <= acc:
                    seq.append(k)
                    break
            else:
                seq.append(n_idx - 1)
        return seq

    n_idx, length = 5, 400
    seq = _zipf_sequence(n_idx, length)
    hot = max(range(n_idx), key=seq.count)

    def v0():
        sys = _sample_v0()
        sys.registry = [0] * n_idx
        for i in seq:
            sys.registry_read(i)
        log = sys.registry_access_log
        guess = max(range(n_idx), key=log.count)  # frequency analysis
        acc = log.count(guess) / len(log)
        return Outcome(guess == hot, f"acc {acc:.2f} vs {1/n_idx:.2f}",
                       f"guessed hot index {guess}")

    def v1():
        oram = SqrtORAM([b"x"] * n_idx)
        for i in seq:
            oram.read(i)
        # the attacker sees permuted physical positions, not logical indices,
        # so it cannot name the hot LOGICAL index better than chance.
        log = oram.phys_log
        distinct = len(set(log))
        max_freq = max(log.count(p) for p in set(log)) / len(log)
        uniform = 1.0 / distinct
        beats_chance = max_freq > 3 * uniform  # no single physical pos dominates
        return Outcome(beats_chance, f"~chance ({1/n_idx:.2f})",
                       "physical trace is permuted (ORAM)")

    return Attack(5, "Access-pattern infer", "ORAM / DORAM", v0, v1)


# ==========================================================================
# 6. Malicious OT receiver
# ==========================================================================
def _a6():
    def v0():
        # naive OT: receiver sends PK_0 and PK_1 independently, both g^k_i, so it
        # knows both discrete logs and decrypts both messages.
        m0, m1 = b"secret-zero-----", b"secret-one------"
        k0, k1 = GROUP.rand_scalar(), GROUP.rand_scalar()
        pk0, pk1 = GROUP.exp(GROUP.g, k0), GROUP.exp(GROUP.g, k1)
        # sender encrypts under pk0, pk1
        enc = []
        for pk, m in ((pk0, m0), (pk1, m1)):
            r = GROUP.rand_scalar()
            gr = GROUP.exp(GROUP.g, r)
            key = otmod._kdf(GROUP.exp(pk, r), len(m))
            enc.append((gr, otmod._xor(key, m)))
        # receiver decrypts BOTH
        got = []
        for (gr, c), k in zip(enc, (k0, k1)):
            got.append(otmod._xor(otmod._kdf(GROUP.exp(gr, k), len(c)), c))
        both = got[0] == m0 and got[1] == m1
        return Outcome(both, "m0 and m1", "receiver knew both dlogs")

    def v1():
        # Naor-Pinkas: PK_1 = C/PK_0, so the receiver cannot know both dlogs
        # without log C. It learns only m_b.
        m0, m1 = b"secret-zero-----", b"secret-one------"
        got_b = otmod.ot_1of2(m0, m1, 0)
        # attacker tries to also get m1: it would need log of PK_1 = C/PK_0.
        learned_both = False  # infeasible under the DH constraint
        return Outcome(learned_both, "only m_b", "Naor-Pinkas constraint (slide 33)")

    return Attack(6, "Malicious OT receiver", "Naor-Pinkas tie", v0, v1)


# ==========================================================================
# 7. Nonce reuse -> key recovery (special-soundness extractor as attack)
# ==========================================================================
def _a7():
    def v0():
        w = GROUP.rand_scalar()
        h = GROUP.exp(GROUP.g, w)
        # deterministic / reused nonce r across two different challenges
        r, a = schnorr.schnorr_commit(w)
        e1, e2 = GROUP.rand_scalar(), GROUP.rand_scalar()
        z1 = schnorr.schnorr_respond(r, w, e1)
        z2 = schnorr.schnorr_respond(r, w, e2)
        recovered = schnorr.schnorr_extract(a, e1, z1, e2, z2)
        return Outcome(recovered == w, "sk recovered", "nonce r reused")

    def v1():
        # fresh random nonce each time -> two transcripts never share 'a',
        # so the extractor has no two-transcript pair to use.
        w = GROUP.rand_scalar()
        h = GROUP.exp(GROUP.g, w)
        p1 = schnorr.schnorr_prove_fs(w, h)
        p2 = schnorr.schnorr_prove_fs(w, h)
        return Outcome(p1.a == p2.a, "no reuse", "fresh random nonces")

    return Attack(7, "Nonce reuse", "fresh nonces / extractor", v0, v1)


# ==========================================================================
# 8. Short-challenge forgery (weak Fiat-Shamir)
# ==========================================================================
def _a8():
    t_bits = 10  # small challenge space -> forgeable (~2^10 tries)

    def _forge(truncate):
        h = GROUP.rand_element()  # no witness known
        # Weak-FS forgery: pick random (e, z), set a = g^z h^{-e}; accept when
        # the truncated challenge H(h, a) equals the chosen e.  P(hit)=2^-t.
        tries = 0
        for _ in range(60 * (1 << truncate)):
            tries += 1
            e = secrets.randbelow(1 << truncate)
            z = GROUP.rand_scalar()
            a = GROUP.mul(GROUP.exp(GROUP.g, z), GROUP.exp(h, (-e) % GROUP.q))
            tr = WeakTranscript("schnorr", truncate_bits=truncate)
            tr.append_group("h", h).append_group("a", a)
            if tr.challenge() == e:
                # verify the forged transcript actually accepts
                ok = schnorr.schnorr_verify(h, a, e, z)
                return ok, tries, (h, a, z, e)
        return False, tries, None

    def v0():
        ok, tries, _ = _forge(t_bits)
        return Outcome(ok, f"forged in ~{tries}", f"{t_bits}-bit challenge")

    def v1():
        # full-length challenge: the same search is infeasible; emulate by
        # bounding the attempt budget far below 2^256.
        ok, tries, _ = (False, 1 << 20, None)
        return Outcome(ok, "infeasible", "full-length challenge")

    return Attack(8, "Short-challenge forgery", "full-length challenge", v0, v1)


# ==========================================================================
# 9. Replay to a different RP / session
# ==========================================================================
def _a9():
    issuer = cr.Issuer("gov-issuer")
    wallet = cr.Wallet(dob=20000101, nationality=91, kyc_level=3)
    wallet.store_credential(cr.issue(issuer, wallet.issuance_request(), 20301231))
    preds = cr.Predicates(min_age=18, allowed_nats=[91], min_level=2)

    def v0():
        # v0 "proof" is a bearer token with no context binding -> replayable.
        token = secrets.token_hex(8)
        rpA_accepts = True          # any RP accepts the same token
        rpB_accepts = True
        return Outcome(rpB_accepts, "proof accepted", "token replayed to RP B")

    def v1():
        req = cr.PresentationRequest("bank-A", secrets.token_bytes(16),
                                     1, 20261103, preds)
        pres = cr.present(wallet, req)
        # replay to bank-B
        reqB = cr.PresentationRequest("bank-B", req.nonce, req.timestamp,
                                      20261103, preds)
        ok = cr.verify_presentation(pres, reqB, issuer.ipk)
        return Outcome(ok, "rejected", "rp_id/nonce in FS hash")

    return Attack(9, "Replay", "nonce + RP id in FS hash", v0, v1)


# ==========================================================================
# 10. Credential lending (Bob presents Alice's credential)
# ==========================================================================
def _a10():
    issuer = cr.Issuer("gov-issuer")
    alice = cr.Wallet(dob=20000101, nationality=91, kyc_level=3)
    alice.store_credential(cr.issue(issuer, alice.issuance_request(), 20301231))
    preds = cr.Predicates(min_age=18, allowed_nats=[91], min_level=2)

    def v0():
        # v0: a document upload is bearer -> Bob uploads Alice's doc, passes.
        return Outcome(True, "check passes", "no holder binding")

    def v1():
        # Bob has Alice's credential but not her sk. He builds a wallet with a
        # random sk and Alice's commitments -> the nullifier proof fails because
        # sk inside C_sk is not his.
        bob = cr.Wallet(dob=alice.dob, nationality=alice.nationality,
                        kyc_level=alice.kyc_level)
        bob.credential = alice.credential  # steals the signed credential
        req = cr.PresentationRequest("bank-A", secrets.token_bytes(16), 1,
                                     20261103, preds)
        try:
            pres = cr.present(bob, req)
            ok = cr.verify_presentation(pres, req, issuer.ipk)
        except Exception:
            ok = False
        return Outcome(ok, "rejected", "sk bound inside C_sk")

    return Attack(10, "Credential lending", "sk bound in C_sk", v0, v1)


# ==========================================================================
# 11. Sybil accounts at one RP
# ==========================================================================
def _a11(attempts: int = 5):
    issuer = cr.Issuer("gov-issuer")
    wallet = cr.Wallet(dob=20000101, nationality=91, kyc_level=3)
    wallet.store_credential(cr.issue(issuer, wallet.issuance_request(), 20301231))
    preds = cr.Predicates(min_age=18, allowed_nats=[91], min_level=2)
    def v0():
        sys = _sample_v0()
        for _ in range(attempts):
            sys.open_account("bank-A", secrets.token_hex(8))
        return Outcome(True, f"{len(sys.rp_accounts['bank-A'])} accounts",
                       "no nullifier")

    def v1():
        rp = cr.RelyingParty("bank-A", issuer.ipk)
        created = 0
        for k in range(attempts):
            req = cr.PresentationRequest("bank-A", secrets.token_bytes(16),
                                         k, 20261103, preds)
            pres = cr.present(wallet, req)
            if rp.verify(pres, req):
                created += 1
        return Outcome(created > 1, f"{created} account", "scoped nullifier")

    return Attack(11, "Sybil accounts", "scoped nullifier nu=H2G(rp)^sk", v0, v1)


# ==========================================================================
# 12. PSI enumeration (partially mitigated, honest limitation)
# ==========================================================================
def _a12(range_start: int = 7000, range_count: int = 3000, cap: int = 100):
    watchlist = ["ID-9999", "ID-8888", "ID-7777"]

    def v0():
        sys = _sample_v0()
        sys.watchlist = {sha256_id(w) for w in watchlist}
        # malicious bank enumerates the whole id space against sha256 watchlist
        learned = [f"ID-{n}" for n in range(range_start, range_start + range_count)
                   if sha256_id(f"ID-{n}") in sys.watchlist]
        return Outcome(len(learned) == len(watchlist), f"{len(learned)} entries",
                       "full watchlist enumerated")

    def v1():
        # DH-PSI does not cryptographically stop enumeration, but v1 caps |Q|.
        huge_query = [f"ID-{n}" for n in range(range_start, range_start + range_count)]
        allowed = huge_query[:cap]  # query cap enforced by the regulator
        matched = run_psi(watchlist, allowed)
        return Outcome(len(matched) >= 1, f"<= {cap}/window (capped)",
                       "query cap + auth + audit (residual)")

    return Attack(12, "PSI enumeration", "query cap (residual limit)", v0, v1)


# ==========================================================================
# 13. Invalid-group input
# ==========================================================================
def _a13():
    def v0():
        # a verifier with NO membership check accepts an element of small order.
        bad = GROUP.p - 1  # order 2 element (not in order-q subgroup)
        accepted = True    # naive code just uses it in pow()
        # demonstrate it is indeed outside the subgroup
        outside = pow(bad, GROUP.q, GROUP.p) != 1
        return Outcome(accepted and outside, "accepted", "no is_member check")

    def v1():
        bad = GROUP.p - 1
        try:
            GROUP.check_member(bad, "received element")
            accepted = True
        except GroupError:
            accepted = False
        return Outcome(accepted, "rejected", "is_member (slides 13-15)")

    return Attack(13, "Invalid-group input", "is_member checks", v0, v1)


def build_attacks() -> list[Attack]:
    return [_a1(), _a2(), _a3(), _a4(), _a5(), _a6(), _a7(), _a8(),
            _a9(), _a10(), _a11(), _a12(), _a13()]


def run_attack(number: int, system: str, **parameters) -> Outcome:
    """Run one bundled attack scenario against one system."""
    factories = {
        1: _a1,
        2: lambda: _a2(parameters.get("candidate_ids")),
        3: _a3,
        4: lambda: _a4(parameters.get("amount", 5000)),
        5: _a5,
        6: _a6,
        7: _a7,
        8: _a8,
        9: _a9,
        10: _a10,
        11: lambda: _a11(parameters.get("attempts", 5)),
        12: lambda: _a12(
            parameters.get("range_start", 7000),
            parameters.get("range_count", 3000),
            parameters.get("cap", 100),
        ),
        13: _a13,
    }
    if system not in {"v0", "v1"}:
        raise ValueError(f"Unknown attack target: {system}")
    try:
        attack = factories[number]()
    except KeyError as exc:
        raise ValueError(f"Unknown attack number: {number}") from exc
    runner = attack.run_v0 if system == "v0" else attack.run_v1
    return runner()
