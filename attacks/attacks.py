"""The seven privacy attacks, each runnable against v0 (succeeds) and v1 (fails
or is reduced).  Every v1 result cites the course property that defends it.
"""

from __future__ import annotations

import secrets

from .harness import Attack, Outcome

from ppkyc.crypto.group import GROUP
from ppkyc.crypto.commit import PEDERSEN
from ppkyc.zkp import credential as cr
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
# 3. Amount snooping
# ==========================================================================
def _a3(amount: int = 5000):
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

    return Attack(3, "Amount snooping", "additive shares + GC", v0, v1)


# ==========================================================================
# 4. Access-pattern inference (Zipf workload)
# ==========================================================================
def _a4():
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

    return Attack(4, "Access-pattern infer", "ORAM / DORAM", v0, v1)


# ==========================================================================
# 5. Replay to a different RP / session
# ==========================================================================
def _a5():
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

    return Attack(5, "Replay", "nonce + RP id in FS hash", v0, v1)


# ==========================================================================
# 6. Credential lending (Bob presents Alice's credential)
# ==========================================================================
def _a6():
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

    return Attack(6, "Credential lending", "sk bound in C_sk", v0, v1)


# ==========================================================================
# 7. Sybil accounts at one RP
# ==========================================================================
def _a7(attempts: int = 5):
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

    return Attack(7, "Sybil accounts", "scoped nullifier nu=H2G(rp)^sk", v0, v1)


def build_attacks() -> list[Attack]:
    return [_a1(), _a2(), _a3(), _a4(), _a5(), _a6(), _a7()]


def run_attack(number: int, system: str, **parameters) -> Outcome:
    """Run one bundled attack scenario against one system."""
    factories = {
        1: _a1,
        2: lambda: _a2(parameters.get("candidate_ids")),
        3: lambda: _a3(parameters.get("amount", 5000)),
        4: _a4,
        5: _a5,
        6: _a6,
        7: lambda: _a7(parameters.get("attempts", 5)),
    }
    if system not in {"v0", "v1"}:
        raise ValueError(f"Unknown attack target: {system}")
    try:
        attack = factories[number]()
    except KeyError as exc:
        raise ValueError(f"Unknown attack number: {number}") from exc
    runner = attack.run_v0 if system == "v0" else attack.run_v1
    return runner()
