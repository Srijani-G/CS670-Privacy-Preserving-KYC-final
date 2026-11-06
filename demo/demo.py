"""End-to-end CLI demo of all four modules, plus the v0-vs-v1 attack lab.

Run with:  python -m demo.demo
"""

from __future__ import annotations

import secrets

from ppkyc.channel import Channel
from ppkyc.psi.dh_psi import run_psi
from ppkyc.mpc.pipeline import run_pipeline
from ppkyc.oram.doram_ro import (
    RegistryServer, RegistryClient, generate_synthetic_registry,
    encode_registry_statuses, KYC_STATUS_LABELS,
)
from ppkyc.zkp import credential as cr
from attacks.attacks import build_attacks
from attacks.harness import run_all


def hr(title):
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def demo_module_d():
    hr("Module D - Verifiable KYC claims (ZKP credentials)")
    issuer = cr.Issuer("gov-issuer-IN")
    print(f"Issuer public key pinned by every RP: {hex(issuer.ipk)[:20]}...")

    # Alice: born 2003-06-15, Indian national (code 91), KYC level 3
    alice = cr.Wallet(dob=20030615, nationality=91, kyc_level=3)
    cred = cr.issue(issuer, alice.issuance_request(), expiry=20301231,
                    expected={"dob": 20030615, "nat": 91, "level": 3})
    alice.store_credential(cred)
    print("Alice received an issuer-signed credential (attributes stay in her wallet).")

    preds = cr.Predicates(min_age=18, allowed_nats=[1, 44, 91], min_level=2)
    print("\nBank-A policy: age >= 18 AND nationality in {US,GB,IN} AND kyc_level >= 2")
    rp = cr.RelyingParty("bank-A", issuer.ipk)
    req = cr.PresentationRequest("bank-A", secrets.token_bytes(16),
                                 1730600000, 20261103, preds)
    pres = cr.present(alice, req)
    print(f"  wallet produced a combined ZK proof (nullifier {hex(pres.nullifier.nu)[:16]}...)")
    print(f"  verifier result: {'ACCEPT' if rp.verify(pres, req) else 'REJECT'} "
          f"(learned only pass/fail, never Alice's DOB/ID)")

    print("\n  Replay the same proof to Bank-B:")
    reqB = cr.PresentationRequest("bank-B", req.nonce, req.timestamp, 20261103, preds)
    print(f"    result: {'ACCEPT' if cr.verify_presentation(pres, reqB, issuer.ipk) else 'REJECT (bound to bank-A)'}")

    print("\n  Alice tries to open a second account at Bank-A (sybil):")
    req2 = cr.PresentationRequest("bank-A", secrets.token_bytes(16), 1730600001, 20261103, preds)
    print(f"    result: {'ACCEPT' if rp.verify(cr.present(alice, req2), req2) else 'REJECT (duplicate nullifier)'}")


def demo_module_a():
    hr("Module A - Sanctions screening (DH private set intersection)")
    watch = ["John Doe|19800101|US", "Mallory|19700505|RU", "Jane Roe|19900202|GB"]
    custs = ["alice|19950303|IN", "MALLORY|19700505|RU", "bob|19880808|US"]
    ch = Channel()
    matched = run_psi(watch, custs, ch)
    print(f"Regulator watchlist size |W| = {len(watch)} (stays hidden)")
    print(f"Bank customers |Q| = {len(custs)}")
    print(f"Bank learns ONLY its own matches: {matched}")
    print(f"  ({ch.rounds()} messages, {ch.total_bytes()} bytes; raw IDs never exchanged)")


def demo_module_b():
    hr("Module B - Cross-bank AML analytics (hybrid MPC)")
    banks = [[1200, 4], [3000, 6], [800, 2]]
    weights = [2, 50]
    ch = Channel()
    r = run_pipeline(banks, weights, threshold=8000, bits=24, channel=ch)
    print("Three banks secret-share per-customer features between S0 and S1.")
    print(f"Regulator's private model weights {weights} never revealed.")
    print(f"Risk score computed under MPC; flag (score >= 8000) = {bool(r['flag'])}")
    print(f"  neither server saw any bank's raw amounts ({ch.rounds()} protocol messages)")


def demo_module_c():
    hr("Module C - Private KYC-status registry (read-only 2-server DORAM)")
    records = generate_synthetic_registry(size=1024, seed=670)
    db = encode_registry_statuses(records)
    s0, s1 = RegistryServer("S0", db), RegistryServer("S1", db)
    cli = RegistryClient(s0, s1)
    ch = Channel()
    idx = 511
    record = records[idx]
    val = cli.read(idx, ch)
    print(f"Synthetic registry contains {len(records):,} fictional customer records.")
    print(f"Both DORAM servers hold identical arrays of {len(db):,} KYC status codes.")
    print(f"Example selected record: {record['customer_id']} | {record['full_name']} | "
          f"{record['nationality']} | risk={record['risk_category']}")
    print(f"Client privately reads its KYC status: {KYC_STATUS_LABELS[val]} "
          f"(expected {record['kyc_status']})")
    print("  DORAM accesses the integer status array; metadata stays in the local fixture.")
    print("  each server got a random one-hot share; neither learns which index.")
    print(f"  server S0 query log (vector lengths only): {s0.query_log}")


def demo_attacks():
    hr("Attack lab - the same attack on v0 (naive) and v1 (private)")
    run_all(build_attacks())


def main():
    print("Privacy-Preserving KYC/AML  -  end-to-end demo")
    demo_module_d()
    demo_module_a()
    demo_module_b()
    demo_module_c()
    demo_attacks()
    print("\nDone.")


if __name__ == "__main__":
    main()
