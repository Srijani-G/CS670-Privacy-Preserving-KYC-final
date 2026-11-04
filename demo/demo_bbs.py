"""Demo: the BBS+ credential upgrade (issues #1 unlinkability, #2 blind issuance).

Run with:  python -m demo.demo_bbs   (requires py_ecc)

Contrast with Module D in demo.demo: there, every presentation reused the same
static commitments (linkable); here each presentation is re-randomised and the
issuer never learns ``sk``.
"""

from __future__ import annotations

from py_ecc.optimized_bls12_381 import eq, normalize

from ppkyc.zkp import credential_bbs as cb


def _tag(pt) -> str:
    x, _ = normalize(pt)
    return hex(x.n)[:18] + "..."


def main():
    print("=" * 72)
    print("BBS+ credential upgrade  -  unlinkable, blindly issued")
    print("=" * 72)

    issuer = cb.Issuer("gov-issuer-IN")
    print(f"Issuer public key (G2) pinned by every RP.")

    # ---- #2 blind issuance ------------------------------------------------
    alice = cb.Wallet(dob=20030615, nationality=91, kyc_level=3)
    cb.issue(issuer, alice, expected={"dob": 20030615, "nat": 91, "level": 3})
    print("\n[#2 blind issuance]")
    print("  Alice commits to sk and proves she knows it; issuer signs the")
    print("  COMMITMENT plus the attributes it verified at KYC time.")
    print("  -> issuer learned dob/nat/level but NEVER sk, and cannot link")
    print("     the issued credential to any future presentation.")

    # ---- #1 unlinkable multi-show ----------------------------------------
    rp_a = cb.RelyingParty("bank-A", issuer.pk, allowed_nats=[1, 44, 91])
    rp_b = cb.RelyingParty("bank-B", issuer.pk, allowed_nats=[1, 44, 91])

    print("\n[#1 multi-show unlinkability]")
    pres1 = cb.present(alice, cb.PresentationRequest("bank-A", disclose=(cb.NAT,)))
    ok1 = rp_a.verify(pres1)
    print(f"  Show #1 at Bank-A: {'ACCEPT' if ok1 else 'REJECT'}  "
          f"(A'={_tag(pres1.Ap)}, nullifier={_tag(pres1.nu)})")

    pres2 = cb.present(alice, cb.PresentationRequest("bank-B", disclose=(cb.NAT,)))
    ok2 = rp_b.verify(pres2)
    print(f"  Show #2 at Bank-B: {'ACCEPT' if ok2 else 'REJECT'}  "
          f"(A'={_tag(pres2.Ap)}, nullifier={_tag(pres2.nu)})")

    print(f"\n  A' differs between shows : {not eq(pres1.Ap, pres2.Ap)}  "
          f"-> the two credentials are UNLINKABLE")
    print(f"  nullifier differs per RP : {not eq(pres1.nu, pres2.nu)}  "
          f"-> Bank-A and Bank-B cannot correlate Alice")

    # ---- sybil resistance still holds ------------------------------------
    print("\n[sybil resistance preserved]")
    pres3 = cb.present(alice, cb.PresentationRequest("bank-A", disclose=(cb.NAT,)))
    ok3 = rp_a.verify(pres3)
    print(f"  Second account attempt at Bank-A: "
          f"{'ACCEPT' if ok3 else 'REJECT (duplicate nullifier)'}")
    print("    (re-randomised proof, but same sk+RP -> same nullifier -> caught)")

    print("\nDone.")


if __name__ == "__main__":
    main()
