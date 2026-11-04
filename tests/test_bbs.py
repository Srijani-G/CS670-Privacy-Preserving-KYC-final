"""Tests for the BBS+ credential upgrade (issues #1 unlinkability, #2 blind issuance).

Run as part of the suite (``python run_tests.py``) or directly
(``python -m tests.test_bbs``).  Requires ``py_ecc``.
"""

from __future__ import annotations

from py_ecc.optimized_bls12_381 import eq

from ppkyc.zkp import bbs
from ppkyc.zkp import credential_bbs as cb


def test_sign_verify_and_tamper():
    p = bbs.BBSParams.create(4)
    k = bbs.BBSKey.generate(p)
    msgs = [bbs.rand_scalar(), 20030615, 91, 3]
    sig = bbs.sign(p, k, msgs)
    assert bbs.verify(p, k.pk, msgs, sig)
    bad = list(msgs); bad[2] = 44
    assert not bbs.verify(p, k.pk, bad, sig)


def test_blind_issuance_hides_sk():
    p = bbs.BBSParams.create(4)
    k = bbs.BBSKey.generate(p)
    sk = bbs.rand_scalar()
    req, s_user = bbs.blind_request(p, sk)
    # issuer only verifies the opening proof; it never receives sk
    assert bbs.blind_request_valid(p, req)
    bsig = bbs.blind_sign(p, k, req, {1: 20030615, 2: 91, 3: 3})
    full = bbs.unblind(bsig, s_user)
    assert bbs.verify(p, k.pk, [sk, 20030615, 91, 3], full)
    # a request with a tampered opening proof is rejected
    req2, _ = bbs.blind_request(p, sk)
    req2.z_sk = (req2.z_sk + 1) % bbs.P
    assert not bbs.blind_request_valid(p, req2)


def test_presentation_unlinkable_but_nullifier_stable():
    p = bbs.BBSParams.create(4)
    k = bbs.BBSKey.generate(p)
    msgs = [bbs.rand_scalar(), 20030615, 91, 3]
    sig = bbs.sign(p, k, msgs)
    pr1 = bbs.present(p, msgs, sig, [2], b"bank-A")
    pr2 = bbs.present(p, msgs, sig, [2], b"bank-A")
    pr3 = bbs.present(p, msgs, sig, [2], b"bank-B")
    assert bbs.verify_present(p, k.pk, pr1, b"bank-A")
    assert bbs.verify_present(p, k.pk, pr2, b"bank-A")
    # #1: re-randomised -> two shows are unlinkable
    assert not eq(pr1.Ap, pr2.Ap)
    assert not eq(pr1.Abar, pr2.Abar)
    # same RP + same sk -> same nullifier (sybil detectable)
    assert eq(pr1.nu, pr2.nu)
    # different RP -> different nullifier (cross-RP unlinkable)
    assert not eq(pr1.nu, pr3.nu)


def test_presentation_soundness():
    p = bbs.BBSParams.create(4)
    k = bbs.BBSKey.generate(p)
    msgs = [bbs.rand_scalar(), 20030615, 91, 3]
    sig = bbs.sign(p, k, msgs)
    pr = bbs.present(p, msgs, sig, [2], b"bank-A")
    pr.z_s = (pr.z_s + 1) % bbs.P
    assert not bbs.verify_present(p, k.pk, pr, b"bank-A")
    # presentation is bound to the RP: verifying under another RP fails
    pr2 = bbs.present(p, msgs, sig, [2], b"bank-A")
    assert not bbs.verify_present(p, k.pk, pr2, b"bank-B")


def test_kyc_flow_blind_issue_and_sybil():
    issuer = cb.Issuer("gov-issuer")
    alice = cb.Wallet(dob=20030615, nationality=91, kyc_level=3)
    cb.issue(issuer, alice, expected={"dob": 20030615, "nat": 91, "level": 3})
    rp = cb.RelyingParty("bank-A", issuer.pk, allowed_nats=[1, 44, 91])
    req = cb.PresentationRequest("bank-A", disclose=(cb.NAT,))
    assert rp.verify(cb.present(alice, req))          # first show accepted
    assert not rp.verify(cb.present(alice, req))      # second show at same RP -> sybil reject
    # a disallowed nationality is rejected
    bob = cb.Wallet(dob=19900101, nationality=7, kyc_level=3)
    cb.issue(issuer, bob)
    assert not rp.verify(cb.present(bob, cb.PresentationRequest("bank-A", disclose=(cb.NAT,))))


def run():
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  PASS {name}")
    print("test_bbs: all passed")


if __name__ == "__main__":
    run()
