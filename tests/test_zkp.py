"""Completeness, soundness, simulator and extractor tests for Module D."""

import secrets

from ppkyc.crypto.group import GROUP
from ppkyc.crypto.commit import PEDERSEN
from ppkyc.zkp import schnorr, dleq, orproof
from ppkyc.zkp import range as rng
from ppkyc.zkp import credential as cr
from ppkyc.zkp import mpcith


# -- sigma: completeness / soundness / SHVZK / extractor -------------------
def test_schnorr_complete_sound():
    w = GROUP.rand_scalar()
    h = GROUP.exp(GROUP.g, w)
    p = schnorr.schnorr_prove_fs(w, h)
    assert schnorr.schnorr_verify_fs(h, p)
    p.z = (p.z + 1) % GROUP.q        # flip a byte -> reject
    assert not schnorr.schnorr_verify_fs(h, p)


def test_schnorr_simulator_verifies():
    h = GROUP.rand_element()
    sim = schnorr.schnorr_simulate(h)
    assert schnorr.schnorr_verify(h, sim.a, sim.e, sim.z)


def test_schnorr_extractor_recovers_witness():
    w = GROUP.rand_scalar()
    r, a = schnorr.schnorr_commit(w)
    e1, e2 = GROUP.rand_scalar(), GROUP.rand_scalar()
    z1 = schnorr.schnorr_respond(r, w, e1)
    z2 = schnorr.schnorr_respond(r, w, e2)
    assert schnorr.schnorr_extract(a, e1, z1, e2, z2) == w


def test_pedersen_opening_proof():
    m = 7777
    C, s = PEDERSEN.commit(m)
    op = schnorr.opening_prove_fs(m, s, C)
    assert schnorr.opening_verify_fs(C, op)
    op.zm = (op.zm + 1) % GROUP.q
    assert not schnorr.opening_verify_fs(C, op)


def test_dleq():
    w = GROUP.rand_scalar()
    g, u = GROUP.g, GROUP.rand_element()
    A, B = GROUP.exp(g, w), GROUP.exp(u, w)
    p = dleq.dleq_prove_fs(w, g, u, A, B)
    assert dleq.dleq_verify_fs(g, u, A, B, p)
    assert not dleq.dleq_verify_fs(g, u, A, GROUP.exp(u, (w + 1) % GROUP.q), p)


def test_or_proof():
    bases = [GROUP.g] * 3
    w = GROUP.rand_scalar()
    targets = [GROUP.rand_element(), GROUP.exp(GROUP.g, w), GROUP.rand_element()]
    p = orproof.or_prove_fs(bases, targets, 1, w, ctx=b"c")
    assert orproof.or_verify_fs(bases, targets, p, ctx=b"c")
    assert not orproof.or_verify_fs(bases, targets, p, ctx=b"other")


def test_range_proof_complete_and_sound():
    for v in [0, 1, 255, 1000, (1 << 16) - 1]:
        C, r = PEDERSEN.commit(v)
        p = rng.range_prove(C, v, r, 16, ctx=b"x")
        assert rng.range_verify(C, p, ctx=b"x")
    # wrong commitment rejected
    C, r = PEDERSEN.commit(5)
    p = rng.range_prove(C, 5, r, 16, ctx=b"x")
    assert not rng.range_verify(GROUP.rand_element(), p, ctx=b"x")


# -- credential issuance / presentation ------------------------------------
def _make_wallet(issuer, dob=20030615, nat=91, level=3, expiry=20301231):
    w = cr.Wallet(dob=dob, nationality=nat, kyc_level=level)
    w.store_credential(cr.issue(issuer, w.issuance_request(), expiry,
                                expected={"dob": dob, "nat": nat, "level": level}))
    return w


def test_credential_honest_presentation():
    issuer = cr.Issuer("gov")
    w = _make_wallet(issuer)
    preds = cr.Predicates(min_age=18, allowed_nats=[1, 44, 91], min_level=2)
    req = cr.PresentationRequest("bank-A", secrets.token_bytes(16), 1, 20261103, preds)
    pres = cr.present(w, req)
    assert cr.verify_presentation(pres, req, issuer.ipk)


def test_credential_replay_rejected():
    issuer = cr.Issuer("gov")
    w = _make_wallet(issuer)
    preds = cr.Predicates(min_age=18, allowed_nats=[91], min_level=2)
    req = cr.PresentationRequest("bank-A", secrets.token_bytes(16), 1, 20261103, preds)
    pres = cr.present(w, req)
    reqB = cr.PresentationRequest("bank-B", req.nonce, req.timestamp, 20261103, preds)
    assert not cr.verify_presentation(pres, reqB, issuer.ipk)


def test_credential_sybil_nullifier():
    issuer = cr.Issuer("gov")
    w = _make_wallet(issuer)
    preds = cr.Predicates(min_age=18, allowed_nats=[91], min_level=2)
    rp = cr.RelyingParty("bank-A", issuer.ipk)
    req1 = cr.PresentationRequest("bank-A", secrets.token_bytes(16), 1, 20261103, preds)
    req2 = cr.PresentationRequest("bank-A", secrets.token_bytes(16), 2, 20261103, preds)
    p1, p2 = cr.present(w, req1), cr.present(w, req2)
    assert p1.nullifier.nu == p2.nullifier.nu  # same RP + sk -> same nullifier
    assert rp.verify(p1, req1)
    assert not rp.verify(p2, req2)             # duplicate rejected


def test_credential_rogue_issuer_rejected():
    issuer = cr.Issuer("gov")
    rogue = cr.Issuer("rogue")
    w = _make_wallet(issuer)
    preds = cr.Predicates(min_age=18, allowed_nats=[91], min_level=2)
    req = cr.PresentationRequest("bank-A", secrets.token_bytes(16), 1, 20261103, preds)
    pres = cr.present(w, req)
    assert not cr.verify_presentation(pres, req, rogue.ipk)


def test_underage_cannot_prove():
    issuer = cr.Issuer("gov")
    w = _make_wallet(issuer, dob=20150101)
    preds = cr.Predicates(min_age=18)
    req = cr.PresentationRequest("bank-A", secrets.token_bytes(16), 1, 20261103, preds)
    try:
        cr.present(w, req)
        assert False, "underage wallet should not produce a proof"
    except ValueError:
        pass


def test_mpcith_age_proof():
    pf = mpcith.prove(50488, 40000, 24, n_rounds=24)
    assert mpcith.verify(pf)
    pf.rounds[0].output_shares[0] ^= 1
    assert not mpcith.verify(pf)
