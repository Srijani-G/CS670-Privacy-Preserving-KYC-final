"""Known-answer and correctness tests for the shared cryptographic core."""

import random
import secrets

from ppkyc.crypto.group import GROUP, PEDERSEN_H, GroupError
from ppkyc.crypto.commit import PEDERSEN, hash_commit, hash_open
from ppkyc.crypto.sharing import AdditiveZ2k, split_zq, combine_zq
from ppkyc.crypto import ot as otmod
from ppkyc.crypto import gc


def test_group_subgroup():
    assert pow(GROUP.g, GROUP.q, GROUP.p) == 1
    assert GROUP.is_member(PEDERSEN_H)
    h = GROUP.rand_element()
    assert GROUP.is_member(h)
    assert not GROUP.is_member(GROUP.p - 1)   # order-2 element
    assert not GROUP.is_member(1)


def test_group_inverse_and_div():
    a = GROUP.rand_element()
    assert GROUP.mul(a, GROUP.inv(a)) == 1
    b = GROUP.rand_element()
    assert GROUP.mul(GROUP.div(a, b), b) == a


def test_hash_to_group_deterministic():
    assert GROUP.hash_to_group(b"x") == GROUP.hash_to_group(b"x")
    assert GROUP.hash_to_group(b"x") != GROUP.hash_to_group(b"y")
    assert GROUP.is_member(GROUP.hash_to_group(b"anything"))


def test_pedersen_hiding_binding():
    c, r = PEDERSEN.commit(42)
    assert PEDERSEN.open(c, 42, r)
    assert not PEDERSEN.open(c, 43, r)
    # homomorphic
    c1, r1 = PEDERSEN.commit(10)
    c2, r2 = PEDERSEN.commit(20)
    assert PEDERSEN.open(PEDERSEN.add(c1, c2), 30, (r1 + r2) % GROUP.q)


def test_hash_commit():
    com, r = hash_commit(b"msg")
    assert hash_open(com, b"msg", r=r)
    assert not hash_open(com, b"other", r=r)


def test_additive_sharing():
    sh = AdditiveZ2k(32)
    s = sh.share(123456789, 3)
    assert sh.reconstruct(s) == 123456789
    a = sh.share(100, 2)
    b = sh.share(250, 2)
    assert sh.reconstruct(sh.add(a, b)) == 350


def test_zq_sharing():
    s = split_zq(999, 3)
    assert combine_zq(s) == 999


def test_ot_correctness_including_zero_bytes():
    for _ in range(100):
        m0 = secrets.token_bytes(16)
        m1 = secrets.token_bytes(16)
        b = secrets.randbelow(2)
        assert otmod.ot_1of2(m0, m1, b) == (m0 if b == 0 else m1)
    # messages ending in zero bytes must still round-trip
    m0 = b"\x00" * 16
    m1 = secrets.token_bytes(15) + b"\x00"
    assert otmod.ot_1of2(m0, m1, 0) == m0
    assert otmod.ot_1of2(m0, m1, 1) == m1


def test_gc_gates_exhaustive():
    for kind in ["XOR", "AND", "OR", "NOT"]:
        cb = gc.CircuitBuilder()
        a = cb.garbler_input()
        b = cb.evaluator_input()
        out = {"XOR": lambda: cb.XOR(a, b), "AND": lambda: cb.AND(a, b),
               "OR": lambda: cb.OR(a, b), "NOT": lambda: cb.NOT(a)}[kind]()
        circ = cb.finish([out])
        for av in (0, 1):
            for bv in (0, 1):
                g = gc.garble(circ)
                gin = gc.garbler_labels(g, [av])
                l0, l1 = gc.evaluator_label_pair(g, b)
                ein = {b: l0 if bv == 0 else l1}
                got = gc.evaluate(g, gin, ein)[0]
                want = {"XOR": av ^ bv, "AND": av & bv,
                        "OR": av | bv, "NOT": 1 - av}[kind]
                assert got == want, (kind, av, bv)


def test_gc_add_compare_matches_plaintext():
    bits = 8
    for _ in range(20):
        a = random.randrange(2 ** bits)
        x = random.randrange(2 ** bits)
        t = random.randrange(2 ** (bits + 1))
        assert gc.run_add_compare(bits, a, x, t) == int((a + x) >= t)
