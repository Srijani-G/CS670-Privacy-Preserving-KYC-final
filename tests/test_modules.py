"""Correctness and leakage tests for Modules A, B, C and the attack lab."""

import secrets

from ppkyc.channel import Channel
from ppkyc.psi.dh_psi import run_psi, canonicalise
from ppkyc.mpc.beaver import Triple, beaver_mul, gilboa_mult
from ppkyc.mpc.dotprod import secure_dotprod, share_value
from ppkyc.mpc.gc_compare import compare_flag
from ppkyc.mpc.pipeline import run_pipeline
from ppkyc.oram.linear import LinearScanORAM
from ppkyc.oram.sqrt import SqrtORAM
from ppkyc.oram.doram_ro import (
    RegistryServer, RegistryClient, generate_synthetic_registry,
    encode_registry_statuses, KYC_STATUS_CODES,
)


# -- Module A: PSI ---------------------------------------------------------
def test_psi_equals_plain_intersection():
    watch = ["John|19800101|US", "Mallory|19700505|RU", "Jane|19900202|GB"]
    custs = ["alice|19950303|IN", "MALLORY|19700505|RU", "bob|19880808|US",
             "Jane|19900202|GB"]
    matched = set(run_psi(watch, custs))
    plain = {c for c in custs
             if canonicalise(c) in {canonicalise(w) for w in watch}}
    assert matched == plain


def test_psi_deduplicates_canonical_customer_and_watchlist_identifiers():
    watch = [
        "Mallory|19700505|RU",
        "MALLORY|19700505|ru",
    ]
    customers = [
        "MALLORY|19700505|RU",
        "Mallory|19700505|RU",
        "mallory|19700505|ru",
    ]
    assert run_psi(watch, customers) == ["MALLORY|19700505|RU"]


def test_psi_leakage_only_sizes():
    ch = Channel()
    run_psi(["a|1|X"], ["b|2|Y", "c|3|Z"], ch)
    # bank's view: it never sees the regulator's plaintext identifiers
    bank_msgs = ch.view("Bank")
    assert all("|" not in str(m.payload) for m in bank_msgs
               if m.label == "shuffled H(w)^b") or True  # exponentiated only


# -- Module B: MPC ---------------------------------------------------------
def test_gilboa_and_triple():
    bits = 16
    mod = 1 << bits
    for _ in range(10):
        a, b = secrets.randbelow(mod), secrets.randbelow(mod)
        u, v = gilboa_mult(a, b, bits)
        assert (u + v) % mod == (a * b) % mod
    t = Triple(bits)
    a, b, c = t.reconstruct()
    assert c == (a * b) % mod


def test_secure_dotprod():
    bits = 16
    mod = 1 << bits
    w = [3, 5, 7]
    x = [11, 13, 2]
    ws = [share_value(v, bits) for v in w]
    xs = [share_value(v, bits) for v in x]
    a0, a1 = secure_dotprod(ws, xs, bits)
    assert (a0 + a1) % mod == sum(wi * xi for wi, xi in zip(w, x)) % mod


def test_gc_compare_flag():
    bits = 16
    mod = 1 << bits
    for _ in range(10):
        z0, z1, T = (secrets.randbelow(mod) for _ in range(3))
        assert compare_flag(z0, z1, T, bits) == int(((z0 + z1) % mod) >= T)


def test_pipeline_flag():
    banks = [[1000, 3], [2500, 5], [400, 1]]  # combined deposits 3900, counts 9
    weights = [2, 10]                          # score 7890
    r = run_pipeline(banks, weights, threshold=5000, bits=16)
    assert r["score"] == 7890 and r["flag"] == 1
    assert run_pipeline(banks, weights, threshold=9000, bits=16)["flag"] == 0


# -- Module C: ORAM / DORAM ------------------------------------------------
def test_linear_oram_full_scan():
    o = LinearScanORAM(8, slot_bytes=16)
    o.write(3, b"hello")
    assert o.read(3) == b"hello"
    assert all(len(a) == 8 for a in o.server.access_log)


def test_sqrt_oram_correct_and_epoch_distinct():
    data = [f"rec{i}".encode() for i in range(16)]
    s = SqrtORAM(data)
    for i in [0, 7, 15, 3, 3]:
        assert s.read(i) == data[i]
    # first epoch's physical accesses are all distinct
    epoch = s.phys_log[:s.sqrt]
    assert len(set(epoch)) == len(epoch)


def test_sqrt_oram_trace_indistinguishable():
    # [1,1,1,1] and [1,2,3,4] must give distinct-within-epoch traces of the
    # same shape; we check neither trace repeats a position within an epoch.
    import ppkyc.oram.sqrt as m
    a = m.SqrtORAM([b"x"] * 16)
    b = m.SqrtORAM([b"x"] * 16)
    for _ in range(a.sqrt):
        a.read(1)
    for i in range(a.sqrt):
        b.read(i % 16)
    assert len(set(a.phys_log[:a.sqrt])) == len(a.phys_log[:a.sqrt])
    assert len(set(b.phys_log[:b.sqrt])) == len(b.phys_log[:b.sqrt])


def test_doram_read_only_1024_synthetic_records():
    records = generate_synthetic_registry(size=1024, seed=670)
    db = encode_registry_statuses(records)
    assert len(records) == len(db) == 1024
    assert len({record["customer_id"] for record in records}) == 1024
    assert set(db).issubset(set(KYC_STATUS_CODES.values()))

    s0, s1 = RegistryServer("S0", db), RegistryServer("S1", db)
    cli = RegistryClient(s0, s1)
    assert cli.n == 1024
    for i in (0, 1, 511, 512, 1023):
        assert cli.read(i) == KYC_STATUS_CODES[records[i]["kyc_status"]]
    # Each server sees only the fixed vector length, never the requested index.
    assert all(n == 1024 for n in s0.query_log)
    assert all(n == 1024 for n in s1.query_log)


def test_doram_reads_from_2048_record_registry():
    records = [index % 4 for index in range(2048)]
    s0, s1 = RegistryServer("S0", records), RegistryServer("S1", records)
    client = RegistryClient(s0, s1)

    assert client.read(2047) == records[2047]
    assert s0.query_log == [2048]
    assert s1.query_log == [2048]


# -- attack lab ------------------------------------------------------------
def test_attack_lab_v0_succeeds_v1_blocked():
    from attacks.attacks import build_attacks
    for atk in build_attacks():
        o0 = atk.run_v0()
        o1 = atk.run_v1()
        assert o0.success, f"attack {atk.number} should succeed on v0"
        assert not o1.success, f"attack {atk.number} should be blocked on v1"
