"""Benchmarks: proof size and time (sigma range vs MPC-in-the-head), GC vs
secret-sharing comparison cost, and read-only DORAM bandwidth vs n.
"""

from __future__ import annotations

import pickle
import time

from ppkyc.crypto.commit import PEDERSEN
from ppkyc.channel import Channel
from ppkyc.zkp import range as rng
from ppkyc.zkp import mpcith
from ppkyc.oram.doram_ro import RegistryServer, RegistryClient


def _time(fn, *a, **k):
    t0 = time.time()
    out = fn(*a, **k)
    return out, time.time() - t0


def bench_range_vs_mpcith():
    print("\n[1] Age proof: sigma range proof vs MPC-in-the-head")
    v, T, bits = 50488, 40000, 24
    C, r = PEDERSEN.commit(v)
    proof, t_prove = _time(rng.range_prove, C, v, r, bits, b"bench")
    _, t_verify = _time(rng.range_verify, C, proof, b"bench")
    size = len(pickle.dumps(proof))
    print(f"   sigma range  : prove {t_prove*1000:6.1f} ms  verify {t_verify*1000:6.1f} ms  size {size/1024:6.1f} KB")

    for rounds in (40, 137):
        pf, t_p = _time(mpcith.prove, v, T, bits, rounds)
        _, t_v = _time(mpcith.verify, pf)
        size = len(pickle.dumps(pf))
        err = f"2^-{abs(round(rounds * 0.585)):d}"
        print(f"   MPCitH ({rounds:3d} r): prove {t_p*1000:6.1f} ms  verify {t_v*1000:6.1f} ms  size {size/1024:6.1f} KB  (soundness ~{err})")


def bench_gc_comparison():
    print("\n[2] Module B threshold comparison: garbled-circuit cost")
    from ppkyc.mpc.gc_compare import compare_flag
    import secrets
    for bits in (8, 16, 24):
        mod = 1 << bits
        ch = Channel()
        z0, z1, T = secrets.randbelow(mod), secrets.randbelow(mod), secrets.randbelow(mod)
        _, dt = _time(compare_flag, z0, z1, T, bits, ch)
        n_ot = sum(1 for m in ch.log if m.label.startswith("OT label"))
        print(f"   {bits:2d}-bit: {dt*1000:6.1f} ms,  {n_ot} input OTs,  {ch.rounds()} messages")


def bench_doram_bandwidth():
    print("\n[3] Read-only DORAM: bandwidth per read vs n (O(n) one-hot)")
    for n in (10, 100, 1000):
        db = list(range(n))
        s0, s1 = RegistryServer("S0", db), RegistryServer("S1", db)
        cli = RegistryClient(s0, s1)
        ch = Channel()
        _, dt = _time(cli.read, n // 2, ch)
        # each query ships two length-n vectors of ~16-byte scalars
        bw = 2 * n * 16
        print(f"   n={n:5d}: {dt*1000:6.2f} ms,  ~{bw/1024:7.1f} KB query (O(n))")


def main():
    print("=" * 70)
    print("BENCHMARKS")
    print("=" * 70)
    bench_range_vs_mpcith()
    bench_gc_comparison()
    bench_doram_bandwidth()
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
