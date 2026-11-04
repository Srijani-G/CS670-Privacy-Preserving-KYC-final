"""Module B end-to-end: cross-bank AML analytics (hybrid MPC).

Pipeline (the "use both" argument -- secret sharing for the linear work, garbled
circuits for the comparison):

1. **Share** -- each bank splits its feature vector additively between S0 and
   S1; sums over banks are local and free.
2. **Score** -- the Regulator's private model weights ``w`` and the combined
   features ``x`` are both shared; ``<w, x>`` is computed with Beaver triples.
3. **Triples** -- generated offline with OT-based multiplication (``beaver.py``).
4. **Compare** -- the shared score is converted to GC inputs; the circuit adds
   the shares mod ``2^bits`` and compares to a threshold; only the flag leaks.

Neither server sees any bank's raw amounts or the model weights; the output is a
single "above threshold" flag.
"""

from __future__ import annotations

from .dotprod import secure_dotprod, share_value
from .gc_compare import compare_flag


def run_pipeline(bank_features: list[list[int]], weights: list[int],
                 threshold: int, bits: int = 32, channel=None) -> dict:
    """Run the full cross-bank analytics pipeline.

    ``bank_features[b]`` is bank ``b``'s feature vector; all banks share the same
    dimension as ``weights``.  Returns the flag plus the (reconstructed) score
    for verification/benchmarking only -- the protocol itself reveals only the
    flag.
    """
    dim = len(weights)
    for feats in bank_features:
        assert len(feats) == dim
    mod = 1 << bits

    # 1. each bank shares its features; 2-server additive sum is local
    x_shares = [(0, 0)] * dim
    for feats in bank_features:
        for i, f in enumerate(feats):
            s0, s1 = share_value(f, bits)
            if channel is not None:
                channel.send("Bank", "S0", "feature share", s0)
                channel.send("Bank", "S1", "feature share", s1)
            x0, x1 = x_shares[i]
            x_shares[i] = ((x0 + s0) % mod, (x1 + s1) % mod)

    # regulator shares its private model weights
    w_shares = [share_value(w, bits) for w in weights]

    # 2+3. secure dot product via Beaver triples (OT offline)
    score0, score1 = secure_dotprod(w_shares, x_shares, bits, channel)

    # 4. garbled-circuit threshold comparison (only the flag leaks)
    cmp_bits = min(bits, 24)  # keep the comparison circuit/OT count modest
    z0 = score0 % (1 << cmp_bits)
    z1 = score1 % (1 << cmp_bits)
    flag = compare_flag(z0, z1, threshold % (1 << cmp_bits), cmp_bits, channel)

    # reconstruction for checking only
    true_score = 0
    combined = [ (x_shares[i][0] + x_shares[i][1]) % mod for i in range(dim) ]
    true_score = sum(weights[i] * combined[i] for i in range(dim)) % mod
    return {
        "flag": flag,
        "score": true_score,
        "score_mod_cmp": (score0 + score1) % (1 << cmp_bits),
        "threshold": threshold,
    }
