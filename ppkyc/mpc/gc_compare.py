"""Share-to-GC conversion and threshold comparison (Module B, step 4).

The risk score ends up as additive shares ``z0`` (held by S0) and ``z1`` (held by
S1) over ``Z_{2^bits}``.  To learn only the flag ``score >= T`` without revealing
the score, S0 garbles a circuit that:

* reduces ``z0 + z1`` modulo ``2^bits`` (drops the carry-out), then
* compares the result against the public threshold ``T``.

S0 is the garbler (its own share and the threshold are garbler inputs); S1 is the
evaluator and obtains its input labels by OT.  Only the one-bit flag is revealed.
"""

from __future__ import annotations

from ..crypto import gc
from ..crypto.ot import ot_1of2


def build_mod_add_compare(bits: int) -> gc.Circuit:
    """Circuit for ``((z0 + z1) mod 2^bits) >= T`` -> single flag bit."""
    cb = gc.CircuitBuilder()
    z0 = [cb.garbler_input() for _ in range(bits)]       # S0 share
    t = [cb.garbler_input() for _ in range(bits)]        # threshold (public)
    z1 = [cb.evaluator_input() for _ in range(bits)]     # S1 share

    # ripple-carry add, keep low `bits` bits (mod 2^bits)
    s = []
    carry = None
    for i in range(bits):
        if carry is None:
            s.append(cb.XOR(z0[i], z1[i]))
            carry = cb.AND(z0[i], z1[i])
        else:
            axor = cb.XOR(z0[i], z1[i])
            s.append(cb.XOR(axor, carry))
            carry = cb.OR(cb.AND(z0[i], z1[i]), cb.AND(carry, axor))
    # compare s (bits) >= t (bits): borrow chain of s - t
    borrow = None
    for i in range(bits):
        si, ti = s[i], t[i]
        if borrow is None:
            borrow = cb.AND(cb.NOT(si), ti)
        else:
            d = cb.XOR(si, ti)
            borrow = cb.OR(cb.AND(cb.NOT(si), ti), cb.AND(cb.NOT(d), borrow))
    return cb.finish([cb.NOT(borrow)])


def compare_flag(z0: int, z1: int, threshold: int, bits: int = 16,
                 channel=None) -> int:
    """Run the garbled comparison; returns the flag ``(z0+z1) mod 2^bits >= T``."""
    circ = build_mod_add_compare(bits)
    gc_ = gc.garble(circ)
    g_bits = [(z0 >> i) & 1 for i in range(bits)] + \
             [(threshold >> i) & 1 for i in range(bits)]
    g_in = gc.garbler_labels(gc_, g_bits)
    if channel is not None:
        channel.send("S0", "S1", "garbled tables", {"gates": len(gc_.tables)})
        channel.send("S0", "S1", "garbler input labels", {"n": len(g_in)})
    e_in = {}
    for i, w in enumerate(circ.evaluator_inputs):
        l0, l1 = gc.evaluator_label_pair(gc_, w)
        bit = (z1 >> i) & 1
        e_in[w] = ot_1of2(l0, l1, bit)  # OT per evaluator input bit
        if channel is not None:
            channel.send("S0", "S1", f"OT label bit {i}", {"ot": True})
    return gc.evaluate(gc_, g_in, e_in)[0]
