"""Garbled circuits with point-and-permute, free-XOR and GRR3.

Optimisations in the order the slides introduce them:

* **point-and-permute** -- the colour bit of a label is its least-significant
  bit, so the evaluator selects a garbled row without learning the wire value.
* **free-XOR** -- a global offset ``Delta`` with ``lsb(Delta) == 1``; the two
  labels on a wire differ by ``Delta``, so XOR and NOT gates need no ciphertext.
* **GRR3** -- an AND gate ships only 3 ciphertexts (the (0,0) colour row is made
  all-zero by defining the output label from the hash, so it is not sent).

Gate encryption is ``H(La || Lb || gate_id)`` used as a one-time pad, via
truncated SHA-256.  Circuits are built in Python; :func:`adder_mod` and
:func:`ge_threshold` build a ripple-carry adder mod ``2^k`` and a comparator.
Every garbled evaluation is checked against plaintext evaluation in the tests.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field

LABEL_BYTES = 16


def _H(a: bytes, b: bytes, gid: int) -> bytes:
    return hashlib.sha256(a + b + gid.to_bytes(8, "big")).digest()[:LABEL_BYTES]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _lsb(label: bytes) -> int:
    return label[-1] & 1


# --------------------------------------------------------------------------
# Circuit description
# --------------------------------------------------------------------------
@dataclass
class Gate:
    kind: str  # 'XOR', 'AND', 'NOT'
    out: int
    a: int
    b: int = -1


@dataclass
class Circuit:
    n_wires: int
    garbler_inputs: list[int]
    evaluator_inputs: list[int]
    gates: list[Gate]
    outputs: list[int]

    def evaluate_plain(self, g_bits: list[int], e_bits: list[int]) -> list[int]:
        """Reference plaintext evaluation (ground truth for the tests)."""
        val: dict[int, int] = {}
        for w, bit in zip(self.garbler_inputs, g_bits):
            val[w] = bit & 1
        for w, bit in zip(self.evaluator_inputs, e_bits):
            val[w] = bit & 1
        for gate in self.gates:
            if gate.kind == "XOR":
                val[gate.out] = val[gate.a] ^ val[gate.b]
            elif gate.kind == "AND":
                val[gate.out] = val[gate.a] & val[gate.b]
            elif gate.kind == "NOT":
                val[gate.out] = 1 - val[gate.a]
            else:
                raise ValueError(gate.kind)
        return [val[o] for o in self.outputs]


class CircuitBuilder:
    """Tiny helper to assemble a :class:`Circuit`."""

    def __init__(self):
        self.n = 0
        self.garbler_inputs: list[int] = []
        self.evaluator_inputs: list[int] = []
        self.gates: list[Gate] = []

    def wire(self) -> int:
        w = self.n
        self.n += 1
        return w

    def garbler_input(self) -> int:
        w = self.wire()
        self.garbler_inputs.append(w)
        return w

    def evaluator_input(self) -> int:
        w = self.wire()
        self.evaluator_inputs.append(w)
        return w

    def XOR(self, a: int, b: int) -> int:
        o = self.wire()
        self.gates.append(Gate("XOR", o, a, b))
        return o

    def AND(self, a: int, b: int) -> int:
        o = self.wire()
        self.gates.append(Gate("AND", o, a, b))
        return o

    def NOT(self, a: int) -> int:
        o = self.wire()
        self.gates.append(Gate("NOT", o, a))
        return o

    def OR(self, a: int, b: int) -> int:
        # a OR b = NOT(NOT a AND NOT b)
        return self.NOT(self.AND(self.NOT(a), self.NOT(b)))

    def finish(self, outputs: list[int]) -> Circuit:
        return Circuit(self.n, self.garbler_inputs, self.evaluator_inputs,
                       self.gates, outputs)


# --------------------------------------------------------------------------
# Garbling
# --------------------------------------------------------------------------
@dataclass
class GarbledCircuit:
    circuit: Circuit
    delta: bytes
    wire0: dict  # wire -> label for value 0
    tables: dict  # gate index -> {(ca,cb): ciphertext}
    output_colour0: list  # lsb of the 0-label for each output wire


def garble(circuit: Circuit) -> GarbledCircuit:
    delta = bytearray(secrets.token_bytes(LABEL_BYTES))
    delta[-1] |= 1  # free-XOR invariant: lsb(Delta) == 1
    delta = bytes(delta)

    wire0: dict[int, bytes] = {}
    for w in circuit.garbler_inputs + circuit.evaluator_inputs:
        wire0[w] = secrets.token_bytes(LABEL_BYTES)

    tables: dict[int, dict] = {}
    for idx, gate in enumerate(circuit.gates):
        if gate.kind == "XOR":
            wire0[gate.out] = _xor(wire0[gate.a], wire0[gate.b])
        elif gate.kind == "NOT":
            wire0[gate.out] = _xor(wire0[gate.a], delta)
        elif gate.kind == "AND":
            a0 = wire0[gate.a]
            b0 = wire0[gate.b]
            a1 = _xor(a0, delta)
            b1 = _xor(b0, delta)
            labels_a = {_lsb(a0): (a0, 0), _lsb(a1): (a1, 1)}
            labels_b = {_lsb(b0): (b0, 0), _lsb(b1): (b1, 1)}
            table: dict[tuple[int, int], bytes] = {}
            out0 = None
            for ca in (0, 1):
                for cb in (0, 1):
                    la, va = labels_a[ca]
                    lb, vb = labels_b[cb]
                    vc = va & vb
                    pad = _H(la, lb, idx)
                    if ca == 0 and cb == 0:
                        # GRR3: define the output label so this row is zero.
                        lc_vc = pad
                        out0 = lc_vc if vc == 0 else _xor(lc_vc, delta)
                    else:
                        table[(ca, cb)] = (pad, vc)  # fill label later
            wire0[gate.out] = out0
            out1 = _xor(out0, delta)
            final: dict[tuple[int, int], bytes] = {}
            for (ca, cb), (pad, vc) in table.items():
                lc = out0 if vc == 0 else out1
                final[(ca, cb)] = _xor(pad, lc)
            tables[idx] = final
        else:
            raise ValueError(gate.kind)

    output_colour0 = [_lsb(wire0[o]) for o in circuit.outputs]
    return GarbledCircuit(circuit, delta, wire0, tables, output_colour0)


def garbler_labels(gc: GarbledCircuit, g_bits: list[int]) -> dict[int, bytes]:
    """Garbler's own input labels, sent directly to the evaluator."""
    out = {}
    for w, bit in zip(gc.circuit.garbler_inputs, g_bits):
        out[w] = gc.wire0[w] if bit == 0 else _xor(gc.wire0[w], gc.delta)
    return out


def evaluator_label_pair(gc: GarbledCircuit, wire: int) -> tuple[bytes, bytes]:
    """The (label0, label1) pair for an evaluator input wire (delivered by OT)."""
    l0 = gc.wire0[wire]
    return l0, _xor(l0, gc.delta)


def evaluate(gc: GarbledCircuit, garbler_in: dict[int, bytes],
             evaluator_in: dict[int, bytes]) -> list[int]:
    """Evaluate the garbled circuit from the active input labels only."""
    val: dict[int, bytes] = {}
    val.update(garbler_in)
    val.update(evaluator_in)
    for idx, gate in enumerate(gc.circuit.gates):
        if gate.kind == "XOR":
            val[gate.out] = _xor(val[gate.a], val[gate.b])
        elif gate.kind == "NOT":
            # NOT is free: the label passes through unchanged and the negation
            # is carried by the flipped colour of the garbler's 0-label.  The
            # evaluator never touches Delta.
            val[gate.out] = val[gate.a]
        elif gate.kind == "AND":
            la = val[gate.a]
            lb = val[gate.b]
            ca, cb = _lsb(la), _lsb(lb)
            pad = _H(la, lb, idx)
            if ca == 0 and cb == 0:
                val[gate.out] = pad
            else:
                val[gate.out] = _xor(pad, gc.tables[idx][(ca, cb)])
        else:
            raise ValueError(gate.kind)
    out_bits = []
    for o, c0 in zip(gc.circuit.outputs, gc.output_colour0):
        out_bits.append(_lsb(val[o]) ^ c0)
    return out_bits


# --------------------------------------------------------------------------
# Example circuits
# --------------------------------------------------------------------------
def build_add_compare(bits: int) -> Circuit:
    """Circuit for ``(garbler_val + evaluator_val) >= threshold_const``.

    Both operands are ``bits``-wide; the comparison is against a threshold
    supplied as extra garbler input bits.  Output is a single flag bit.  Used by
    Module B (sum of two banks' shares, compared to a private threshold).
    """
    cb = CircuitBuilder()
    a = [cb.garbler_input() for _ in range(bits)]      # garbler operand
    t = [cb.garbler_input() for _ in range(bits + 1)]  # threshold (bits+1 wide)
    x = [cb.evaluator_input() for _ in range(bits)]    # evaluator operand

    # ripple-carry add a + x -> sum (bits+1 wide)
    s = []
    carry = None
    for i in range(bits):
        if carry is None:
            s.append(cb.XOR(a[i], x[i]))
            carry = cb.AND(a[i], x[i])
        else:
            axor = cb.XOR(a[i], x[i])
            s.append(cb.XOR(axor, carry))
            # carry' = (a&x) | (carry & (a^x))
            c1 = cb.AND(a[i], x[i])
            c2 = cb.AND(carry, axor)
            carry = cb.OR(c1, c2)
    s.append(carry)  # top bit (bits+1 total)

    # compare s >= t  (both bits+1 wide), unsigned.
    # s >= t  iff  NOT (s < t).  Compute borrow chain of s - t; borrow out == (s < t).
    borrow = None
    for i in range(bits + 1):
        si, ti = s[i], t[i]
        if borrow is None:
            # diff bit = si ^ ti ; borrow = (not si) and ti
            borrow = cb.AND(cb.NOT(si), ti)
        else:
            d = cb.XOR(si, ti)
            # borrow' = ((not si) and ti) or ((not (si ^ ti)) and borrow)
            b1 = cb.AND(cb.NOT(si), ti)
            b2 = cb.AND(cb.NOT(d), borrow)
            borrow = cb.OR(b1, b2)
    ge = cb.NOT(borrow)  # s >= t
    return cb.finish([ge])


def run_add_compare(bits: int, a_val: int, x_val: int, threshold: int) -> int:
    """End-to-end honest GC run (garble, deliver labels, evaluate)."""
    from .ot import ot_1of2  # local import to avoid cycles

    circ = build_add_compare(bits)
    gc = garble(circ)

    g_bits = [(a_val >> i) & 1 for i in range(bits)] + \
             [(threshold >> i) & 1 for i in range(bits + 1)]
    g_in = garbler_labels(gc, g_bits)

    # evaluator obtains its input labels by OT (one per bit)
    e_in = {}
    for i, w in enumerate(circ.evaluator_inputs):
        l0, l1 = evaluator_label_pair(gc, w)
        bit = (x_val >> i) & 1
        e_in[w] = ot_1of2(l0, l1, bit)
    return evaluate(gc, g_in, e_in)[0]
