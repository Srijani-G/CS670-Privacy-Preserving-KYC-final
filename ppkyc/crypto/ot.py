"""1-out-of-2 oblivious transfer, Naor-Pinkas style (slide 33).

This is the "tie Bob's hands" OT.  The sender holds two messages ``(m0, m1)``;
the receiver holds a choice bit ``b`` and learns only ``m_b`` while the sender
learns nothing about ``b``.

    Sender:   pick c, send C = g^c
    Receiver: choice b; pick k; PK_b = g^k; PK_{1-b} = C / PK_b; send PK_0
    Sender:   PK_1 = C / PK_0; for i in {0,1}: pick r_i,
              send ( g^{r_i} , H(PK_i^{r_i}) XOR m_i )
    Receiver: m_b = e_b XOR H( (g^{r_b})^k )

The receiver cannot know the discrete logs of *both* public keys without knowing
``log C``; doing so anyway is the malicious-receiver attack.

Messages are byte strings; :func:`ot_send` / :func:`ot_receive` exchange plain
Python objects (the demo's :class:`~ppkyc.channel.Channel` records them as the
parties' views).  :func:`random_ot` and :func:`batch_ot` sit on top for GC input
labels and Beaver-triple generation.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from .group import GROUP, GroupError


def _kdf(point: int, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(
            b"ot-kdf" + point.to_bytes(256, "big") + counter.to_bytes(4, "big")
        ).digest()
        counter += 1
    return out[:length]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


@dataclass
class SenderState:
    c: int
    C: int


def sender_setup() -> SenderState:
    c = GROUP.rand_scalar()
    return SenderState(c=c, C=GROUP.exp(GROUP.g, c))


@dataclass
class ReceiverState:
    b: int
    k: int


def receiver_choose(C: int, b: int) -> tuple[ReceiverState, int]:
    """Receiver picks its key pair; returns (state, PK_0 to send)."""
    GROUP.check_member(C, "OT setup C")
    k = GROUP.rand_scalar()
    pk_b = GROUP.exp(GROUP.g, k)
    pk_other = GROUP.div(C, pk_b)
    pk0 = pk_b if b == 0 else pk_other
    return ReceiverState(b=b, k=k), pk0


def sender_transfer(state: SenderState, pk0: int,
                    m0: bytes, m1: bytes) -> tuple[tuple[int, bytes], tuple[int, bytes]]:
    """Sender encrypts both messages under the derived keys."""
    GROUP.check_member(pk0, "OT PK_0")
    pk1 = GROUP.div(state.C, pk0)
    out = []
    # Length-prefix each message and pad to a common length, so the receiver
    # recovers the exact bytes even when a message ends in zero bytes.
    length = max(len(m0), len(m1)) + 4
    for pk, m in ((pk0, m0), (pk1, m1)):
        r = GROUP.rand_scalar()
        gr = GROUP.exp(GROUP.g, r)
        key = _kdf(GROUP.exp(pk, r), length)
        payload = len(m).to_bytes(4, "big") + m
        out.append((gr, _xor(key, payload.ljust(length, b"\x00"))))
    return out[0], out[1]


def receiver_finish(state: ReceiverState,
                    c0: tuple[int, bytes], c1: tuple[int, bytes]) -> bytes:
    gr, enc = (c0, c1)[state.b]
    GROUP.check_member(gr, "OT g^r")
    key = _kdf(GROUP.exp(gr, state.k), len(enc))
    payload = _xor(key, enc)
    mlen = int.from_bytes(payload[:4], "big")
    return payload[4:4 + mlen]


def ot_1of2(m0: bytes, m1: bytes, b: int) -> bytes:
    """Convenience wrapper running the full honest protocol in-process."""
    s = sender_setup()
    rstate, pk0 = receiver_choose(s.C, b)
    c0, c1 = sender_transfer(s, pk0, m0, m1)
    return receiver_finish(rstate, c0, c1)


# --------------------------------------------------------------------------
# Random OT and batching (used by GC input labels / Beaver triples)
# --------------------------------------------------------------------------
def random_ot(length: int = 16) -> tuple[bytes, bytes, int, bytes]:
    """Random OT: returns ``(m0, m1, b, m_b)`` for a random choice bit."""
    m0 = secrets.token_bytes(length)
    m1 = secrets.token_bytes(length)
    b = secrets.randbelow(2)
    return m0, m1, b, ot_1of2(m0, m1, b)


def batch_ot(pairs: list[tuple[bytes, bytes]], choices: list[int]) -> list[bytes]:
    """Run many independent 1-out-of-2 OTs (honest, in-process)."""
    assert len(pairs) == len(choices)
    return [ot_1of2(m0, m1, b) for (m0, m1), b in zip(pairs, choices)]
