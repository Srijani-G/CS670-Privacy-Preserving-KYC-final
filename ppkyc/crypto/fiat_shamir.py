"""Fiat-Shamir transcript (strong and deliberately-weak variants).

A :class:`Transcript` absorbs length-prefixed, domain-separated messages and
squeezes out a challenge in ``Z_q``.  The *strong* transcript binds the group
parameters, the statement, the verifier context (RP id, nonce, timestamp) and
every first message, which is what defeats replay (attack #5).

Two deliberately broken variants live here for illustrative weak-Fiat-Shamir
tests:

* ``WeakTranscript(truncate_bits=t)`` emits a ``t``-bit challenge, enabling
  short-challenge forgery.
* ``WeakTranscript(bind_context=False)`` drops the verifier context so a proof
  can be replayed to another RP/session (the replay attack, #5).
"""

from __future__ import annotations

import hashlib

from .group import GROUP


class Transcript:
    """Strong Fiat-Shamir transcript over SHA-256."""

    def __init__(self, domain: str, bind_params: bool = True):
        self._h = hashlib.sha256()
        self._append_raw(b"domain", domain.encode())
        if bind_params:
            self.append_int("p", GROUP.p)
            self.append_int("q", GROUP.q)
            self.append_int("g", GROUP.g)

    # -- absorbing ---------------------------------------------------------
    def _append_raw(self, label: bytes, data: bytes) -> "Transcript":
        self._h.update(len(label).to_bytes(4, "big"))
        self._h.update(label)
        self._h.update(len(data).to_bytes(8, "big"))
        self._h.update(data)
        return self

    def append_bytes(self, label: str, data: bytes) -> "Transcript":
        return self._append_raw(label.encode(), data)

    def append_int(self, label: str, value: int) -> "Transcript":
        n = (value.bit_length() + 8) // 8 or 1
        return self._append_raw(label.encode(), value.to_bytes(n, "big"))

    def append_group(self, label: str, elem: int) -> "Transcript":
        return self.append_int(label, elem)

    def append_context(self, rp_id: str, nonce: bytes, timestamp: int) -> "Transcript":
        self.append_bytes("rp_id", rp_id.encode())
        self.append_bytes("nonce", nonce)
        self.append_int("timestamp", timestamp)
        return self

    # -- squeezing ---------------------------------------------------------
    def challenge(self, label: str = "challenge") -> int:
        """Derive a challenge in ``[0, q)`` (full length)."""
        counter = 0
        acc = b""
        need = (GROUP.q.bit_length() + 7) // 8 + 16
        snap = self._h.copy()
        snap.update(len(label).to_bytes(4, "big"))
        snap.update(label.encode())
        while len(acc) < need:
            d = snap.copy()
            d.update(counter.to_bytes(4, "big"))
            acc += d.digest()
            counter += 1
        return int.from_bytes(acc[:need], "big") % GROUP.q


class WeakTranscript(Transcript):
    """Broken transcript kept solely for the attack lab.

    * ``truncate_bits`` -- reduce the challenge to this many bits (short-challenge forgery).
    * ``bind_context=False`` -- do not bind rp_id/nonce/timestamp (replay, attack #5).
    """

    def __init__(self, domain: str, truncate_bits: int | None = None,
                 bind_context: bool = True):
        super().__init__(domain)
        self.truncate_bits = truncate_bits
        self.bind_context = bind_context

    def append_context(self, rp_id: str, nonce: bytes, timestamp: int) -> "Transcript":
        if not self.bind_context:
            return self  # vulnerable: context is ignored
        return super().append_context(rp_id, nonce, timestamp)

    def challenge(self, label: str = "challenge") -> int:
        c = super().challenge(label)
        if self.truncate_bits is not None:
            c &= (1 << self.truncate_bits) - 1
        return c
