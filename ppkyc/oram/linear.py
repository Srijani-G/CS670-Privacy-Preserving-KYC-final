"""Linear-scan ORAM (Module C1 baseline).

The client keeps ``n`` encrypted documents on an untrusted server.  Every access
(read or write) touches **every** slot -- it reads all ciphertexts and rewrites
all of them (re-encrypting so ciphertexts change) -- so the server's physical
access pattern is independent of the logical index.  This is the simplest thing
that defeats access-pattern inference (attack #4), at O(n) cost per access.

Encryption here is a SHA-256 keystream XOR (a stand-in PRG, slides allow using a
PRG/AES); the point of the module is the access pattern, not the cipher.
"""

from __future__ import annotations

import hashlib
import secrets


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


class EncryptedServer:
    """Untrusted store that logs the physical slots touched on each access."""

    def __init__(self, n: int, slot_bytes: int):
        self.slots: list[bytes] = [b"\x00" * (slot_bytes + 12)] * n
        self.slot_bytes = slot_bytes
        self.access_log: list[list[int]] = []

    def read_all(self) -> list[bytes]:
        self.access_log.append(list(range(len(self.slots))))
        return list(self.slots)

    def write_all(self, blobs: list[bytes]) -> None:
        self.slots = list(blobs)


class LinearScanORAM:
    def __init__(self, n: int, slot_bytes: int = 32):
        self.n = n
        self.slot_bytes = slot_bytes
        self.key = secrets.token_bytes(32)
        self.server = EncryptedServer(n, slot_bytes)

    def _enc(self, plain: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        ks = _keystream(self.key, nonce, self.slot_bytes)
        return nonce + bytes(a ^ b for a, b in zip(plain.ljust(self.slot_bytes, b"\x00"), ks))

    def _dec(self, blob: bytes) -> bytes:
        nonce, ct = blob[:12], blob[12:]
        ks = _keystream(self.key, nonce, self.slot_bytes)
        return bytes(a ^ b for a, b in zip(ct, ks))

    def access(self, index: int, write_value: bytes | None = None) -> bytes:
        """Read (and optionally overwrite) slot ``index`` with a full scan."""
        blobs = self.server.read_all()
        plains = [self._dec(b) for b in blobs]
        result = plains[index]
        if write_value is not None:
            plains[index] = write_value.ljust(self.slot_bytes, b"\x00")[:self.slot_bytes]
        # re-encrypt EVERYTHING (fresh nonces) so ciphertexts all change
        self.server.write_all([self._enc(p) for p in plains])
        return result.rstrip(b"\x00")

    def read(self, index: int) -> bytes:
        return self.access(index)

    def write(self, index: int, value: bytes) -> None:
        self.access(index, value)
