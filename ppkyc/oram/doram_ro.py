"""Read-only 2-server DORAM for the shared KYC-status registry (Module C2).

For read-only memory both servers can hold the plaintext database, and a read
becomes a dot product with shares of a one-hot vector (slides 59-62):

    Client knows index i.
      pick random v0, v1 with v0 + v1 = e_i (one-hot)
      send v0 to S0, v1 to S1
    Each server computes <D, v_j> locally (no MPC needed).
    Client adds the two replies and gets D[i].  Neither server learns i.

Cost is O(n) communication per read (reported in the benchmarks).  Registry
updates come from the Regulator, who knows the index, so they are plain epoch
updates.  A DPF would cut the query from O(n) to O(log n) (future work).
"""

from __future__ import annotations

import secrets

MOD = (1 << 127) - 1  # a Mersenne prime; registry values must be < MOD


class RegistryServer:
    """Holds the plaintext database and answers dot-product queries."""

    def __init__(self, name: str, database: list[int]):
        self.name = name
        self.db = [v % MOD for v in database]
        self.query_log: list[int] = []  # records |v| seen (not i)

    def update(self, index: int, value: int) -> None:
        """Plain epoch update from the Regulator (who legitimately knows i)."""
        self.db[index] = value % MOD

    def dot(self, v: list[int]) -> int:
        self.query_log.append(len(v))
        return sum((d * x) % MOD for d, x in zip(self.db, v)) % MOD


class RegistryClient:
    """Issues oblivious reads against two non-colluding registry servers."""

    def __init__(self, s0: RegistryServer, s1: RegistryServer):
        assert len(s0.db) == len(s1.db)
        self.s0 = s0
        self.s1 = s1
        self.n = len(s0.db)

    def read(self, index: int, channel=None) -> int:
        assert 0 <= index < self.n
        # one-hot e_i, additively split into v0 + v1 = e_i
        v0 = [secrets.randbelow(MOD) for _ in range(self.n)]
        v1 = [((1 if k == index else 0) - v0[k]) % MOD for k in range(self.n)]
        if channel is not None:
            channel.send("Client", "S0", "share v0", {"len": len(v0)})
            channel.send("Client", "S1", "share v1", {"len": len(v1)})
        r0 = self.s0.dot(v0)
        r1 = self.s1.dot(v1)
        if channel is not None:
            channel.send("S0", "Client", "reply", r0)
            channel.send("S1", "Client", "reply", r1)
        return (r0 + r1) % MOD
