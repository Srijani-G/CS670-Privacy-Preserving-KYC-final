"""Square-root ORAM (Module C1).

Layout (slides 28-35): a permuted array of ``m = n + sqrt(n)`` blocks (``n`` real
plus ``sqrt(n)`` dummies) under a secret permutation ``pi`` known only to the
client, plus a **stash** of up to ``sqrt(n)`` blocks that is scanned on every
access.

On access to logical index ``i``:

* scan the whole stash (a fixed pattern, independent of ``i``);
* if ``i`` is already in the stash, fetch the *next dummy* from the permuted
  array; otherwise fetch ``pi[i]``.  Either way exactly one, never-before-touched
  permuted position is read this epoch;
* append the block to the stash.

After ``sqrt(n)`` accesses the structure is reshuffled under a fresh permutation
and the stash is emptied.  Within an epoch no permuted position repeats, so the
logical sequences ``[1,1,1,1]`` and ``[1,2,3,4]`` induce indistinguishable
physical traces (checked with a chi-squared test in the attack lab).
"""

from __future__ import annotations

import math
import secrets


class SqrtORAM:
    def __init__(self, data: list[bytes]):
        self.n = len(data)
        self.sqrt = max(1, int(math.isqrt(self.n)) + 1)
        self.data = {i: data[i] for i in range(self.n)}  # client-side truth
        self.phys_log: list[int] = []  # permuted-array positions touched
        self._reshuffle()

    # -- internal ----------------------------------------------------------
    def _reshuffle(self) -> None:
        m = self.n + self.sqrt
        perm = list(range(m))
        secrets.SystemRandom().shuffle(perm)
        # pi[j] = physical position of logical block j (j in [0,n): real;
        # j in [n, n+sqrt): dummy)
        self.pi = perm
        self.used_dummies = 0
        self.used_accesses = 0
        self.stash: dict[int, bytes] = {}

    def _scan_stash(self, i: int) -> bytes | None:
        # a real implementation touches every stash slot; we just emulate that
        # the scan is a fixed, index-independent pattern.
        return self.stash.get(i)

    # -- public ------------------------------------------------------------
    def access(self, i: int, write_value: bytes | None = None) -> bytes:
        found = self._scan_stash(i)
        if found is not None:
            pos = self.pi[self.n + self.used_dummies]  # fetch a dummy
            self.used_dummies += 1
            value = found
        else:
            pos = self.pi[i]
            value = self.data[i]
        self.phys_log.append(pos)  # the one permuted access the server sees

        if write_value is not None:
            value = write_value
            self.data[i] = write_value
        self.stash[i] = value

        self.used_accesses += 1
        if self.used_accesses >= self.sqrt:
            self._reshuffle()
        return value

    def read(self, i: int) -> bytes:
        return self.access(i)

    def write(self, i: int, value: bytes) -> None:
        self.access(i, value)
