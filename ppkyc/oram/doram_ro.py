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

import random
import secrets
from datetime import date, timedelta

MOD = (1 << 127) - 1  # a Mersenne prime; registry values must be < MOD

# DORAM stores compact integer status codes; metadata stays in the local fixture.
KYC_STATUS_CODES = {"pending": 0, "verified": 1, "rejected": 2, "under_review": 3}
KYC_STATUS_LABELS = {value: key for key, value in KYC_STATUS_CODES.items()}
_FIRST_NAMES = ("Aarav", "Aditi", "Ananya", "Arjun", "Diya", "Ishaan", "Kabir", "Meera",
                "Neha", "Rohan", "Sara", "Vihaan", "Zoya", "Maya", "Dev", "Ira")
_LAST_NAMES = ("Sharma", "Verma", "Iyer", "Reddy", "Patel", "Kapoor", "Das", "Nair",
               "Khan", "Mehta", "Rao", "Sen", "Malhotra", "Joshi", "Bose", "Menon")
_NATIONALITIES = ("IN", "US", "GB", "SG", "AE", "CA", "AU", "DE")
_RISK_CATEGORIES = ("low", "medium", "high")


def generate_synthetic_registry(size: int = 1024, seed: int = 670) -> list[dict]:
    """Generate reproducible fictional KYC records; never use real customer data."""
    if size < 1:
        raise ValueError("Registry size must be at least 1")
    rng = random.Random(seed)
    reference_date = date(2026, 11, 1)
    statuses = ("pending", "verified", "rejected", "under_review")
    records = []
    for index in range(size):
        status = rng.choices(statuses, weights=(12, 72, 6, 10), k=1)[0]
        risk = rng.choices(_RISK_CATEGORIES, weights=(65, 27, 8), k=1)[0]
        dob = date(1960, 1, 1) + timedelta(days=rng.randint(0, 18000))
        reviewed = reference_date - timedelta(days=rng.randint(0, 730))
        records.append({
            "customer_id": f"KYC-{index + 1:06d}",
            "full_name": f"{rng.choice(_FIRST_NAMES)} {rng.choice(_LAST_NAMES)}",
            "date_of_birth": dob.isoformat(),
            "nationality": rng.choice(_NATIONALITIES),
            "kyc_status": status,
            "risk_category": risk,
            "last_reviewed": reviewed.isoformat(),
        })
    return records


def encode_registry_statuses(records: list[dict]) -> list[int]:
    """Convert full fixture records to the integer array queried by DORAM."""
    try:
        return [KYC_STATUS_CODES[record["kyc_status"]] for record in records]
    except KeyError as exc:
        raise ValueError(f"Unknown KYC status: {exc.args[0]}") from exc



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
