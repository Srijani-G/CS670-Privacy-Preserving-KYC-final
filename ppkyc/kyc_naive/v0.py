"""v0: the naive, deliberately-flawed KYC system.

These are *real* services with real weaknesses, so the attack lab's attacks
genuinely succeed against them:

* a central SQLite table of full PII, with ``SHA-256(national_id)`` as the join
  key (attack #1 breach, #2 hash dictionary);
* a watchlist check that is just ``sha256(id) in set`` (attack #2);
* a central risk engine that receives raw per-bank amounts (attack #3);
* a registry queried by plaintext index with server-side access logging
  (attack #4);
* bearer-token sessions and a "document upload" as an age proof, with no nonce
  or RP binding (attacks #5, #6, #7).
"""

from __future__ import annotations

import hashlib
import sqlite3


def sha256_id(national_id: str) -> str:
    return hashlib.sha256(national_id.encode()).hexdigest()


class V0System:
    def __init__(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute(
            "CREATE TABLE customers (id_hash TEXT PRIMARY KEY, national_id TEXT, "
            "name TEXT, dob INTEGER, nationality TEXT, kyc_level INTEGER)"
        )
        self.watchlist: set[str] = set()      # sha256(id) of sanctioned persons
        self.bank_amounts: dict[str, list[int]] = {}  # id_hash -> raw per-bank amounts
        self.registry: list[int] = []         # plaintext-indexed status registry
        self.registry_access_log: list[int] = []
        self.documents: dict[str, bytes] = {}  # "age proofs" (document uploads)
        self.sessions: dict[str, str] = {}     # bearer token -> id_hash
        self.rp_accounts: dict[str, set] = {}  # rp_id -> set of accounts (no sybil defence)

    # -- enrolment ---------------------------------------------------------
    def add_customer(self, national_id, name, dob, nationality, kyc_level,
                     amounts=None, on_watchlist=False):
        h = sha256_id(national_id)
        self.db.execute("INSERT OR REPLACE INTO customers VALUES (?,?,?,?,?,?)",
                        (h, national_id, name, dob, nationality, kyc_level))
        self.db.commit()
        if amounts:
            self.bank_amounts[h] = list(amounts)
        if on_watchlist:
            self.watchlist.add(h)
        return h

    # -- flawed services ---------------------------------------------------
    def is_sanctioned(self, national_id: str) -> bool:
        return sha256_id(national_id) in self.watchlist

    def risk_engine(self, id_hash: str, weights: list[int], threshold: int):
        """Central engine that *sees* the raw per-bank amounts."""
        amts = self.bank_amounts.get(id_hash, [])
        score = sum(w * a for w, a in zip(weights, amts))
        return {"score": score, "flag": score >= threshold, "amounts_seen": list(amts)}

    def registry_read(self, index: int) -> int:
        self.registry_access_log.append(index)  # leaks the access pattern
        return self.registry[index]

    def present_age(self, national_id: str, claimed_age: int) -> bool:
        """Age 'proof' is a document upload; no cryptographic check."""
        return sha256_id(national_id) in self.documents

    def open_account(self, rp_id: str, token: str) -> bool:
        """No nullifier: one person can open unlimited accounts."""
        self.rp_accounts.setdefault(rp_id, set()).add(token)
        return True
