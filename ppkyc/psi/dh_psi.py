"""Module A: sanctions screening via DH-based private set intersection.

The Regulator is the sender (watchlist ``W``); the Bank is the receiver
(customer identifiers ``Q``).  Each party holds a secret exponent.

    1. Bank -> Regulator:  { H(q)^a : q in Q }                    (order preserved)
    2. Regulator -> Bank:  { H(q)^{ab} } (same order)  and
                           shuffled { H(w)^b : w in W }
    3. Bank computes (H(w)^b)^a for each w, and intersects locally.

The Bank learns which of *its* customers matched, and ``|W|``.  The Regulator
learns ``|Q|``.

``H`` hashes **into the group** (:meth:`Group.hash_to_group`); hashing to plain
integers instead leaks ratios.  Every received element is checked for subgroup
membership.  Identifiers are canonicalised; fuzzy matching is out of scope.  A
malicious bank can still enumerate the identifier space -- PSI cannot prevent
that cryptographically; v1 only mitigates it with authenticated queries, a
query cap and an audit log.
"""

from __future__ import annotations

import secrets

from ..crypto.group import GROUP
from ..channel import Channel


def canonicalise(identifier: str) -> bytes:
    """Normalise an identifier (lowercase, strip, collapse spaces)."""
    return "|".join(part.strip().lower() for part in identifier.split("|")).encode()


def deduplicate_identifiers(identifiers: list[str]) -> list[str]:
    """Keep the first spelling of each canonical identifier, preserving order."""
    seen: set[bytes] = set()
    unique = []
    for identifier in identifiers:
        key = canonicalise(identifier)
        if key not in seen:
            seen.add(key)
            unique.append(identifier)
    return unique


class Regulator:
    """PSI sender: holds the secret watchlist ``W``."""

    def __init__(self, watchlist: list[str]):
        self.b = GROUP.rand_scalar()
        self._w_items = [canonicalise(w) for w in deduplicate_identifiers(watchlist)]
        # cache H(w)
        self._hw = [GROUP.hash_to_group(w) for w in self._w_items]

    def respond(self, hq_a: list[int]) -> tuple[list[int], list[int]]:
        """Given { H(q)^a }, return ({ H(q)^{ab} }, shuffled { H(w)^b })."""
        for elem in hq_a:
            GROUP.check_member(elem, "H(q)^a")
        hq_ab = [GROUP.exp(e, self.b) for e in hq_a]
        hw_b = [GROUP.exp(hw, self.b) for hw in self._hw]
        secrets.SystemRandom().shuffle(hw_b)  # hide the order of W
        return hq_ab, hw_b


class Bank:
    """PSI receiver: holds its customer identifiers ``Q``."""

    def __init__(self, customers: list[str]):
        self.a = GROUP.rand_scalar()
        self.customers = deduplicate_identifiers(customers)
        self._q_items = [canonicalise(c) for c in self.customers]

    def query(self) -> list[int]:
        """Message 1: { H(q)^a } preserving the order of ``Q``."""
        return [GROUP.exp(GROUP.hash_to_group(q), self.a) for q in self._q_items]

    def intersect(self, hq_ab: list[int], hw_b: list[int]) -> list[str]:
        """Message 3: learn which of the bank's own customers are on the list."""
        for elem in hq_ab + hw_b:
            GROUP.check_member(elem, "PSI reply")
        # raise regulator's H(w)^b to the bank's exponent a
        hw_ab = {GROUP.exp(e, self.a) for e in hw_b}
        matched = []
        for cust, val in zip(self.customers, hq_ab):
            if val in hw_ab:
                matched.append(cust)
        return matched


def run_psi(watchlist: list[str], customers: list[str],
            channel: Channel | None = None) -> list[str]:
    """Full honest DH-PSI run; records messages on ``channel`` if given."""
    reg = Regulator(watchlist)
    bank = Bank(customers)

    msg1 = bank.query()
    if channel:
        channel.send("Bank", "Regulator", "H(q)^a", [str(x) for x in msg1])
    hq_ab, hw_b = reg.respond(msg1)
    if channel:
        channel.send("Regulator", "Bank", "H(q)^ab", [str(x) for x in hq_ab])
        channel.send("Regulator", "Bank", "shuffled H(w)^b", [str(x) for x in hw_b])
    return bank.intersect(hq_ab, hw_b)
