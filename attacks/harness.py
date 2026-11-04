"""Attack-lab harness.

Each attack exposes ``run_v0()`` and ``run_v1()`` returning an :class:`Outcome`.
The runner executes every attack against both systems and prints a side-by-side
table; for v1 it also prints the course property that stops (or reduces) the
attack.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Outcome:
    success: bool          # did the attack achieve its goal?
    metric: str            # the success metric (IDs recovered, accuracy, ...)
    evidence: str = ""     # short human-readable evidence


@dataclass
class Attack:
    number: int
    name: str
    defence: str           # the v1 course property that stops/reduces it
    run_v0: object         # callable -> Outcome
    run_v1: object         # callable -> Outcome


def run_all(attacks: list[Attack]) -> None:
    print("=" * 100)
    print(f"{'#':>2}  {'Attack':<24} {'v0':<22} {'v1':<22} {'v1 defence':<24}")
    print("-" * 100)
    for atk in attacks:
        o0 = atk.run_v0()
        o1 = atk.run_v1()
        v0 = ("SUCCESS " if o0.success else "blocked ") + f"({o0.metric})"
        v1 = ("SUCCESS " if o1.success else "blocked ") + f"({o1.metric})"
        print(f"{atk.number:>2}  {atk.name:<24} {v0:<22} {v1:<22} {atk.defence:<24}")
    print("=" * 100)
    print("A v1 'blocked' (or reduced) cell is defended by the named course property.")
