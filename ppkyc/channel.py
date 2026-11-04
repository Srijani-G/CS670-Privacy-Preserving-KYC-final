"""View-recording channel.

Every message between parties passes through a :class:`Channel` that records the
bytes, so each party's *view* (the messages it sent and received, slide 30) is
available afterwards.  The semi-honest attacks and the leakage tests are simply
a party reading its own view.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


def _canon(obj: Any) -> bytes:
    """A canonical byte encoding of a message, for the recorded transcript."""
    if isinstance(obj, bytes):
        return b"bytes:" + obj.hex().encode()
    return b"json:" + json.dumps(obj, sort_keys=True, default=str).encode()


@dataclass
class Message:
    sender: str
    receiver: str
    label: str
    payload: Any

    def size_bytes(self) -> int:
        return len(_canon(self.payload))


@dataclass
class Channel:
    """Records all messages; each party's view is filterable from the log."""

    log: list[Message] = field(default_factory=list)

    def send(self, sender: str, receiver: str, label: str, payload: Any) -> Any:
        self.log.append(Message(sender, receiver, label, payload))
        return payload

    def view(self, party: str) -> list[Message]:
        """Messages a semi-honest ``party`` sees (sent or received)."""
        return [m for m in self.log if m.sender == party or m.receiver == party]

    def total_bytes(self) -> int:
        return sum(m.size_bytes() for m in self.log)

    def rounds(self) -> int:
        return len(self.log)
