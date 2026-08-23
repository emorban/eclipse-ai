from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable
import uuid


@dataclass(frozen=True)
class MemoryRecord:
    id: str
    text: str
    tags: tuple[str, ...] = field(default_factory=tuple)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class InMemoryStore:
    """Small portfolio example of a durable-memory boundary.

    A real system would replace this store with persistent/vector-backed storage,
    access controls, retention policy, and richer retrieval. The important design
    idea is that memory is written and queried through an explicit interface
    rather than being treated as an unstructured transcript dump.
    """

    def __init__(self) -> None:
        self._records: list[MemoryRecord] = []

    def add(self, text: str, tags: Iterable[str] = ()) -> MemoryRecord:
        cleaned = text.strip()
        if not cleaned:
            raise ValueError("memory text cannot be empty")

        record = MemoryRecord(
            id=str(uuid.uuid4()),
            text=cleaned,
            tags=tuple(sorted({tag.strip().lower() for tag in tags if tag.strip()})),
        )
        self._records.append(record)
        return record

    def search(self, query: str, limit: int = 5) -> list[MemoryRecord]:
        terms = {term.lower() for term in query.split() if term.strip()}
        if not terms or limit <= 0:
            return []

        def score(record: MemoryRecord) -> int:
            haystack = f"{record.text} {' '.join(record.tags)}".lower()
            return sum(term in haystack for term in terms)

        ranked = sorted(
            ((score(record), index, record) for index, record in enumerate(self._records)),
            key=lambda item: (-item[0], item[1]),
        )
        return [record for points, _, record in ranked if points > 0][:limit]

    def all(self) -> tuple[MemoryRecord, ...]:
        return tuple(self._records)
