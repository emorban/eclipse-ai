from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


ToolHandler = Callable[..., Any]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    handler: ToolHandler
    writes_state: bool = False


class ToolRouter:
    """Capability-aware tool router for an agentic system.

    Read operations can execute normally. State-changing tools require an
    explicit write permit at invocation time. Production systems would layer
    authentication, scoped permissions, audit logs, and richer policy on top.
    """

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        if not spec.name.strip():
            raise ValueError("tool name cannot be empty")
        if spec.name in self._tools:
            raise ValueError(f"tool already registered: {spec.name}")
        self._tools[spec.name] = spec

    def invoke(
        self,
        name: str,
        *args: Any,
        permit_writes: bool = False,
        **kwargs: Any,
    ) -> Any:
        spec = self._tools.get(name)
        if spec is None:
            raise KeyError(f"unknown tool: {name}")
        if spec.writes_state and not permit_writes:
            raise PermissionError(f"write-capable tool requires explicit permit: {name}")
        return spec.handler(*args, **kwargs)

    def describe(self) -> tuple[tuple[str, bool], ...]:
        return tuple(
            (spec.name, spec.writes_state)
            for spec in sorted(self._tools.values(), key=lambda item: item.name)
        )
