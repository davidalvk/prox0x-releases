"""Buffer circular de flujos en memoria para la API y la UI (Plan.md §7.2).

Implementa un *ring buffer* acotado: al llenarse, el flujo más antiguo se
descarta (§7.5.6, "nunca se bloquea la red"). ``total`` conserva el número de
flujos vistos aunque se hayan descartado, para que la API pueda informar del
volumen real. La persistencia en SQLite llega en F1/F5; este store es la fuente
de lectura en vivo.
"""

from __future__ import annotations

from collections import deque

from core.model import Flow


class FlowStore:
    """Almacén circular de ``Flow``, indexado por id y en orden de llegada."""

    def __init__(self, maxsize: int = 5_000) -> None:
        if maxsize < 1:
            raise ValueError("maxsize debe ser >= 1")
        self._maxsize = maxsize
        self._flows: deque[Flow] = deque()
        self._by_id: dict[int, Flow] = {}
        self._total = 0
        self._id_counter = 0

    @property
    def maxsize(self) -> int:
        return self._maxsize

    @property
    def total(self) -> int:
        """Flujos añadidos desde el arranque (incluidos los ya descartados)."""
        return self._total

    def next_id(self) -> int:
        """Identificador monótono para correlacionar logs y flujos.

        Contador propio: no depende de ``total`` (que solo crece en ``add``),
        de modo que se puede pedir un id antes de construir el flujo.
        """
        self._id_counter += 1
        return self._id_counter

    def ensure_next_id(self, last_used: int) -> None:
        """Avanza el contador para no reutilizar IDs persistidos (SQLite)."""
        if last_used > self._id_counter:
            self._id_counter = last_used

    def clear(self, *, last_used: int = 0) -> None:
        """Vacía el buffer en memoria y reinicia el contador de IDs."""
        self._flows.clear()
        self._by_id.clear()
        self._total = 0
        self._id_counter = max(0, last_used)

    def add(self, flow: Flow) -> Flow:
        """Inserta un flujo; si el buffer está lleno, descarta el más antiguo."""
        if flow.id in self._by_id:
            raise ValueError(f"flow id duplicado: {flow.id}")
        self._flows.append(flow)
        self._by_id[flow.id] = flow
        self._total += 1
        if len(self._flows) > self._maxsize:
            evicted = self._flows.popleft()
            del self._by_id[evicted.id]
        return flow

    def get(self, flow_id: int) -> Flow | None:
        return self._by_id.get(flow_id)

    def update(self, flow: Flow) -> Flow:
        """Sustituye un flujo existente conservando su posición (p. ej. frames WS)."""
        if flow.id not in self._by_id:
            raise KeyError(f"flow id inexistente: {flow.id}")
        for index, current in enumerate(self._flows):
            if current.id == flow.id:
                self._flows[index] = flow
                break
        self._by_id[flow.id] = flow
        return flow

    def recent(self, limit: int | None = None) -> list[Flow]:
        """Flujos más recientes primero (hasta ``limit``, o todos los retenidos)."""
        flows = list(self._flows)
        flows.reverse()
        return flows if limit is None else flows[:limit]

    def __len__(self) -> int:
        return len(self._flows)

    def __contains__(self, flow_id: int) -> bool:
        return flow_id in self._by_id
