"""Pestañas del Repeater: versiones inmutables, edición y envío (Plan.md §4).

Un ``Tab`` es inmutable: cada edición crea una versión nueva y la selecciona.
Eso permite deshacer, comparar y reenviar sin efectos colaterales, y encaja con
el modelo de ``core.model`` (toda mutación devuelve un objeto nuevo).

El envío 1..N delega en ``core.engine.RequestEngine``: el Repeater no tiene
cliente HTTP propio (Plan.md §4.5).
"""

from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass, replace
from typing import Literal

from core.engine import Attempt, RequestEngine, RequestOptions
from core.model import Flow, HttpService, Request
from core.net.wire import parse_request

from .diff import DiffResult, diff_responses

# --------------------------------------------------------------------- wire


def request_from_record(record: dict) -> Request:
    """Reconstruye la petición de un registro JSONL de ``prox0x flows``.

    Si el flujo fue editado por el interceptor se usa ``final_request`` (lo que
    realmente salió a la red), que es lo que el usuario vio en el historial.
    """
    key = "final_request" if record.get("edited") and record.get("final_request") else "request"
    message = record.get(key)
    if not isinstance(message, dict) or "raw" not in message:
        raise ValueError("el registro no contiene una petición válida")
    return parse_request(base64.b64decode(str(message["raw"])))


# ----------------------------------------------------------------------- tab


@dataclass(frozen=True, slots=True, kw_only=True)
class Tab:
    """Pestaña del Repeater con historial de versiones y respuestas."""

    id: int
    name: str
    service: HttpService
    base_request: Request
    versions: tuple[Request, ...]
    selected_version: int = 0
    responses: tuple[Attempt, ...] = ()

    def __post_init__(self) -> None:
        if not self.versions:
            raise ValueError("una pestaña necesita al menos una versión")
        if not 0 <= self.selected_version < len(self.versions):
            raise ValueError(
                f"selected_version {self.selected_version} fuera de rango"
            )

    @property
    def current(self) -> Request:
        return self.versions[self.selected_version]

    @property
    def version_count(self) -> int:
        return len(self.versions)

    @property
    def response_count(self) -> int:
        return len(self.responses)

    def with_version(self, request: Request) -> "Tab":
        """Añade una versión y la selecciona (nunca modifica las anteriores)."""
        return replace(
            self,
            versions=self.versions + (request,),
            selected_version=len(self.versions),
        )

    def with_selection(self, index: int) -> "Tab":
        if not 0 <= index < len(self.versions):
            raise ValueError(
                f"versión {index} fuera de rango (0..{len(self.versions) - 1})"
            )
        return replace(self, selected_version=index)

    def with_response(self, attempt: Attempt) -> "Tab":
        return replace(self, responses=self.responses + (attempt,))

    def undo(self) -> "Tab":
        return self.with_selection(max(0, self.selected_version - 1))

    def redo(self) -> "Tab":
        return self.with_selection(
            min(len(self.versions) - 1, self.selected_version + 1)
        )


# ------------------------------------------------------------------ repeater

_DEFAULT_TAB_NAME = "tab"


class Repeater:
    """Colección de pestañas en memoria + envío a través del motor común."""

    def __init__(
        self,
        *,
        engine: RequestEngine | None = None,
        max_tabs: int = 100,
    ) -> None:
        if max_tabs < 1:
            raise ValueError("max_tabs debe ser >= 1")
        self._engine = engine or RequestEngine()
        self._max_tabs = max_tabs
        self._tabs: dict[int, Tab] = {}
        self._next_id = 1

    # ------------------------------------------------------------ pestañas

    @property
    def engine(self) -> RequestEngine:
        return self._engine

    @property
    def tabs(self) -> tuple[Tab, ...]:
        return tuple(self._tabs[key] for key in sorted(self._tabs))

    def get(self, tab_id: int) -> Tab:
        try:
            return self._tabs[tab_id]
        except KeyError as exc:
            raise KeyError(f"no existe la pestaña {tab_id}") from exc

    def create_tab(
        self,
        request: Request,
        service: HttpService,
        *,
        name: str | None = None,
    ) -> Tab:
        if len(self._tabs) >= self._max_tabs:
            raise ValueError(f"límite de {self._max_tabs} pestañas alcanzado")
        tab = Tab(
            id=self._next_id,
            name=name or f"{_DEFAULT_TAB_NAME} {self._next_id}",
            service=service,
            base_request=request,
            versions=(request,),
        )
        self._tabs[tab.id] = tab
        self._next_id += 1
        return tab

    def send_to_repeater(
        self,
        request: Request,
        service: HttpService,
        *,
        name: str | None = None,
    ) -> Tab:
        """Puente ``sendToRepeater(request, name?)`` del contrato (Plan.md §A.2)."""
        return self.create_tab(request, service, name=name)

    def from_flow(self, flow: Flow, *, name: str | None = None) -> Tab:
        """Crea una pestaña desde un flujo del Proxy (request final + servicio)."""
        request = flow.final_request
        if not isinstance(request, Request):
            request = flow.request
        if not isinstance(request, Request):
            raise TypeError("el flujo no contiene un Request")
        return self.send_to_repeater(
            request, flow.service, name=name or f"flow #{flow.id}"
        )

    def _replace(self, tab: Tab) -> Tab:
        self._tabs[tab.id] = tab
        return tab

    # -------------------------------------------------------------- edición

    def set_raw(self, tab_id: int, raw: bytes) -> Tab:
        """Sustituye la petición por una versión parseada del texto pegado."""
        tab = self.get(tab_id)
        return self._replace(tab.with_version(parse_request(raw)))

    def set_header(self, tab_id: int, name: str, value: str) -> Tab:
        tab = self.get(tab_id)
        return self._replace(tab.with_version(tab.current.with_header(name, value)))

    def set_body(self, tab_id: int, body: bytes) -> Tab:
        tab = self.get(tab_id)
        return self._replace(tab.with_version(tab.current.with_body(body)))

    def replace(self, tab_id: int, old: str, new: str) -> Tab:
        """Reemplaza texto en la petición completa (cabeceras + cuerpo)."""
        if not old:
            raise ValueError("el texto a reemplazar no puede estar vacío")
        tab = self.get(tab_id)
        wire = tab.current.to_bytes()
        needle = old.encode("utf-8")
        if needle not in wire:
            raise ValueError(f"no se encontró {old!r} en la petición")
        return self.set_raw(tab_id, wire.replace(needle, new.encode("utf-8")))

    def undo(self, tab_id: int) -> Tab:
        return self._replace(self.get(tab_id).undo())

    def redo(self, tab_id: int) -> Tab:
        return self._replace(self.get(tab_id).redo())

    def select_version(self, tab_id: int, index: int) -> Tab:
        return self._replace(self.get(tab_id).with_selection(index))

    # --------------------------------------------------------------- envío

    async def send(
        self,
        tab_id: int,
        *,
        count: int = 1,
        options: RequestOptions | None = None,
        concurrency: int = 1,
        mode: Literal["single", "sequential", "parallel"] = "parallel",
        delay_ms: int = 0,
    ) -> tuple[Attempt, ...]:
        """Envía la versión actual ``count`` veces y guarda las respuestas.

        ``single`` fuerza un único envío; ``sequential`` espera ``delay_ms``
        entre peticiones y ``parallel`` delega en el semáforo del motor.
        """
        if count < 1:
            raise ValueError("count debe ser >= 1")
        if delay_ms < 0:
            raise ValueError("delay_ms debe ser >= 0")
        if mode not in ("single", "sequential", "parallel"):
            raise ValueError(f"modo de envío desconocido: {mode!r}")

        tab = self.get(tab_id)
        label = f"{tab.name} v{tab.selected_version}"

        if mode == "single":
            count = 1

        if mode == "sequential":
            attempts: list[Attempt] = []
            for index in range(count):
                attempt = await self._engine.send(
                    tab.current,
                    tab.service,
                    options=options,
                    label=f"{label} [{index + 1}/{count}]",
                )
                attempts.append(replace(attempt, index=index))
                if index < count - 1 and delay_ms:
                    await asyncio.sleep(delay_ms / 1000)
        else:
            requests = [tab.current] * count
            labels = [label for _ in range(count)]
            attempts = await self._engine.send_requests(
                requests,
                tab.service,
                options=options,
                concurrency=concurrency,
                labels=labels,
            )

        updated = tab
        for attempt in attempts:
            updated = updated.with_response(attempt)
        self._replace(updated)
        return tuple(attempts)

    # ----------------------------------------------------------------- diff

    def diff(
        self,
        tab_id: int,
        first: int = 0,
        second: int = -1,
        *,
        ignore_headers: bool = True,
    ) -> DiffResult:
        """Compara dos respuestas guardadas de la pestaña (índices 0-based)."""
        tab = self.get(tab_id)
        if not tab.responses:
            raise ValueError("la pestaña no tiene respuestas todavía")
        try:
            left = tab.responses[first]
            right = tab.responses[second]
        except IndexError as exc:
            raise ValueError(
                f"índice de respuesta fuera de rango (0..{len(tab.responses) - 1})"
            ) from exc
        if left.response is None or right.response is None:
            raise ValueError("alguna de las respuestas seleccionadas falló")
        return diff_responses(
            left.response, right.response, ignore_headers=ignore_headers
        )
