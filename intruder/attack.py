"""Ataques del Intruder: modos, combinaciones y ejecución (Plan.md §5.4).

El Intruder **no abre sockets**: construye peticiones y las entrega al
``RequestEngine`` compartido. La sustitución de offsets la hace
``RequestTemplate`` (de derecha a izquierda) y aquí solo se orquesta el flujo:

    combinaciones → procesadores (USE/SKIP) → plantilla → motor → resultados

Los cuatro modos siguen exactamente la tabla de Plan.md §5.4.
"""

from __future__ import annotations

import asyncio
import itertools
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from core.engine import Attempt, AttemptStatus, RequestEngine, RequestOptions
from core.logging import get_logger
from core.model import HttpService, Request, Response

from .payloads import PayloadSet
from .processors import (
    ProcessingAction,
    ProcessorChain,
    PayloadProcessor,
    make_chain,
)
from .template import InsertionPoint, RequestTemplate

Combo = Mapping[int, bytes]
_log = get_logger("prox0x.intruder")


class AttackMode(StrEnum):
    """Modos de ataque soportados (Plan.md §5.4)."""

    SNIPER = "sniper"
    BATTERING_RAM = "battering-ram"
    PITCHFORK = "pitchfork"
    CLUSTER_BOMB = "cluster-bomb"


def generate_combinations(
    mode: AttackMode,
    sets: Sequence[Sequence[bytes]],
    positions: Sequence[InsertionPoint],
) -> Iterator[dict[int, bytes]]:
    """Genera las combinaciones de payloads de un modo de ataque.

    - ``SNIPER``: una posición activa por petición, el resto conservan su
      ``base_value`` (un solo set, ``P × m`` combinaciones).
    - ``BATTERING_RAM``: el mismo payload en todas las posiciones (``m``).
    - ``PITCHFORK``: un set por posición, avance en paralelo; corta en el más
      corto (``min(m_i)``).
    - ``CLUSTER_BOMB``: producto cartesiano (``∏ m_i``).
    """
    mode = AttackMode(mode)
    normalized = tuple(tuple(items) for items in sets)
    if not positions:
        raise ValueError("el ataque necesita al menos una posición")
    if not normalized:
        raise ValueError("el ataque necesita al menos un set de payloads")

    if mode is AttackMode.SNIPER:
        if len(normalized) != 1:
            raise ValueError("SNIPER usa exactamente un set de payloads")
        for position in positions:
            for payload in normalized[0]:
                yield {position.index: payload}
        return

    if mode is AttackMode.BATTERING_RAM:
        if len(normalized) != 1:
            raise ValueError("BATTERING_RAM usa exactamente un set de payloads")
        for payload in normalized[0]:
            yield {position.index: payload for position in positions}
        return

    if len(normalized) != len(positions):
        raise ValueError(
            f"{mode.value} necesita un set por posición "
            f"({len(positions)} sets, recibidos {len(normalized)})"
        )

    if mode is AttackMode.PITCHFORK:
        for combination in zip(*normalized):
            yield {
                position.index: payload
                for position, payload in zip(positions, combination)
            }
        return

    if mode is AttackMode.CLUSTER_BOMB:
        for combination in itertools.product(*normalized):
            yield {
                position.index: payload
                for position, payload in zip(positions, combination)
            }
        return

    raise ValueError(f"modo de ataque no soportado: {mode}")


def _display(payload: bytes, *, limit: int = 80) -> str:
    text = payload.decode("utf-8", errors="replace").replace("\r", "\\r").replace("\n", "\\n")
    return text if len(text) <= limit else text[: limit - 1] + "…"


@dataclass(frozen=True, slots=True, kw_only=True)
class AttackResult:
    """Fila de resultado de un ataque (Plan.md §5.3)."""

    index: int
    combo: tuple[tuple[int, bytes], ...]
    mode: AttackMode
    label: str = ""
    request: Request | None = None
    response: Response | None = None
    status: AttemptStatus = AttemptStatus.DROPPED
    error: str | None = None
    latency_ms: float = 0.0
    ttfb_ms: float | None = None
    total_ms: float | None = None
    retries: int = 0

    @property
    def ok(self) -> bool:
        return self.status is AttemptStatus.RESPONDED

    @property
    def status_code(self) -> int | None:
        return self.response.status_code if self.response is not None else None

    @property
    def length(self) -> int:
        return len(self.response.body) if self.response is not None else 0

    @property
    def payloads(self) -> tuple[bytes, ...]:
        return tuple(payload for _index, payload in self.combo)

    @classmethod
    def from_attempt(
        cls,
        *,
        index: int,
        combo: Mapping[int, bytes],
        mode: AttackMode,
        label: str,
        attempt: Attempt,
    ) -> "AttackResult":
        return cls(
            index=index,
            combo=tuple(sorted(combo.items())),
            mode=AttackMode(mode),
            label=label,
            request=attempt.request,
            response=attempt.response,
            status=attempt.status,
            error=attempt.error,
            latency_ms=attempt.latency_ms,
            ttfb_ms=attempt.ttfb_ms,
            total_ms=attempt.total_ms,
            retries=attempt.retries,
        )


class Attack:
    """Orquesta combinaciones + procesadores + ``RequestEngine``."""

    def __init__(
        self,
        *,
        template: RequestTemplate,
        service: HttpService,
        mode: AttackMode,
        sets: Sequence[PayloadSet | Sequence[bytes | str]],
        engine: RequestEngine | None = None,
        options: RequestOptions | None = None,
        concurrency: int = 10,
        processors: Sequence[PayloadProcessor] | ProcessorChain | None = None,
        max_requests: int | None = None,
        batch_size: int | None = None,
        on_result: Callable[[AttackResult], None] | None = None,
    ) -> None:
        if not template.points:
            raise ValueError("la plantilla no tiene posiciones")
        if concurrency < 1:
            raise ValueError("concurrency debe ser >= 1")
        if max_requests is not None and max_requests < 1:
            raise ValueError("max_requests debe ser >= 1")

        self.template = template
        self.service = service
        self.mode = AttackMode(mode)
        self.concurrency = concurrency
        self.options = options or RequestOptions()
        self._engine = engine or RequestEngine(max_concurrency=concurrency)
        self._processors: ProcessorChain = make_chain(processors)
        self._sets = self._normalize_sets(sets)
        self._max_requests = max_requests
        # Con throttle global espaciamos envíos de uno en uno; si no, un lote
        # del tamaño de la concurrencia mantiene el motor ocupado.
        throttled = self.options.throttle_ms > 0
        self._batch_size = max(
            1, batch_size or (1 if throttled else concurrency)
        )
        self._next_start: float | None = None
        self._on_result = on_result
        self._skipped = 0

        # Valida la cardinalidad de sets para el modo elegido.
        if self.mode in (AttackMode.SNIPER, AttackMode.BATTERING_RAM):
            if len(self._sets) != 1:
                raise ValueError(
                    f"{self.mode.value} usa exactamente un set de payloads"
                )
        elif len(self._sets) != len(template.points):
            raise ValueError(
                f"{self.mode.value} necesita un set por posición "
                f"({len(template.points)} sets, recibidos {len(self._sets)})"
            )

    # ------------------------------------------------------------ propiedades

    @property
    def engine(self) -> RequestEngine:
        return self._engine

    @property
    def skipped(self) -> int:
        """Combinaciones descartadas por un procesador ``SKIP``."""
        return self._skipped

    @property
    def expected_requests(self) -> int:
        """Nº teórico de peticiones antes de procesadores ``SKIP``."""
        lengths = [len(items) for items in self._sets]
        if self.mode is AttackMode.SNIPER:
            return len(self.template.points) * lengths[0]
        if self.mode is AttackMode.BATTERING_RAM:
            return lengths[0]
        if self.mode is AttackMode.PITCHFORK:
            return min(lengths)
        return _product(lengths)

    def combinations(self) -> Iterator[dict[int, bytes]]:
        """Combinaciones crudas (sin procesadores)."""
        return generate_combinations(self.mode, self._sets, self.template.points)

    def label(self, combo: Mapping[int, bytes]) -> str:
        parts: list[str] = []
        for index in sorted(combo):
            point = self.template.points[index]
            name = point.name or f"pos{index}"
            parts.append(f"{name}={_display(combo[index])}")
        return ", ".join(parts)

    def cancel(self) -> None:
        """Cancela los envíos aún no iniciados (cooperativo)."""
        self._engine.cancel()

    def reset_cancel(self) -> None:
        self._engine.reset_cancel()

    # ---------------------------------------------------------------- ejecución

    def _processed(self) -> Iterator[dict[int, bytes]]:
        for combo in self.combinations():
            processed: dict[int, bytes] = {}
            skipped = False
            for index, payload in combo.items():
                point = self.template.points[index]
                result = self._processors.apply(
                    payload, insertion_point=point
                )
                if result.action is ProcessingAction.SKIP:
                    skipped = True
                    break
                processed[index] = result.payload
            if skipped:
                self._skipped += 1
                continue
            yield processed

    async def run(self) -> tuple[AttackResult, ...]:
        """Ejecuta el ataque y devuelve los resultados en orden de lanzamiento."""
        self.reset_cancel()
        self._skipped = 0
        self._next_start = None
        results: list[AttackResult] = []
        batch: list[tuple[int, dict[int, bytes], Request]] = []
        launch_index = 0

        async def flush() -> None:
            if not batch:
                return
            requests = [request for _index, _combo, request in batch]
            labels = [self.label(combo) for _index, combo, _request in batch]
            attempts = await self._engine.send_requests(
                requests,
                self.service,
                options=self.options,
                concurrency=self.concurrency,
                labels=labels,
            )
            for (index, combo, _request), attempt in zip(batch, attempts):
                result = AttackResult.from_attempt(
                    index=index,
                    combo=combo,
                    mode=self.mode,
                    label=self.label(combo),
                    attempt=attempt,
                )
                results.append(result)
                self._emit(result)
            batch.clear()

        for combo in self._processed():
            if self._max_requests is not None and launch_index >= self._max_requests:
                break
            label = self.label(combo)
            try:
                request = self.template.build_request(combo)
            except (ValueError, TypeError, UnicodeError) as exc:
                await flush()  # conserva el orden de lanzamiento de los lotes previos
                result = AttackResult(
                    index=launch_index,
                    combo=tuple(sorted(combo.items())),
                    mode=self.mode,
                    label=label,
                    status=AttemptStatus.DROPPED,
                    error=f"no se pudo construir la petición: {exc}",
                )
                results.append(result)
                self._emit(result)
            else:
                await self._wait_throttle()
                batch.append((launch_index, combo, request))
            launch_index += 1
            if len(batch) >= self._batch_size:
                await flush()

        await flush()
        return tuple(results)

    # ------------------------------------------------------------------ interno

    def _emit(self, result: AttackResult) -> None:
        """Notifica un resultado parcial sin permitir que el callback tumbe el ataque."""
        if self._on_result is None:
            return
        try:
            self._on_result(result)
        except Exception:
            _log.exception("attack_result_callback_failed", index=result.index)

    async def _wait_throttle(self) -> None:
        """Espacia los envíos de forma global (Plan.md §5.5)."""
        interval = self.options.throttle_s
        if interval <= 0:
            return
        loop = asyncio.get_running_loop()
        now = loop.time()
        if self._next_start is not None and now < self._next_start:
            await asyncio.sleep(self._next_start - now)
            now = loop.time()
        self._next_start = now + interval

    @staticmethod
    def _normalize_sets(
        sets: Sequence[PayloadSet | Sequence[bytes | str]],
    ) -> tuple[tuple[bytes, ...], ...]:
        normalized: list[tuple[bytes, ...]] = []
        for source in sets:
            items = source.items if isinstance(source, PayloadSet) else tuple(source)
            converted = tuple(
                item.encode("utf-8") if isinstance(item, str) else bytes(item)
                for item in items
            )
            if not converted:
                raise ValueError("un set de payloads no puede estar vacío")
            normalized.append(converted)
        if not normalized:
            raise ValueError("el ataque necesita al menos un set de payloads")
        return tuple(normalized)


def _product(values: Sequence[int]) -> int:
    result = 1
    for value in values:
        result *= value
    return result
