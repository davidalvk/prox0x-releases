import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  Activity,
  Globe2,
  Loader2,
  Radar,
  RadioTower,
  RefreshCw,
  Search,
  ShieldCheck,
  Trash2,
  Wand2,
  X,
  Zap,
} from "lucide-react";
import type { FlowSummaryRecord } from "../types";
import {
  WS_URL,
  deleteFlows,
  fetchFlows,
  flowHost,
  flowPath,
  flowPathOnly,
  formatMs,
  formatTime,
  methodTone,
  startBatchScan,
  statusTone,
} from "../lib/api";
import { FlowDetailPanel } from "../components/FlowDetailPanel";
import { HelpTooltip } from "../components/HelpTooltip";
import { DATA_TABLE, DATA_TABLE_HEAD } from "../lib/tableStyles";
import { useApp } from "../context/AppContext";

type SocketStatus = "connecting" | "online" | "offline";

const MAX_ROWS = 500;

export function ProxyPage() {
  const {
    proxyRouteFilter,
    setProxyRouteFilter,
    currentProject,
    scopeRevision,
    selectedFlowId,
    setSelectedFlowId,
    setActiveModule,
  } = useApp();
  const [flows, setFlows] = useState<FlowSummaryRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [socketStatus, setSocketStatus] = useState<SocketStatus>("connecting");
  const [filter, setFilter] = useState("");
  const [onlyInScope, setOnlyInScope] = useState(false);
  const [showScanFlows, setShowScanFlows] = useState(false);
  const [confirmClear, setConfirmClear] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [batchBusy, setBatchBusy] = useState(false);
  const [topPercent, setTopPercent] = useState(50);
  const [resizing, setResizing] = useState(false);
  const splitRef = useRef<HTMLDivElement>(null);
  const selectAllRef = useRef<HTMLInputElement>(null);
  const pendingFlows = useRef<FlowSummaryRecord[]>([]);
  const showScanFlowsRef = useRef(showScanFlows);

  useEffect(() => {
    showScanFlowsRef.current = showScanFlows;
  }, [showScanFlows]);

  const load = useCallback(async () => {
    setError(null);
    try {
      const data = await fetchFlows(MAX_ROWS, showScanFlows);
      setFlows(data);
      // La recarga trae el estado canónico (p. ej. in_scope reevaluado).
      // Descarta duplicados pendientes del WS para no reinyectar metadatos
      // antiguos encima de la recarga.
      const loadedIds = new Set(data.map((flow) => flow.id));
      pendingFlows.current = pendingFlows.current.filter(
        (flow) => !loadedIds.has(flow.id),
      );
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "No se pudo cargar el historial");
    } finally {
      setLoading(false);
    }
  }, [showScanFlows]);

  useEffect(() => {
    pendingFlows.current = [];
    setFlows([]);
    setLoading(true);
    setSelectedIds(new Set());
    void load();
  }, [load, currentProject]);

  // Batching: los WebSocket pueden entregar decenas de imágenes por segundo.
  // Acumulamos y volcamos al estado de React cada 500 ms para no re-renderizar
  // una vez por mensaje.
  useEffect(() => {
    const timer = window.setInterval(() => {
      if (pendingFlows.current.length === 0) return;
      const batch = pendingFlows.current.splice(0);
      console.log(`[prox0x][WS] flush ${batch.length} flujos`);
      setFlows((previous) => {
        const byId = new Map(previous.map((flow) => [flow.id, flow]));
        for (const flow of batch) byId.set(flow.id, flow);
        return [...byId.values()]
          .sort((left, right) => right.id - left.id)
          .slice(0, MAX_ROWS);
      });
    }, 500);
    return () => {
      window.clearInterval(timer);
      pendingFlows.current = [];
    };
  }, []);

  useEffect(() => {
    if (scopeRevision === 0) return;
    void load();
  }, [load, scopeRevision]);

  useEffect(() => {
    let socket: WebSocket | null = null;
    let reconnectTimer: number | undefined;
    let stopped = false;

    const connect = () => {
      if (stopped) return;
      setSocketStatus("connecting");
      socket = new WebSocket(WS_URL);
      socket.onopen = () => setSocketStatus("online");
      socket.onmessage = (event) => {
        try {
          const flow = JSON.parse(event.data as string) as FlowSummaryRecord;
          if (!showScanFlowsRef.current && flow.is_scan_flow) {
            return;
          }
          console.log(
            `[prox0x][WS] flow #${flow.id}`,
            flow.mime || "(sin mime)",
            flow.request?.target ?? "/",
            `req=${flow.request_size ?? 0}B resp=${flow.response_size ?? 0}B`,
          );
          pendingFlows.current.push(flow);
          if (pendingFlows.current.length > MAX_ROWS) {
            pendingFlows.current.splice(
              0,
              pendingFlows.current.length - MAX_ROWS,
            );
          }
        } catch {
          console.warn("[prox0x][WS] mensaje no JSON ignorado");
        }
      };
      socket.onerror = () => {
        socket?.close();
      };
      socket.onclose = () => {
        setSocketStatus("offline");
        if (!stopped) {
          reconnectTimer = window.setTimeout(connect, 3000);
        }
      };
    };

    connect();
    return () => {
      stopped = true;
      if (reconnectTimer !== undefined) window.clearTimeout(reconnectTimer);
      socket?.close();
    };
  }, []);

  const visibleFlows = useMemo(() => {
    const query = filter.trim().toLowerCase();
    return flows.filter((flow) => {
      if (!showScanFlows && flow.is_scan_flow) return false;
      if (onlyInScope && flow.in_scope === false) return false;
      if (proxyRouteFilter) {
        if (flow.service.host !== proxyRouteFilter.host) return false;
        if (flowPathOnly(flow) !== proxyRouteFilter.path) return false;
      }
      if (!query) return true;
      const haystack = [
        flow.request.method,
        flowHost(flow),
        flowPath(flow),
        flow.response?.status?.toString(),
        flow.service.host,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return haystack.includes(query);
    });
  }, [filter, flows, onlyInScope, proxyRouteFilter, showScanFlows]);

  const selectedFlows = useMemo(
    () => flows.filter((flow) => selectedIds.has(flow.id)),
    [flows, selectedIds],
  );
  const domainHost =
    selectedFlows[0]?.service.host ??
    visibleFlows[0]?.service.host ??
    flows[0]?.service.host ??
    null;
  const allVisibleSelected =
    visibleFlows.length > 0 &&
    visibleFlows.every((flow) => selectedIds.has(flow.id));
  const someVisibleSelected = visibleFlows.some((flow) =>
    selectedIds.has(flow.id),
  );

  useEffect(() => {
    if (selectAllRef.current) {
      selectAllRef.current.indeterminate =
        someVisibleSelected && !allVisibleSelected;
    }
  }, [someVisibleSelected, allVisibleSelected]);

  const toggleFlow = (flowId: number) => {
    setSelectedIds((previous) => {
      const next = new Set(previous);
      if (next.has(flowId)) next.delete(flowId);
      else next.add(flowId);
      return next;
    });
  };

  const toggleAllVisible = () => {
    setSelectedIds((previous) => {
      const next = new Set(previous);
      if (allVisibleSelected) {
        for (const flow of visibleFlows) next.delete(flow.id);
      } else {
        for (const flow of visibleFlows) next.add(flow.id);
      }
      return next;
    });
  };

  const launchBatchScan = async (payload: {
    flow_ids?: number[];
    host?: string;
  }) => {
    setBatchBusy(true);
    setError(null);
    try {
      await startBatchScan(payload);
      setActiveModule("active-scan");
    } catch (err: unknown) {
      setError(
        err instanceof Error
          ? `No se pudo iniciar el escaneo: ${err.message}`
          : "No se pudo iniciar el escaneo",
      );
    } finally {
      setBatchBusy(false);
    }
  };

  useEffect(() => {
    if (!resizing) return;
    const onMove = (event: PointerEvent) => {
      const rect = splitRef.current?.getBoundingClientRect();
      if (!rect) return;
      const percent = ((event.clientY - rect.top) / rect.height) * 100;
      setTopPercent(Math.min(80, Math.max(20, percent)));
    };
    const stop = () => setResizing(false);
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", stop);
    window.addEventListener("pointercancel", stop);
    document.body.style.cursor = "row-resize";
    document.body.style.userSelect = "none";
    return () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", stop);
      window.removeEventListener("pointercancel", stop);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
  }, [resizing]);

  const resizeTop = (delta: number) => {
    setTopPercent((value) => Math.min(80, Math.max(20, value + delta)));
  };

  const handleClearHistory = async () => {
    setClearing(true);
    setError(null);
    try {
      await deleteFlows();
      setFlows([]);
      setSelectedIds(new Set());
      setSelectedFlowId(null);
      setConfirmClear(false);
    } catch (err: unknown) {
      setError(
        err instanceof Error ? err.message : "No se pudo limpiar el historial",
      );
    } finally {
      setClearing(false);
    }
  };

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-3 border-b border-surface-800 bg-surface-900/40 px-5 py-3">
        <span className="flex items-center gap-2 rounded-full border border-surface-700 bg-surface-850 px-3 py-1.5 text-[11px] text-zinc-400">
          <span
            className={[
              "h-2 w-2 rounded-full",
              socketStatus === "online"
                ? "bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.8)]"
                : socketStatus === "connecting"
                  ? "animate-pulse bg-amber-400"
                  : "bg-rose-500",
            ].join(" ")}
          />
          {socketStatus === "online"
            ? "live · ws conectado"
            : socketStatus === "connecting"
              ? "conectando ws…"
              : "ws desconectado"}
        </span>

        <div className="flex items-center gap-2 text-xs text-zinc-500">
          <Activity size={14} className="text-accent" />
          <span>
            {visibleFlows.length} de {flows.length} flujos
          </span>
        </div>

        <label className="flex cursor-pointer items-center gap-2 rounded-lg border border-surface-700 bg-surface-850 px-3 py-2 text-xs text-zinc-400 transition hover:border-surface-600 hover:text-zinc-200">
          <input
            type="checkbox"
            checked={onlyInScope}
            onChange={(event) => setOnlyInScope(event.target.checked)}
            className="h-3.5 w-3.5 accent-emerald-400"
          />
          <ShieldCheck size={14} className="text-emerald-400" />
          Mostrar solo tráfico en Alcance
        </label>

        <label
          className="flex cursor-pointer items-center gap-2 rounded-lg border border-surface-700 bg-surface-850 px-3 py-2 text-xs text-zinc-400 transition hover:border-surface-600 hover:text-zinc-200"
          title="Muestra los flujos sintéticos creados por el Full Site Scan"
        >
          <input
            type="checkbox"
            checked={showScanFlows}
            onChange={(event) => setShowScanFlows(event.target.checked)}
            className="h-3.5 w-3.5 accent-cyan-400"
          />
          <Radar size={14} className="text-cyan-400" />
          Mostrar tráfico del escáner
        </label>

        {proxyRouteFilter && (
          <span className="flex items-center gap-2 rounded-lg border border-accent/40 bg-accent/10 px-3 py-2 font-mono text-[11px] text-accent">
            <span className="max-w-[22rem] truncate">
              {proxyRouteFilter.host}
              {proxyRouteFilter.path}
            </span>
            <button
              type="button"
              onClick={() => setProxyRouteFilter(null)}
              className="rounded p-0.5 text-accent/70 transition hover:bg-accent/20 hover:text-accent"
              aria-label="Quitar filtro de ruta"
              title="Quitar filtro de ruta"
            >
              <X size={13} />
            </button>
          </span>
        )}

        <div className="relative ml-auto w-full max-w-xs">
          <Search
            size={14}
            className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-zinc-600"
          />
          <input
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            placeholder="Filtrar host, ruta, método…"
            className="w-full rounded-lg border border-surface-700 bg-surface-950 py-2 pl-9 pr-3 font-mono text-xs text-zinc-300 outline-none transition placeholder:text-zinc-600 focus:border-accent/60"
          />
        </div>

        <button
          type="button"
          onClick={() => void load()}
          className="flex items-center gap-2 rounded-lg border border-surface-700 px-3 py-2 text-xs text-zinc-400 transition hover:border-surface-600 hover:text-zinc-100"
        >
          <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
          Recargar
        </button>

        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={() =>
              void launchBatchScan({ flow_ids: [...selectedIds] })
            }
            disabled={selectedIds.size === 0 || batchBusy}
            className="flex items-center gap-2 rounded-lg border border-amber-400/40 bg-amber-400/10 px-3 py-2 text-xs font-semibold text-amber-300 transition hover:bg-amber-400/20 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {batchBusy ? (
              <Loader2 size={14} className="animate-spin" />
            ) : (
              <Zap size={14} />
            )}
            Escanear Seleccionadas
            {selectedIds.size > 0 ? ` (${selectedIds.size})` : ""}
          </button>
          <HelpTooltip
            label="Escanear Seleccionadas"
            text="Lanza XSS, SQLi y path traversal contra los parámetros de las peticiones marcadas."
          />
        </div>

        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={() =>
              domainHost
                ? void launchBatchScan({ host: domainHost })
                : undefined
            }
            disabled={!domainHost || batchBusy}
            className="flex items-center gap-2 rounded-lg border border-cyan-400/40 bg-cyan-950/30 px-3 py-2 text-xs font-semibold text-cyan-300 transition hover:border-accent hover:text-accent disabled:cursor-not-allowed disabled:opacity-40"
          >
            {batchBusy ? (
              <Loader2 size={14} className="animate-spin" />
            ) : (
              <Globe2 size={14} />
            )}
            Escanear todo el Dominio
          </button>
          <HelpTooltip
            label="Escanear todo el Dominio"
            text={
              domainHost
                ? `Escanea todas las peticiones capturadas de ${domainHost}.`
                : "Selecciona un flujo o captura tráfico para elegir un host."
            }
          />
        </div>

        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={() => setConfirmClear(true)}
            disabled={flows.length === 0 || clearing}
            className="flex items-center gap-2 rounded-lg border border-rose-500/40 bg-rose-950/30 px-3 py-2 text-xs text-rose-300 transition hover:border-rose-500 hover:text-rose-200 disabled:opacity-40"
          >
            <Trash2 size={14} />
            Limpiar Historial
          </button>
          <HelpTooltip
            label="Limpiar Historial"
            text="Borra todos los flujos de la tabla actual (no borra el proyecto)."
          />
        </div>
      </div>

      {error && (
        <div className="mx-5 mt-4 flex items-center justify-between rounded-lg border border-rose-900/60 bg-rose-950/30 px-4 py-3 text-sm text-rose-300">
          <span>Error: {error}</span>
          <button
            type="button"
            onClick={() => void load()}
            className="rounded bg-rose-900/40 px-2 py-1 text-xs hover:bg-rose-900/70"
          >
            Reintentar
          </button>
        </div>
      )}

      <div ref={splitRef} className="flex min-h-0 flex-1 flex-col">
        <div
          className="min-h-0 overflow-auto"
          style={{ flexGrow: topPercent, flexBasis: 0 }}
        >
        {loading ? (
          <div className="flex h-full items-center justify-center text-sm text-zinc-500">
            <Loader2 size={20} className="mr-2 animate-spin text-accent" />
            Cargando flujos…
          </div>
        ) : visibleFlows.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-3 text-center text-zinc-500">
            <RadioTower size={34} className="text-zinc-700" />
            <div>
              <p className="text-sm text-zinc-400">
                {flows.length === 0 ? "Aún no hay tráfico" : "Sin resultados"}
              </p>
              <p className="mt-1 max-w-sm text-xs text-zinc-600">
                {flows.length === 0
                  ? "Arranca `prox0x proxy start`, navega y los flujos aparecerán aquí en vivo."
                  : onlyInScope
                    ? "Ningún flujo coincide con el Alcance actual. Ajusta las reglas o desactiva el filtro."
                    : proxyRouteFilter
                      ? "No hay flujos capturados para esta host y ruta."
                      : "Prueba con otro filtro."}
              </p>
            </div>
          </div>
        ) : (
          <table className={DATA_TABLE}>
            <thead className={DATA_TABLE_HEAD}>
              <tr className="border-b border-surface-800">
                <th className="w-10 px-2 py-2.5 font-medium">
                  <input
                    ref={selectAllRef}
                    type="checkbox"
                    aria-label="Seleccionar todos los flujos visibles"
                    checked={allVisibleSelected}
                    onChange={toggleAllVisible}
                    disabled={visibleFlows.length === 0}
                    className="h-3.5 w-3.5 accent-amber-400 disabled:opacity-40"
                  />
                </th>
                <th className="w-[120px] px-4 py-2.5 font-medium">ID</th>
                <th className="w-24 px-2 py-2.5 font-medium">Hora</th>
                <th className="w-24 px-2 py-2.5 font-medium">Método</th>
                <th className="w-48 px-2 py-2.5 font-medium">Host</th>
                <th className="px-2 py-2.5 font-medium">Ruta</th>
                <th className="w-16 px-2 py-2.5 text-right font-medium">Cód.</th>
                <th className="w-24 px-4 py-2.5 text-right font-medium">TTFB</th>
              </tr>
            </thead>
            <tbody>
              {visibleFlows.map((flow) => (
                <tr
                  key={flow.id}
                  onClick={() => setSelectedFlowId(flow.id)}
                  className={[
                    "cursor-pointer border-b border-surface-800/70 transition",
                    flow.in_scope === false ? "opacity-50" : "",
                    flow.dropped || flow.status === "DROPPED"
                      ? "bg-rose-950/20 hover:bg-rose-950/30"
                      : selectedFlowId === flow.id
                        ? "bg-accent/10"
                        : selectedIds.has(flow.id)
                          ? "bg-amber-400/5 hover:bg-surface-850"
                          : "hover:bg-surface-850",
                  ].join(" ")}
                  title={
                    flow.in_scope === false
                      ? "Fuera del Alcance de auditoría"
                      : undefined
                  }
                >
                  <td
                    className="px-2 py-2.5"
                    onClick={(event) => event.stopPropagation()}
                  >
                    <input
                      type="checkbox"
                      aria-label={`Seleccionar flujo #${flow.id}`}
                      checked={selectedIds.has(flow.id)}
                      onChange={() => toggleFlow(flow.id)}
                      className="h-3.5 w-3.5 accent-amber-400"
                    />
                  </td>
                  <td
                    className="max-w-[120px] overflow-hidden px-4 py-2.5 text-accent"
                    title={`#${flow.id}`}
                  >
                    <span className="block max-w-[120px] truncate">
                      #{flow.id}
                    </span>
                  </td>
                  <td className="px-2 py-2.5 text-zinc-500">
                    {formatTime(flow.at)}
                  </td>
                  <td
                    className={`px-2 py-2.5 font-semibold ${methodTone(
                      flow.request.method,
                    )}`}
                  >
                    <span className="inline-flex items-center gap-1">
                      {flow.request.method ?? "—"}
                      {flow.modified_by_rule && (
                        <span
                          data-testid="modified-by-rule"
                          role="img"
                          aria-label="Modificado por regla de Transformación"
                          title="Modificado por regla de Transformación"
                          className="text-cyan-300"
                        >
                          <Wand2 size={11} />
                        </span>
                      )}
                    </span>
                  </td>
                  <td className="truncate px-2 py-2.5 text-zinc-400">
                    {flowHost(flow)}
                  </td>
                  <td className="truncate px-2 py-2.5 text-zinc-300">
                    {flowPath(flow)}
                  </td>
                  <td
                    className={[
                      "px-2 py-2.5 text-right font-semibold",
                      flow.dropped || flow.status === "DROPPED"
                        ? "text-rose-400"
                        : statusTone(flow.response?.status),
                    ].join(" ")}
                  >
                    {flow.dropped || flow.status === "DROPPED"
                      ? "DROPPED"
                      : (flow.response?.status ?? "—")}
                  </td>
                  <td className="px-4 py-2.5 text-right text-zinc-500">
                    {formatMs(flow.timing?.ttfb_ms)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        </div>

        <div
          role="separator"
          aria-orientation="horizontal"
          aria-label="Redimensionar historial y detalle"
          aria-valuemin={20}
          aria-valuemax={80}
          aria-valuenow={Math.round(topPercent)}
          tabIndex={0}
          onPointerDown={(event) => {
            event.preventDefault();
            setResizing(true);
          }}
          onKeyDown={(event) => {
            if (event.key === "ArrowUp") {
              event.preventDefault();
              resizeTop(-2);
            } else if (event.key === "ArrowDown") {
              event.preventDefault();
              resizeTop(2);
            }
          }}
          className="relative h-1.5 shrink-0 cursor-row-resize bg-surface-800 transition hover:bg-accent/60 focus:bg-accent focus:outline-none"
          title="Arrastra para redimensionar historial/detalle"
        >
          <span className="pointer-events-none absolute inset-x-1/4 top-1/2 h-px -translate-y-1/2 bg-accent/40" />
        </div>

        <div
          className="min-h-0 overflow-hidden"
          style={{ flexGrow: 100 - topPercent, flexBasis: 0 }}
        >
          {selectedFlowId !== null ? (
            <FlowDetailPanel
              flowId={selectedFlowId}
              onClose={() => setSelectedFlowId(null)}
            />
          ) : (
            <div className="flex h-full flex-col items-center justify-center gap-2 border-t border-surface-800 bg-surface-900/40 text-center text-zinc-600">
              <RadioTower size={28} className="text-zinc-700" />
              <p className="text-[10px] uppercase tracking-[0.18em] text-zinc-500">
                Detalle del flujo
              </p>
              <p className="max-w-md text-[11px]">
                Selecciona una fila del historial para inspeccionar Request y
                Response en paralelo.
              </p>
            </div>
          )}
        </div>
      </div>

      {confirmClear &&
        createPortal(
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm"
            onClick={() => setConfirmClear(false)}
            role="presentation"
          >
            <section
              role="dialog"
              aria-label="Confirmar limpiar historial"
              onClick={(event) => event.stopPropagation()}
              className="terminal-modal w-full max-w-md rounded-2xl border border-surface-700 bg-surface-900 p-5 shadow-2xl"
            >
              <h2 className="text-sm font-semibold text-accent">
                ¿Limpiar todo el historial?
              </h2>
              <p className="mt-2 text-xs text-zinc-400">
                Esta acción eliminará todos los flujos capturados en el proyecto
                actual ({flows.length} flujos). No se puede deshacer.
              </p>
              <div className="mt-5 flex items-center justify-end gap-2">
                <button
                  type="button"
                  disabled={clearing}
                  onClick={() => setConfirmClear(false)}
                  className="rounded-lg border border-surface-700 px-3 py-2 text-xs text-zinc-400 hover:text-zinc-200"
                >
                  Cancelar
                </button>
                <button
                  type="button"
                  disabled={clearing}
                  onClick={() => void handleClearHistory()}
                  className="flex items-center gap-2 rounded-lg bg-rose-500 px-4 py-2 text-xs font-semibold text-white transition hover:bg-rose-400 disabled:opacity-50"
                >
                  {clearing ? (
                    <Loader2 size={14} className="animate-spin" />
                  ) : (
                    <Trash2 size={14} />
                  )}
                  Confirmar
                </button>
              </div>
            </section>
          </div>,
          document.body,
        )}
    </div>
  );
}
