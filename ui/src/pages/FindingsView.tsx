import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowUpRight,
  Bug,
  FileText,
  Loader2,
  Search,
  Trash2,
} from "lucide-react";
import type { FindingRecord } from "../types";
import {
  FINDINGS_WS_URL,
  deleteFindings,
  fetchFindings,
  formatTime,
} from "../lib/api";
import {
  KIND_LABELS,
  kindLabel,
  severityClass,
  severityLabel,
} from "../lib/findings";
import { DATA_TABLE, DATA_TABLE_HEAD } from "../lib/tableStyles";
import { useApp } from "../context/AppContext";
import { FlowDetailPanel } from "../components/FlowDetailPanel";
import { SplitPane } from "../components/SplitPane";

const KIND_OPTIONS = Object.entries(KIND_LABELS);

export function FindingsView() {
  const { currentProject, setActiveModule, setSelectedFlowId } = useApp();
  const [findings, setFindings] = useState<FindingRecord[]>([]);
  const [severity, setSeverity] = useState("");
  const [kind, setKind] = useState("");
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [clearing, setClearing] = useState(false);
  const [selectedFindingId, setSelectedFindingId] = useState<number | null>(
    null,
  );

  const selectedFinding = useMemo(
    () =>
      findings.find((finding) => finding.id === selectedFindingId) ?? null,
    [findings, selectedFindingId],
  );

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchFindings({
        severity: severity || undefined,
        kind: kind || undefined,
      });
      setFindings(data);
    } catch (err: unknown) {
      setError(
        err instanceof Error ? err.message : "No se pudieron cargar los hallazgos",
      );
    } finally {
      setLoading(false);
    }
  }, [severity, kind]);

  useEffect(() => {
    void load();
  }, [load, currentProject]);

  useEffect(() => {
    setSelectedFindingId(null);
  }, [currentProject]);

  useEffect(() => {
    let stopped = false;
    let socket: WebSocket | null = null;
    let reconnectTimer: number | undefined;

    const connect = () => {
      if (stopped) return;
      socket = new WebSocket(FINDINGS_WS_URL);
      socket.onopen = () => setConnected(true);
      socket.onmessage = (event) => {
        try {
          const finding = JSON.parse(event.data as string) as FindingRecord;
          if (severity && finding.severity !== severity) return;
          if (kind && finding.kind !== kind) return;
          setFindings((previous) => {
            if (previous.some((item) => item.id === finding.id)) return previous;
            return [finding, ...previous];
          });
        } catch {
          // Ignora mensajes no JSON.
        }
      };
      socket.onerror = () => socket?.close();
      socket.onclose = () => {
        setConnected(false);
        if (!stopped) {
          reconnectTimer = window.setTimeout(connect, 2_000);
        }
      };
    };

    connect();
    return () => {
      stopped = true;
      if (reconnectTimer !== undefined) window.clearTimeout(reconnectTimer);
      socket?.close();
    };
  }, [severity, kind, currentProject]);

  const visible = useMemo(() => {
    const term = search.trim().toLowerCase();
    if (!term) return findings;
    return findings.filter((finding) =>
      [finding.url, finding.evidence, finding.kind, finding.severity]
        .join(" ")
        .toLowerCase()
        .includes(term),
    );
  }, [findings, search]);

  const clear = async () => {
    setClearing(true);
    setError(null);
    try {
      await deleteFindings();
      setFindings([]);
      setSelectedFindingId(null);
    } catch (err: unknown) {
      setError(
        err instanceof Error ? err.message : "No se pudieron borrar los hallazgos",
      );
    } finally {
      setClearing(false);
    }
  };

  const openFlow = (finding: FindingRecord) => {
    setSelectedFlowId(finding.flow_id);
    setActiveModule("proxy");
  };

  return (
    <div className="flex h-full min-h-0 flex-col bg-surface-950">
      <div className="flex flex-wrap items-end justify-between gap-3 border-b border-surface-800 px-5 py-3">
        <div>
          <h2 className="flex items-center gap-2 text-sm font-bold text-zinc-100">
            <Bug size={16} className="text-accent" />
            Hallazgos pasivos
          </h2>
          <p className="mt-1 text-[11px] text-zinc-500">
            {findings.length} hallazgo{findings.length === 1 ? "" : "s"} ·{" "}
            {connected ? "live · ws conectado" : "reconectando…"}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <label className="flex items-center gap-1.5 text-[10px] uppercase tracking-[0.12em] text-zinc-500">
            Severidad
            <select
              value={severity}
              onChange={(event) => setSeverity(event.target.value)}
              className="rounded border border-surface-700 bg-surface-900 px-2 py-1.5 text-xs text-zinc-200"
            >
              <option value="">Todas</option>
              <option value="high">Alta</option>
              <option value="medium">Media</option>
              <option value="info">Info</option>
            </select>
          </label>
          <label className="flex items-center gap-1.5 text-[10px] uppercase tracking-[0.12em] text-zinc-500">
            Tipo
            <select
              value={kind}
              onChange={(event) => setKind(event.target.value)}
              className="rounded border border-surface-700 bg-surface-900 px-2 py-1.5 text-xs text-zinc-200"
            >
              <option value="">Todos</option>
              {KIND_OPTIONS.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <label className="flex items-center gap-2 rounded border border-surface-700 bg-surface-900 px-2 py-1.5">
            <Search size={13} className="text-zinc-500" />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Filtrar URL o evidencia…"
              className="w-48 bg-transparent text-xs text-zinc-200 outline-none placeholder:text-zinc-600"
            />
          </label>
          <a
            href="/api/report"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-2 text-xs font-semibold text-cyan-300 transition hover:bg-cyan-500/20"
          >
            <FileText size={14} />
            Exportar Reporte
          </a>
          <button
            type="button"
            onClick={() => {
              if (selectedFinding) openFlow(selectedFinding);
            }}
            disabled={!selectedFinding}
            className="flex items-center gap-2 rounded-lg border border-accent/40 bg-accent/10 px-3 py-2 text-xs font-semibold text-accent transition hover:bg-accent/20 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <ArrowUpRight size={14} />
            Ir a Interceptación
          </button>
          <button
            type="button"
            onClick={() => void clear()}
            disabled={clearing || findings.length === 0}
            className="flex items-center gap-2 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs font-semibold text-rose-300 transition hover:bg-rose-500/20 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {clearing ? (
              <Loader2 size={14} className="animate-spin" />
            ) : (
              <Trash2 size={14} />
            )}
            Limpiar Hallazgos
          </button>
        </div>
      </div>

      {error && (
        <div className="border-b border-rose-900/60 bg-rose-950/30 px-5 py-2 text-xs text-rose-300">
          {error}
        </div>
      )}

      <SplitPane
        orientation="vertical"
        label="Redimensionar hallazgos y detalle"
        initial={55}
        min={25}
        max={80}
        first={
          <div className="h-full min-h-0 overflow-auto">
            {loading ? (
              <div className="flex h-full items-center justify-center text-sm text-zinc-500">
                <Loader2 size={20} className="mr-2 animate-spin text-accent" />
                Cargando hallazgos…
              </div>
            ) : visible.length === 0 ? (
              <div className="flex h-full flex-col items-center justify-center gap-3 text-center text-zinc-500">
                <AlertTriangle size={34} className="text-zinc-700" />
                <div>
                  <p className="text-sm text-zinc-400">Sin hallazgos todavía</p>
                  <p className="mt-1 max-w-md text-xs text-zinc-600">
                    Navega con el Proxy activo. El escáner analiza HTML, JSON,
                    JavaScript y texto plano en segundo plano.
                  </p>
                </div>
              </div>
            ) : (
              <table className={DATA_TABLE}>
                <thead className={DATA_TABLE_HEAD}>
                  <tr className="border-b border-surface-800">
                    <th className="w-24 px-4 py-2.5 font-medium">Severidad</th>
                    <th className="w-28 px-2 py-2.5 font-medium">Tipo</th>
                    <th className="w-72 px-2 py-2.5 font-medium">URL</th>
                    <th className="px-2 py-2.5 font-medium">Evidencia</th>
                    <th className="w-28 px-4 py-2.5 text-right font-medium">
                      Flow
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((finding) => (
                    <tr
                      key={finding.id}
                      onClick={() => setSelectedFindingId(finding.id)}
                      className={[
                        "cursor-pointer border-b border-surface-800/70 transition",
                        selectedFindingId === finding.id
                          ? "bg-accent/10"
                          : "hover:bg-surface-850",
                      ].join(" ")}
                      title="Ver el detalle del flujo"
                    >
                      <td className="px-4 py-2.5">
                        <span
                          className={[
                            "inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide",
                            severityClass(finding.severity),
                          ].join(" ")}
                        >
                          {severityLabel(finding.severity)}
                        </span>
                      </td>
                      <td className="px-2 py-2.5 text-zinc-300">
                        {kindLabel(finding.kind)}
                      </td>
                      <td
                        className="truncate px-2 py-2.5 text-cyan-300/80"
                        title={finding.url}
                      >
                        {finding.url}
                      </td>
                      <td
                        className="truncate px-2 py-2.5 text-zinc-400"
                        title={finding.evidence}
                      >
                        {finding.evidence}
                      </td>
                      <td className="px-4 py-2.5 text-right text-zinc-500">
                        <span className="inline-flex items-center gap-1">
                          #{finding.flow_id}
                          <button
                            type="button"
                            onClick={(event) => {
                              event.stopPropagation();
                              openFlow(finding);
                            }}
                            aria-label={`Ir a Interceptación del flujo #${finding.flow_id}`}
                            title="Ir a Interceptación"
                            className="rounded p-1 text-zinc-500 transition hover:bg-surface-800 hover:text-accent"
                          >
                            <ArrowUpRight size={12} />
                          </button>
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        }
        second={
          selectedFinding ? (
            <FlowDetailPanel
              flowId={selectedFinding.flow_id}
              onClose={() => setSelectedFindingId(null)}
            />
          ) : (
            <div className="flex h-full flex-col items-center justify-center gap-2 border-t border-surface-800 bg-surface-900/40 text-center text-zinc-600">
              <Bug size={26} className="text-zinc-700" />
              <p className="text-[10px] uppercase tracking-[0.18em] text-zinc-500">
                Detalle del hallazgo
              </p>
              <p className="max-w-md text-[11px]">
                Selecciona un hallazgo para inspeccionar su petición y respuesta.
              </p>
            </div>
          )
        }
      />

      <footer className="border-t border-surface-800 px-5 py-1.5 text-[10px] text-zinc-600">
        {visible.length} de {findings.length} · análisis pasivo en segundo plano ·
        escaneo activo bajo demanda
        {findings[0] ? ` · último ${formatTime(findings[0].at)}` : ""}
      </footer>
    </div>
  );
}
