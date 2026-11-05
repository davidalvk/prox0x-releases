import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowRight,
  Bug,
  Download,
  FileCode2,
  FolderTree,
  Loader2,
  Radar,
  RefreshCw,
  ShieldCheck,
  Square,
  Zap,
} from "lucide-react";
import type {
  ActiveScanStatus,
  CrawlStatus,
  DashboardStats,
  FindingRecord,
  FlowSummaryRecord,
  TemplateScanStatus,
} from "../types";
import {
  FINDINGS_WS_URL,
  WS_URL,
  fetchActiveTemplateScan,
  fetchCrawlStatus,
  fetchDashboardStats,
  fetchFindings,
  fetchFlows,
  fetchLatestScan,
  flowHost,
  flowPath,
  formatTime,
  statusTone,
  stopTemplateScan,
} from "../lib/api";
import { kindLabel, severityClass, severityLabel } from "../lib/findings";
import { DATA_TABLE, DATA_TABLE_HEAD } from "../lib/tableStyles";
import { useApp } from "../context/AppContext";

const EMPTY_STATS: DashboardStats = {
  flows: 0,
  findings: 0,
  routes: 0,
  scan_flows: 0,
};

const REFRESH_MS = 3_000;

function phaseLabel(value: string): string {
  const labels: Record<string, string> = {
    crawling: "Rastreando sitio",
    analyzing: "Analizando formularios",
    saving: "Guardando rutas",
    scanning: "Lanzando ataques",
    completed: "Completado",
    failed: "Fallido",
  };
  return labels[value] ?? value;
}

function templatePhaseLabel(value: string): string {
  const labels: Record<string, string> = {
    detecting: "Detectando tecnología",
    loading: "Cargando plantillas",
    crawling: "Rastreando dominio",
    scanning: "Lanzando plantillas",
    completed: "Completado",
    failed: "Fallido",
  };
  return labels[value] ?? phaseLabel(value);
}

export function HomeView() {
  const {
    currentProject,
    setActiveModule,
    requestFullScan,
  } = useApp();
  const [stats, setStats] = useState<DashboardStats>(EMPTY_STATS);
  const [flows, setFlows] = useState<FlowSummaryRecord[]>([]);
  const [findings, setFindings] = useState<FindingRecord[]>([]);
  const [scan, setScan] = useState<ActiveScanStatus | null>(null);
  const [crawl, setCrawl] = useState<CrawlStatus | null>(null);
  const [templateScan, setTemplateScan] =
    useState<TemplateScanStatus | null>(null);
  const [stoppingTemplates, setStoppingTemplates] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [
        nextStats,
        nextFlows,
        nextFindings,
        nextScan,
        nextCrawl,
        nextTemplateScan,
      ] = await Promise.all([
        fetchDashboardStats(),
        fetchFlows(5),
        fetchFindings({ limit: 5 }),
        fetchLatestScan(),
        fetchCrawlStatus(),
        fetchActiveTemplateScan(),
      ]);
      setStats(nextStats);
      setFlows(nextFlows.slice(0, 5));
      setFindings(nextFindings.slice(0, 5));
      setScan(nextScan);
      setCrawl(nextCrawl);
      setTemplateScan(nextTemplateScan);
      setError(null);
    } catch (err: unknown) {
      setError(
        err instanceof Error
          ? err.message
          : "No se pudo actualizar el panel de control",
      );
    } finally {
      setLoading(false);
    }
  }, [currentProject]);

  useEffect(() => {
    setStats(EMPTY_STATS);
    setFlows([]);
    setFindings([]);
    setScan(null);
    setCrawl(null);
    setTemplateScan(null);
    setLoading(true);
    void refresh();
    const timer = window.setInterval(() => void refresh(), REFRESH_MS);
    return () => window.clearInterval(timer);
  }, [refresh, currentProject]);

  useEffect(() => {
    let stopped = false;
    let socket: WebSocket | null = null;
    let reconnectTimer: number | undefined;

    const connect = () => {
      if (stopped) return;
      socket = new WebSocket(WS_URL);
      socket.onmessage = (event) => {
        try {
          const flow = JSON.parse(event.data as string) as FlowSummaryRecord;
          if (flow.is_scan_flow) return;
          setFlows((previous) =>
            [flow, ...previous.filter((item) => item.id !== flow.id)].slice(
              0,
              5,
            ),
          );
        } catch {
          // Ignora mensajes no JSON.
        }
      };
      socket.onerror = () => socket?.close();
      socket.onclose = () => {
        if (!stopped) reconnectTimer = window.setTimeout(connect, 2_000);
      };
    };

    connect();
    return () => {
      stopped = true;
      if (reconnectTimer !== undefined) window.clearTimeout(reconnectTimer);
      socket?.close();
    };
  }, [currentProject]);

  useEffect(() => {
    let stopped = false;
    let socket: WebSocket | null = null;
    let reconnectTimer: number | undefined;

    const connect = () => {
      if (stopped) return;
      socket = new WebSocket(FINDINGS_WS_URL);
      socket.onmessage = (event) => {
        try {
          const finding = JSON.parse(event.data as string) as FindingRecord;
          setFindings((previous) =>
            [
              finding,
              ...previous.filter((item) => item.id !== finding.id),
            ].slice(0, 5),
          );
        } catch {
          // Ignora mensajes no JSON.
        }
      };
      socket.onerror = () => socket?.close();
      socket.onclose = () => {
        if (!stopped) reconnectTimer = window.setTimeout(connect, 2_000);
      };
    };

    connect();
    return () => {
      stopped = true;
      if (reconnectTimer !== undefined) window.clearTimeout(reconnectTimer);
      socket?.close();
    };
  }, [currentProject]);

  const runningScan = scan?.status === "running" ? scan : null;
  const runningCrawl = crawl?.status === "running" ? crawl : null;
  const runningTemplates =
    templateScan?.status === "running" ? templateScan : null;
  const hasOperations = Boolean(
    runningScan || runningCrawl || runningTemplates,
  );
  const templateIndeterminate = Boolean(
    runningTemplates &&
      ["detecting", "loading", "crawling"].includes(runningTemplates.phase),
  );

  const stopTemplates = async () => {
    if (!runningTemplates) return;
    setStoppingTemplates(true);
    try {
      const stopped = await stopTemplateScan(runningTemplates.scan_id);
      setTemplateScan(stopped);
      setError(null);
    } catch (err: unknown) {
      setError(
        err instanceof Error
          ? err.message
          : "No se pudo detener el escaneo de plantillas",
      );
    } finally {
      setStoppingTemplates(false);
    }
  };

  const quickActions = useMemo(
    () => [
      {
        label: "Full Site Scan",
        hint: "Crawl + fuzzing XSS, SQLi, command y traversal",
        icon: Radar,
        onClick: requestFullScan,
      },
      {
        label: "Ir a Interceptación",
        hint: "Revisa el tráfico real capturado por el Proxy",
        icon: Activity,
        onClick: () => setActiveModule("proxy"),
      },
    ],
    [requestFullScan, setActiveModule],
  );

  return (
    <div className="flex h-full min-h-0 flex-col bg-surface-950">
      <div className="flex flex-wrap items-end justify-between gap-3 border-b border-surface-800 px-5 py-3">
        <div>
          <h2 className="flex items-center gap-2 text-sm font-bold text-zinc-100">
            <Zap size={16} className="text-amber-300" />
            Panel de control
          </h2>
          <p className="mt-1 text-[11px] text-zinc-500">
            {currentProject ? `Proyecto ${currentProject}` : "Sin proyecto"} ·
            resumen en tiempo real
          </p>
        </div>
        <button
          type="button"
          onClick={() => void refresh()}
          disabled={loading}
          className="flex items-center gap-2 rounded-lg border border-surface-700 px-3 py-2 text-xs text-zinc-400 transition hover:border-surface-600 hover:text-zinc-100 disabled:opacity-40"
        >
          <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
          Actualizar
        </button>
      </div>

      <div className="min-h-0 flex-1 overflow-auto p-5">
        {error && (
          <div
            role="alert"
            className="mb-4 rounded-lg border border-rose-900/60 bg-rose-950/30 px-4 py-3 text-xs text-rose-300"
          >
            {error}
          </div>
        )}

        <section
          aria-label="Resumen rápido"
          className="grid gap-4 md:grid-cols-3"
        >
          <article className="rounded-xl border border-surface-800 bg-surface-900/60 p-4">
            <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
              <Activity size={14} className="text-cyan-300" />
              Flujos capturados
            </div>
            <p className="mt-3 font-mono text-3xl font-bold text-cyan-300">
              {stats.flows}
            </p>
            <p className="mt-1 text-[10px] text-zinc-600">
              {stats.scan_flows} flujos sintéticos del escáner ocultos en el
              Proxy
            </p>
          </article>

          <article className="rounded-xl border border-surface-800 bg-surface-900/60 p-4">
            <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
              <Bug size={14} className="text-rose-300" />
              Hallazgos
            </div>
            <p className="mt-3 font-mono text-3xl font-bold text-rose-300">
              {stats.findings}
            </p>
            <p className="mt-1 text-[10px] text-zinc-600">
              Vulnerabilidades y datos sensibles detectados
            </p>
          </article>

          <article className="rounded-xl border border-surface-800 bg-surface-900/60 p-4">
            <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
              <FolderTree size={14} className="text-emerald-300" />
              Rutas en el mapa
            </div>
            <p className="mt-3 font-mono text-3xl font-bold text-emerald-300">
              {stats.routes}
            </p>
            <p className="mt-1 text-[10px] text-zinc-600">
              Endpoints descubiertos por el Proxy y el crawler
            </p>
          </article>
        </section>

        <div className="mt-4 grid gap-4 xl:grid-cols-2">
          <section className="rounded-xl border border-surface-800 bg-surface-900/60 p-4">
            <div className="flex items-center justify-between gap-2">
              <h3 className="flex items-center gap-2 text-xs font-bold text-zinc-200">
                <Loader2
                  size={14}
                  className={hasOperations ? "animate-spin text-accent" : "text-zinc-600"}
                />
                Operaciones en curso
              </h3>
              {hasOperations && (
                <span className="rounded-full border border-accent/40 bg-accent/10 px-2 py-0.5 text-[9px] font-semibold uppercase tracking-[0.14em] text-accent">
                  Live
                </span>
              )}
            </div>

            {!hasOperations ? (
              <div className="mt-6 rounded-lg border border-dashed border-surface-700 bg-surface-950/40 px-4 py-8 text-center text-xs text-zinc-600">
                No hay operaciones en curso. Lanza un Full Site Scan, un
                Crawler o un escaneo de CVEs (Nuclei) desde sus vistas.
              </div>
            ) : (
              <div className="mt-4 space-y-4">
                {runningScan && (
                  <div className="rounded-lg border border-amber-500/30 bg-amber-950/20 p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-mono text-[11px] text-amber-200">
                        Full Site Scan · {runningScan.seed_url}
                      </span>
                      <span className="text-[10px] uppercase tracking-[0.12em] text-amber-300/80">
                        {phaseLabel(runningScan.phase ?? "")}
                      </span>
                    </div>
                    <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-surface-800">
                      <div
                        className="h-full rounded-full bg-amber-400 transition-[width] duration-300"
                        style={{ width: `${Math.max(2, runningScan.progress)}%` }}
                      />
                    </div>
                    <p className="mt-2 font-mono text-[10px] text-zinc-500">
                      {runningScan.total_attempts} ataques ·{" "}
                      {runningScan.vulnerable} vulnerables · {runningScan.errors} errores
                    </p>
                  </div>
                )}

                {runningCrawl && (
                  <div className="rounded-lg border border-cyan-500/30 bg-cyan-950/20 p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-mono text-[11px] text-cyan-200">
                        Crawler · {runningCrawl.seed_url}
                      </span>
                      <span className="text-[10px] uppercase tracking-[0.12em] text-cyan-300/80">
                        {phaseLabel(runningCrawl.phase)}
                      </span>
                    </div>
                    <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-surface-800">
                      <div
                        className="h-full rounded-full bg-cyan-400 transition-[width] duration-300"
                        style={{ width: `${Math.max(2, runningCrawl.progress)}%` }}
                      />
                    </div>
                    <p className="mt-2 font-mono text-[10px] text-zinc-500">
                      {runningCrawl.urls_found} URLs · {runningCrawl.pages_found} páginas ·{" "}
                      {runningCrawl.forms_found} formularios
                    </p>
                  </div>
                )}

                {runningTemplates && (
                  <div
                    data-testid="dashboard-template-scan"
                    className="rounded-lg border border-emerald-500/30 bg-emerald-950/20 p-3"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="flex min-w-0 items-center gap-1.5 font-mono text-[11px] text-emerald-200">
                        <FileCode2 size={12} className="shrink-0" />
                        <span className="truncate">
                          CVEs (Nuclei) · {runningTemplates.url}
                        </span>
                      </span>
                      <span className="text-[10px] uppercase tracking-[0.12em] text-emerald-300/80">
                        {templatePhaseLabel(runningTemplates.phase)}
                      </span>
                    </div>
                    <div
                      role="progressbar"
                      aria-label="Progreso del escaneo de plantillas en curso"
                      aria-valuemin={0}
                      aria-valuemax={100}
                      aria-valuenow={
                        templateIndeterminate
                          ? 100
                          : runningTemplates.progress
                      }
                      className="mt-2 h-1.5 overflow-hidden rounded-full bg-surface-800"
                    >
                      <div
                        className={[
                          "h-full rounded-full transition-[width] duration-300",
                          templateIndeterminate
                            ? "animate-pulse bg-amber-400"
                            : "bg-emerald-400",
                        ].join(" ")}
                        style={{
                          width: `${
                            templateIndeterminate
                              ? 100
                              : Math.max(2, runningTemplates.progress)
                          }%`,
                        }}
                      />
                    </div>
                    <p className="mt-2 font-mono text-[10px] text-zinc-500">
                      {runningTemplates.attacks_run}/
                      {runningTemplates.attacks_total} ataques ·{" "}
                      {runningTemplates.templates_run}/
                      {runningTemplates.templates_total} plantillas
                      {runningTemplates.crawl
                        ? ` · ${runningTemplates.urls_scanned}/${runningTemplates.urls_total} URLs`
                        : ""}{" "}
                      · {runningTemplates.matches} coincidencias ·{" "}
                      {runningTemplates.errors} errores
                    </p>
                    {runningTemplates.auto_tech && (
                      <p className="mt-1 font-mono text-[10px] text-cyan-300/80">
                        Auto-Tech:{" "}
                        {runningTemplates.detected_technologies.length
                          ? runningTemplates.detected_technologies.join(", ")
                          : "detectando…"}
                        {runningTemplates.effective_tags.length
                          ? ` · tags: ${runningTemplates.effective_tags.join(", ")}`
                          : ""}
                      </p>
                    )}
                    <button
                      type="button"
                      onClick={() => void stopTemplates()}
                      disabled={stoppingTemplates}
                      className="mt-2 flex items-center gap-1.5 rounded-lg border border-rose-500/50 bg-rose-950/30 px-2.5 py-1.5 text-[10px] font-semibold text-rose-200 transition hover:bg-rose-500/20 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      {stoppingTemplates ? (
                        <Loader2 size={12} className="animate-spin" />
                      ) : (
                        <Square size={10} />
                      )}
                      Detener Escaneo
                    </button>
                  </div>
                )}
              </div>
            )}
          </section>

          <section className="rounded-xl border border-surface-800 bg-surface-900/60 p-4">
            <h3 className="flex items-center gap-2 text-xs font-bold text-zinc-200">
              <Zap size={14} className="text-accent" />
              Accesos rápidos
            </h3>
            <div className="mt-4 grid gap-2 sm:grid-cols-2">
              {quickActions.map((action) => {
                const Icon = action.icon;
                return (
                  <button
                    key={action.label}
                    type="button"
                    onClick={action.onClick}
                    className="group flex min-h-24 flex-col items-start justify-between rounded-lg border border-surface-700 bg-surface-950/60 p-3 text-left transition hover:border-accent/60 hover:bg-accent/5"
                  >
                    <Icon size={18} className="text-accent" />
                    <span>
                      <span className="block text-xs font-bold text-zinc-200 group-hover:text-accent">
                        {action.label}
                      </span>
                      <span className="mt-1 block text-[10px] leading-relaxed text-zinc-600">
                        {action.hint}
                      </span>
                    </span>
                  </button>
                );
              })}
              <a
                href="/api/certificate"
                download="prox0x-ca.pem"
                className="group flex min-h-24 flex-col items-start justify-between rounded-lg border border-surface-700 bg-surface-950/60 p-3 text-left transition hover:border-cyan-400/60 hover:bg-cyan-400/5"
              >
                <Download size={18} className="text-cyan-300" />
                <span>
                  <span className="block text-xs font-bold text-zinc-200 group-hover:text-cyan-300">
                    Descargar Certificado CA
                  </span>
                  <span className="mt-1 block text-[10px] leading-relaxed text-zinc-600">
                    Instala la CA local para interceptar HTTPS
                  </span>
                </span>
              </a>
            </div>
          </section>
        </div>

        <div className="mt-4 grid gap-4 xl:grid-cols-2">
          <section className="overflow-hidden rounded-xl border border-surface-800 bg-surface-900/60">
            <header className="flex items-center justify-between gap-2 border-b border-surface-800 px-4 py-3">
              <h3 className="flex items-center gap-2 text-xs font-bold text-zinc-200">
                <Bug size={14} className="text-rose-300" />
                Últimos hallazgos
              </h3>
              <button
                type="button"
                onClick={() => setActiveModule("findings")}
                className="flex items-center gap-1 text-[10px] font-semibold text-accent transition hover:text-accent-soft"
              >
                Ver todos <ArrowRight size={11} />
              </button>
            </header>
            <table className={DATA_TABLE}>
              <thead className={DATA_TABLE_HEAD}>
                <tr className="border-b border-surface-800">
                  <th className="w-36 px-4 py-2 font-medium">Tipo</th>
                  <th className="px-2 py-2 font-medium">URL</th>
                  <th className="w-24 px-4 py-2 text-right font-medium">Severidad</th>
                </tr>
              </thead>
              <tbody>
                {findings.length === 0 ? (
                  <tr>
                    <td
                      colSpan={3}
                      className="px-4 py-6 text-center text-xs text-zinc-600"
                    >
                      No hay hallazgos para mostrar.
                    </td>
                  </tr>
                ) : (
                  findings.map((finding) => (
                    <tr key={finding.id} className="border-b border-surface-800/60">
                      <td
                        className="truncate px-4 py-2 text-zinc-300"
                        title={kindLabel(finding.kind)}
                      >
                        {kindLabel(finding.kind)}
                      </td>
                      <td
                        className="truncate px-2 py-2 text-zinc-500"
                        title={finding.url}
                      >
                        {finding.url}
                      </td>
                      <td className="px-4 py-2 text-right">
                        <span
                          className={[
                            "inline-flex rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide",
                            severityClass(finding.severity),
                          ].join(" ")}
                        >
                          {severityLabel(finding.severity)}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </section>

          <section className="overflow-hidden rounded-xl border border-surface-800 bg-surface-900/60">
            <header className="flex items-center justify-between gap-2 border-b border-surface-800 px-4 py-3">
              <h3 className="flex items-center gap-2 text-xs font-bold text-zinc-200">
                <Activity size={14} className="text-cyan-300" />
                Últimas peticiones
              </h3>
              <button
                type="button"
                onClick={() => setActiveModule("proxy")}
                className="flex items-center gap-1 text-[10px] font-semibold text-accent transition hover:text-accent-soft"
              >
                Ver todas <ArrowRight size={11} />
              </button>
            </header>
            <table className={DATA_TABLE}>
              <thead className={DATA_TABLE_HEAD}>
                <tr className="border-b border-surface-800">
                  <th className="w-20 px-4 py-2 font-medium">Método</th>
                  <th className="px-2 py-2 font-medium">Petición</th>
                  <th className="w-16 px-2 py-2 text-right font-medium">Cód.</th>
                  <th className="w-24 px-4 py-2 text-right font-medium">Hora</th>
                </tr>
              </thead>
              <tbody>
                {flows.length === 0 ? (
                  <tr>
                    <td
                      colSpan={4}
                      className="px-4 py-6 text-center text-xs text-zinc-600"
                    >
                      No hay peticiones para mostrar.
                    </td>
                  </tr>
                ) : (
                  flows.map((flow) => (
                    <tr key={flow.id} className="border-b border-surface-800/60">
                      <td className="px-4 py-2 font-semibold text-cyan-300">
                        {flow.request.method ?? "—"}
                      </td>
                      <td
                        className="truncate px-2 py-2 text-zinc-400"
                        title={`${flowHost(flow)}${flowPath(flow)}`}
                      >
                        {flowPath(flow)}
                      </td>
                      <td
                        className={[
                          "px-2 py-2 text-right font-semibold",
                          statusTone(flow.response?.status),
                        ].join(" ")}
                      >
                        {flow.response?.status ?? "—"}
                      </td>
                      <td className="px-4 py-2 text-right text-zinc-600">
                        {formatTime(flow.at)}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </section>
        </div>

        <div className="mt-4 flex items-center justify-end gap-2 text-[10px] text-zinc-600">
          <ShieldCheck size={12} className="text-emerald-400" />
          Panel actualizado automáticamente cada {REFRESH_MS / 1000} s
        </div>
      </div>
    </div>
  );
}
