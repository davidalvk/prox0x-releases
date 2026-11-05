import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
} from "react";
import {
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  CheckCircle2,
  EyeOff,
  FileCode2,
  Filter,
  Loader2,
  Radar,
  RadioTower,
  RefreshCw,
  Search,
  Square,
  Trash2,
  X,
  Zap,
} from "lucide-react";
import type {
  ActiveScanAttempt,
  ActiveScanStatus,
  ScanAttemptResult,
  ScanIntensity,
} from "../types";
import {
  SCAN_WS_URL,
  deleteScanAttempts,
  fetchLatestScan,
  fetchScanAttempts,
  fetchScanStatus,
  formatTime,
  startFullScan,
  stopScan,
} from "../lib/api";
import { DATA_TABLE, DATA_TABLE_HEAD } from "../lib/tableStyles";
import { useApp } from "../context/AppContext";
import { FlowDetailPanel } from "../components/FlowDetailPanel";
import { CrawlLimitFields } from "../components/CrawlLimitFields";
import { HelpTooltip } from "../components/HelpTooltip";
import { SplitPane } from "../components/SplitPane";
import { TemplateScanPanel } from "../components/TemplateScanPanel";

const MAX_VISIBLE_ATTEMPTS = 3_000;

const ATTACK_LABELS: Record<string, string> = {
  xss: "XSS",
  sqli: "SQLi",
  command: "Command",
  traversal: "Traversal",
  route: "Ruta",
};

const INTENSITY_LABELS: Record<ScanIntensity, string> = {
  low: "Baja",
  medium: "Media",
  high: "Alta",
};

const RESULT_LABELS: Record<ScanAttemptResult, string> = {
  vulnerable: "Vulnerable",
  safe: "No vulnerable",
  error: "Error",
};

const RESULT_CLASSES: Record<ScanAttemptResult, string> = {
  vulnerable:
    "border-rose-400/80 bg-rose-500/15 text-rose-200 shadow-[0_0_12px_rgba(244,63,94,0.55)]",
  safe: "border-surface-700 bg-surface-850 text-zinc-500",
  error: "border-amber-500/60 bg-amber-950/40 text-amber-300",
};

type ResultFilter = "all" | "vulnerable" | "error";
type SortKey = "created_at" | "result" | "status_code";
type SortDirection = "asc" | "desc";

const SORTABLE_COLUMNS: Record<
  Exclude<SortKey, "created_at">,
  { asc: string; desc: string }
> = {
  result: { asc: "Resultado ascendente", desc: "Resultado descendente" },
  status_code: { asc: "Código ascendente", desc: "Código descendente" },
};

function attackLabel(value: string): string {
  return ATTACK_LABELS[value] ?? value;
}

function resultLabel(value: string): string {
  return RESULT_LABELS[value as ScanAttemptResult] ?? value;
}

function resultClass(value: string): string {
  return (
    RESULT_CLASSES[value as ScanAttemptResult] ??
    "border-surface-700 bg-surface-850 text-zinc-400"
  );
}

function resultRank(value: string): number {
  if (value === "vulnerable") return 0;
  if (value === "error") return 1;
  if (value === "safe") return 2;
  return 3;
}

function compareAttempts(
  left: ActiveScanAttempt,
  right: ActiveScanAttempt,
  key: SortKey,
): number {
  if (key === "created_at") {
    return left.created_at.localeCompare(right.created_at);
  }
  if (key === "status_code") {
    return (left.status_code ?? -1) - (right.status_code ?? -1);
  }
  return resultRank(left.result) - resultRank(right.result);
}

export function ActiveScanView() {
  const {
    currentProject,
    setActiveModule,
    setSelectedFlowId,
    pendingFullScan,
    consumeFullScanRequest,
  } = useApp();
  const [attempts, setAttempts] = useState<ActiveScanAttempt[]>([]);
  const [scan, setScan] = useState<ActiveScanStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [clearing, setClearing] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [activeTab, setActiveTab] = useState<"active" | "templates">(
    "active",
  );
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedAttemptId, setSelectedAttemptId] = useState<number | null>(
    null,
  );
  const [fullModalOpen, setFullModalOpen] = useState(false);
  const [fullUrl, setFullUrl] = useState("");
  const [fullIntensity, setFullIntensity] =
    useState<ScanIntensity>("medium");
  const [fullDepth, setFullDepth] = useState(3);
  const [fullMaxPages, setFullMaxPages] = useState(200);
  const [fullUnlimited, setFullUnlimited] = useState(false);
  const [fullHeaders, setFullHeaders] = useState("");
  const [fullStarting, setFullStarting] = useState(false);
  const [fullError, setFullError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [resultFilter, setResultFilter] = useState<ResultFilter>("all");
  const [attackFilter, setAttackFilter] = useState("all");
  const [sortKey, setSortKey] = useState<SortKey>("created_at");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");
  const lastIdRef = useRef(0);

  useEffect(() => {
    if (!pendingFullScan) return;
    setFullError(null);
    setFullModalOpen(true);
    consumeFullScanRequest();
  }, [pendingFullScan, consumeFullScanRequest]);

  const visibleAttempts = useMemo(
    () =>
      scan?.scan_id
        ? attempts.filter((attempt) => attempt.scan_id === scan.scan_id)
        : attempts,
    [attempts, scan?.scan_id],
  );

  const filteredAttempts = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const result = visibleAttempts.filter((attempt) => {
      if (resultFilter !== "all" && attempt.result !== resultFilter) {
        return false;
      }
      if (attackFilter !== "all" && attempt.attack !== attackFilter) {
        return false;
      }
      if (!needle) return true;
      return [attempt.url, attempt.parameter, attempt.payload].some((value) =>
        value.toLowerCase().includes(needle),
      );
    });
    const direction = sortDirection === "asc" ? 1 : -1;
    return result.sort(
      (left, right) =>
        compareAttempts(left, right, sortKey) * direction,
    );
  }, [
    visibleAttempts,
    search,
    resultFilter,
    attackFilter,
    sortKey,
    sortDirection,
  ]);

  const filtersActive =
    search.trim().length > 0 ||
    resultFilter !== "all" ||
    attackFilter !== "all";

  const selectedAttempt =
    visibleAttempts.find((attempt) => attempt.id === selectedAttemptId) ??
    null;

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [items, latest] = await Promise.all([
        fetchScanAttempts(MAX_VISIBLE_ATTEMPTS),
        fetchLatestScan(),
      ]);
      setAttempts(items);
      lastIdRef.current = items.reduce(
        (maximum, item) => Math.max(maximum, item.id),
        0,
      );
      setScan(latest);
    } catch (err: unknown) {
      setError(
        err instanceof Error ? err.message : "No se pudo cargar el escáner",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    lastIdRef.current = 0;
    setAttempts([]);
    setScan(null);
    setSelectedAttemptId(null);
    void load();
  }, [load, currentProject]);

  const scanId = scan?.scan_id;
  const scanStatus = scan?.status;

  useEffect(() => {
    if (!scanId || scanStatus !== "running") return;
    const timer = window.setInterval(() => {
      void fetchScanStatus(scanId)
        .then(async (next) => {
          setScan(next);
          if (next.status !== "running") {
            const items = await fetchScanAttempts(MAX_VISIBLE_ATTEMPTS);
            setAttempts(items);
            lastIdRef.current = items.reduce(
              (maximum, item) => Math.max(maximum, item.id),
              0,
            );
          }
        })
        .catch((err: unknown) => {
          setError(
            err instanceof Error
              ? err.message
              : "No se pudo consultar el progreso",
          );
        });
    }, 700);
    return () => window.clearInterval(timer);
  }, [scanId, scanStatus]);

  useEffect(() => {
    if (loading) return;
    let stopped = false;
    let socket: WebSocket | null = null;
    let reconnectTimer: number | undefined;

    const connect = () => {
      if (stopped) return;
      socket = new WebSocket(`${SCAN_WS_URL}?after=${lastIdRef.current}`);
      socket.onopen = () => setConnected(true);
      socket.onmessage = (event) => {
        try {
          const attempt = JSON.parse(event.data as string) as ActiveScanAttempt;
          if (attempt.id <= lastIdRef.current) return;
          lastIdRef.current = attempt.id;
          setAttempts((previous) =>
            previous.some((item) => item.id === attempt.id)
              ? previous
              : [attempt, ...previous].slice(0, MAX_VISIBLE_ATTEMPTS),
          );
        } catch {
          // Ignora mensajes no JSON.
        }
      };
      socket.onerror = () => socket?.close();
      socket.onclose = () => {
        setConnected(false);
        if (!stopped) reconnectTimer = window.setTimeout(connect, 2_000);
      };
    };

    connect();
    return () => {
      stopped = true;
      if (reconnectTimer !== undefined) window.clearTimeout(reconnectTimer);
      socket?.close();
    };
  }, [currentProject, loading]);

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDirection((previous) => (previous === "asc" ? "desc" : "asc"));
      return;
    }
    setSortKey(key);
    setSortDirection(key === "created_at" ? "desc" : "asc");
  };

  const resetFilters = () => {
    setSearch("");
    setResultFilter("all");
    setAttackFilter("all");
  };

  const reloadAttempts = async () => {
    try {
      const items = await fetchScanAttempts(MAX_VISIBLE_ATTEMPTS);
      setAttempts(items);
      lastIdRef.current = items.reduce(
        (maximum, item) => Math.max(maximum, item.id),
        0,
      );
    } catch (err: unknown) {
      setError(
        err instanceof Error ? err.message : "No se pudieron recargar los ataques",
      );
    }
  };

  const clearAttempts = async () => {
    setClearing(true);
    setError(null);
    try {
      await deleteScanAttempts();
      setAttempts([]);
      setSelectedAttemptId(null);
      lastIdRef.current = 0;
    } catch (err: unknown) {
      setError(
        err instanceof Error ? err.message : "No se pudieron borrar los ataques",
      );
    } finally {
      setClearing(false);
    }
  };

  const stopRunningScan = async () => {
    if (!scan || scan.status !== "running") return;
    setStopping(true);
    try {
      const stopped = await stopScan(scan.scan_id);
      setScan(stopped);
      setError(null);
    } catch (err: unknown) {
      setError(
        err instanceof Error
          ? err.message
          : "No se pudo detener el escaneo",
      );
    } finally {
      setStopping(false);
    }
  };

  const submitFullScan = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const target = fullUrl.trim();
    if (!target) {
      setFullError("Introduce una URL http(s) válida.");
      return;
    }
    setFullStarting(true);
    setFullError(null);
    setError(null);
    try {
      const job = await startFullScan({
        url: target,
        intensity: fullIntensity,
        custom_headers: fullHeaders,
        max_depth: fullUnlimited ? 0 : fullDepth,
        max_urls: fullUnlimited ? 0 : fullMaxPages,
      });
      setScan(job);
      setSelectedAttemptId(null);
      setFullModalOpen(false);
    } catch (err: unknown) {
      setFullError(
        err instanceof Error
          ? err.message
          : "No se pudo iniciar el escaneo de sitio completo",
      );
    } finally {
      setFullStarting(false);
    }
  };

  const openFlow = (flowId: number) => {
    setSelectedFlowId(flowId);
    setActiveModule("proxy");
  };

  const vulnerableCount = visibleAttempts.filter(
    (attempt) => attempt.result === "vulnerable",
  ).length;
  const running = scan?.status === "running";
  const progress = scan ? Math.max(0, Math.min(100, scan.progress)) : 0;
  const isFullScan = scan?.mode === "full";
  const phase = scan?.phase;
  const crawling =
    running && isFullScan && (phase === "crawling" || phase === "analyzing");
  const phaseLabel = !scan
    ? ""
    : scan.status === "failed"
      ? `Escaneo fallido: ${scan.error ?? "error desconocido"}`
      : scan.status === "completed"
        ? isFullScan
          ? `Escaneo completado · ${scan.pages_found ?? 0} páginas · ${scan.total_attempts} ataques · ${scan.vulnerable} vulnerabilidades`
          : `Escaneo completado · ${scan.completed} de ${scan.total} peticiones`
        : isFullScan
          ? phase === "crawling"
            ? "Rastreando sitio..."
            : phase === "analyzing"
              ? "Analizando formularios..."
              : "Lanzando ataques XSS/SQLi/Command/Traversal..."
          : `Escaneando ${scan.completed} de ${scan.total} peticiones…`;

  return (
    <div className="flex h-full min-h-0 flex-col bg-surface-950">
      <div className="flex items-center gap-1 border-b border-surface-800 bg-surface-900/40 px-4 py-2">
        <button
          type="button"
          onClick={() => setActiveTab("active")}
          aria-pressed={activeTab === "active"}
          className={[
            "flex items-center gap-2 rounded-lg px-3 py-1.5 text-[11px] font-semibold transition",
            activeTab === "active"
              ? "bg-accent/15 text-accent"
              : "text-zinc-500 hover:bg-surface-850 hover:text-zinc-200",
          ].join(" ")}
        >
          <Zap size={13} />
          Fuzzing (XSS/SQLi)
        </button>
        <HelpTooltip
          label="Fuzzing (XSS/SQLi)"
          text="Lanza payloads automáticos de XSS, SQLi, command injection y path traversal sobre peticiones seleccionadas o sobre todo el dominio."
        />
        <button
          type="button"
          onClick={() => setActiveTab("templates")}
          aria-pressed={activeTab === "templates"}
          className={[
            "flex items-center gap-2 rounded-lg px-3 py-1.5 text-[11px] font-semibold transition",
            activeTab === "templates"
              ? "bg-cyan-400/15 text-cyan-300"
              : "text-zinc-500 hover:bg-surface-850 hover:text-zinc-200",
          ].join(" ")}
        >
          <FileCode2 size={13} />
          CVEs (Nuclei)
        </button>
        <HelpTooltip
          label="CVEs (Nuclei)"
          text="Ejecuta plantillas HTTP compatibles con Nuclei, con Auto-Tech y crawl opcional para barrer todas las rutas del dominio."
        />
      </div>

      <div
        className={
          activeTab === "active"
            ? "flex min-h-0 flex-1 flex-col"
            : "hidden"
        }
      >
      <div className="flex flex-wrap items-end justify-between gap-3 border-b border-surface-800 px-5 py-3">
        <div>
          <h2 className="flex items-center gap-2 text-sm font-bold text-zinc-100">
            <Zap size={16} className="text-amber-300" />
            Fuzzing (XSS/SQLi)
          </h2>
          <p className="mt-1 text-[11px] text-zinc-500">
            {connected ? "live · ws conectado" : "reconectando…"} ·{" "}
            {visibleAttempts.length} ataque
            {visibleAttempts.length === 1 ? "" : "s"} · {vulnerableCount}{" "}
            vulnerable{vulnerableCount === 1 ? "" : "s"}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => void reloadAttempts()}
            className="flex items-center gap-2 rounded-lg border border-surface-700 px-3 py-2 text-xs text-zinc-400 transition hover:border-surface-600 hover:text-zinc-100"
          >
            <RefreshCw size={14} />
            Recargar
          </button>
          <button
            type="button"
            onClick={() => void clearAttempts()}
            disabled={clearing || running || attempts.length === 0}
            className="flex items-center gap-2 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs font-semibold text-rose-300 transition hover:bg-rose-500/20 disabled:opacity-40"
          >
            {clearing ? (
              <Loader2 size={14} className="animate-spin" />
            ) : (
              <Trash2 size={14} />
            )}
            Limpiar
          </button>
        </div>
      </div>

      <div className="border-b border-surface-800 bg-gradient-to-r from-accent/10 via-surface-900/40 to-cyan-500/10 px-5 py-3">
        <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={() => {
            setFullError(null);
            setFullModalOpen(true);
          }}
          disabled={running}
          className="group flex min-w-0 flex-1 items-center gap-3 rounded-xl border border-accent/50 bg-accent/10 px-4 py-3 text-left transition hover:border-accent hover:bg-accent/15 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <span className="grid h-10 w-10 shrink-0 place-items-center rounded-lg border border-accent/40 bg-surface-950 text-accent shadow-glow">
            <Radar size={20} className="group-hover:animate-pulse" />
          </span>
          <span className="min-w-0 flex-1">
            <span className="block text-sm font-bold text-accent">
              Full Site Scan (Crawl + Fuzzing)
            </span>
            <span className="mt-0.5 block text-[11px] text-zinc-400">
              Rastrea el sitio, descubre formularios y lanza XSS, SQLi,
              command injection y traversal sobre todas las URLs encontradas.
            </span>
          </span>
          <span className="hidden rounded border border-cyan-400/40 bg-cyan-950/40 px-2 py-1 font-mono text-[9px] uppercase tracking-[0.16em] text-cyan-300 sm:block">
            Full Site
          </span>
        </button>
        <HelpTooltip
          label="Full Site Scan"
          text="Rastrea el dominio, descubre formularios y lanza fuzzing XSS/SQLi/Command/Traversal sobre todas las URLs encontradas."
        />
        </div>
      </div>

      {error && (
        <div
          role="alert"
          className="border-b border-rose-900/60 bg-rose-950/30 px-5 py-2 text-xs text-rose-300"
        >
          {error}
        </div>
      )}

      {scan && (
        <div
          className={[
            "border-b px-5 py-3",
            running
              ? "border-amber-900/60 bg-amber-950/20"
              : scan.status === "failed"
                ? "border-rose-900/60 bg-rose-950/20"
                : "border-emerald-900/60 bg-emerald-950/20",
          ].join(" ")}
        >
          <div className="flex flex-wrap items-center justify-between gap-2 text-[11px]">
            <span
              className={[
                "flex items-center gap-2 font-semibold",
                running
                  ? "text-amber-300"
                  : scan.status === "failed"
                    ? "text-rose-300"
                    : "text-emerald-300",
              ].join(" ")}
            >
              {running ? (
                <Loader2 size={13} className="animate-spin" />
              ) : scan.status === "failed" ? (
                <AlertTriangle size={13} />
              ) : (
                <CheckCircle2 size={13} />
              )}
              {phaseLabel}
            </span>
            <span className="font-mono text-zinc-400">
              {isFullScan ? (
                <>
                  URLs descubiertas: {scan.urls_found ?? 0} · Formularios:{" "}
                  {scan.forms_found ?? 0} · Ataques: {scan.total_attempts} ·{" "}
                  {scan.vulnerable} vulnerables · {scan.errors} errores
                </>
              ) : (
                <>
                  {scan.total_attempts} ataques · {scan.vulnerable} vulnerables
                  {" · "}
                  {scan.errors} errores
                </>
              )}
              {scan.host ? ` · ${scan.host}` : ""}
              {scan.intensity
                ? ` · Intensidad ${INTENSITY_LABELS[scan.intensity]}`
                : ""}
            </span>
          </div>
          {running && (
            <div className="mt-2 flex items-center gap-3">
              <div
                role="progressbar"
                aria-label="Progreso del escaneo activo"
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={crawling ? 100 : progress}
                className="h-2 min-w-0 flex-1 overflow-hidden rounded-full bg-surface-800"
              >
                <div
                  className={[
                    "h-full rounded-full bg-amber-400 transition-[width] duration-300",
                    crawling ? "animate-pulse" : "",
                  ].join(" ")}
                  style={{ width: `${crawling ? 100 : progress}%` }}
                />
              </div>
              <button
                type="button"
                onClick={() => void stopRunningScan()}
                disabled={stopping || !scan?.scan_id}
                className="flex shrink-0 items-center gap-2 rounded-lg border border-rose-500/60 bg-rose-950/40 px-3 py-1.5 text-xs font-semibold text-rose-200 transition hover:border-rose-400 hover:bg-rose-500/20 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {stopping ? (
                  <Loader2 size={13} className="animate-spin" />
                ) : (
                  <Square size={12} />
                )}
                {stopping ? "Deteniendo…" : "Detener Escaneo"}
              </button>
            </div>
          )}
          {isFullScan && scan.status === "completed" && (
            <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
              <div className="rounded-lg border border-surface-700 bg-surface-950/60 px-3 py-2">
                <p className="text-[9px] uppercase tracking-[0.14em] text-zinc-500">
                  Páginas
                </p>
                <p className="font-mono text-lg font-bold text-cyan-300">
                  {scan.pages_found ?? 0}
                </p>
              </div>
              <div className="rounded-lg border border-surface-700 bg-surface-950/60 px-3 py-2">
                <p className="text-[9px] uppercase tracking-[0.14em] text-zinc-500">
                  URLs
                </p>
                <p className="font-mono text-lg font-bold text-cyan-300">
                  {scan.urls_found ?? 0}
                </p>
              </div>
              <div className="rounded-lg border border-surface-700 bg-surface-950/60 px-3 py-2">
                <p className="text-[9px] uppercase tracking-[0.14em] text-zinc-500">
                  Ataques
                </p>
                <p className="font-mono text-lg font-bold text-amber-300">
                  {scan.total_attempts}
                </p>
              </div>
              <div className="rounded-lg border border-surface-700 bg-surface-950/60 px-3 py-2">
                <p className="text-[9px] uppercase tracking-[0.14em] text-zinc-500">
                  Vulnerabilidades
                </p>
                <p className="font-mono text-lg font-bold text-rose-300">
                  {scan.vulnerable}
                </p>
              </div>
            </div>
          )}
        </div>
      )}

      <SplitPane
        orientation="vertical"
        label="Redimensionar ataques y detalle"
        initial={55}
        min={25}
        max={80}
        first={
          <div className="flex h-full min-h-0 flex-col">
            <div className="flex items-center justify-between gap-3 border-b border-surface-800 bg-surface-900/40 px-5 py-2">
              <div className="flex min-w-0 items-center gap-2">
                <span className="shrink-0 text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
                  Ataques realizados
                </span>
                <span
                  className="hidden items-center gap-1 truncate rounded-full border border-zinc-700/70 bg-surface-950 px-2 py-0.5 text-[9px] text-zinc-500 sm:inline-flex"
                  title="Los flujos sintéticos del escáner están ocultos en Interceptación por defecto"
                >
                  <EyeOff size={9} />
                  Flujos del escáner ocultos en Proxy
                </span>
              </div>
              <span className="shrink-0 font-mono text-[10px] text-zinc-600">
                {filteredAttempts.length} de {visibleAttempts.length} registro
                {visibleAttempts.length === 1 ? "" : "s"}
              </span>
            </div>

            <div className="border-b border-surface-800 bg-surface-900/30 px-5 py-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <label className="relative min-w-48 flex-1">
                  <Search
                    size={13}
                    className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-600"
                  />
                  <input
                    type="search"
                    aria-label="Buscar ataques"
                    placeholder="Buscar por URL, parámetro o payload…"
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                    className="w-full rounded-lg border border-surface-700 bg-surface-950 py-1.5 pl-8 pr-2.5 text-xs text-zinc-200 outline-none placeholder:text-zinc-600 focus:border-accent"
                  />
                </label>

                <div
                  role="group"
                  aria-label="Filtrar por resultado"
                  className="flex overflow-hidden rounded-lg border border-surface-700"
                >
                  {(
                    [
                      ["all", "Todos"],
                      ["vulnerable", "Solo Vulnerables"],
                      ["error", "Solo Errores"],
                    ] as const
                  ).map(([value, label]) => (
                    <button
                      key={value}
                      type="button"
                      onClick={() => setResultFilter(value)}
                      aria-pressed={resultFilter === value}
                      className={[
                        "px-2.5 py-1.5 text-[10px] font-semibold transition",
                        resultFilter === value
                          ? "bg-accent/15 text-accent"
                          : "bg-surface-950 text-zinc-500 hover:text-zinc-200",
                      ].join(" ")}
                    >
                      {label}
                    </button>
                  ))}
                </div>

                <label className="flex items-center gap-1.5 rounded-lg border border-surface-700 bg-surface-950 px-2 py-1.5">
                  <Filter size={12} className="text-zinc-600" />
                  <select
                    aria-label="Filtrar por tipo de ataque"
                    value={attackFilter}
                    onChange={(event) => setAttackFilter(event.target.value)}
                    className="bg-transparent text-[10px] font-semibold text-zinc-300 outline-none"
                  >
                    <option value="all">Todos los ataques</option>
                    <option value="xss">XSS</option>
                    <option value="sqli">SQLi</option>
                    <option value="command">Command Injection</option>
                    <option value="traversal">Path Traversal</option>
                  </select>
                </label>

                {filtersActive && (
                  <button
                    type="button"
                    onClick={resetFilters}
                    className="rounded-lg border border-surface-700 px-2.5 py-1.5 text-[10px] text-zinc-400 transition hover:border-surface-600 hover:text-zinc-100"
                  >
                    Limpiar filtros
                  </button>
                )}
              </div>
            </div>

            <div className="min-h-0 flex-1 overflow-auto">
              {loading ? (
                <div className="flex h-full items-center justify-center text-sm text-zinc-500">
                  <Loader2 size={20} className="mr-2 animate-spin text-accent" />
                  Cargando ataques…
                </div>
              ) : filteredAttempts.length === 0 ? (
                <div className="flex h-full flex-col items-center justify-center gap-3 text-center text-zinc-500">
                  <Zap size={34} className="text-zinc-700" />
                  <div>
                    <p className="text-sm text-zinc-400">
                      {filtersActive
                        ? "Ningún ataque coincide con los filtros"
                        : "Sin ataques todavía"}
                    </p>
                    <p className="mt-1 max-w-md text-xs text-zinc-600">
                      {filtersActive
                        ? "Prueba con otro texto, resultado o tipo de ataque."
                        : "Selecciona peticiones en Interceptación y pulsa «Escanear Seleccionadas», o lanza «Full Site Scan (Crawl + Fuzzing)»."}
                    </p>
                    {filtersActive && (
                      <button
                        type="button"
                        onClick={resetFilters}
                        className="mt-3 rounded-lg border border-surface-700 px-3 py-1.5 text-[10px] text-zinc-300 transition hover:border-surface-600 hover:text-zinc-100"
                      >
                        Limpiar filtros
                      </button>
                    )}
                  </div>
                </div>
              ) : (
                <table className={DATA_TABLE}>
                  <thead className={DATA_TABLE_HEAD}>
                    <tr className="border-b border-surface-800">
                      <th className="w-28 px-4 py-2.5 font-medium">Petición</th>
                      <th className="w-20 px-2 py-2.5 font-medium">Ataque</th>
                      <th className="w-32 px-2 py-2.5 font-medium">
                        Parámetro
                      </th>
                      <th className="w-64 px-2 py-2.5 font-medium">Payload</th>
                      <th
                        aria-sort={
                          sortKey === "status_code"
                            ? sortDirection === "asc"
                              ? "ascending"
                              : "descending"
                            : "none"
                        }
                        className="w-16 px-2 py-2.5 text-right font-medium"
                      >
                        <button
                          type="button"
                          onClick={() => toggleSort("status_code")}
                          className="ml-auto flex items-center gap-1 uppercase tracking-[0.16em] transition hover:text-zinc-200"
                          title={SORTABLE_COLUMNS.status_code[sortDirection]}
                        >
                          Cód.
                          {sortKey === "status_code" &&
                            (sortDirection === "asc" ? (
                              <ArrowUp size={10} />
                            ) : (
                              <ArrowDown size={10} />
                            ))}
                        </button>
                      </th>
                      <th
                        aria-sort={
                          sortKey === "result"
                            ? sortDirection === "asc"
                              ? "ascending"
                              : "descending"
                            : "none"
                        }
                        className="w-28 px-2 py-2.5 font-medium"
                      >
                        <button
                          type="button"
                          onClick={() => toggleSort("result")}
                          className="flex items-center gap-1 uppercase tracking-[0.16em] transition hover:text-zinc-200"
                          title={SORTABLE_COLUMNS.result[sortDirection]}
                        >
                          Resultado
                          {sortKey === "result" &&
                            (sortDirection === "asc" ? (
                              <ArrowUp size={10} />
                            ) : (
                              <ArrowDown size={10} />
                            ))}
                        </button>
                      </th>
                      <th className="px-2 py-2.5 font-medium">Evidencia</th>
                      <th
                        aria-sort={
                          sortKey === "created_at"
                            ? sortDirection === "asc"
                              ? "ascending"
                              : "descending"
                            : "none"
                        }
                        className="w-24 px-4 py-2.5 text-right font-medium"
                      >
                        <button
                          type="button"
                          onClick={() => toggleSort("created_at")}
                          className="ml-auto flex items-center gap-1 uppercase tracking-[0.16em] transition hover:text-zinc-200"
                          title={`Hora ${
                            sortDirection === "asc" ? "ascendente" : "descendente"
                          }`}
                        >
                          Hora
                          {sortKey === "created_at" &&
                            (sortDirection === "asc" ? (
                              <ArrowUp size={10} />
                            ) : (
                              <ArrowDown size={10} />
                            ))}
                        </button>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredAttempts.map((attempt) => (
                      <tr
                        key={attempt.id}
                        onClick={() => setSelectedAttemptId(attempt.id)}
                        className={[
                          "cursor-pointer border-b border-surface-800/70 align-top transition",
                          selectedAttemptId === attempt.id
                            ? "bg-accent/10"
                            : "hover:bg-surface-850",
                        ].join(" ")}
                        title="Ver el detalle del ataque"
                      >
                        <td className="px-4 py-2.5">
                          <button
                            type="button"
                            onClick={(event) => {
                              event.stopPropagation();
                              openFlow(attempt.flow_id);
                            }}
                            className="font-semibold text-accent transition hover:underline"
                            title={`Abrir flujo #${attempt.flow_id}\n${attempt.url}`}
                          >
                            #{attempt.id}
                          </button>
                          <p className="mt-0.5 truncate text-[10px] text-zinc-600">
                            {attempt.url}
                          </p>
                        </td>
                        <td className="px-2 py-2.5">
                          <span className="rounded border border-cyan-500/40 bg-cyan-950/30 px-1.5 py-0.5 text-[9px] font-bold uppercase text-cyan-300">
                            {attackLabel(attempt.attack)}
                          </span>
                        </td>
                        <td className="truncate px-2 py-2.5 text-zinc-300">
                          {attempt.parameter}
                          <span className="ml-1 text-[9px] uppercase text-zinc-600">
                            {attempt.location}
                          </span>
                        </td>
                        <td
                          className="truncate px-2 py-2.5 text-zinc-400"
                          title={attempt.payload}
                        >
                          {attempt.payload}
                        </td>
                        <td className="px-2 py-2.5 text-right text-zinc-400">
                          {attempt.status_code ?? "—"}
                        </td>
                        <td className="px-2 py-2.5">
                          <span
                            className={[
                              "rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase",
                              resultClass(attempt.result),
                            ].join(" ")}
                          >
                            {resultLabel(attempt.result)}
                          </span>
                        </td>
                        <td
                          className="truncate px-2 py-2.5 text-rose-300/90"
                          title={attempt.evidence}
                        >
                          {attempt.evidence || "—"}
                        </td>
                        <td className="px-4 py-2.5 text-right text-zinc-500">
                          {formatTime(attempt.created_at)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        }
        second={
          selectedAttempt ? (
            <FlowDetailPanel
              flowId={selectedAttempt.flow_id}
              onClose={() => setSelectedAttemptId(null)}
              requestRaw={selectedAttempt.request_raw}
              responseRaw={selectedAttempt.response_raw}
              previewLabel={`${attackLabel(selectedAttempt.attack)} · ${
                selectedAttempt.parameter
              }`}
              evidence={selectedAttempt.evidence}
              evidenceMatch={selectedAttempt.evidence_match}
              evidenceOffset={selectedAttempt.evidence_offset}
              vulnerability={attackLabel(selectedAttempt.attack)}
              affectedUrl={selectedAttempt.url}
              attackParameter={selectedAttempt.parameter}
              attackPayload={selectedAttempt.payload}
              readOnlyPreview
            />
          ) : (
            <div className="flex h-full flex-col items-center justify-center gap-2 border-t border-surface-800 bg-surface-900/40 text-center text-zinc-600">
              <Zap size={26} className="text-zinc-700" />
              <p className="text-[10px] uppercase tracking-[0.18em] text-zinc-500">
                Detalle del ataque
              </p>
              <p className="max-w-md text-[11px]">
                Selecciona un ataque para ver la petición con el payload y la
                respuesta exacta del servidor.
              </p>
            </div>
          )
        }
      />

      {visibleAttempts.length === 0 && !loading && !scan && (
        <div className="flex items-center justify-center gap-2 border-t border-surface-800 px-5 py-2 text-[10px] text-zinc-600">
          <RadioTower size={13} />
          Esperando a que lances un escaneo desde el historial del Proxy o un
          Full Site Scan.
        </div>
      )}

      {fullModalOpen && (
        <div
          className="fixed inset-0 z-50 grid place-items-center bg-black/75 p-4"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget && !fullStarting) {
              setFullModalOpen(false);
            }
          }}
        >
          <form
            role="dialog"
            aria-modal="true"
            aria-labelledby="full-scan-title"
            onSubmit={(event) => void submitFullScan(event)}
            className="w-full max-w-lg rounded-xl border border-accent/40 bg-surface-900 p-5 shadow-2xl"
          >
            <div className="flex items-start justify-between gap-3">
              <div>
                <h3
                  id="full-scan-title"
                  className="flex items-center gap-2 text-base font-bold text-zinc-100"
                >
                  <Radar size={18} className="text-accent" />
                  Full Site Scan (Crawl + Fuzzing)
                </h3>
                <p className="mt-1 text-xs text-zinc-400">
                  El crawler descubrirá páginas y formularios; después el
                  fuzzing probará XSS, SQLi, command injection y path
                  traversal en cada punto.
                </p>
              </div>
              <button
                type="button"
                aria-label="Cerrar"
                onClick={() => setFullModalOpen(false)}
                disabled={fullStarting}
                className="rounded p-1 text-zinc-500 transition hover:bg-surface-800 hover:text-zinc-200 disabled:opacity-40"
              >
                <X size={16} />
              </button>
            </div>

            <label className="mt-5 block space-y-1.5">
              <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-400">
                URL objetivo
              </span>
              <input
                autoFocus
                type="url"
                required
                aria-label="URL objetivo"
                value={fullUrl}
                onChange={(event) => setFullUrl(event.target.value)}
                placeholder="http://192.168.0.9:5000/"
                className="w-full rounded-lg border border-surface-700 bg-surface-950 px-3 py-2.5 font-mono text-sm text-zinc-100 outline-none placeholder:text-zinc-600 focus:border-accent"
              />
              <span className="block text-[10px] text-zinc-600">
                Debe incluir esquema http:// o https://. Solo se rastreará el
                host/puerto indicado.
              </span>
            </label>

            <label className="mt-4 block space-y-1.5">
              <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-400">
                Intensidad
              </span>
              <select
                aria-label="Intensidad del escaneo"
                value={fullIntensity}
                onChange={(event) =>
                  setFullIntensity(event.target.value as ScanIntensity)
                }
                className="w-full rounded-lg border border-surface-700 bg-surface-950 px-3 py-2.5 text-sm text-zinc-100 outline-none focus:border-accent"
              >
                <option value="low">
                  Baja · payloads básicos y rápidos
                </option>
                <option value="medium">
                  Media · equilibrio entre cobertura y ruido
                </option>
                <option value="high">
                  Alta · todos los payloads, time-based incluido
                </option>
              </select>
              <span className="block text-[10px] text-zinc-600">
                La intensidad alta envía todos los payloads y puede tardar
                varios minutos.
              </span>
            </label>

            <div className="mt-4">
              <span className="mb-1.5 block text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-400">
                Límites del crawler
              </span>
              <CrawlLimitFields
                depth={fullDepth}
                maxPages={fullMaxPages}
                unlimited={fullUnlimited}
                onDepthChange={setFullDepth}
                onMaxPagesChange={setFullMaxPages}
                onUnlimitedChange={setFullUnlimited}
              />
            </div>

            <label className="mt-4 block space-y-1.5">
              <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-400">
                Cabeceras personalizadas (Opcional)
              </span>
              <textarea
                aria-label="Cabeceras personalizadas"
                value={fullHeaders}
                onChange={(event) => setFullHeaders(event.target.value)}
                rows={4}
                spellCheck={false}
                placeholder={"Cookie: session=1234\nAuthorization: Bearer token"}
                className="w-full resize-y rounded-lg border border-surface-700 bg-surface-950 px-3 py-2 font-mono text-xs text-zinc-200 outline-none placeholder:text-zinc-600 focus:border-accent"
              />
              <span className="block text-[10px] text-zinc-600">
                Una cabecera por línea con formato <code>Nombre: valor</code>.
                Se añadirán al crawler y a todos los ataques.
              </span>
            </label>

            {fullError && (
              <div
                role="alert"
                className="mt-3 rounded-lg border border-rose-900/60 bg-rose-950/30 px-3 py-2 text-xs text-rose-300"
              >
                {fullError}
              </div>
            )}

            <div className="mt-5 flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={() => setFullModalOpen(false)}
                disabled={fullStarting}
                className="rounded-lg border border-surface-700 px-3 py-2 text-xs text-zinc-300 transition hover:bg-surface-800 disabled:opacity-40"
              >
                Cancelar
              </button>
              <button
                type="submit"
                disabled={fullStarting || !fullUrl.trim()}
                className="flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-xs font-bold text-surface-950 transition hover:bg-accent-soft disabled:cursor-not-allowed disabled:opacity-40"
              >
                {fullStarting ? (
                  <Loader2 size={14} className="animate-spin" />
                ) : (
                  <Radar size={14} />
                )}
                {fullStarting ? "Iniciando…" : "Iniciar escaneo"}
              </button>
            </div>
          </form>
        </div>
      )}
      </div>

      {activeTab === "templates" && (
        <div className="min-h-0 flex-1">
          <TemplateScanPanel />
        </div>
      )}
    </div>
  );
}
