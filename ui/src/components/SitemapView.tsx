import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type FormEvent,
} from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Folder,
  FolderOpen,
  FolderTree,
  Loader2,
  Radar,
  RefreshCw,
  X,
} from "lucide-react";
import type { CrawlStatus, SitemapEntry, SitemapTree } from "../types";
import {
  fetchCrawlStatus,
  fetchSitemap,
  startCrawl,
} from "../lib/api";
import { useApp } from "../context/AppContext";
import { CrawlLimitFields } from "./CrawlLimitFields";

const METHOD_BADGE: Record<string, string> = {
  GET: "border-emerald-800/70 bg-emerald-950/40 text-emerald-300",
  POST: "border-cyan-800/70 bg-cyan-950/40 text-cyan-300",
  PUT: "border-amber-800/70 bg-amber-950/40 text-amber-300",
  PATCH: "border-amber-800/70 bg-amber-950/40 text-amber-300",
  DELETE: "border-rose-800/70 bg-rose-950/40 text-rose-300",
  OPTIONS: "border-zinc-700 bg-zinc-900/60 text-zinc-400",
  HEAD: "border-zinc-700 bg-zinc-900/60 text-zinc-400",
};

function badgeTone(method: string): string {
  return METHOD_BADGE[method.toUpperCase()] ?? "border-zinc-700 bg-zinc-900/60 text-zinc-300";
}

function hostCount(entries: Record<string, SitemapEntry>): number {
  return Object.values(entries).reduce((total, entry) => total + entry.count, 0);
}

export function SitemapView() {
  const { setActiveModule, setProxyRouteFilter, currentProject } = useApp();
  const [tree, setTree] = useState<SitemapTree>({});
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [crawlModalOpen, setCrawlModalOpen] = useState(false);
  const [crawlUrl, setCrawlUrl] = useState("");
  const [crawlDepth, setCrawlDepth] = useState(3);
  const [crawlMaxPages, setCrawlMaxPages] = useState(200);
  const [crawlUnlimited, setCrawlUnlimited] = useState(false);
  const [crawlStarting, setCrawlStarting] = useState(false);
  const [crawlError, setCrawlError] = useState<string | null>(null);
  const [crawl, setCrawl] = useState<CrawlStatus | null>(null);

  const load = useCallback(async () => {
    setError(null);
    setLoading(true);
    try {
      const data = await fetchSitemap();
      setTree(data);
      setExpanded(new Set(Object.keys(data)));
    } catch (err: unknown) {
      setError(
        err instanceof Error
          ? err.message
          : "No se pudo cargar el Mapa de Rutas",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load, currentProject]);

  const activeCrawlId = crawl?.crawl_id;
  const crawlRunning = crawl?.status === "running";

  useEffect(() => {
    if (!activeCrawlId || !crawlRunning) return;
    const timer = window.setInterval(() => {
      void fetchCrawlStatus(activeCrawlId)
        .then((next) => {
          if (!next) return;
          setCrawl(next);
          if (next.status !== "running") {
            void load();
          }
        })
        .catch((err: unknown) => {
          setCrawlError(
            err instanceof Error
              ? err.message
              : "No se pudo consultar el crawler",
          );
        });
    }, 800);
    return () => window.clearInterval(timer);
  }, [activeCrawlId, crawlRunning, load]);

  const openCrawlModal = () => {
    const firstHost = Object.keys(tree).sort()[0] ?? "";
    setCrawlUrl(firstHost ? `http://${firstHost}/` : "");
    setCrawlError(null);
    setCrawlModalOpen(true);
  };

  const submitCrawl = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const target = crawlUrl.trim();
    if (!target) {
      setCrawlError("Introduce una URL http(s) válida.");
      return;
    }
    try {
      const parsed = new URL(target);
      if (!["http:", "https:"].includes(parsed.protocol)) {
        throw new Error("protocolo inválido");
      }
    } catch {
      setCrawlError("Introduce una URL http(s) válida.");
      return;
    }

    setCrawlStarting(true);
    setCrawlError(null);
    try {
      const job = await startCrawl({
        url: target,
        max_depth: crawlUnlimited ? 0 : crawlDepth,
        max_urls: crawlUnlimited ? 0 : crawlMaxPages,
      });
      setCrawl(job);
      setCrawlModalOpen(false);
    } catch (err: unknown) {
      setCrawlError(
        err instanceof Error
          ? err.message
          : "No se pudo iniciar el crawler",
      );
    } finally {
      setCrawlStarting(false);
    }
  };

  const hosts = useMemo(
    () =>
      Object.entries(tree).sort(([a], [b]) => a.localeCompare(b)),
    [tree],
  );

  const totalPaths = useMemo(
    () => hosts.reduce((total, [, entries]) => total + Object.keys(entries).length, 0),
    [hosts],
  );

  const toggleHost = (host: string) => {
    setExpanded((previous) => {
      const next = new Set(previous);
      if (next.has(host)) {
        next.delete(host);
      } else {
        next.add(host);
      }
      return next;
    });
  };

  const openInProxy = (host: string, path: string) => {
    setProxyRouteFilter({ host, path });
    setActiveModule("proxy");
  };

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-3 border-b border-surface-800 bg-surface-900/40 px-5 py-3">
        <span className="flex items-center gap-2 rounded-full border border-surface-700 bg-surface-850 px-3 py-1.5 text-[11px] text-zinc-400">
          <FolderTree size={14} className="text-accent" />
          {hosts.length} hosts · {totalPaths} rutas
        </span>
        <p className="text-xs text-zinc-500">
          Haz clic en una ruta para ver sus flujos en Interceptación.
        </p>
        <div className="ml-auto flex items-center gap-2">
          <button
            type="button"
            onClick={openCrawlModal}
            className="flex items-center gap-2 rounded-lg border border-accent/50 bg-accent/10 px-3 py-2 text-xs font-bold text-accent transition hover:border-accent hover:bg-accent/15"
          >
            <Radar size={14} />
            Descubrir Rutas (Solo Crawler)
          </button>
          <button
            type="button"
            onClick={() => void load()}
            className="flex items-center gap-2 rounded-lg border border-surface-700 px-3 py-2 text-xs text-zinc-400 transition hover:border-surface-600 hover:text-zinc-100"
          >
            <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
            Recargar
          </button>
        </div>
      </div>

      {crawl && (
        <div
          className={[
            "mx-5 mt-3 rounded-xl border px-4 py-3",
            crawl.status === "failed"
              ? "border-rose-900/60 bg-rose-950/30"
              : crawl.status === "completed"
                ? "border-emerald-900/60 bg-emerald-950/20"
                : "border-accent/40 bg-accent/5",
          ].join(" ")}
        >
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {crawl.status === "failed" ? (
              <AlertTriangle size={15} className="text-rose-300" />
            ) : crawl.status === "completed" ? (
              <CheckCircle2 size={15} className="text-emerald-300" />
            ) : (
              <Loader2 size={15} className="animate-spin text-accent" />
            )}
            <span
              className={
                crawl.status === "failed"
                  ? "font-semibold text-rose-300"
                  : crawl.status === "completed"
                    ? "font-semibold text-emerald-300"
                    : "font-semibold text-accent"
              }
            >
              {crawl.status === "failed"
                ? `Crawler fallido: ${crawl.error ?? "error desconocido"}`
                : crawl.status === "completed"
                  ? `Crawler completado · ${crawl.routes_saved} rutas guardadas`
                  : crawl.phase === "saving"
                    ? "Guardando rutas descubiertas…"
                    : `Rastreando sitio… ${crawl.urls_found} URLs encontradas`}
            </span>
            <span className="font-mono text-[10px] text-zinc-500">
              {crawl.host ?? crawl.seed_url} · {crawl.pages_found} páginas ·{" "}
              {crawl.forms_found} formularios · {crawl.errors} errores
            </span>
          </div>
          {crawl.status === "running" && (
            <div
              role="progressbar"
              aria-label="Progreso del crawler"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={crawl.progress}
              className="mt-2 h-1.5 overflow-hidden rounded-full bg-surface-800"
            >
              <div
                className="h-full rounded-full bg-accent transition-[width] duration-300"
                style={{ width: `${Math.max(2, crawl.progress)}%` }}
              />
            </div>
          )}
        </div>
      )}

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

      <div className="min-h-0 flex-1 overflow-auto p-4">
        {loading ? (
          <div className="flex h-full items-center justify-center text-sm text-zinc-500">
            <Loader2 size={20} className="mr-2 animate-spin text-accent" />
            Construyendo el mapa de endpoints…
          </div>
        ) : hosts.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-3 text-center text-zinc-500">
            <FolderTree size={34} className="text-zinc-700" />
            <div>
              <p className="text-sm text-zinc-400">Mapa de Rutas vacío</p>
              <p className="mt-1 max-w-sm text-xs text-zinc-600">
                Navega a través de Interceptación para descubrir hosts y rutas. El
                mapa se construye automáticamente con el tráfico capturado.
              </p>
            </div>
          </div>
        ) : (
          <div className="mx-auto max-w-5xl space-y-2">
            {hosts.map(([host, entries]) => {
              const isOpen = expanded.has(host);
              const paths = Object.entries(entries).sort(([a], [b]) =>
                a.localeCompare(b),
              );
              return (
                <section
                  key={host}
                  className="overflow-hidden rounded-xl border border-surface-800 bg-surface-900/60"
                >
                  <button
                    type="button"
                    onClick={() => toggleHost(host)}
                    aria-expanded={isOpen}
                    className="flex w-full items-center gap-3 px-4 py-3 text-left transition hover:bg-surface-850/70"
                  >
                    {isOpen ? (
                      <ChevronDown size={16} className="shrink-0 text-zinc-500" />
                    ) : (
                      <ChevronRight size={16} className="shrink-0 text-zinc-500" />
                    )}
                    {isOpen ? (
                      <FolderOpen size={17} className="shrink-0 text-accent" />
                    ) : (
                      <Folder size={17} className="shrink-0 text-accent/70" />
                    )}
                    <span className="truncate font-mono text-sm text-zinc-200">
                      {host}
                    </span>
                    <span className="ml-auto shrink-0 rounded-full border border-surface-700 bg-surface-850 px-2 py-0.5 text-[10px] text-zinc-500">
                      {paths.length} rutas · {hostCount(entries)} peticiones
                    </span>
                  </button>

                  {isOpen && (
                    <ul className="border-t border-surface-800/80">
                      {paths.map(([path, entry]) => (
                        <li key={path}>
                          <button
                            type="button"
                            onClick={() => openInProxy(host, path)}
                            className="group flex w-full items-center gap-3 border-b border-surface-800/50 px-4 py-2.5 pl-12 text-left transition last:border-b-0 hover:bg-accent/5"
                            title={`Ver ${host}${path} en Interceptación`}
                          >
                            <span className="truncate font-mono text-xs text-zinc-300 group-hover:text-accent">
                              {path}
                            </span>
                            <span className="ml-auto flex shrink-0 items-center gap-1.5">
                              {entry.methods.map((method) => (
                                <span
                                  key={method}
                                  className={`rounded border px-1.5 py-0.5 font-mono text-[9px] font-semibold uppercase tracking-wide ${badgeTone(
                                    method,
                                  )}`}
                                >
                                  {method}
                                </span>
                              ))}
                              <span className="min-w-12 text-right font-mono text-[10px] text-zinc-500">
                                {entry.count} req
                              </span>
                            </span>
                          </button>
                        </li>
                      ))}
                    </ul>
                  )}
                </section>
              );
            })}
          </div>
        )}
      </div>

      {crawlModalOpen && (
        <div
          className="fixed inset-0 z-50 grid place-items-center bg-black/75 p-4"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget && !crawlStarting) {
              setCrawlModalOpen(false);
            }
          }}
        >
          <form
            role="dialog"
            aria-modal="true"
            aria-labelledby="crawl-title"
            onSubmit={(event) => void submitCrawl(event)}
            className="w-full max-w-lg rounded-xl border border-accent/40 bg-surface-900 p-5 shadow-2xl"
          >
            <div className="flex items-start justify-between gap-3">
              <div>
                <h3
                  id="crawl-title"
                  className="flex items-center gap-2 text-base font-bold text-zinc-100"
                >
                  <Radar size={18} className="text-accent" />
                  Descubrir Rutas (Solo Crawler)
                </h3>
                <p className="mt-1 text-xs text-zinc-400">
                  Rastrea el sitio y guarda URLs y formularios en el Mapa de
                  rutas. No lanza ataques ni usa el Escáner Web.
                </p>
              </div>
              <button
                type="button"
                aria-label="Cerrar"
                onClick={() => setCrawlModalOpen(false)}
                disabled={crawlStarting}
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
                aria-label="URL objetivo del crawler"
                value={crawlUrl}
                onChange={(event) => setCrawlUrl(event.target.value)}
                placeholder="http://192.168.0.9:5000/"
                className="w-full rounded-lg border border-surface-700 bg-surface-950 px-3 py-2.5 font-mono text-sm text-zinc-100 outline-none placeholder:text-zinc-600 focus:border-accent"
              />
              <span className="block text-[10px] text-zinc-600">
                Debe incluir esquema http:// o https://. Solo se rastreará el
                host/puerto indicado.
              </span>
            </label>

            <div className="mt-4">
              <span className="mb-1.5 block text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-400">
                Límites del crawler
              </span>
              <CrawlLimitFields
                depth={crawlDepth}
                maxPages={crawlMaxPages}
                unlimited={crawlUnlimited}
                onDepthChange={setCrawlDepth}
                onMaxPagesChange={setCrawlMaxPages}
                onUnlimitedChange={setCrawlUnlimited}
              />
            </div>

            {crawlError && (
              <div
                role="alert"
                className="mt-3 rounded-lg border border-rose-900/60 bg-rose-950/30 px-3 py-2 text-xs text-rose-300"
              >
                {crawlError}
              </div>
            )}

            <div className="mt-5 flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={() => setCrawlModalOpen(false)}
                disabled={crawlStarting}
                className="rounded-lg border border-surface-700 px-3 py-2 text-xs text-zinc-300 transition hover:bg-surface-800 disabled:opacity-40"
              >
                Cancelar
              </button>
              <button
                type="submit"
                disabled={crawlStarting || !crawlUrl.trim()}
                className="flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-xs font-bold text-surface-950 transition hover:bg-accent-soft disabled:cursor-not-allowed disabled:opacity-40"
              >
                {crawlStarting ? (
                  <Loader2 size={14} className="animate-spin" />
                ) : (
                  <Radar size={14} />
                )}
                {crawlStarting ? "Iniciando…" : "Descubrir rutas"}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
