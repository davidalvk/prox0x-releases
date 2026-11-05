import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  ChevronDown,
  FileCode2,
  Globe,
  Loader2,
  Play,
  RefreshCw,
  Square,
  Tags,
  X,
} from "lucide-react";
import type { TemplateScanResult, TemplateScanStatus } from "../types";
import {
  fetchLatestTemplateScan,
  fetchTemplateInfo,
  fetchTemplateScanStatus,
  fetchTemplateTags,
  startTemplateScan,
  stopTemplateScan,
  updateNucleiTemplates,
} from "../lib/api";
import { DATA_TABLE, DATA_TABLE_HEAD } from "../lib/tableStyles";
import { useApp } from "../context/AppContext";
import { CrawlLimitFields } from "./CrawlLimitFields";
import { FlowDetailPanel } from "./FlowDetailPanel";
import { SplitPane } from "./SplitPane";

const SEVERITY_CLASSES: Record<string, string> = {
  critical: "border-rose-400/70 bg-rose-500/15 text-rose-200",
  high: "border-rose-500/60 bg-rose-950/40 text-rose-300",
  medium: "border-amber-500/60 bg-amber-950/40 text-amber-300",
  low: "border-cyan-500/50 bg-cyan-950/30 text-cyan-300",
  info: "border-surface-700 bg-surface-850 text-zinc-400",
  unknown: "border-surface-700 bg-surface-850 text-zinc-500",
};

function severityClass(severity: string): string {
  return SEVERITY_CLASSES[severity.toLowerCase()] ?? SEVERITY_CLASSES.unknown;
}

export function TemplateScanPanel() {
  const { currentProject } = useApp();
  const [url, setUrl] = useState("");
  const [selectedTags, setSelectedTags] = useState<string[]>(["cve"]);
  const [crawl, setCrawl] = useState(false);
  const [crawlDepth, setCrawlDepth] = useState(3);
  const [crawlMaxPages, setCrawlMaxPages] = useState(50);
  const [crawlUnlimited, setCrawlUnlimited] = useState(false);
  const [autoTech, setAutoTech] = useState(false);
  const [allWeb, setAllWeb] = useState(false);
  const [availableTags, setAvailableTags] = useState<string[]>([]);
  const [tagQuery, setTagQuery] = useState("");
  const [tagsOpen, setTagsOpen] = useState(false);
  const [tagsLoading, setTagsLoading] = useState(false);
  const [tagsError, setTagsError] = useState<string | null>(null);
  const [maxTemplates, setMaxTemplates] = useState(500);
  const [limitTouched, setLimitTouched] = useState(false);
  const [totalAvailable, setTotalAvailable] = useState<number | null>(null);
  const [infoLoading, setInfoLoading] = useState(true);
  const [infoError, setInfoError] = useState<string | null>(null);
  const [selectedResult, setSelectedResult] =
    useState<TemplateScanResult | null>(null);
  const [job, setJob] = useState<TemplateScanStatus | null>(null);
  const [starting, setStarting] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const tagBoxRef = useRef<HTMLDivElement>(null);

  const refreshTags = useCallback(async () => {
    setTagsLoading(true);
    setTagsError(null);
    try {
      const tags = await fetchTemplateTags();
      setAvailableTags([...tags].sort((left, right) => left.localeCompare(right)));
    } catch (err: unknown) {
      setTagsError(
        err instanceof Error ? err.message : "No se pudieron cargar los tags",
      );
    } finally {
      setTagsLoading(false);
    }
  }, []);

  const refreshInfo = useCallback(async () => {
    setInfoLoading(true);
    setInfoError(null);
    try {
      const info = await fetchTemplateInfo();
      setTotalAvailable(info.total_available);
    } catch (err: unknown) {
      setInfoError(
        err instanceof Error
          ? err.message
          : "No se pudo calcular el número de plantillas disponibles",
      );
    } finally {
      setInfoLoading(false);
    }
  }, []);

  const openTags = () => {
    if (autoTech) return;
    setTagsOpen(true);
    if (availableTags.length === 0 && !tagsLoading) {
      void refreshTags();
    }
  };

  useEffect(() => {
    if (!tagsOpen) return;
    const onPointerDown = (event: PointerEvent) => {
      if (!tagBoxRef.current?.contains(event.target as Node)) {
        setTagsOpen(false);
      }
    };
    window.addEventListener("pointerdown", onPointerDown);
    return () => window.removeEventListener("pointerdown", onPointerDown);
  }, [tagsOpen]);

  const toggleTag = (tag: string) => {
    setAllWeb(false);
    setSelectedTags((previous) =>
      previous.includes(tag)
        ? previous.filter((item) => item !== tag)
        : [...previous, tag],
    );
    setTagQuery("");
  };

  const toggleAllWeb = () => {
    if (allWeb) {
      setAllWeb(false);
      if (selectedTags.length === 0) setSelectedTags(["cve"]);
      return;
    }
    setAllWeb(true);
    setSelectedTags([]);
    setLimitTouched(false);
    setMaxTemplates(
      totalAvailable !== null
        ? Math.max(1, Math.min(2000, totalAvailable))
        : 2000,
    );
    setTagQuery("");
  };

  const filteredTags = useMemo(() => {
    const query = tagQuery.trim().toLowerCase();
    const matches = query
      ? availableTags.filter((tag) => tag.includes(query))
      : availableTags;
    return matches.slice(0, 200);
  }, [availableTags, tagQuery]);

  const loadLatest = useCallback(async () => {
    try {
      const latest = await fetchLatestTemplateScan();
      setJob(latest);
    } catch (err: unknown) {
      setError(
        err instanceof Error
          ? err.message
          : "No se pudo cargar el último escaneo de plantillas",
      );
    }
  }, []);

  useEffect(() => {
    setJob(null);
    setSelectedResult(null);
    setError(null);
    setNotice(null);
    void loadLatest();
    void refreshInfo();
  }, [loadLatest, refreshInfo, currentProject]);

  const scanId = job?.scan_id;
  const running = job?.status === "running";
  const limitInvalid =
    totalAvailable !== null && maxTemplates > totalAvailable;
  const limitMessage = limitInvalid
    ? `El límite no puede superar las ${totalAvailable?.toLocaleString(
        "es-ES",
      )} plantillas HTTP disponibles.`
    : infoError;

  useEffect(() => {
    setSelectedResult(null);
  }, [scanId]);

  useEffect(() => {
    if (totalAvailable === null) return;
    if (allWeb || !limitTouched) {
      if (maxTemplates > totalAvailable) {
        setMaxTemplates(Math.max(1, totalAvailable));
      }
    }
  }, [allWeb, limitTouched, maxTemplates, totalAvailable]);

  useEffect(() => {
    if (!scanId || !running) return;
    const timer = window.setInterval(() => {
      void fetchTemplateScanStatus(scanId)
        .then((next) => setJob(next))
        .catch((err: unknown) => {
          setError(
            err instanceof Error
              ? err.message
              : "No se pudo consultar el escaneo de plantillas",
          );
        });
    }, 1_000);
    return () => window.clearInterval(timer);
  }, [scanId, running]);

  const updateTemplates = async () => {
    setUpdating(true);
    setNotice(null);
    setError(null);
    try {
      const result = await updateNucleiTemplates();
      if (result.error) {
        setError(result.error);
      } else {
        await Promise.all([refreshTags(), refreshInfo()]);
        setNotice(
          `Plantillas actualizadas · ${result.templates} YAML · ${result.duration_ms} ms`,
        );
      }
    } catch (err: unknown) {
      setError(
        err instanceof Error
          ? err.message
          : "No se pudieron actualizar las plantillas",
      );
    } finally {
      setUpdating(false);
    }
  };

  const start = async () => {
    const target = url.trim();
    if (!target) {
      setError("Introduce una URL http(s) válida.");
      return;
    }
    if (limitInvalid) {
      setError(limitMessage ?? "El límite indicado no es válido.");
      return;
    }
    setStarting(true);
    setError(null);
    setNotice(null);
    try {
      const next = await startTemplateScan({
        url: target,
        tags: allWeb ? [] : selectedTags.length > 0 ? selectedTags : ["cve"],
        max_templates: maxTemplates,
        concurrency: 5,
        throttle_ms: 50,
        crawl,
        auto_tech: autoTech,
        max_depth: crawlUnlimited ? 0 : crawlDepth,
        max_urls: crawlUnlimited ? 0 : crawlMaxPages,
      });
      setJob(next);
    } catch (err: unknown) {
      setError(
        err instanceof Error
          ? err.message
          : "No se pudo iniciar el escaneo de plantillas",
      );
    } finally {
      setStarting(false);
    }
  };

  const stop = async () => {
    if (!scanId) return;
    setStopping(true);
    try {
      const next = await stopTemplateScan(scanId);
      setJob(next);
    } catch (err: unknown) {
      setError(
        err instanceof Error
          ? err.message
          : "No se pudo detener el escaneo de plantillas",
      );
    } finally {
      setStopping(false);
    }
  };

  const results = useMemo(
    () => (job?.results ?? []).slice().reverse(),
    [job?.results],
  );
  const crawling = job?.status === "running" && job.phase === "crawling";
  const detecting = job?.status === "running" && job.phase === "detecting";

  return (
    <div className="flex h-full min-h-0 flex-col bg-surface-950">
      <div className="flex flex-wrap items-end justify-between gap-3 border-b border-surface-800 px-5 py-3">
        <div>
          <h2 className="flex items-center gap-2 text-sm font-bold text-zinc-100">
            <FileCode2 size={16} className="text-cyan-300" />
            CVEs (Nuclei)
          </h2>
          <p className="mt-1 text-[11px] text-zinc-500">
            Motor compatible con un subconjunto de plantillas HTTP de Nuclei ·
            matchers status/word/regex · Auto-Tech opcional
          </p>
        </div>
        <button
          type="button"
          onClick={() => void updateTemplates()}
          disabled={updating || running}
          className="flex items-center gap-2 rounded-lg border border-cyan-400/50 bg-cyan-400/10 px-3 py-2 text-xs font-semibold text-cyan-200 transition hover:bg-cyan-400/20 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {updating ? (
            <Loader2 size={14} className="animate-spin" />
          ) : (
            <RefreshCw size={14} />
          )}
          {updating ? "Actualizando…" : "Actualizar Plantillas"}
        </button>
      </div>

      <div className="border-b border-surface-800 bg-surface-900/30 px-5 py-3">
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-64 flex-[2] space-y-1.5">
            <div className="flex items-center justify-between gap-2">
              <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
                URL objetivo
              </span>
              <label className="flex items-center gap-1.5 text-[10px] font-semibold text-zinc-400">
                <input
                  type="checkbox"
                  checked={crawl}
                  onChange={(event) => setCrawl(event.target.checked)}
                  disabled={running}
                  className="h-3.5 w-3.5 accent-cyan-400 disabled:cursor-not-allowed"
                />
                Full Crawl + CVEs
              </label>
            </div>
            <input
              type="url"
              aria-label="URL objetivo"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              placeholder="https://objetivo.local"
              className="w-full rounded-lg border border-surface-700 bg-surface-950 px-3 py-2 font-mono text-xs text-zinc-200 outline-none placeholder:text-zinc-600 focus:border-accent"
            />
            {crawl && (
              <CrawlLimitFields
                compact
                depth={crawlDepth}
                maxPages={crawlMaxPages}
                unlimited={crawlUnlimited}
                onDepthChange={setCrawlDepth}
                onMaxPagesChange={setCrawlMaxPages}
                onUnlimitedChange={setCrawlUnlimited}
              />
            )}
          </div>

          <div className="min-w-64 flex-1 space-y-1.5">
            <span className="flex flex-wrap items-center justify-between gap-1 text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
              <span className="flex items-center gap-1">
                <Tags size={11} />
                Tags
              </span>
              <label className="flex items-center gap-1.5 text-[10px] font-semibold normal-case tracking-normal text-cyan-300">
                <input
                  type="checkbox"
                  aria-label="Escaneo Inteligente (Auto-Tech)"
                  checked={autoTech}
                  disabled={running}
                  onChange={(event) => {
                    setAutoTech(event.target.checked);
                    if (event.target.checked) setTagsOpen(false);
                  }}
                  className="h-3.5 w-3.5 accent-cyan-400 disabled:cursor-not-allowed"
                />
                🤖 Auto-Tech
              </label>
            </span>
            <div ref={tagBoxRef} className="relative">
              <div
                aria-disabled={autoTech}
                className={[
                  "flex min-h-9 flex-wrap items-center gap-1.5 rounded-lg border border-surface-700 bg-surface-950 px-2 py-1.5 focus-within:border-accent",
                  autoTech
                    ? "cursor-not-allowed opacity-50"
                    : "",
                ].join(" ")}
                onClick={openTags}
              >
                {allWeb && (
                  <span className="inline-flex items-center gap-1 rounded border border-amber-500/50 bg-amber-950/40 px-1.5 py-0.5 font-mono text-[10px] text-amber-200">
                    <Globe size={10} />
                    Todos los ataques Web
                    <button
                      type="button"
                      aria-label="Quitar filtro Todos los ataques Web"
                      disabled={autoTech}
                      onClick={(event) => {
                        event.stopPropagation();
                        toggleAllWeb();
                      }}
                      className="rounded text-amber-300/70 transition hover:bg-amber-400/20 hover:text-amber-100 disabled:cursor-not-allowed"
                    >
                      <X size={10} />
                    </button>
                  </span>
                )}
                {selectedTags.map((tag) => (
                  <span
                    key={tag}
                    className="inline-flex items-center gap-1 rounded border border-cyan-500/40 bg-cyan-950/40 px-1.5 py-0.5 font-mono text-[10px] text-cyan-200"
                  >
                    {tag}
                    <button
                      type="button"
                      aria-label={`Quitar tag ${tag}`}
                      disabled={autoTech}
                      onClick={(event) => {
                        event.stopPropagation();
                        setSelectedTags((previous) =>
                          previous.filter((item) => item !== tag),
                        );
                      }}
                      className="rounded text-cyan-300/70 transition hover:bg-cyan-400/20 hover:text-cyan-100 disabled:cursor-not-allowed"
                    >
                      <X size={10} />
                    </button>
                  </span>
                ))}
                <input
                  aria-label="Tags"
                  value={tagQuery}
                  disabled={autoTech}
                  onChange={(event) => setTagQuery(event.target.value)}
                  onFocus={autoTech ? undefined : openTags}
                  placeholder={
                    autoTech
                      ? "Tags automáticos"
                      : allWeb
                        ? "Añadir tags específicos…"
                        : selectedTags.length
                          ? "Añadir tag…"
                          : "cve, rce…"
                  }
                  className="min-w-20 flex-1 bg-transparent py-0.5 font-mono text-xs text-zinc-200 outline-none placeholder:text-zinc-600 disabled:cursor-not-allowed"
                />
                <ChevronDown size={13} className="shrink-0 text-zinc-600" />
              </div>

              {tagsOpen && !autoTech && (
                <div
                  role="listbox"
                  aria-label="Tags disponibles"
                  className="absolute z-40 mt-1 max-h-64 w-full overflow-auto rounded-lg border border-surface-700 bg-surface-900 py-1 shadow-2xl"
                >
                  <button
                    type="button"
                    role="option"
                    aria-selected={allWeb}
                    onClick={toggleAllWeb}
                    className={[
                      "flex w-full items-center justify-between gap-2 px-3 py-2 text-left text-[11px] font-semibold transition",
                      allWeb
                        ? "bg-amber-400/10 text-amber-200"
                        : "text-amber-200/90 hover:bg-surface-850 hover:text-amber-100",
                    ].join(" ")}
                  >
                    <span className="flex items-center gap-1.5">
                      <Globe size={12} />
                      Todos los ataques Web (Filtro automático HTTP)
                    </span>
                    {allWeb && <Check size={12} />}
                  </button>
                  <div className="border-t border-surface-800" />
                  {tagsLoading ? (
                    <div className="flex items-center gap-2 px-3 py-2 text-[11px] text-zinc-500">
                      <Loader2 size={12} className="animate-spin text-accent" />
                      Cargando tags…
                    </div>
                  ) : tagsError ? (
                    <div className="px-3 py-2 text-[11px] text-rose-300">
                      {tagsError}
                    </div>
                  ) : filteredTags.length === 0 ? (
                    <div className="px-3 py-2 text-[11px] text-zinc-600">
                      No hay tags que coincidan.
                    </div>
                  ) : (
                    filteredTags.map((tag) => {
                      const selected = selectedTags.includes(tag);
                      return (
                        <button
                          key={tag}
                          type="button"
                          role="option"
                          aria-selected={selected}
                          onClick={() => toggleTag(tag)}
                          className={[
                            "flex w-full items-center justify-between px-3 py-1.5 text-left font-mono text-[11px] transition",
                            selected
                              ? "bg-cyan-400/10 text-cyan-200"
                              : "text-zinc-300 hover:bg-surface-850 hover:text-zinc-100",
                          ].join(" ")}
                        >
                          <span>{tag}</span>
                          {selected && <Check size={12} />}
                        </button>
                      );
                    })
                  )}
                  {!tagsLoading && !tagsError && availableTags.length > 0 && (
                    <p className="border-t border-surface-800 px-3 py-1.5 text-[10px] text-zinc-600">
                      {availableTags.length.toLocaleString("es-ES")} tags HTTP
                      disponibles
                      {availableTags.length > filteredTags.length && tagQuery
                        ? ` · mostrando ${filteredTags.length}`
                        : ""}
                    </p>
                  )}
                </div>
              )}
            </div>
            <span
              className={[
                "block text-[10px]",
                autoTech ? "text-cyan-300/80" : "text-zinc-600",
              ].join(" ")}
            >
              {autoTech
                ? "Se detectará la tecnología del objetivo y se lanzarán solo las plantillas relevantes (WordPress, Apache, Jira, etc.)."
                : allWeb
                  ? "Filtro automático: solo plantillas HTTP ejecutables."
                  : "Selecciona varios tags. Por defecto: cve."}
            </span>
          </div>

          <label className="w-40 space-y-1.5">
            <span className="flex items-baseline justify-between gap-1 text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
              Límite
              <span
                className={[
                  "font-mono text-[9px] normal-case tracking-normal",
                  limitInvalid ? "text-rose-300" : "text-zinc-600",
                ].join(" ")}
              >
                {infoLoading
                  ? "(calculando…)"
                  : totalAvailable !== null
                    ? `(Máx: ${totalAvailable.toLocaleString("es-ES")})`
                    : "(Máx: —)"}
              </span>
            </span>
            <input
              type="number"
              min={1}
              max={totalAvailable ?? 5000}
              value={maxTemplates}
              aria-invalid={limitInvalid}
              aria-describedby={limitMessage ? "template-limit-error" : undefined}
              onChange={(event) => {
                setLimitTouched(true);
                setMaxTemplates(Number(event.target.value) || 1);
              }}
              className={[
                "w-full rounded-lg border bg-surface-950 px-3 py-2 font-mono text-xs text-zinc-200 outline-none",
                limitInvalid
                  ? "border-rose-500 focus:border-rose-400"
                  : "border-surface-700 focus:border-accent",
              ].join(" ")}
            />
            {limitMessage && (
              <span
                id="template-limit-error"
                role="alert"
                className="block text-[10px] leading-snug text-rose-300"
              >
                {limitMessage}
              </span>
            )}
          </label>

          <button
            type="button"
            onClick={() => void start()}
            disabled={
              starting || running || !url.trim() || limitInvalid
            }
            className="flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-xs font-bold text-surface-950 transition hover:bg-accent-soft disabled:cursor-not-allowed disabled:opacity-40"
          >
            {starting ? (
              <Loader2 size={14} className="animate-spin" />
            ) : (
              <Play size={14} />
            )}
            {starting ? "Iniciando…" : "Escanear plantillas"}
          </button>

          {running && (
            <button
              type="button"
              onClick={() => void stop()}
              disabled={stopping}
              className="flex items-center gap-2 rounded-lg border border-rose-500/60 bg-rose-950/40 px-3 py-2 text-xs font-semibold text-rose-200 transition hover:bg-rose-500/20 disabled:opacity-40"
            >
              {stopping ? (
                <Loader2 size={14} className="animate-spin" />
              ) : (
                <Square size={12} />
              )}
              Detener
            </button>
          )}
        </div>

        {allWeb && (
          <div
            role="alert"
            className="mt-3 flex items-start gap-2 rounded-lg border border-amber-500/50 bg-amber-950/30 px-3 py-2 text-xs text-amber-200"
          >
            <AlertTriangle size={14} className="mt-0.5 shrink-0" />
            <span>
              Atención: Se ejecutarán todas las plantillas HTTP. Esto puede
              tardar mucho y saturar el objetivo.
            </span>
          </div>
        )}

        {crawl && (
          <div className="mt-3 flex items-start gap-2 rounded-lg border border-cyan-500/50 bg-cyan-950/30 px-3 py-2 text-xs text-cyan-200">
            <Globe size={14} className="mt-0.5 shrink-0" />
            <span>
              El Crawler descubrirá rutas primero y luego lanzará las
              plantillas sobre todas ellas. Esto puede tardar mucho.
            </span>
          </div>
        )}

        {notice && (
          <div
            role="status"
            className="mt-3 flex items-center gap-2 rounded-lg border border-emerald-900/60 bg-emerald-950/30 px-3 py-2 text-xs text-emerald-300"
          >
            <CheckCircle2 size={14} />
            {notice}
          </div>
        )}
        {error && (
          <div
            role="alert"
            className="mt-3 flex items-center gap-2 rounded-lg border border-rose-900/60 bg-rose-950/30 px-3 py-2 text-xs text-rose-300"
          >
            <AlertTriangle size={14} />
            {error}
          </div>
        )}
      </div>

      {job && (
        <div className="border-b border-surface-800 px-5 py-3">
          <div className="flex flex-wrap items-center gap-3 text-[11px] text-zinc-500">
            <span
              className={[
                "font-semibold",
                job.status === "failed"
                  ? "text-rose-300"
                  : job.status === "completed"
                    ? "text-emerald-300"
                    : "text-accent",
              ].join(" ")}
            >
              {job.status === "failed"
                ? `Escaneo fallido: ${job.error ?? "error desconocido"}`
                : job.status === "completed"
                  ? `Escaneo completado · ${job.matches} coincidencias`
                  : job.phase === "detecting"
                    ? "Detectando tecnología del objetivo…"
                    : job.phase === "loading"
                      ? "Cargando plantillas compatibles…"
                      : job.phase === "crawling"
                        ? `Fase 1: Rastreando el dominio... (${job.urls_found} URLs encontradas)`
                        : job.crawl
                          ? `Fase 2: Lanzando plantillas Nuclei... (${job.attacks_run} de ${job.attacks_total} ataques)`
                          : "Ejecutando plantillas…"}
            </span>
            <span className="font-mono">
              {job.crawl
                ? `${job.urls_scanned}/${job.urls_total} URLs · ${job.attacks_run}/${job.attacks_total} ataques`
                : `${job.templates_run}/${job.templates_total} plantillas`}{" "}
              · {job.templates_skipped} omitidas · {job.matches} coincidencias ·{" "}
              {job.errors} errores
            </span>
            <span className="truncate font-mono text-zinc-600">
              {job.url} · tags:{" "}
              {job.tags.length ? job.tags.join(", ") : "todos los HTTP"}
              {job.crawl ? ` · ${job.urls_found} URLs descubiertas` : ""}
            </span>
            {job.auto_tech && job.detected_technologies.length > 0 && (
              <span className="font-mono text-cyan-300/80">
                Auto-Tech: {job.detected_technologies.join(", ")} · tags:{" "}
                {job.effective_tags.length
                  ? job.effective_tags.join(", ")
                  : "todos los HTTP"}
              </span>
            )}
            {job.auto_tech && job.tech_error && (
              <span className="font-mono text-amber-300">
                Auto-Tech: {job.tech_error}
              </span>
            )}
          </div>
          {job.status === "running" && (
            <div
              role="progressbar"
              aria-label="Progreso del escaneo de plantillas"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={crawling || detecting ? 100 : job.progress}
              className="mt-2 h-2 overflow-hidden rounded-full bg-surface-800"
            >
              <div
                className={[
                  "h-full rounded-full transition-[width] duration-300",
                  crawling || detecting
                    ? "animate-pulse bg-amber-400"
                    : "bg-cyan-400",
                ].join(" ")}
                style={{
                  width: `${crawling || detecting ? 100 : Math.max(2, job.progress)}%`,
                }}
              />
            </div>
          )}
          {job.error && job.status === "completed" && (
            <p className="mt-2 text-[11px] text-amber-300">{job.error}</p>
          )}
        </div>
      )}

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        {!job || results.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-3 overflow-auto text-center text-zinc-500">
            <FileCode2 size={34} className="text-zinc-700" />
            <div>
              <p className="text-sm text-zinc-400">
                {job?.status === "running"
                  ? "Buscando CVEs con plantillas Nuclei…"
                  : "Sin coincidencias todavía"}
              </p>
              <p className="mt-1 max-w-md text-xs text-zinc-600">
                Actualiza las plantillas, indica una URL y un filtro de tags
                como <code>cve,log4j</code>, o elige{" "}
                <strong>Todos los ataques Web</strong> para ejecutar todas las
                plantillas HTTP compatibles.
              </p>
            </div>
          </div>
        ) : (
          <SplitPane
            orientation="vertical"
            label="Redimensionar resultados y detalle del hallazgo"
            initial={25}
            min={20}
            max={80}
            first={
              <div className="h-full min-h-0 overflow-auto">
                <table className={DATA_TABLE}>
                  <thead className={DATA_TABLE_HEAD}>
                    <tr className="border-b border-surface-800">
                      <th className="w-40 px-4 py-2.5 font-medium">
                        Template ID
                      </th>
                      <th className="w-56 px-2 py-2.5 font-medium">Nombre</th>
                      <th className="w-20 px-2 py-2.5 font-medium">
                        Severidad
                      </th>
                      <th className="px-2 py-2.5 font-medium">URL</th>
                      <th className="w-32 px-2 py-2.5 font-medium">Matcher</th>
                      <th className="w-80 px-4 py-2.5 font-medium">
                        Evidencia
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.map((result: TemplateScanResult) => {
                      const selected =
                        selectedResult?.flow_id === result.flow_id;
                      return (
                        <tr
                          key={`${result.template_id}-${result.flow_id}`}
                          onClick={() => setSelectedResult(result)}
                          aria-selected={selected}
                          title="Ver la petición y respuesta exactas del hallazgo"
                          className={[
                            "cursor-pointer border-b border-surface-800/70 align-top transition",
                            selected
                              ? "bg-cyan-400/10"
                              : "hover:bg-surface-850",
                          ].join(" ")}
                        >
                          <td
                            className="truncate px-4 py-2.5 font-semibold text-cyan-300"
                            title={result.template_id}
                          >
                            {result.template_id}
                          </td>
                          <td
                            className="truncate px-2 py-2.5 text-zinc-300"
                            title={result.name}
                          >
                            {result.name}
                          </td>
                          <td className="px-2 py-2.5">
                            <span
                              className={[
                                "rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide",
                                severityClass(result.severity),
                              ].join(" ")}
                            >
                              {result.severity}
                            </span>
                          </td>
                          <td
                            className="truncate px-2 py-2.5 text-zinc-400"
                            title={result.url}
                          >
                            {result.url}
                          </td>
                          <td
                            className="truncate px-2 py-2.5 text-zinc-400"
                            title={result.matcher}
                          >
                            {result.matcher}
                          </td>
                          <td
                            className="truncate px-4 py-2.5 text-rose-300/90"
                            title={result.evidence}
                          >
                            {result.evidence}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            }
            second={
              selectedResult ? (
                <FlowDetailPanel
                  flowId={selectedResult.flow_id}
                  onClose={() => setSelectedResult(null)}
                  previewLabel={`Nuclei · ${selectedResult.template_id}`}
                  evidence={selectedResult.evidence}
                  vulnerability={selectedResult.name}
                  affectedUrl={selectedResult.url}
                  attackParameter="template"
                  attackPayload={selectedResult.template_id}
                />
              ) : (
                <div className="flex h-full flex-col items-center justify-center gap-2 border-t border-surface-800 bg-surface-900/40 text-center text-zinc-600">
                  <FileCode2 size={26} className="text-zinc-700" />
                  <p className="text-[10px] uppercase tracking-[0.18em] text-zinc-500">
                    Detalle del hallazgo
                  </p>
                  <p className="max-w-md text-[11px]">
                    Haz clic en una coincidencia para ver la petición exacta
                    del template y la respuesta del servidor.
                  </p>
                </div>
              )
            }
          />
        )}
      </div>
    </div>
  );
}
