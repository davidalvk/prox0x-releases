import { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowUpRight,
  Check,
  ClipboardCopy,
  Crosshair,
  Download,
  Loader2,
  Repeat2,
  Target,
  Wand2,
  X,
} from "lucide-react";
import type { FlowRecord, MessageRecord } from "../types";
import {
  addScopeHost,
  decodeMessage,
  fetchFlow,
  flowHost,
  flowPath,
  formatBody,
  formatMs,
  formatTime,
  parseRawMessage,
  statusTone,
} from "../lib/api";
import { downloadBytes, formatBytes, suggestDownloadName } from "../lib/binary";
import { writeClipboard } from "../lib/clipboard";
import {
  buildCurlFromFlow,
  buildCurlFromRaw,
  buildFetchFromFlow,
} from "../lib/curl";
import { CurlButton } from "./CurlButton";
import { FetchButton } from "./FetchButton";
import { HelpTooltip } from "./HelpTooltip";
import { SyntaxView } from "./SyntaxView";
import { useApp } from "../context/AppContext";

interface FlowDetailPanelProps {
  flowId: number;
  onClose: () => void;
  /** Petición modificada para previsualizaciones del escáner activo. */
  requestRaw?: string | null;
  /** Respuesta asociada a la petición previsualizada. */
  responseRaw?: string | null;
  /** Etiqueta corta que describe la previsualización. */
  previewLabel?: string;
  /** Texto de evidencia del hallazgo. */
  evidence?: string;
  /** Fragmento exacto que disparó la evidencia. */
  evidenceMatch?: string | null;
  /** Offset opcional del fragmento dentro del cuerpo. */
  evidenceOffset?: number | null;
  /** Tipo de vulnerabilidad para el Markdown de evidencia. */
  vulnerability?: string;
  /** URL afectada por el ataque. */
  affectedUrl?: string;
  /** Parámetro atacado. */
  attackParameter?: string;
  /** Payload exacto del ataque. */
  attackPayload?: string;
  /** Oculta acciones que operarían sobre el flujo original. */
  readOnlyPreview?: boolean;
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function flowBaseUrl(flow: FlowRecord): string {
  const scheme = flow.service.secure ? "https" : "http";
  const defaultPort = flow.service.secure ? 443 : 80;
  const authority =
    flow.service.port === defaultPort
      ? flow.service.host
      : `${flow.service.host}:${flow.service.port}`;
  const origin = `${scheme}://${authority}/`;
  const target = flow.request.target ?? "/";
  try {
    const url = new URL(target, origin);
    const directory = url.pathname.endsWith("/")
      ? url.pathname
      : `${url.pathname.slice(0, url.pathname.lastIndexOf("/") + 1)}`;
    return `${url.origin}${directory}`;
  } catch {
    return origin;
  }
}

function triggerDownload(url: string): void {
  const link = document.createElement("a");
  link.href = url;
  link.download = "";
  document.body.appendChild(link);
  link.click();
  link.remove();
}

function LargeBodyNotice({
  flowId,
  message,
  kind,
}: {
  flowId: number;
  message: MessageRecord;
  kind: "request" | "response";
}) {
  const href =
    message.download_url ?? `/api/flows/${flowId}/download?message=${kind}`;
  return (
    <div
      data-testid="body-too-large"
      className="rounded-lg border border-amber-500/40 bg-amber-950/20 p-4 text-xs text-amber-200"
    >
      <p className="font-semibold">
        El cuerpo es demasiado grande para mostrarlo en pantalla.
      </p>
      <p className="mt-1 text-amber-300/80">
        Tamaño aproximado: {formatBytes(message.size ?? 0)}. Usa el botón
        «Descargar archivo» para guardarlo en disco.
      </p>
      <a
        href={href}
        download
        className="mt-3 inline-flex items-center gap-2 rounded-lg border border-amber-400/50 bg-amber-400/10 px-3 py-2 font-semibold text-amber-200 transition hover:bg-amber-400/20"
      >
        <Download size={14} />
        Descargar archivo
      </a>
    </div>
  );
}

export function FlowDetailPanel({
  flowId,
  onClose,
  requestRaw,
  responseRaw,
  previewLabel,
  evidence,
  evidenceMatch,
  evidenceOffset,
  vulnerability,
  affectedUrl,
  attackParameter,
  attackPayload,
  readOnlyPreview = false,
}: FlowDetailPanelProps) {
  const { sendToRepeater, sendToIntruder, notifyScopeChanged } = useApp();
  const [flow, setFlow] = useState<FlowRecord | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [requestPercent, setRequestPercent] = useState(50);
  const [dragging, setDragging] = useState(false);
  const [scopeBusy, setScopeBusy] = useState(false);
  const [scopeNotice, setScopeNotice] = useState<{
    kind: "ok" | "error";
    text: string;
  } | null>(null);
  const [mdCopied, setMdCopied] = useState(false);
  const mdTimer = useRef<number | undefined>(undefined);
  const splitRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const controller = new AbortController();
    setFlow(null);
    setLoading(true);
    setError(null);
    setScopeNotice(null);
    fetchFlow(flowId, controller.signal)
      .then((data) => {
        if (!controller.signal.aborted) setFlow(data);
      })
      .catch((err: unknown) => {
        if (
          controller.signal.aborted ||
          (err as { name?: string } | null)?.name === "AbortError"
        ) {
          return;
        }
        setError(err instanceof Error ? err.message : "No se pudo cargar el flujo");
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [flowId]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  useEffect(() => {
    if (!scopeNotice) return;
    const timer = window.setTimeout(() => setScopeNotice(null), 3500);
    return () => window.clearTimeout(timer);
  }, [scopeNotice]);

  useEffect(
    () => () => {
      if (mdTimer.current !== undefined) window.clearTimeout(mdTimer.current);
    },
    [],
  );

  const addCurrentHostToScope = async () => {
    if (!flow) return;
    setScopeBusy(true);
    setScopeNotice(null);
    try {
      const result = await addScopeHost(flow.service.host);
      setScopeNotice({
        kind: "ok",
        text: result.added
          ? "Host añadido al alcance"
          : "El host ya estaba en el alcance",
      });
      notifyScopeChanged();
    } catch (err: unknown) {
      setScopeNotice({
        kind: "error",
        text:
          err instanceof Error
            ? err.message
            : "No se pudo añadir el host al Alcance",
      });
    } finally {
      setScopeBusy(false);
    }
  };

  const copyEvidenceMarkdown = async () => {
    const markdown = [
      `**Vulnerabilidad:** ${vulnerability ?? previewLabel ?? "—"}`,
      `**URL:** ${affectedUrl ?? (flow ? flowPath(flow) : "—")}`,
      `**Parámetro:** ${attackParameter ?? "—"}`,
      `**Payload:** ${attackPayload ?? "—"}`,
      `**Evidencia:** ${evidence ?? "—"}`,
    ].join("\n");
    try {
      await writeClipboard(markdown);
      setMdCopied(true);
      if (mdTimer.current !== undefined) window.clearTimeout(mdTimer.current);
      mdTimer.current = window.setTimeout(() => setMdCopied(false), 2000);
    } catch {
      setScopeNotice({
        kind: "error",
        text: "No se pudo copiar la evidencia al portapapeles",
      });
    }
  };

  useEffect(() => {
    if (!dragging) return;
    const onMove = (event: PointerEvent) => {
      const rect = splitRef.current?.getBoundingClientRect();
      if (!rect) return;
      const percent = ((event.clientX - rect.left) / rect.width) * 100;
      setRequestPercent(clamp(percent, 25, 75));
    };
    const stop = () => setDragging(false);
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", stop);
    window.addEventListener("pointercancel", stop);
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
    return () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", stop);
      window.removeEventListener("pointercancel", stop);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
  }, [dragging]);

  const hasPreview = Boolean(requestRaw || responseRaw);
  const requestView = useMemo(
    () =>
      hasPreview
        ? requestRaw
          ? parseRawMessage(requestRaw)
          : null
        : flow
          ? decodeMessage(flow.final_request ?? flow.request)
          : null,
    [flow, hasPreview, requestRaw],
  );
  const responseView = useMemo(
    () =>
      hasPreview
        ? responseRaw
          ? parseRawMessage(responseRaw)
          : null
        : flow
          ? decodeMessage(flow.response)
          : null,
    [flow, hasPreview, responseRaw],
  );
  const requestRecord = hasPreview
    ? null
    : (flow?.final_request ?? flow?.request ?? null);
  const responseRecord = hasPreview ? null : (flow?.response ?? null);
  const htmlBaseUrl = useMemo(
    () => (flow ? flowBaseUrl(flow) : undefined),
    [flow],
  );
  const responseDownloadName = useMemo(
    () =>
      responseView
        ? suggestDownloadName(
            responseView.contentType,
            responseView.headers,
            `prox0x-flow-${flowId}-response`,
          )
        : `prox0x-flow-${flowId}-response.bin`,
    [responseView, flowId],
  );
  const requestDownloadName = useMemo(
    () =>
      requestView
        ? suggestDownloadName(
            requestView.contentType,
            requestView.headers,
            `prox0x-flow-${flowId}-request`,
          )
        : `prox0x-flow-${flowId}-request.bin`,
    [requestView, flowId],
  );
  const previewResponseStatus = useMemo(() => {
    if (!hasPreview || !responseView) return undefined;
    const match = responseView.startLine.match(/^HTTP\/[\d.]+\s+(\d{3})/);
    return match ? Number(match[1]) : undefined;
  }, [hasPreview, responseView]);
  const responseStatus = hasPreview
    ? previewResponseStatus
    : flow?.response?.status;
  const dropped = flow?.dropped === true || flow?.status === "DROPPED";
  const curlCommand = useMemo(
    () => (flow ? buildCurlFromFlow(flow) : ""),
    [flow],
  );
  const fetchCommand = useMemo(
    () => (flow ? buildFetchFromFlow(flow) : ""),
    [flow],
  );
  const previewCurlCommand = useMemo(
    () =>
      requestRaw && flow ? buildCurlFromRaw(requestRaw, flow.service) : "",
    [flow, requestRaw],
  );
  const responseDisplayBody = useMemo(
    () =>
      responseView
        ? formatBody(responseView.body, responseView.contentType)
        : "",
    [responseView],
  );
  const evidenceFound = useMemo(() => {
    if (!evidenceMatch || !responseDisplayBody) return false;
    return responseDisplayBody
      .toLowerCase()
      .includes(evidenceMatch.toLowerCase());
  }, [evidenceMatch, responseDisplayBody]);

  return (
    <section
      className="flex h-full min-h-0 flex-col border-t border-surface-800 bg-surface-900/60"
      aria-label={`Detalle del flujo ${flowId}`}
    >
      <header className="flex flex-wrap items-start justify-between gap-3 border-b border-surface-800 px-4 py-2.5">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.18em] text-zinc-500">
            <span className="font-mono text-accent">#{flowId}</span>
            <span>·</span>
            <span>{flow ? formatTime(flow.at) : "cargando"}</span>
            {flow && (
              <span className={dropped ? "text-rose-400" : statusTone(responseStatus)}>
                {dropped ? "DROPPED" : (responseStatus ?? "sin respuesta")}
              </span>
            )}
            {flow?.modified_by_rule && (
              <span
                data-testid="modified-by-rule-badge"
                title="Modificado por regla de Transformación"
                className="inline-flex items-center gap-1 rounded border border-cyan-400/40 bg-cyan-950/40 px-1.5 py-0.5 text-[9px] font-semibold text-cyan-300"
              >
                <Wand2 size={10} />
                Modificado por regla
              </span>
            )}
            {previewLabel && (
              <span className="rounded border border-amber-400/40 bg-amber-950/40 px-1.5 py-0.5 text-[9px] font-semibold text-amber-300">
                {previewLabel}
              </span>
            )}
          </div>
          <h2 className="mt-0.5 truncate font-mono text-xs text-zinc-100">
            {flow ? (
              <>
                <span className="text-accent">{flow.request.method}</span>{" "}
                <span>{flowPath(flow)}</span>
                <span className="ml-2 text-zinc-600">
                  {flowHost(flow)} · TTFB {formatMs(flow.timing?.ttfb_ms)} · total{" "}
                  {formatMs(flow.timing?.total_ms)}
                </span>
              </>
            ) : (
              "Detalle del flujo"
            )}
          </h2>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {flow && !readOnlyPreview && (
            <>
              <div className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => {
                    sendToRepeater(flow.id);
                  }}
                  className="flex items-center gap-2 rounded-lg bg-accent px-3 py-2 text-xs font-semibold text-surface-950 transition hover:bg-accent-soft"
                >
                  <Repeat2 size={14} />
                  Enviar a Reenvío
                </button>
                <HelpTooltip
                  label="Reenvío"
                  text="Copia esta petición y la manda al módulo de Reenvío para editarla."
                />
              </div>
              <div className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => {
                    sendToIntruder(flow.id);
                  }}
                  className="flex items-center gap-2 rounded-lg border border-accent/40 bg-accent/10 px-3 py-2 text-xs font-semibold text-accent transition hover:bg-accent/20"
                >
                  <Crosshair size={14} />
                  Enviar a Intrusión
                </button>
                <HelpTooltip
                  label="Intrusión"
                  text="Manda esta petición al módulo de Intrusión para usar diccionarios."
                />
              </div>
              <div className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => void addCurrentHostToScope()}
                  disabled={scopeBusy}
                  className="flex items-center gap-2 rounded-lg border border-cyan-400/40 bg-cyan-950/30 px-3 py-2 text-xs font-semibold text-cyan-300 transition hover:border-accent hover:text-accent disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {scopeBusy ? (
                    <Loader2 size={14} className="animate-spin" />
                  ) : (
                    <Target size={14} />
                  )}
                  Añadir al Alcance
                </button>
                <HelpTooltip
                  label="Añadir al Alcance"
                  text="Añade el host de esta petición a las reglas del Alcance."
                />
              </div>
              <CurlButton command={curlCommand} />
              <FetchButton command={fetchCommand} />
            </>
          )}
          {flow && hasPreview && requestRaw && (
            <>
              <div className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => sendToRepeater(flow.id, requestRaw)}
                  className="flex items-center gap-2 rounded-lg bg-accent px-3 py-2 text-xs font-semibold text-surface-950 transition hover:bg-accent-soft"
                >
                  <Repeat2 size={14} />
                  Enviar a Reenvío
                </button>
                <HelpTooltip
                  label="Enviar a Reenvío"
                  text="Abre esta petición exacta, con el payload del ataque, en Reenvío."
                />
              </div>
              <CurlButton command={previewCurlCommand} />
              {evidence && (
                <button
                  type="button"
                  onClick={() => void copyEvidenceMarkdown()}
                  className="flex items-center gap-2 rounded-lg border border-surface-700 bg-surface-850 px-3 py-2 text-xs text-zinc-300 transition hover:border-surface-600 hover:text-zinc-100"
                >
                  {mdCopied ? (
                    <Check size={14} className="text-emerald-400" />
                  ) : (
                    <ClipboardCopy size={14} className="text-accent" />
                  )}
                  {mdCopied ? "¡Copiado!" : "Copiar Evidencia (MD)"}
                </button>
              )}
            </>
          )}
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-surface-700 p-2 text-zinc-400 transition hover:border-surface-600 hover:text-zinc-100"
            aria-label="Cerrar detalle"
            title="Cerrar detalle"
          >
            <X size={15} />
          </button>
        </div>
      </header>

      {scopeNotice && (
        <div
          role="status"
          className={[
            "border-b px-4 py-1.5 text-[11px]",
            scopeNotice.kind === "ok"
              ? "border-emerald-900/60 bg-emerald-950/30 text-emerald-300"
              : "border-rose-900/60 bg-rose-950/30 text-rose-300",
          ].join(" ")}
        >
          {scopeNotice.text}
        </div>
      )}

      {evidence && (
        <div className="flex flex-wrap items-center gap-2 border-b border-amber-500/30 bg-amber-950/20 px-4 py-1.5 text-[11px] text-amber-200">
          <Crosshair size={12} className="shrink-0 text-amber-300" />
          <span className="min-w-0 flex-1 truncate" title={evidence}>
            {evidence}
          </span>
          {evidenceMatch ? (
            <span
              className={[
                "shrink-0 rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide",
                evidenceFound
                  ? "border-amber-400/60 bg-amber-400/15 text-amber-200"
                  : "border-surface-600 bg-surface-950/40 text-zinc-500",
              ].join(" ")}
            >
              {evidenceFound
                ? "Evidencia encontrada aquí ↓"
                : "Sin coincidencia literal"}
            </span>
          ) : (
            <span className="shrink-0 rounded border border-cyan-500/40 bg-cyan-950/30 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide text-cyan-300">
              Evidencia temporal / boolean
            </span>
          )}
        </div>
      )}

      {loading && (
        <div className="flex flex-1 flex-col items-center justify-center gap-1 text-zinc-500">
          <span className="flex items-center">
            <Loader2 size={20} className="mr-2 animate-spin text-accent" />
            Cargando petición #{flowId}…
          </span>
          <span className="text-[11px] text-zinc-600">
            Puedes hacer clic en otra fila para cancelar.
          </span>
        </div>
      )}

      {!loading && error && (
        <div className="m-4 rounded-lg border border-rose-900/60 bg-rose-950/30 p-4 text-sm text-rose-300">
          {error}
        </div>
      )}

      {!loading && flow && !error && (
        <div ref={splitRef} className="flex min-h-0 flex-1">
          <section
            className="flex min-w-0 flex-col overflow-hidden"
            style={{ flexGrow: requestPercent, flexBasis: 0 }}
            aria-label="Request en crudo"
          >
            <header className="flex items-center justify-between border-b border-surface-800 bg-surface-950/50 px-3 py-1.5">
              <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-emerald-400">
                Request
              </span>
              <span className="font-mono text-[10px] text-zinc-600">
                {flow.request.method} ·{" "}
                {requestRecord?.body_too_large
                  ? `${formatBytes(requestRecord.size ?? 0)} (omitido)`
                  : `${requestView?.bodyBytes.length ?? 0} B`}
              </span>
            </header>
            <div className="min-h-0 flex-1 overflow-auto p-3">
              {requestRecord?.body_too_large ? (
                <LargeBodyNotice
                  flowId={flow.id}
                  message={requestRecord}
                  kind="request"
                />
              ) : requestView ? (
                <SyntaxView
                  startLine={requestView.startLine}
                  headers={requestView.headers}
                  body={formatBody(requestView.body, requestView.contentType)}
                  contentType={requestView.contentType}
                  bodyBytes={requestView.bodyBytes}
                  originalBodyBytes={requestView.originalBodyBytes}
                  downloadName={requestDownloadName}
                  baseUrl={htmlBaseUrl}
                  viewKey={`${flow.id}-request`}
                />
              ) : (
                <span className="font-mono text-[11px] text-zinc-500">—</span>
              )}

              {flow.websocket_frames && flow.websocket_frames.length > 0 && (
                <div className="mt-4 rounded-lg border border-surface-800 bg-surface-850 p-3">
                  <h3 className="mb-2 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-400">
                    <ArrowUpRight size={13} className="text-accent" />
                    WebSocket frames ({flow.websocket_frames.length})
                  </h3>
                  <div className="space-y-1 font-mono text-[10px] text-zinc-500">
                    {flow.websocket_frames.map((frame, index) => (
                      <div key={`${frame.at}-${index}`} className="flex gap-3">
                        <span className="w-28 truncate">{frame.direction}</span>
                        <span className="w-16 text-accent">{frame.name}</span>
                        <span>{frame.size} B</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </section>

          <div
            role="separator"
            aria-orientation="vertical"
            aria-label="Redimensionar Request y Response"
            aria-valuemin={25}
            aria-valuemax={75}
            aria-valuenow={Math.round(requestPercent)}
            tabIndex={0}
            onPointerDown={(event) => {
              event.preventDefault();
              setDragging(true);
            }}
            onKeyDown={(event) => {
              if (event.key === "ArrowLeft") {
                event.preventDefault();
                setRequestPercent((value) => clamp(value - 2, 25, 75));
              } else if (event.key === "ArrowRight") {
                event.preventDefault();
                setRequestPercent((value) => clamp(value + 2, 25, 75));
              }
            }}
            className="relative w-1.5 shrink-0 cursor-col-resize bg-surface-800 transition hover:bg-accent/60 focus:bg-accent focus:outline-none"
            title="Arrastra para redimensionar Request/Response"
          >
            <span className="pointer-events-none absolute inset-y-1/4 left-1/2 w-px -translate-x-1/2 bg-accent/40" />
          </div>

          <section
            className="flex min-w-0 flex-col overflow-hidden"
            style={{ flexGrow: 100 - requestPercent, flexBasis: 0 }}
            aria-label="Response en crudo"
          >
            <header className="flex items-center justify-between border-b border-surface-800 bg-surface-950/50 px-3 py-1.5">
              <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-emerald-400">
                Response
              </span>
              <span className="flex items-center gap-2 font-mono text-[10px] text-zinc-600">
                <span>
                  {dropped
                    ? "DROPPED"
                    : flow.response
                      ? `${responseStatus ?? "—"} · ${
                          responseRecord?.body_too_large
                            ? `${formatBytes(responseRecord.size ?? 0)} (omitido)`
                            : `${responseView?.bodyBytes.length ?? 0} B`
                        }`
                      : "sin respuesta"}
                </span>
                {evidenceFound && (
                  <span
                    data-testid="evidence-found-badge"
                    className="rounded border border-amber-400/60 bg-amber-400/15 px-1 py-0.5 text-[9px] font-semibold text-amber-200"
                  >
                    Evidencia aquí ↓
                  </span>
                )}
                {flow.response?.content_encoding && (
                  <span
                    title={`Cuerpo descomprimido (${flow.response.content_encoding}); el tráfico original conserva los bytes comprimidos.`}
                    className="rounded border border-amber-400/40 bg-amber-950/40 px-1 py-0.5 text-[9px] text-amber-300"
                  >
                    {flow.response.content_encoding} → texto
                  </span>
                )}
                {flow.response && responseView && (
                  <button
                    type="button"
                    onClick={() => {
                      if (responseRecord?.body_too_large) {
                        triggerDownload(
                          responseRecord.download_url ??
                            `/api/flows/${flow.id}/download?message=response`,
                        );
                        return;
                      }
                      downloadBytes(
                        responseView.originalBodyBytes,
                        responseDownloadName,
                      );
                    }}
                    aria-label="Descargar cuerpo de la respuesta"
                    title={
                      responseRecord?.body_too_large
                        ? "Descargar el cuerpo completo omitido del visor"
                        : `Descargar ${responseDownloadName} (bytes originales)`
                    }
                    className="flex items-center gap-1 rounded border border-surface-700 px-1.5 py-0.5 text-[9px] font-semibold text-zinc-300 transition hover:border-accent hover:text-accent"
                  >
                    <Download size={11} />
                    Descargar
                  </button>
                )}
              </span>
            </header>
            <div className="min-h-0 flex-1 overflow-auto p-3">
              {dropped ? (
                <div className="rounded-lg border border-rose-900/60 bg-rose-950/25 px-4 py-3 text-xs text-rose-300">
                  Petición descartada en{" "}
                  <span className="font-mono">
                    {flow.drop_reason ?? "intercepción"}
                  </span>
                  . No se envió al origen.
                </div>
              ) : !flow.response ? (
                <div className="rounded-lg border border-surface-800 bg-surface-850 p-4 text-xs text-zinc-500">
                  Esta petición no recibió respuesta (timeout o fallo de conexión).
                </div>
              ) : responseRecord?.body_too_large ? (
                <LargeBodyNotice
                  flowId={flow.id}
                  message={responseRecord}
                  kind="response"
                />
              ) : responseView ? (
                <SyntaxView
                  startLine={responseView.startLine}
                  headers={responseView.headers}
                  body={formatBody(responseView.body, responseView.contentType)}
                  contentType={responseView.contentType}
                  bodyBytes={responseView.bodyBytes}
                  originalBodyBytes={responseView.originalBodyBytes}
                  downloadName={responseDownloadName}
                  baseUrl={htmlBaseUrl}
                  viewKey={`${flow.id}-response`}
                  evidenceMatch={evidenceMatch}
                  evidenceOffset={evidenceOffset}
                />
              ) : (
                <span className="font-mono text-[11px] text-zinc-500">—</span>
              )}
            </div>
          </section>
        </div>
      )}

      {mdCopied && (
        <div
          role="status"
          className="fixed bottom-5 right-5 z-[70] flex items-center gap-2 rounded-lg border border-emerald-800/70 bg-emerald-950/90 px-4 py-2.5 text-xs font-medium text-emerald-200 shadow-2xl backdrop-blur"
        >
          <Check size={14} />
          ¡Copiado!
        </div>
      )}
    </section>
  );
}
