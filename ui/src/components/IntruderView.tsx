import { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowLeft,
  Crosshair,
  FileUp,
  Highlighter,
  Loader2,
  Play,
} from "lucide-react";
import type {
  AttackResultDetail,
  AttackResultRecord,
  FlowRecord,
  IntruderJob,
  IntruderMode,
} from "../types";
import {
  fetchFlow,
  fetchIntruderJob,
  fetchIntruderResult,
  flowHost,
  flowPath,
  formatMs,
  messageRaw,
  startIntruder,
  statusTone,
} from "../lib/api";
import { useApp } from "../context/AppContext";
import { CONCURRENCY_HELP } from "../lib/helpTexts";
import { DATA_TABLE, DATA_TABLE_HEAD } from "../lib/tableStyles";
import { HelpTooltip } from "./HelpTooltip";
import { HighlightedTextarea } from "./HighlightedTextarea";
import { IntruderResultModal } from "./IntruderResultModal";
import { SplitPane } from "./SplitPane";

const POLL_MS = 500;

const MODES: Array<{ value: IntruderMode; label: string; hint: string }> = [
  {
    value: "sniper",
    label: "Sniper",
    hint: "Prueba un payload en una posición a la vez",
  },
  {
    value: "battering_ram",
    label: "Battering Ram",
    hint: "Coloca el mismo payload en todas las posiciones a la vez",
  },
  {
    value: "pitchfork",
    label: "Pitchfork",
    hint: "Un diccionario por posición, avanzando en paralelo",
  },
  {
    value: "cluster_bomb",
    label: "Cluster Bomb",
    hint: "Producto cartesiano: prueba todas las combinaciones de diccionarios",
  },
];

const MULTI_MODES: IntruderMode[] = ["pitchfork", "cluster_bomb"];

function parseMarkerPositions(value: string): string[] {
  const positions: string[] = [];
  const pattern = /§([^§]*)§/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(value)) !== null) {
    positions.push(match[1]);
  }
  return positions;
}

function countMarkers(value: string): number {
  return (value.match(/§/g) ?? []).length;
}

function parsePayloads(value: string): string[] {
  return value
    .split(/\r?\n/)
    .map((line) => line.replace(/\r$/, ""))
    .filter((line) => line.trim().length > 0);
}

function positionLabel(name: string): string {
  const match = /^pos(\d+)$/.exec(name);
  return match ? `Posición ${Number(match[1]) + 1}` : name;
}

function comboLabel(result: AttackResultRecord): string {
  const entries = Object.entries(result.combo);
  if (entries.length === 0) return result.label || "—";
  return entries
    .map(([name, value]) => `${positionLabel(name)}=${value}`)
    .join(", ");
}

function summaryDuration(job: IntruderJob | null): string {
  if (!job?.started_at) return "—";
  const end = job.finished_at ? new Date(job.finished_at) : new Date();
  const start = new Date(job.started_at);
  const elapsed = end.getTime() - start.getTime();
  if (!Number.isFinite(elapsed) || elapsed < 0) return "—";
  return elapsed < 1000 ? `${elapsed} ms` : `${(elapsed / 1000).toFixed(2)} s`;
}

export function IntruderView() {
  const { selectedFlowId, setActiveModule } = useApp();
  const [flow, setFlow] = useState<FlowRecord | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [mode, setMode] = useState<IntruderMode>("sniper");
  const [rawRequest, setRawRequest] = useState("");
  const [payloadTexts, setPayloadTexts] = useState<string[]>([""]);
  const [concurrency, setConcurrency] = useState(10);
  const [throttle, setThrottle] = useState(0);
  const requestEditorRef = useRef<HTMLTextAreaElement | null>(null);

  const [starting, setStarting] = useState(false);
  const [attackId, setAttackId] = useState<string | null>(null);
  const [job, setJob] = useState<IntruderJob | null>(null);
  const [selectedResult, setSelectedResult] =
    useState<AttackResultRecord | null>(null);
  const [resultDetail, setResultDetail] = useState<AttackResultDetail | null>(
    null,
  );
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const detailRequestRef = useRef(0);

  const positions = useMemo(
    () => parseMarkerPositions(rawRequest),
    [rawRequest],
  );
  const markersUnbalanced = countMarkers(rawRequest) % 2 !== 0;
  const multi = MULTI_MODES.includes(mode);
  const payloadSlots = multi ? Math.max(positions.length, 1) : 1;

  useEffect(() => {
    if (selectedFlowId === null) {
      setFlow(null);
      setRawRequest("");
      setAttackId(null);
      setJob(null);
      setSelectedResult(null);
      setResultDetail(null);
      setDetailError(null);
      setDetailLoading(false);
      detailRequestRef.current += 1;
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    setRawRequest("");
    setAttackId(null);
    setJob(null);
    setSelectedResult(null);
    setResultDetail(null);
    setDetailError(null);
    setDetailLoading(false);
    detailRequestRef.current += 1;
    fetchFlow(selectedFlowId)
      .then((data) => {
        if (cancelled) return;
        setFlow(data);
        setRawRequest(messageRaw(data.final_request ?? data.request));
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "No se pudo cargar el flujo");
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedFlowId]);

  useEffect(() => {
    if (!attackId) return;
    let cancelled = false;
    let timer: number | undefined;

    const poll = async () => {
      try {
        const next = await fetchIntruderJob(attackId);
        if (cancelled) return;
        setJob(next);
        if (next.status === "running") {
          timer = window.setTimeout(() => void poll(), POLL_MS);
        }
      } catch (err: unknown) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Error consultando el ataque");
        }
      }
    };

    void poll();
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [attackId]);

  const closeResult = () => {
    detailRequestRef.current += 1;
    setSelectedResult(null);
    setResultDetail(null);
    setDetailError(null);
    setDetailLoading(false);
  };

  const openResult = (result: AttackResultRecord) => {
    setSelectedResult(result);
    setResultDetail(null);
    setDetailError(null);

    // Respuestas síncronas antiguas pueden traer el detalle inline.
    if (result.request || result.response) {
      setResultDetail({
        attack_id: attackId ?? "",
        index: result.index,
        request: result.request ?? null,
        response: result.response ?? null,
      });
      setDetailLoading(false);
      return;
    }

    if (!attackId) {
      setDetailError("El detalle no está disponible para este ataque.");
      setDetailLoading(false);
      return;
    }

    const requestId = ++detailRequestRef.current;
    setDetailLoading(true);
    void fetchIntruderResult(attackId, result.index)
      .then((detail) => {
        if (detailRequestRef.current === requestId) setResultDetail(detail);
      })
      .catch((err: unknown) => {
        if (detailRequestRef.current === requestId) {
          setDetailError(
            err instanceof Error
              ? err.message
              : "No se pudo cargar el detalle del intento",
          );
        }
      })
      .finally(() => {
        if (detailRequestRef.current === requestId) setDetailLoading(false);
      });
  };

  const markPosition = () => {
    const textarea = requestEditorRef.current;
    if (!textarea) return;

    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    if (start === end) {
      setError("Selecciona el texto que quieres marcar como posición.");
      return;
    }

    const current = textarea.value;
    const selected = current.slice(start, end);
    if (!selected) {
      setError("La selección está vacía.");
      return;
    }

    const next = `${current.slice(0, start)}§${selected}§${current.slice(end)}`;
    setRawRequest(next);
    setError(null);

    window.requestAnimationFrame(() => {
      textarea.focus();
      const innerStart = start + 1;
      textarea.setSelectionRange(innerStart, innerStart + selected.length);
    });
  };

  const updatePayload = (index: number, value: string) => {
    setPayloadTexts((previous) => {
      const copy = [...previous];
      while (copy.length <= index) copy.push("");
      copy[index] = value;
      return copy;
    });
  };

  const loadFile = (index: number, file: File | null) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      updatePayload(index, String(reader.result ?? ""));
    };
    reader.readAsText(file);
  };

  const start = async () => {
    if (!flow) return;
    if (!rawRequest.trim()) {
      setError("La petición está vacía.");
      return;
    }
    if (markersUnbalanced) {
      setError("Hay un marcador § sin cerrar en la petición.");
      return;
    }
    if (positions.length === 0) {
      setError(
        "Marca al menos una posición: selecciona texto y pulsa Marcar Posición (o Ctrl+B).",
      );
      return;
    }
    const sets = Array.from({ length: payloadSlots }, (_, index) =>
      parsePayloads(payloadTexts[index] ?? ""),
    );
    if (sets.some((items) => items.length === 0)) {
      setError("Cada diccionario necesita al menos un payload.");
      return;
    }

    setStarting(true);
    setError(null);
    setJob(null);
    setAttackId(null);
    setSelectedResult(null);
    setResultDetail(null);
    setDetailError(null);
    setDetailLoading(false);
    detailRequestRef.current += 1;
    try {
      const started = await startIntruder({
        flow_id: flow.id,
        mode,
        raw_request: rawRequest,
        ...(multi ? { payload_sets: sets } : { payloads: sets[0] }),
        concurrency: Math.max(1, concurrency),
        throttle_ms: Math.max(0, throttle),
        background: true,
      });
      setJob(started);
      setAttackId(started.attack_id);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "No se pudo iniciar el ataque");
    } finally {
      setStarting(false);
    }
  };

  const results = useMemo(
    () => [...(job?.results ?? [])].sort((left, right) => left.index - right.index),
    [job],
  );
  const expected = job?.expected ?? 0;
  const progress = expected > 0 ? Math.min(100, (results.length / expected) * 100) : 0;
  const running = starting || job?.status === "running";
  const responded = results.filter((result) => result.status === "responded").length;
  const failed = results.length - responded;

  if (selectedFlowId === null) {
    return (
      <div className="flex h-full items-center justify-center p-6">
        <div className="max-w-md rounded-2xl border border-surface-800 bg-surface-900/60 p-8 text-center">
          <div className="mx-auto grid h-12 w-12 place-items-center rounded-xl bg-accent/10 text-accent">
            <Crosshair size={22} />
          </div>
          <h2 className="mt-4 text-lg font-semibold text-zinc-100">Sin flujo seleccionado</h2>
          <p className="mt-2 text-sm text-zinc-400">
            Abre un flujo en Interceptación y pulsa{" "}
            <span className="font-medium text-zinc-200">Enviar a Intrusión</span>.
          </p>
          <button
            type="button"
            onClick={() => setActiveModule("proxy")}
            className="mt-6 inline-flex items-center gap-2 rounded-lg border border-surface-700 px-4 py-2 text-xs text-zinc-300 hover:text-white"
          >
            <ArrowLeft size={14} />
            Ir a Interceptación
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden">
      <header className="flex flex-wrap items-center gap-3 border-b border-surface-800 bg-surface-900/40 px-5 py-2.5">
        <div className="min-w-0 flex-1">
          <p className="font-mono text-xs text-zinc-300">
            {flow ? (
              <>
                <span className="text-accent">{flow.request.method}</span>{" "}
                {flowPath(flow)}
                <span className="ml-2 text-zinc-600">#{flow.id}</span>
              </>
            ) : (
              `Flujo #${selectedFlowId}`
            )}
          </p>
          <p className="mt-0.5 text-[11px] text-zinc-500">
            {flow ? flowHost(flow) : "Cargando…"}
            {multi && positions.length > 0 && (
              <span className="ml-2 text-zinc-600">
                {positions.length} posiciones · un diccionario por posición
              </span>
            )}
          </p>
        </div>
        {job && (
          <span
            className={[
              "flex items-center gap-2 rounded-full border px-3 py-1.5 text-[11px]",
              job.status === "running"
                ? "border-amber-500/30 bg-amber-500/10 text-amber-300"
                : job.status === "completed"
                  ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                  : "border-rose-500/30 bg-rose-500/10 text-rose-300",
            ].join(" ")}
          >
            {job.status === "running" && <Loader2 size={12} className="animate-spin" />}
            {job.status}
          </span>
        )}
      </header>

      {error && (
        <div className="border-b border-rose-900/60 bg-rose-950/30 px-5 py-2 text-xs text-rose-300">
          {error}
        </div>
      )}

      {loading ? (
        <div className="grid flex-1 place-items-center text-zinc-500">
          <Loader2 size={20} className="animate-spin text-accent" />
        </div>
      ) : !flow ? (
        <div className="grid flex-1 place-items-center text-xs text-zinc-600">
          No se pudo cargar el flujo seleccionado.
        </div>
      ) : (
        <SplitPane
          orientation="vertical"
          label="Redimensionar paneles de Intrusión"
          initial={62}
          min={35}
          max={80}
          className="p-3"
          first={
            <SplitPane
              orientation="horizontal"
              label="Redimensionar petición y configuración de Intrusión"
              initial={48}
              min={30}
              max={70}
              className="h-full"
              first={
                <section
                  className="flex h-full min-h-0 flex-col overflow-hidden rounded-lg border border-surface-800 bg-surface-950"
                  aria-label="Petición de Intrusión"
                  data-testid="intruder-request-view"
                >
                  <header className="flex items-center justify-between gap-2 border-b border-surface-800 bg-surface-900/60 px-3 py-2">
                    <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-zinc-500">
                      Request
                    </span>
                    <div className="flex items-center gap-1.5">
                      <span className="font-mono text-[10px] text-zinc-600">
                        {rawRequest.length} chars
                      </span>
                      <button
                        type="button"
                        onMouseDown={(event) => event.preventDefault()}
                        onClick={markPosition}
                        title="Envuelve el texto seleccionado en §...§ (Ctrl+B)"
                        className="flex items-center gap-1 rounded-lg border border-cyan-400/40 bg-cyan-950/30 px-2 py-1 text-[10px] font-semibold text-cyan-300 transition hover:border-accent hover:text-accent"
                      >
                        <Highlighter size={12} />
                        Marcar Posición
                      </button>
                    </div>
                  </header>
                  <div className="min-h-0 flex-1">
                    <HighlightedTextarea
                      value={rawRequest}
                      onChange={setRawRequest}
                      ariaLabel="Petición de Intrusión en crudo"
                      textareaRef={(element) => {
                        requestEditorRef.current = element;
                      }}
                      onKeyDown={(event) => {
                        if (
                          (event.ctrlKey || event.metaKey) &&
                          event.key.toLowerCase() === "b"
                        ) {
                          event.preventDefault();
                          markPosition();
                        }
                      }}
                      className="h-full min-h-[10rem]"
                    />
                  </div>
                  <div
                    className="shrink-0 border-t border-surface-800 bg-surface-900/40 px-3 py-2"
                    data-testid="intruder-positions"
                  >
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="text-[10px] uppercase tracking-[0.14em] text-zinc-500">
                        Posiciones detectadas: {positions.length}
                      </span>
                      {positions.map((value, index) => (
                        <code
                          key={`${index}-${value}`}
                          className="rounded border border-cyan-400/40 bg-cyan-950/30 px-1.5 py-0.5 font-mono text-[10px] text-cyan-300"
                        >
                          {index + 1} ({value || "vacío"})
                        </code>
                      ))}
                    </div>
                    {markersUnbalanced ? (
                      <p className="mt-1 text-[10px] text-amber-400">
                        Hay un § sin cerrar. Cada posición necesita apertura y
                        cierre.
                      </p>
                    ) : positions.length === 0 ? (
                      <p className="mt-1 text-[10px] text-zinc-600">
                        Selecciona texto en la petición y pulsa Marcar Posición
                        (o Ctrl+B).
                      </p>
                    ) : null}
                  </div>
                </section>
              }
              second={
                <section
                  className="flex h-full min-h-0 flex-col overflow-hidden rounded-lg border border-surface-800 bg-surface-900/40"
                  aria-label="Configuración de Intrusión"
                >
                  <header className="flex flex-wrap items-center justify-between gap-2 border-b border-surface-800 px-3 py-2">
                    <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-zinc-500">
                      Configuración
                    </span>
                    <button
                      type="button"
                      onClick={() => void start()}
                      disabled={running}
                      className="flex items-center gap-2 rounded-lg bg-accent px-3 py-1.5 text-[11px] font-semibold text-surface-950 transition hover:bg-accent-soft disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {running ? (
                        <Loader2 size={13} className="animate-spin" />
                      ) : (
                        <Play size={13} />
                      )}
                      {running ? "Attack running…" : "Start Attack"}
                    </button>
                  </header>

                  <div className="min-h-0 flex-1 space-y-3 overflow-auto p-3">
                    <section className="rounded-lg border border-surface-800 bg-surface-950 p-3">
                      <div className="grid gap-3 sm:grid-cols-2">
                        <div className="flex flex-col gap-1">
                          <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-[0.14em] text-zinc-500">
                            <label htmlFor="intruder-mode-select">Modo</label>
                            <HelpTooltip
                              label="Modos de Ataque"
                              text="Sniper: Prueba un payload en una posición a la vez. Battering Ram: Mismo payload en todas. Pitchfork: Un diccionario por posición en paralelo. Cluster Bomb: Todas las combinaciones."
                            />
                          </div>
                          <select
                            id="intruder-mode-select"
                            aria-label="Modo"
                            value={mode}
                            onChange={(event) =>
                              setMode(event.target.value as IntruderMode)
                            }
                            className="rounded-lg border border-surface-700 bg-surface-950 px-3 py-2 font-mono text-xs normal-case tracking-normal text-zinc-200 outline-none focus:border-accent/60"
                          >
                            {MODES.map((item) => (
                              <option key={item.value} value={item.value}>
                                {item.label}
                              </option>
                            ))}
                          </select>
                        </div>

                        <div className="flex flex-col gap-1">
                          <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-[0.14em] text-zinc-500">
                            <label htmlFor="intruder-concurrency">
                              Concurrencia
                            </label>
                            <HelpTooltip
                              label="Concurrencia"
                              text={CONCURRENCY_HELP}
                            />
                          </div>
                          <input
                            id="intruder-concurrency"
                            aria-label="Concurrencia"
                            type="number"
                            min={1}
                            max={999}
                            value={concurrency}
                            onChange={(event) =>
                              setConcurrency(
                                Math.max(1, Number(event.target.value) || 1),
                              )
                            }
                            className="rounded-lg border border-surface-700 bg-surface-950 px-3 py-2 font-mono text-xs normal-case tracking-normal text-zinc-200 outline-none focus:border-accent/60"
                          />
                        </div>

                        <label className="flex flex-col gap-1 text-[10px] uppercase tracking-[0.14em] text-zinc-500">
                          Throttle (ms)
                          <input
                            aria-label="Throttle en milisegundos"
                            type="number"
                            min={0}
                            value={throttle}
                            onChange={(event) =>
                              setThrottle(
                                Math.max(0, Number(event.target.value) || 0),
                              )
                            }
                            className="rounded-lg border border-surface-700 bg-surface-950 px-3 py-2 font-mono text-xs normal-case tracking-normal text-zinc-200 outline-none focus:border-accent/60"
                          />
                        </label>
                      </div>
                      <p className="mt-2 text-[11px] text-zinc-600">
                        {MODES.find((item) => item.value === mode)?.hint}. Marca
                        las posiciones con §texto§ o seleccionando texto y
                        pulsando Marcar Posición.
                      </p>
                    </section>

                    <section className="rounded-lg border border-surface-800 bg-surface-950 p-3">
                      <div className="mb-2 flex items-center justify-between">
                        <h3 className="text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
                          Payloads
                        </h3>
                        <span className="text-[10px] text-zinc-600">
                          {multi ? "un diccionario por posición" : "uno por línea"}
                        </span>
                      </div>
                      <div className="grid gap-3">
                        {Array.from({ length: payloadSlots }, (_, index) => {
                          const label = multi
                            ? `Payloads · ${positions[index] ?? `posición ${index + 1}`}`
                            : "Payloads";
                          return (
                            <div
                              key={`${mode}-${index}`}
                              className="flex min-h-36 flex-col rounded-lg border border-surface-800 bg-surface-950"
                            >
                              <div className="flex items-center justify-between border-b border-surface-800 px-3 py-1.5">
                                <span className="font-mono text-[10px] text-zinc-500">
                                  {label}
                                </span>
                                <label className="flex cursor-pointer items-center gap-1 text-[10px] text-zinc-500 hover:text-accent">
                                  <FileUp size={12} />
                                  Cargar
                                  <input
                                    type="file"
                                    accept=".txt,.pay,text/plain"
                                    className="hidden"
                                    onChange={(event) => {
                                      loadFile(index, event.target.files?.[0] ?? null);
                                      event.target.value = "";
                                    }}
                                  />
                                </label>
                              </div>
                              <textarea
                                value={payloadTexts[index] ?? ""}
                                onChange={(event) =>
                                  updatePayload(index, event.target.value)
                                }
                                placeholder={"admin\nroot\nguest"}
                                spellCheck={false}
                                className="min-h-28 flex-1 resize-y bg-transparent p-3 font-mono text-[11px] leading-relaxed text-zinc-300 outline-none placeholder:text-zinc-700"
                              />
                            </div>
                          );
                        })}
                      </div>
                      {multi && positions.length === 0 && (
                        <p className="mt-2 text-[11px] text-amber-400/80">
                          Marca al menos una posición en la petición de la
                          izquierda para generar un diccionario por cada una.
                        </p>
                      )}
                    </section>
                  </div>
                </section>
              }
            />
          }
          second={
            <section
              className="flex h-full min-h-0 flex-col overflow-hidden rounded-lg border border-surface-800 bg-surface-900/40"
              aria-label="Resultados de Intrusión"
            >
              <header className="space-y-2 border-b border-surface-800 px-4 py-2.5">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.16em] text-zinc-500">
                    <Crosshair size={13} className="text-accent" />
                    Resultados
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-[10px] text-zinc-600">
                      clic en una fila para ver petición y respuesta
                    </span>
                    <span className="font-mono text-[10px] text-zinc-500">
                      {results.length} / {expected || "—"}
                    </span>
                  </div>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-surface-800">
                  <div
                    className="h-full rounded-full bg-accent transition-[width] duration-300"
                    style={{ width: `${progress}%` }}
                  />
                </div>
              </header>

              {results.length === 0 ? (
                <div className="grid flex-1 place-items-center px-4 text-center text-xs text-zinc-600">
                  Configura el ataque y pulsa Start Attack.
                </div>
              ) : (
                <div className="min-h-0 flex-1 overflow-auto">
                  <table className={DATA_TABLE}>
                    <thead className={DATA_TABLE_HEAD}>
                      <tr className="border-b border-surface-800">
                        <th className="w-12 px-3 py-2 font-medium">#</th>
                        <th className="px-2 py-2 font-medium">Payload(s)</th>
                        <th className="w-16 px-2 py-2 font-medium">Cód</th>
                        <th className="w-24 px-2 py-2 text-right font-medium">Tamaño</th>
                        <th className="w-24 px-2 py-2 text-right font-medium">TTFB</th>
                        <th className="w-24 px-2 py-2 text-right font-medium">Total</th>
                        <th className="w-32 px-2 py-2 font-medium">Estado</th>
                        <th className="w-40 px-3 py-2 font-medium">Error</th>
                      </tr>
                    </thead>
                    <tbody>
                      {results.map((result) => (
                        <tr
                          key={result.index}
                          onClick={() => openResult(result)}
                          aria-selected={selectedResult?.index === result.index}
                          title="Ver petición y respuesta de este intento"
                          className={[
                            "cursor-pointer border-b border-surface-800/60",
                            selectedResult?.index === result.index
                              ? "bg-accent/10"
                              : "hover:bg-surface-850",
                          ].join(" ")}
                        >
                          <td className="px-3 py-1.5 text-accent">
                            {result.index + 1}
                          </td>
                          <td className="truncate px-2 py-1.5 text-zinc-300">
                            {comboLabel(result)}
                          </td>
                          <td
                            className={`px-2 py-1.5 ${statusTone(
                              result.status_code ?? undefined,
                            )}`}
                          >
                            {result.status_code ?? "—"}
                          </td>
                          <td className="px-2 py-1.5 text-right text-zinc-500">
                            {result.length} B
                          </td>
                          <td className="px-2 py-1.5 text-right text-zinc-500">
                            {formatMs(result.ttfb_ms)}
                          </td>
                          <td className="px-2 py-1.5 text-right text-zinc-500">
                            {formatMs(result.total_ms)}
                          </td>
                          <td className="px-2 py-1.5 text-zinc-400">
                            {result.status}
                          </td>
                          <td className="truncate px-3 py-1.5 text-rose-400">
                            {result.error ?? ""}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {job && (
                <div className="flex shrink-0 flex-wrap items-center gap-4 border-t border-surface-800 px-4 py-2 text-[10px] text-zinc-500">
                  <span>
                    estado:{" "}
                    <span
                      className={
                        job.status === "completed"
                          ? "text-emerald-400"
                          : job.status === "failed"
                            ? "text-rose-400"
                            : "text-amber-400"
                      }
                    >
                      {job.status}
                    </span>
                  </span>
                  <span>completados: {responded}</span>
                  <span>fallidos: {failed}</span>
                  <span>saltados: {job.skipped}</span>
                  <span>tiempo: {summaryDuration(job)}</span>
                  {job.error && <span className="text-rose-400">{job.error}</span>}
                </div>
              )}
            </section>
          }
        />
      )}

      {selectedResult && (
        <IntruderResultModal
          result={selectedResult}
          detail={resultDetail}
          loading={detailLoading}
          error={detailError}
          onClose={closeResult}
        />
      )}
    </div>
  );
}
