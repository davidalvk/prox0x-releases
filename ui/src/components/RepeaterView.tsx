import { useEffect, useMemo, useState } from "react";
import {
  ArrowLeft,
  Loader2,
  Repeat2,
  RotateCcw,
  Send,
} from "lucide-react";
import type {
  AttemptRecord,
  FlowRecord,
  MessageView,
  RepeaterSendMode,
} from "../types";
import {
  decodeMessage,
  fetchFlow,
  flowHost,
  flowPath,
  formatBody,
  formatMs,
  formatTime,
  messageRaw,
  sendRepeater,
  statusTone,
} from "../lib/api";
import { useApp } from "../context/AppContext";
import { suggestDownloadName } from "../lib/binary";
import { buildCurlFromRaw } from "../lib/curl";
import { CONCURRENCY_HELP } from "../lib/helpTexts";
import { DATA_TABLE, DATA_TABLE_HEAD } from "../lib/tableStyles";
import { CurlButton } from "./CurlButton";
import { HelpTooltip } from "./HelpTooltip";
import { HighlightedTextarea } from "./HighlightedTextarea";
import { SplitPane } from "./SplitPane";
import { SyntaxView } from "./SyntaxView";

const SEND_MODES: Array<{ id: RepeaterSendMode; label: string; help: string }> = [
  {
    id: "single",
    label: "Single",
    help: "Envía la petición una sola vez.",
  },
  {
    id: "sequential",
    label: "Sequential",
    help: "Envía varias peticiones, una tras otra, esperando un tiempo entre ellas.",
  },
  {
    id: "parallel",
    label: "Parallel",
    help: "Envía varias peticiones al mismo tiempo (útil para probar concurrencia).",
  },
];

export function RepeaterView() {
  const {
    selectedFlowId,
    repeaterRawRequest,
    setActiveModule,
  } = useApp();
  const [flow, setFlow] = useState<FlowRecord | null>(null);
  const [initialRaw, setInitialRaw] = useState("");
  const [raw, setRaw] = useState("");
  const [loading, setLoading] = useState(false);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [attempts, setAttempts] = useState<AttemptRecord[]>([]);
  const [selectedAttempt, setSelectedAttempt] = useState<number | null>(null);
  const [count, setCount] = useState(5);
  const [concurrency, setConcurrency] = useState(5);
  const [delayMs, setDelayMs] = useState(100);
  const [mode, setMode] = useState<RepeaterSendMode>("single");

  useEffect(() => {
    if (selectedFlowId === null) {
      setFlow(null);
      setRaw("");
      setInitialRaw("");
      setAttempts([]);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    setAttempts([]);
    setSelectedAttempt(null);
    fetchFlow(selectedFlowId)
      .then((data) => {
        if (cancelled) return;
        setFlow(data);
        const message = data.final_request ?? data.request;
        const decoded = repeaterRawRequest ?? messageRaw(message);
        setInitialRaw(decoded);
        setRaw(decoded);
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
  }, [selectedFlowId, repeaterRawRequest]);

  const selectedData = useMemo(() => {
    if (attempts.length === 0) return null;
    return (
      attempts.find((attempt) => attempt.index === selectedAttempt) ??
      attempts[attempts.length - 1]
    );
  }, [attempts, selectedAttempt]);

  const responseView: MessageView | null = selectedData?.response
    ? decodeMessage(selectedData.response)
    : null;

  const curlCommand = useMemo(
    () => (flow && raw.trim() ? buildCurlFromRaw(raw, flow.service) : ""),
    [flow, raw],
  );

  const selectAttempt = (attempt: AttemptRecord) => {
    setSelectedAttempt(attempt.index);
    // Recupera la petición exacta de ese intento (incluye redirects).
    if (attempt.request) {
      setRaw(messageRaw(attempt.request));
    }
  };

  const run = async () => {
    if (!flow || !raw.trim()) return;
    setSending(true);
    setError(null);
    try {
      const response = await sendRepeater(flow.id, raw, {
        mode,
        count: mode === "single" ? 1 : Math.min(10_000, Math.max(1, count)),
        concurrency:
          mode === "parallel" ? Math.min(999, Math.max(1, concurrency)) : 1,
        delayMs:
          mode === "sequential" ? Math.min(60_000, Math.max(0, delayMs)) : 0,
      });
      setAttempts(response.attempts);
      setSelectedAttempt(
        response.attempts.length > 0
          ? response.attempts[response.attempts.length - 1].index
          : null,
      );
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "No se pudo enviar");
    } finally {
      setSending(false);
    }
  };

  const sendLabel =
    mode === "single"
      ? "Send Single"
      : mode === "sequential"
        ? `Send ${count} Sequentially`
        : `Send ${count} in Parallel`;

  if (selectedFlowId === null) {
    return (
      <div className="flex h-full items-center justify-center p-6">
        <div className="max-w-md rounded-2xl border border-surface-800 bg-surface-900/60 p-8 text-center">
          <div className="mx-auto grid h-12 w-12 place-items-center rounded-xl bg-accent/10 text-accent">
            <Repeat2 size={22} />
          </div>
          <h2 className="mt-4 text-lg font-semibold text-zinc-100">Sin flujo seleccionado</h2>
          <p className="mt-2 text-sm text-zinc-400">
            Abre un flujo en Interceptación y pulsa{" "}
            <span className="font-medium text-zinc-200">Enviar a Reenvío</span>.
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
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex flex-wrap items-start justify-between gap-2 border-b border-surface-800 bg-surface-900/40 px-5 py-2.5">
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
            {flow ? `${flowHost(flow)} · ${formatTime(flow.at)}` : "Cargando…"}
            <span className="ml-2 text-zinc-600">
              Edita la petición, envíala y compara la respuesta por intento.
            </span>
          </p>
        </div>
        <CurlButton command={curlCommand} />
      </header>

      {error && (
        <div className="border-b border-rose-900/60 bg-rose-950/30 px-5 py-2 text-xs text-rose-300">
          {error}
        </div>
      )}

      <SplitPane
        orientation="vertical"
        label="Redimensionar paneles de Reenvío"
        initial={62}
        min={35}
        max={80}
        className="p-3"
        first={
          <SplitPane
            orientation="horizontal"
            label="Redimensionar petición y respuesta de Reenvío"
            initial={50}
            min={25}
            max={75}
            className="h-full"
            first={
              <section
                className="flex h-full min-h-0 flex-col overflow-hidden rounded-lg border border-surface-800 bg-surface-950"
                aria-label="Petición de Reenvío"
              >
                <header className="flex flex-wrap items-center justify-between gap-2 border-b border-surface-800 bg-surface-900/60 px-3 py-2">
                  <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-zinc-500">
                    Request
                  </span>
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="font-mono text-[10px] text-zinc-600">
                      {raw.length} chars
                    </span>
                    <button
                      type="button"
                      onClick={() => void run()}
                      disabled={sending || !flow || !raw.trim()}
                      className="flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-[11px] font-semibold text-surface-950 transition hover:bg-accent-soft disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {sending ? (
                        <Loader2 size={13} className="animate-spin" />
                      ) : (
                        <Send size={13} />
                      )}
                      {sending ? "Sending…" : sendLabel}
                    </button>
                    <button
                      type="button"
                      onClick={() => setRaw(initialRaw)}
                      disabled={sending || raw === initialRaw}
                      className="rounded-lg border border-surface-700 p-1.5 text-zinc-400 transition hover:text-zinc-100 disabled:opacity-40"
                      title="Restaurar petición original"
                      aria-label="Restaurar petición original"
                    >
                      <RotateCcw size={13} />
                    </button>
                  </div>
                </header>

                <div className="flex flex-wrap items-center gap-2 border-b border-surface-800/70 bg-surface-900/30 px-3 py-2">
                  <div
                    role="radiogroup"
                    aria-label="Modo de envío"
                    className="flex items-center gap-1 rounded-lg border border-surface-700 bg-surface-950 p-1"
                  >
                    {SEND_MODES.map((item) => (
                      <div key={item.id} className="flex items-center gap-1 pr-1">
                        <label
                          className={[
                            "cursor-pointer rounded px-2 py-1 text-[9px] font-semibold uppercase tracking-[0.12em] transition",
                            mode === item.id
                              ? "bg-accent text-surface-950"
                              : "text-zinc-500 hover:text-zinc-200",
                          ].join(" ")}
                        >
                          <input
                            type="radio"
                            name="repeater-send-mode"
                            value={item.id}
                            checked={mode === item.id}
                            onChange={() => setMode(item.id)}
                            className="sr-only"
                          />
                          {item.label}
                        </label>
                        <HelpTooltip label={item.label} text={item.help} />
                      </div>
                    ))}
                  </div>

                  {mode !== "single" && (
                    <label className="flex items-center gap-1 text-[10px] text-zinc-500">
                      veces
                      <input
                        aria-label="Número de envíos"
                        type="number"
                        min={1}
                        max={10_000}
                        value={count}
                        onChange={(event) =>
                          setCount(Math.max(1, Number(event.target.value) || 1))
                        }
                        className="w-14 rounded border border-surface-700 bg-surface-950 px-1.5 py-1 font-mono text-[10px] text-zinc-200 outline-none focus:border-accent/60"
                      />
                    </label>
                  )}

                  {mode === "sequential" && (
                    <label className="flex items-center gap-1 text-[10px] text-zinc-500">
                      delay ms
                      <input
                        aria-label="Delay en milisegundos"
                        type="number"
                        min={0}
                        max={60_000}
                        value={delayMs}
                        onChange={(event) =>
                          setDelayMs(Math.max(0, Number(event.target.value) || 0))
                        }
                        className="w-16 rounded border border-surface-700 bg-surface-950 px-1.5 py-1 font-mono text-[10px] text-zinc-200 outline-none focus:border-accent/60"
                      />
                    </label>
                  )}

                  {mode === "parallel" && (
                    <div className="flex items-center gap-1">
                      <label className="flex items-center gap-1 text-[10px] text-zinc-500">
                        concurrencia
                        <input
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
                          className="w-16 rounded border border-surface-700 bg-surface-950 px-1.5 py-1 font-mono text-[10px] text-zinc-200 outline-none focus:border-accent/60"
                        />
                      </label>
                      <HelpTooltip label="Concurrencia" text={CONCURRENCY_HELP} />
                    </div>
                  )}
                </div>

                <div className="min-h-0 flex-1">
                  {loading ? (
                    <div className="grid h-full place-items-center text-zinc-500">
                      <Loader2 size={20} className="animate-spin text-accent" />
                    </div>
                  ) : (
                    <HighlightedTextarea
                      value={raw}
                      onChange={setRaw}
                      ariaLabel="Petición en crudo"
                      className="h-full min-h-[10rem]"
                    />
                  )}
                </div>
              </section>
            }
            second={
              <section
                className="flex h-full min-h-0 flex-col overflow-hidden rounded-lg border border-surface-800 bg-surface-950"
                aria-label="Respuesta de Reenvío"
                data-testid="repeater-response"
                data-attempt-index={selectedData?.index ?? ""}
              >
                <header className="flex flex-wrap items-center justify-between gap-2 border-b border-surface-800 bg-surface-900/60 px-3 py-2">
                  <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-zinc-500">
                    Response
                  </span>
                  {selectedData && (
                    <span className="flex flex-wrap items-center gap-2 font-mono text-[10px] text-zinc-500">
                      <span className={statusTone(selectedData.status_code ?? undefined)}>
                        {selectedData.status_code ?? "—"}
                      </span>
                      <span>TTFB {formatMs(selectedData.ttfb_ms)}</span>
                      <span>total {formatMs(selectedData.total_ms)}</span>
                      {selectedData.response?.content_encoding && (
                        <span
                          title={`Cuerpo descomprimido (${selectedData.response.content_encoding}) para mostrarlo como texto plano.`}
                          className="rounded border border-amber-400/40 bg-amber-950/40 px-1 py-0.5 text-[9px] text-amber-300"
                        >
                          {selectedData.response.content_encoding} → texto
                        </span>
                      )}
                    </span>
                  )}
                </header>

                <div className="min-h-0 flex-1 overflow-auto p-3">
                  {!selectedData ? (
                    <div className="grid h-full place-items-center text-center text-xs text-zinc-600">
                      Envía una petición o selecciona un intento para ver su
                      respuesta.
                    </div>
                  ) : !selectedData.response ? (
                    <div className="rounded-lg border border-rose-900/40 bg-rose-950/20 p-4 text-xs text-rose-300">
                      {selectedData.error ?? "Sin respuesta"}
                    </div>
                  ) : (
                    responseView && <ResponsePane view={responseView} />
                  )}
                </div>
              </section>
            }
          />
        }
        second={
          <section
            className="flex h-full min-h-0 flex-col overflow-hidden rounded-lg border border-surface-800 bg-surface-900/40"
            aria-label="Intentos de Reenvío"
          >
            <header className="flex flex-wrap items-center justify-between gap-2 border-b border-surface-800 px-4 py-2">
              <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-zinc-500">
                Intentos ({attempts.length})
              </span>
              <span className="text-[10px] text-zinc-600">
                clic en una fila para cargar su petición y respuesta
              </span>
            </header>
            {attempts.length === 0 ? (
              <div className="grid flex-1 place-items-center px-4 text-center text-xs text-zinc-600">
                Aún no hay intentos. Pulsa Send para enviar la petición.
              </div>
            ) : (
              <div className="min-h-0 flex-1 overflow-auto">
                <table className={DATA_TABLE}>
                  <thead className={DATA_TABLE_HEAD}>
                    <tr>
                      <th className="w-12 px-4 py-1.5 font-medium">#</th>
                      <th className="w-28 px-2 py-1.5 font-medium">Estado</th>
                      <th className="w-16 px-2 py-1.5 font-medium">Cód</th>
                      <th className="w-24 px-2 py-1.5 text-right font-medium">Tamaño</th>
                      <th className="w-24 px-2 py-1.5 text-right font-medium">TTFB</th>
                      <th className="w-24 px-2 py-1.5 text-right font-medium">Total</th>
                      <th className="px-4 py-1.5 font-medium">Error</th>
                    </tr>
                  </thead>
                  <tbody>
                    {attempts.map((attempt) => (
                      <tr
                        key={attempt.index}
                        onClick={() => selectAttempt(attempt)}
                        aria-selected={selectedData?.index === attempt.index}
                        title="Cargar esta petición y su respuesta"
                        className={[
                          "cursor-pointer border-b border-surface-800/60",
                          selectedData?.index === attempt.index
                            ? "bg-accent/10"
                            : "hover:bg-surface-850",
                        ].join(" ")}
                      >
                        <td className="px-4 py-1.5 text-accent">
                          {attempt.index + 1}
                        </td>
                        <td className="px-2 py-1.5 text-zinc-400">
                          {attempt.status}
                        </td>
                        <td
                          className={`px-2 py-1.5 ${statusTone(
                            attempt.status_code ?? undefined,
                          )}`}
                        >
                          {attempt.status_code ?? "—"}
                        </td>
                        <td className="px-2 py-1.5 text-right text-zinc-500">
                          {attempt.length} B
                        </td>
                        <td className="px-2 py-1.5 text-right text-zinc-500">
                          {formatMs(attempt.ttfb_ms)}
                        </td>
                        <td className="px-2 py-1.5 text-right text-zinc-500">
                          {formatMs(attempt.total_ms)}
                        </td>
                        <td className="truncate px-4 py-1.5 text-rose-400">
                          {attempt.error ?? ""}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        }
      />
    </div>
  );
}

function ResponsePane({ view }: { view: MessageView }) {
  return (
    <SyntaxView
      startLine={view.startLine}
      headers={view.headers}
      body={formatBody(view.body, view.contentType)}
      contentType={view.contentType}
      bodyBytes={view.bodyBytes}
      originalBodyBytes={view.originalBodyBytes}
      downloadName={suggestDownloadName(
        view.contentType,
        view.headers,
        "prox0x-repeater-response",
      )}
      className="rounded-lg border border-surface-800 bg-surface-950 p-3"
    />
  );
}
