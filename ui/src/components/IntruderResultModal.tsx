import { useEffect } from "react";
import { createPortal } from "react-dom";
import { Crosshair, Loader2, X } from "lucide-react";
import type { AttackResultDetail, AttackResultRecord } from "../types";
import { decodeMessage, formatBody, formatMs, statusTone } from "../lib/api";
import { suggestDownloadName } from "../lib/binary";
import { SyntaxView } from "./SyntaxView";

interface IntruderResultModalProps {
  result: AttackResultRecord;
  detail: AttackResultDetail | null;
  loading: boolean;
  error: string | null;
  onClose: () => void;
}

function comboText(result: AttackResultRecord): string {
  const entries = Object.entries(result.combo);
  if (entries.length === 0) return result.label || "—";
  return entries
    .map(([name, value]) => {
      const match = /^pos(\d+)$/.exec(name);
      return `${match ? `Posición ${Number(match[1]) + 1}` : name}=${value}`;
    })
    .join(", ");
}

/**
 * Detalle de un intento de Intrusión: petición exacta (con payload sustituido),
 * respuesta del servidor, tiempos y estado.
 */
export function IntruderResultModal({
  result,
  detail,
  loading,
  error,
  onClose,
}: IntruderResultModalProps) {
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  const requestRecord = detail?.request ?? result.request ?? null;
  const responseRecord = detail?.response ?? result.response ?? null;
  const requestView = requestRecord ? decodeMessage(requestRecord) : null;
  const responseView = responseRecord ? decodeMessage(responseRecord) : null;

  return createPortal(
    <div
      role="presentation"
      onClick={onClose}
      className="fixed inset-0 z-[80] flex items-center justify-center bg-black/75 p-4"
    >
      <section
        role="dialog"
        aria-label="Detalle del intento de ataque"
        data-testid="intruder-result-modal"
        onClick={(event) => event.stopPropagation()}
        className="terminal-modal flex max-h-[90vh] w-full max-w-5xl flex-col overflow-hidden rounded-2xl border border-accent bg-surface-900 shadow-2xl"
      >
        <header className="flex flex-wrap items-start justify-between gap-3 border-b border-surface-700 px-5 py-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.18em] text-zinc-500">
              <Crosshair size={13} className="text-accent" />
              Intento #{result.index + 1}
              <span className={statusTone(result.status_code ?? undefined)}>
                {result.status_code ?? "—"}
              </span>
              <span>{result.status}</span>
            </div>
            <h2 className="mt-1 truncate font-mono text-sm text-zinc-100">
              {comboText(result)}
            </h2>
            <p className="mt-0.5 font-mono text-[10px] text-zinc-600">
              TTFB {formatMs(result.ttfb_ms)} · total {formatMs(result.total_ms)} ·{" "}
              {result.length} B
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Cerrar detalle del intento"
            className="rounded-lg border border-surface-700 p-2 text-zinc-400 transition hover:text-zinc-100"
          >
            <X size={16} />
          </button>
        </header>

        <div className="grid min-h-0 flex-1 gap-3 overflow-auto p-4 lg:grid-cols-2">
          {loading ? (
            <div className="flex h-48 items-center justify-center gap-2 text-xs text-zinc-500 lg:col-span-2">
              <Loader2 size={16} className="animate-spin text-accent" />
              Cargando petición y respuesta del intento…
            </div>
          ) : error ? (
            <div className="rounded-lg border border-rose-900/60 bg-rose-950/30 p-4 text-xs text-rose-300 lg:col-span-2">
              {error}
            </div>
          ) : (
            <>
              <section
                className="flex min-h-0 flex-col overflow-hidden rounded-lg border border-surface-800 bg-surface-950"
                aria-label="Petición del intento"
              >
                <header className="border-b border-surface-800 bg-surface-900/60 px-3 py-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-zinc-500">
                  Request enviado
                </header>
                <div className="min-h-0 flex-1 overflow-auto p-3">
                  {requestView ? (
                    <SyntaxView
                      startLine={requestView.startLine}
                      headers={requestView.headers}
                      body={formatBody(requestView.body, requestView.contentType)}
                      contentType={requestView.contentType}
                      bodyBytes={requestView.bodyBytes}
                      originalBodyBytes={requestView.originalBodyBytes}
                      downloadName={suggestDownloadName(
                        requestView.contentType,
                        requestView.headers,
                        `prox0x-attack-${result.index + 1}-request`,
                      )}
                      viewKey={`attack-${result.index}-request`}
                    />
                  ) : (
                    <p className="text-xs text-zinc-600">Sin petición registrada.</p>
                  )}
                </div>
              </section>

              <section
                className="flex min-h-0 flex-col overflow-hidden rounded-lg border border-surface-800 bg-surface-950"
                aria-label="Respuesta del intento"
              >
                <header className="flex items-center justify-between border-b border-surface-800 bg-surface-900/60 px-3 py-2">
                  <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-zinc-500">
                    Response
                  </span>
                  {result.error && (
                    <span className="truncate font-mono text-[10px] text-rose-400">
                      {result.error}
                    </span>
                  )}
                </header>
                <div className="min-h-0 flex-1 overflow-auto p-3">
                  {responseView ? (
                    <SyntaxView
                      startLine={responseView.startLine}
                      headers={responseView.headers}
                      body={formatBody(responseView.body, responseView.contentType)}
                      contentType={responseView.contentType}
                      bodyBytes={responseView.bodyBytes}
                      originalBodyBytes={responseView.originalBodyBytes}
                      downloadName={suggestDownloadName(
                        responseView.contentType,
                        responseView.headers,
                        `prox0x-attack-${result.index + 1}-response`,
                      )}
                      viewKey={`attack-${result.index}-response`}
                    />
                  ) : (
                    <p className="text-xs text-rose-300">
                      {result.error ?? "Este intento no recibió respuesta."}
                    </p>
                  )}
                </div>
              </section>
            </>
          )}
        </div>

        <footer className="flex items-center justify-between border-t border-surface-800 px-5 py-2.5">
          <span className="font-mono text-[10px] text-zinc-600">
            Payload aplicado · petición y respuesta exactas
          </span>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-surface-700 px-3 py-1.5 text-xs text-zinc-400 transition hover:text-zinc-100"
          >
            Cerrar
          </button>
        </footer>
      </section>
    </div>,
    document.body,
  );
}
