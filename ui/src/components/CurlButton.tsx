import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Check, ClipboardCopy, Code2, Eye, X } from "lucide-react";
import { writeClipboard } from "../lib/clipboard";
import { HelpTooltip } from "./HelpTooltip";

interface CurlButtonProps {
  command: string;
}

export function CurlButton({ command }: CurlButtonProps) {
  const [copied, setCopied] = useState(false);
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const timer = useRef<number | undefined>(undefined);

  useEffect(
    () => () => {
      if (timer.current !== undefined) window.clearTimeout(timer.current);
    },
    [],
  );

  useEffect(() => {
    setCopied(false);
  }, [command]);

  const copy = async () => {
    if (!command) return;
    setError(null);
    try {
      await writeClipboard(command);
      setCopied(true);
      if (timer.current !== undefined) window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => setCopied(false), 2000);
    } catch {
      setError("No se pudo copiar el comando al portapapeles.");
      setOpen(true);
    }
  };

  return (
    <>
      <div className="flex items-center gap-1">
        <button
          type="button"
          onClick={() => void copy()}
          disabled={!command}
          title="Genera la petición como comando curl y cópiala"
          className="flex items-center gap-2 rounded-lg border border-surface-700 bg-surface-850 px-3 py-2 text-xs text-zinc-300 transition hover:border-surface-600 hover:text-zinc-100 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {copied ? (
            <Check size={14} className="text-emerald-400" />
          ) : (
            <Code2 size={14} className="text-accent" />
          )}
          {copied ? "¡Copiado!" : "Copy as cURL"}
        </button>
        <button
          type="button"
          onClick={() => setOpen(true)}
          disabled={!command}
          aria-label="Ver comando cURL"
          title="Ver comando cURL"
          className="rounded-lg border border-surface-700 p-2 text-zinc-400 transition hover:border-surface-600 hover:text-zinc-100 disabled:cursor-not-allowed disabled:opacity-40"
        >
          <Eye size={14} />
        </button>
        <HelpTooltip
          label="Copy as cURL"
          text="Genera el comando de terminal cURL exacto para replicar esta petición."
        />
      </div>

      {copied &&
        createPortal(
          <div
            role="status"
            className="fixed bottom-5 right-5 z-[70] flex items-center gap-2 rounded-lg border border-emerald-800/70 bg-emerald-950/90 px-4 py-2.5 text-xs font-medium text-emerald-200 shadow-2xl backdrop-blur"
          >
            <Check size={14} />
            ¡Comando cURL copiado!
          </div>,
          document.body,
        )}

      {open &&
        createPortal(
          <div
            className="fixed inset-0 z-[70] flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm"
            onClick={() => setOpen(false)}
            role="presentation"
          >
            <section
              role="region"
              aria-label="Comando cURL"
              onClick={(event) => event.stopPropagation()}
              className="terminal-modal flex max-h-[85vh] w-full max-w-3xl flex-col rounded-2xl border border-surface-700 bg-surface-900 shadow-2xl"
            >
              <header className="flex items-center justify-between border-b border-surface-800 px-5 py-4">
                <div>
                  <h2 className="flex items-center gap-2 text-sm font-semibold text-zinc-100">
                    <Code2 size={16} className="text-accent" />
                    Comando cURL
                  </h2>
                  <p className="mt-0.5 text-[11px] text-zinc-500">
                    Listo para pegar en Bash. Revísalo antes de ejecutarlo.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setOpen(false)}
                  className="rounded-lg border border-surface-700 p-2 text-zinc-400 transition hover:border-surface-600 hover:text-zinc-100"
                  aria-label="Cerrar comando cURL"
                >
                  <X size={16} />
                </button>
              </header>

              {error && (
                <div
                  role="alert"
                  className="mx-5 mt-4 rounded-lg border border-rose-900/60 bg-rose-950/30 px-3 py-2 text-xs text-rose-300"
                >
                  {error}
                </div>
              )}

              <pre className="m-5 max-h-[50vh] overflow-auto rounded-lg border border-surface-800 bg-surface-950 p-4 font-mono text-[11px] leading-relaxed text-emerald-200">
                {command}
              </pre>

              <footer className="flex items-center justify-between border-t border-surface-800 px-5 py-3">
                <p className="text-[10px] text-zinc-600">
                  Host y Content-Length se omiten: curl los calcula automáticamente.
                </p>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setOpen(false)}
                    className="rounded-lg border border-surface-700 px-3 py-2 text-xs text-zinc-400 transition hover:text-zinc-100"
                  >
                    Cerrar
                  </button>
                  <button
                    type="button"
                    onClick={() => void copy()}
                    className="flex items-center gap-2 rounded-lg bg-accent px-3 py-2 text-xs font-semibold text-surface-950 transition hover:bg-accent-soft"
                  >
                    {copied ? <Check size={14} /> : <ClipboardCopy size={14} />}
                    {copied ? "¡Copiado!" : "Copiar comando"}
                  </button>
                </div>
              </footer>
            </section>
          </div>,
          document.body,
        )}
    </>
  );
}
