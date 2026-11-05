import { useEffect, useRef, useState } from "react";
import { Check, ClipboardCopy, Zap } from "lucide-react";
import { writeClipboard } from "../lib/clipboard";
import { HelpTooltip } from "./HelpTooltip";

interface FetchButtonProps {
  command: string;
}

export function FetchButton({ command }: FetchButtonProps) {
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => {
    setCopied(false);
    setError(null);
  }, [command]);

  useEffect(
    () => () => {
      if (timer.current !== undefined) window.clearTimeout(timer.current);
    },
    [],
  );

  const copy = async () => {
    if (!command) return;
    setError(null);
    try {
      await writeClipboard(command);
      setCopied(true);
      if (timer.current !== undefined) window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => setCopied(false), 2_000);
    } catch {
      setError("No se pudo copiar el código fetch.");
    }
  };

  return (
    <div className="flex items-center gap-1">
      <button
        type="button"
        onClick={() => void copy()}
        disabled={!command}
        title={
          error ??
          "Genera un fetch() de JavaScript equivalente a esta petición y cópialo"
        }
        className="flex items-center gap-2 rounded-lg border border-surface-700 bg-surface-850 px-3 py-2 text-xs text-zinc-300 transition hover:border-surface-600 hover:text-zinc-100 disabled:cursor-not-allowed disabled:opacity-40"
      >
        {copied ? (
          <Check size={14} className="text-emerald-400" />
        ) : (
          <Zap size={14} className="text-amber-300" />
        )}
        {copied ? "¡Copiado!" : "Copy as Fetch"}
      </button>
      <HelpTooltip
        label="Copy as Fetch"
        text="Genera un fetch() de JavaScript con método, cabeceras y cuerpo para replicar la petición desde la consola del navegador."
      />
      {error && (
        <span role="alert" className="text-[10px] text-rose-300">
          {error}
        </span>
      )}
      {copied && (
        <span
          role="status"
          className="flex items-center gap-1 text-[10px] text-emerald-300"
        >
          <ClipboardCopy size={11} />
          fetch copiado
        </span>
      )}
    </div>
  );
}
