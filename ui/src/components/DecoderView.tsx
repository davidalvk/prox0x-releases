import { useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  ArrowDownUp,
  Check,
  ClipboardCopy,
  Eraser,
  Loader2,
  Sparkles,
} from "lucide-react";
import { transform, type CodecMode } from "../lib/codec";

const MODE_OPTIONS: Array<{
  group: string;
  items: Array<{ value: CodecMode; label: string }>;
}> = [
  {
    group: "URL",
    items: [
      { value: "url-encode", label: "URL Encode" },
      { value: "url-decode", label: "URL Decode" },
    ],
  },
  {
    group: "Base64",
    items: [
      { value: "base64-encode", label: "Base64 Encode" },
      { value: "base64-decode", label: "Base64 Decode" },
    ],
  },
  {
    group: "Hex",
    items: [
      { value: "hex-encode", label: "Hex Encode" },
      { value: "hex-decode", label: "Hex Decode" },
    ],
  },
  {
    group: "Hash",
    items: [
      { value: "md5", label: "MD5" },
      { value: "sha1", label: "SHA-1" },
      { value: "sha256", label: "SHA-256" },
    ],
  },
  {
    group: "Utilidades",
    items: [{ value: "json-pretty", label: "JSON Pretty Print" }],
  },
];

const INVERSE_MODE: Partial<Record<CodecMode, CodecMode>> = {
  "url-encode": "url-decode",
  "url-decode": "url-encode",
  "base64-encode": "base64-decode",
  "base64-decode": "base64-encode",
  "hex-encode": "hex-decode",
  "hex-decode": "hex-encode",
};

const MODE_HINT: Record<CodecMode, string> = {
  "url-encode": "Percent-encoding de componentes de URL",
  "url-decode": "Revierte el percent-encoding",
  "base64-encode": "UTF-8 → Base64 estándar",
  "base64-decode": "Base64 estándar o URL-safe → UTF-8",
  "hex-encode": "UTF-8 → hexadecimal en minúsculas",
  "hex-decode": "Hexadecimal (con espacios, : o 0x) → UTF-8",
  md5: "Hash MD5 en hexadecimal (128 bits)",
  sha1: "Hash SHA-1 en hexadecimal (160 bits)",
  sha256: "Hash SHA-256 en hexadecimal (256 bits)",
  "json-pretty": "Formatea JSON con indentación de 2 espacios",
};

export function DecoderView() {
  const [mode, setMode] = useState<CodecMode>("base64-encode");
  const [input, setInput] = useState("");
  const [output, setOutput] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [copied, setCopied] = useState(false);
  const copyTimer = useRef<number | undefined>(undefined);

  useEffect(() => {
    let cancelled = false;
    setError(null);
    setCopied(false);

    if (input === "") {
      setOutput("");
      setRunning(false);
      return;
    }

    setRunning(true);
    void transform(mode, input)
      .then((result) => {
        if (!cancelled) setOutput(result);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setOutput("");
          setError(err instanceof Error ? err.message : "Transformación inválida");
        }
      })
      .finally(() => {
        if (!cancelled) setRunning(false);
      });

    return () => {
      cancelled = true;
    };
  }, [input, mode]);

  useEffect(
    () => () => {
      if (copyTimer.current !== undefined) window.clearTimeout(copyTimer.current);
    },
    [],
  );

  const copyOutput = async () => {
    if (!output) return;
    try {
      await navigator.clipboard.writeText(output);
      setCopied(true);
      if (copyTimer.current !== undefined) window.clearTimeout(copyTimer.current);
      copyTimer.current = window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setError("No se pudo escribir en el portapapeles.");
    }
  };

  const clear = () => {
    setInput("");
    setOutput("");
    setError(null);
    setCopied(false);
  };

  const swap = () => {
    if (!output) return;
    const previousOutput = output;
    const inverse = INVERSE_MODE[mode];
    setInput(previousOutput);
    if (inverse) setMode(inverse);
  };

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-3 border-b border-surface-800 bg-surface-900/40 px-5 py-3">
        <label
          htmlFor="codec-mode"
          className="text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-500"
        >
          Transformación
        </label>
        <select
          id="codec-mode"
          value={mode}
          onChange={(event) => setMode(event.target.value as CodecMode)}
          className="min-w-48 rounded-lg border border-surface-700 bg-surface-950 px-3 py-2 text-xs text-zinc-200 outline-none transition focus:border-accent/60"
        >
          {MODE_OPTIONS.map((group) => (
            <optgroup key={group.group} label={group.group}>
              {group.items.map((item) => (
                <option key={item.value} value={item.value}>
                  {item.label}
                </option>
              ))}
            </optgroup>
          ))}
        </select>

        <span className="hidden items-center gap-2 text-[11px] text-zinc-500 md:flex">
          <Sparkles size={13} className="text-accent" />
          {MODE_HINT[mode]}
        </span>

        <div className="ml-auto flex items-center gap-2">
          <button
            type="button"
            onClick={swap}
            disabled={!output}
            className="flex items-center gap-2 rounded-lg border border-surface-700 px-3 py-2 text-xs text-zinc-400 transition hover:border-surface-600 hover:text-zinc-100 disabled:opacity-40"
          >
            <ArrowDownUp size={14} />
            Intercambiar
          </button>
          <button
            type="button"
            onClick={clear}
            disabled={!input && !output}
            className="flex items-center gap-2 rounded-lg border border-surface-700 px-3 py-2 text-xs text-zinc-400 transition hover:border-surface-600 hover:text-zinc-100 disabled:opacity-40"
          >
            <Eraser size={14} />
            Limpiar
          </button>
          <button
            type="button"
            onClick={() => void copyOutput()}
            disabled={!output}
            className="flex items-center gap-2 rounded-lg bg-accent px-3 py-2 text-xs font-semibold text-surface-950 transition hover:bg-accent-soft disabled:opacity-40"
          >
            {copied ? <Check size={14} /> : <ClipboardCopy size={14} />}
            {copied ? "¡Copiado!" : "Copiar salida"}
          </button>
        </div>
      </div>

      {error && (
        <div
          role="alert"
          className="mx-5 mt-4 flex items-start gap-2 rounded-lg border border-rose-900/60 bg-rose-950/30 px-4 py-3 text-sm text-rose-300"
        >
          <AlertTriangle size={16} className="mt-0.5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <div className="grid min-h-0 flex-1 gap-4 overflow-auto p-4 md:grid-cols-2">
        <section className="flex min-h-64 flex-col overflow-hidden rounded-xl border border-surface-800 bg-surface-900/60">
          <header className="flex items-center justify-between border-b border-surface-800 px-4 py-2.5">
            <label
              htmlFor="decoder-input"
              className="text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-400"
            >
              Entrada
            </label>
            <span className="font-mono text-[10px] text-zinc-600">
              {input.length} caracteres
            </span>
          </header>
          <textarea
            id="decoder-input"
            value={input}
            onChange={(event) => setInput(event.target.value)}
            spellCheck={false}
            placeholder="Pega aquí el texto, JSON o payload a transformar…"
            className="min-h-56 flex-1 resize-none bg-surface-950/60 p-4 font-mono text-xs leading-relaxed text-zinc-200 outline-none placeholder:text-zinc-600 focus:bg-surface-950"
          />
        </section>

        <section className="flex min-h-64 flex-col overflow-hidden rounded-xl border border-surface-800 bg-surface-900/60">
          <header className="flex items-center justify-between border-b border-surface-800 px-4 py-2.5">
            <label
              htmlFor="decoder-output"
              className="text-[10px] font-semibold uppercase tracking-[0.16em] text-emerald-400"
            >
              Salida
            </label>
            <span className="flex items-center gap-2 font-mono text-[10px] text-zinc-600">
              {running && <Loader2 size={11} className="animate-spin text-accent" />}
              {output.length} caracteres
            </span>
          </header>
          <textarea
            id="decoder-output"
            value={output}
            readOnly
            spellCheck={false}
            placeholder="El resultado aparecerá aquí automáticamente."
            className="min-h-56 flex-1 resize-none bg-surface-950/60 p-4 font-mono text-xs leading-relaxed text-emerald-200 outline-none placeholder:text-zinc-600"
          />
        </section>
      </div>

      <div className="flex items-center justify-between border-t border-surface-800 bg-surface-900/40 px-5 py-2 text-[10px] text-zinc-600">
        <span>
          Las transformaciones se aplican en vivo y nunca salen del navegador.
        </span>
        <span aria-live="polite" className="text-emerald-400">
          {copied ? "Salida copiada al portapapeles" : ""}
        </span>
      </div>
    </div>
  );
}
