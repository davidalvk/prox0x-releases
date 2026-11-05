import { X } from "lucide-react";
import { SplitPane } from "./SplitPane";

interface RawMessageDetailProps {
  title: string;
  requestRaw: string | null;
  responseRaw: string | null;
  onClose: () => void;
}

function RawPane({
  label,
  text,
  tone,
}: {
  label: string;
  text: string | null;
  tone: "request" | "response";
}) {
  return (
    <section
      className="flex h-full min-h-0 flex-col overflow-hidden"
      aria-label={label}
    >
      <header className="flex items-center justify-between border-b border-surface-800 bg-surface-950/50 px-3 py-1.5">
        <span
          className={[
            "text-[10px] font-semibold uppercase tracking-[0.18em]",
            tone === "request" ? "text-emerald-400" : "text-cyan-400",
          ].join(" ")}
        >
          {label}
        </span>
        <span className="font-mono text-[10px] text-zinc-600">
          {text ? `${text.length} B` : "—"}
        </span>
      </header>
      <pre className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-words bg-surface-950 p-3 font-mono text-[11px] leading-relaxed text-zinc-300">
        {text || "—"}
      </pre>
    </section>
  );
}

export function RawMessageDetail({
  title,
  requestRaw,
  responseRaw,
  onClose,
}: RawMessageDetailProps) {
  return (
    <section
      className="flex h-full min-h-0 flex-col border-t border-surface-800 bg-surface-900/60"
      aria-label="Detalle de la interacción OOB"
    >
      <header className="flex items-center justify-between gap-3 border-b border-surface-800 px-4 py-2">
        <span className="truncate font-mono text-xs text-zinc-200">{title}</span>
        <button
          type="button"
          onClick={onClose}
          className="rounded-lg border border-surface-700 p-1.5 text-zinc-400 transition hover:border-surface-600 hover:text-zinc-100"
          aria-label="Cerrar detalle"
          title="Cerrar detalle"
        >
          <X size={14} />
        </button>
      </header>
      <SplitPane
        orientation="horizontal"
        label="Redimensionar petición y respuesta OOB"
        initial={50}
        min={25}
        max={75}
        first={
          <RawPane label="Request OOB" text={requestRaw} tone="request" />
        }
        second={
          <RawPane label="Response OOB" text={responseRaw} tone="response" />
        }
      />
    </section>
  );
}
