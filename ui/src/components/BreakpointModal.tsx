import { useEffect, useMemo, useState } from "react";
import {
  ArrowRight,
  ChevronLeft,
  ChevronRight,
  Loader2,
  Radar,
  ShieldOff,
} from "lucide-react";
import {
  decodeBase64,
  dropBreakpoint,
  forwardBreakpoint,
  forwardFrameBreakpoint,
} from "../lib/api";
import { base64ToBytes, bytesToBase64 } from "../lib/binary";
import { useIntercept } from "../context/InterceptContext";

const POINT_LABELS: Record<string, string> = {
  request_received: "Request recibida",
  request_to_be_sent: "Request a enviar",
  response_received: "Response recibida",
  response_to_be_sent: "Response a enviar",
  websocket_frame: "Frame WebSocket",
};

function bytesToHex(bytes: Uint8Array): string {
  const lines: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    lines.push(
      [...bytes.subarray(offset, offset + 16)]
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join(" "),
    );
  }
  return lines.join("\n");
}

function hexToBytes(value: string): Uint8Array {
  const clean = value.replace(/\s+/g, "");
  if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) {
    throw new Error("El hex debe tener un número par de dígitos 0-9/a-f.");
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(clean.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

export function BreakpointModal() {
  const { pending, refreshPending } = useIntercept();
  const [index, setIndex] = useState(0);
  const [raw, setRaw] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (pending.length === 0) {
      setIndex(0);
      return;
    }
    if (index >= pending.length) {
      setIndex(Math.max(0, pending.length - 1));
    }
  }, [pending.length, index]);

  const current = useMemo(() => {
    if (pending.length === 0) return null;
    return pending[Math.min(index, pending.length - 1)];
  }, [pending, index]);

  const frame = current?.frame ?? null;
  const frameIsText = frame?.opcode === 0x1;

  useEffect(() => {
    if (!current) {
      setRaw("");
      return;
    }
    if (current.frame) {
      const bytes = base64ToBytes(current.frame.payload);
      setRaw(
        current.frame.opcode === 0x1 ? decodeBase64(current.frame.payload) : bytesToHex(bytes),
      );
    } else {
      // El hook normaliza los breakpoints, pero esta frontera sigue siendo
      // defensiva: nunca pasamos `undefined` al editor ni a `decodeBase64`.
      setRaw(decodeBase64(current.message?.raw ?? ""));
    }
    setError(null);
  }, [current?.id, current?.message?.raw, current?.frame?.payload, current?.frame?.opcode]);

  if (!current) return null;

  const resolve = async (action: "forward" | "drop") => {
    setBusy(true);
    setError(null);
    try {
      if (action === "forward") {
        if (current.frame) {
          let payload: Uint8Array;
          try {
            payload =
              current.frame.opcode === 0x1
                ? new TextEncoder().encode(raw)
                : hexToBytes(raw);
          } catch (err: unknown) {
            setError(
              err instanceof Error ? err.message : "Payload de frame inválido",
            );
            return;
          }
          await forwardFrameBreakpoint(current.id, bytesToBase64(payload));
        } else {
          await forwardBreakpoint(current.id, raw);
        }
      } else {
        await dropBreakpoint(current.id);
      }
      await refreshPending();
      if (index >= pending.length - 1) {
        setIndex(Math.max(0, pending.length - 2));
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "No se pudo resolver el breakpoint");
    } finally {
      setBusy(false);
    }
  };

  const title = current.frame
    ? `WS ${current.frame.direction === "client_to_server" ? "cliente → servidor" : "servidor → cliente"} · ${current.frame.opcode_name}`
    : current.kind === "request"
      ? `${current.method ?? "GET"} ${current.target ?? "/"}`
      : `${current.status ?? "?"} ${current.reason ?? ""}`.trim();

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
      <section className="terminal-modal flex h-[82vh] w-full max-w-5xl flex-col overflow-hidden rounded-2xl border border-amber-500/30 bg-surface-900 shadow-2xl">
        <header className="flex flex-wrap items-center gap-3 border-b border-surface-800 px-5 py-3">
          <div className="grid h-9 w-9 place-items-center rounded-lg bg-amber-500/15 text-amber-300">
            <Radar size={18} />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.16em] text-zinc-500">
              <span className="text-amber-300">Intercepción en pausa</span>
              <span>·</span>
              <span>{POINT_LABELS[current.point] ?? current.point}</span>
              <span>·</span>
              <span className="font-mono text-accent">flow #{current.flow_id}</span>
            </div>
            <h2 className="mt-0.5 truncate font-mono text-sm text-zinc-100">
              {title}
            </h2>
          </div>

          <div className="flex items-center gap-1 rounded-lg border border-surface-700 bg-surface-850 p-1">
            <button
              type="button"
              onClick={() => setIndex((value) => Math.max(0, value - 1))}
              disabled={index === 0}
              className="rounded p-1.5 text-zinc-400 hover:bg-surface-800 hover:text-zinc-100 disabled:opacity-30"
              aria-label="Breakpoint anterior"
            >
              <ChevronLeft size={15} />
            </button>
            <span className="min-w-16 text-center font-mono text-[11px] text-zinc-400">
              {index + 1} de {pending.length}
            </span>
            <button
              type="button"
              onClick={() =>
                setIndex((value) => Math.min(pending.length - 1, value + 1))
              }
              disabled={index >= pending.length - 1}
              className="rounded p-1.5 text-zinc-400 hover:bg-surface-800 hover:text-zinc-100 disabled:opacity-30"
              aria-label="Breakpoint siguiente"
            >
              <ChevronRight size={15} />
            </button>
          </div>
        </header>

        {error && (
          <div className="border-b border-rose-900/60 bg-rose-950/30 px-5 py-2 text-xs text-rose-300">
            {error}
          </div>
        )}

        <div className="flex min-h-0 flex-1 flex-col p-4">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
              {current.frame
                ? `Editor de frame (${frameIsText ? "texto" : "hex"})`
                : "Editor raw"}
            </span>
            <span className="font-mono text-[10px] text-zinc-600">
              {current.frame
                ? `${current.frame.direction} · ${current.frame.size} B · opcode ${current.frame.opcode}`
                : `${current.service} · ${raw.length} chars`}
            </span>
          </div>
          <textarea
            value={raw}
            onChange={(event) => setRaw(event.target.value)}
            spellCheck={false}
            className="min-h-0 flex-1 resize-none rounded-xl border border-surface-800 bg-surface-950 p-4 font-mono text-xs leading-relaxed text-zinc-300 outline-none focus:border-amber-500/50"
          />
        </div>

        <footer className="flex flex-wrap items-center justify-between gap-3 border-t border-surface-800 bg-surface-950/60 px-5 py-3">
          <p className="text-[11px] text-zinc-500">
            {current.frame
              ? frameIsText
                ? "Edita el texto del frame y pulsa Forward; Drop lo descarta."
                : "Edita el payload en hexadecimal y pulsa Forward; Drop lo descarta."
              : "Edita el mensaje y pulsa Forward; Drop lo descarta sin enviarlo."}
          </p>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => void resolve("drop")}
              disabled={busy}
              className="flex items-center gap-2 rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-2 text-xs font-semibold text-rose-300 transition hover:bg-rose-500/20 disabled:opacity-50"
            >
              <ShieldOff size={14} />
              Drop
            </button>
            <button
              type="button"
              onClick={() => void resolve("forward")}
              disabled={busy}
              className="flex items-center gap-2 rounded-lg bg-amber-400 px-4 py-2 text-xs font-semibold text-surface-950 transition hover:bg-amber-300 disabled:opacity-50"
            >
              {busy ? (
                <Loader2 size={14} className="animate-spin" />
              ) : (
                <ArrowRight size={14} />
              )}
              Forward
            </button>
          </div>
        </footer>
      </section>
    </div>
  );
}
