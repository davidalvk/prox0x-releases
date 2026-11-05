import { useMemo, useState } from "react";
import { ArrowLeftRight, GitCompare, Trash2 } from "lucide-react";
import { diffLines } from "../lib/diff";

export function ComparerView() {
  const [left, setLeft] = useState("");
  const [right, setRight] = useState("");
  const diff = useMemo(() => diffLines(left, right), [left, right]);

  return (
    <div className="flex h-full min-h-0 flex-col bg-surface-950">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-surface-800 px-5 py-3">
        <div>
          <h2 className="flex items-center gap-2 text-sm font-bold text-zinc-100">
            <GitCompare size={16} className="text-accent" />
            Comparador de textos
          </h2>
          <p className="mt-1 text-[11px] text-zinc-500">
            Pega dos peticiones o respuestas para ver las diferencias línea a línea.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="rounded border border-surface-700 bg-surface-900 px-2 py-1 font-mono text-[10px]">
            <span className="text-emerald-400">+{diff.added}</span>{" "}
            <span className="text-rose-400">-{diff.removed}</span>
          </span>
          <button
            type="button"
            onClick={() => {
              setLeft(right);
              setRight(left);
            }}
            className="flex items-center gap-2 rounded-lg border border-surface-700 bg-surface-850 px-3 py-2 text-xs text-zinc-300 transition hover:border-surface-600 hover:text-zinc-100"
          >
            <ArrowLeftRight size={14} />
            Intercambiar
          </button>
          <button
            type="button"
            onClick={() => {
              setLeft("");
              setRight("");
            }}
            className="flex items-center gap-2 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs font-semibold text-rose-300 transition hover:bg-rose-500/20"
          >
            <Trash2 size={14} />
            Limpiar
          </button>
        </div>
      </div>

      <div className="grid min-h-[220px] flex-[0_0_42%] grid-cols-1 border-b border-surface-800 md:grid-cols-2">
        <section className="flex min-h-0 flex-col border-b border-surface-800 md:border-b-0 md:border-r">
          <header className="border-b border-surface-800 bg-surface-900/60 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-cyan-300">
            Izquierda
          </header>
          <textarea
            aria-label="Texto izquierdo"
            value={left}
            onChange={(event) => setLeft(event.target.value)}
            spellCheck={false}
            placeholder="Pega aquí la primera petición o respuesta…"
            className="min-h-0 flex-1 resize-none bg-surface-950 p-3 font-mono text-[11px] leading-relaxed text-zinc-300 outline-none placeholder:text-zinc-600"
          />
        </section>
        <section className="flex min-h-0 flex-col">
          <header className="border-b border-surface-800 bg-surface-900/60 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-amber-300">
            Derecha
          </header>
          <textarea
            aria-label="Texto derecho"
            value={right}
            onChange={(event) => setRight(event.target.value)}
            spellCheck={false}
            placeholder="Pega aquí la segunda petición o respuesta…"
            className="min-h-0 flex-1 resize-none bg-surface-950 p-3 font-mono text-[11px] leading-relaxed text-zinc-300 outline-none placeholder:text-zinc-600"
          />
        </section>
      </div>

      <section className="flex min-h-0 flex-1 flex-col bg-surface-900/40">
        <header className="flex items-center justify-between border-b border-surface-800 bg-surface-900/60 px-3 py-1.5">
          <span className="text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-400">
            Diferencias
          </span>
          {diff.truncated && (
            <span className="text-[10px] text-amber-300">
              Texto muy grande: diff aproximado por prefijo/sufijo.
            </span>
          )}
        </header>
        <div
          data-testid="comparer-diff"
          className="min-h-0 flex-1 overflow-auto font-mono text-[11px] leading-relaxed"
        >
          {diff.lines.map((line, index) => (
            <div
              key={`${index}-${line.kind}`}
              className={[
                "flex min-w-max border-b border-surface-900/80",
                line.kind === "add"
                  ? "bg-emerald-950/30 text-emerald-300"
                  : line.kind === "remove"
                    ? "bg-rose-950/30 text-rose-300"
                    : "text-zinc-400",
              ].join(" ")}
            >
              <span className="w-12 shrink-0 select-none border-r border-surface-800 px-2 text-right text-zinc-600">
                {line.leftLine ?? ""}
              </span>
              <span className="w-12 shrink-0 select-none border-r border-surface-800 px-2 text-right text-zinc-600">
                {line.rightLine ?? ""}
              </span>
              <span className="w-6 shrink-0 select-none px-2 text-center">
                {line.kind === "add" ? "+" : line.kind === "remove" ? "-" : " "}
              </span>
              <span className="whitespace-pre px-1">{line.text || " "}</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
