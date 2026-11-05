import { useEffect, useMemo, useRef, useState } from "react";
import { Loader2, Search, X } from "lucide-react";
import type { SearchResultRecord } from "../types";
import { searchFlows } from "../lib/api";
import { useApp } from "../context/AppContext";

export function GlobalSearch() {
  const { setSelectedFlowId, setActiveModule } = useApp();
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResultRecord[]>([]);
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const clean = query.trim();
    if (clean.length < 2) {
      setResults([]);
      setOpen(false);
      setLoading(false);
      setError(null);
      return;
    }

    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      setLoading(true);
      setError(null);
      searchFlows(clean, controller.signal)
        .then((items) => {
          if (controller.signal.aborted) return;
          setResults(items);
          setOpen(true);
        })
        .catch((err: unknown) => {
          if (
            controller.signal.aborted ||
            (err as { name?: string } | null)?.name === "AbortError"
          ) {
            return;
          }
          setError(err instanceof Error ? err.message : "Búsqueda fallida");
          setOpen(true);
        })
        .finally(() => {
          if (!controller.signal.aborted) setLoading(false);
        });
    }, 280);

    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [query]);

  useEffect(() => {
    const onPointerDown = (event: PointerEvent) => {
      if (!containerRef.current?.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    window.addEventListener("pointerdown", onPointerDown);
    return () => window.removeEventListener("pointerdown", onPointerDown);
  }, []);

  const summary = useMemo(() => {
    if (loading) return "Buscando…";
    if (!query.trim() || query.trim().length < 2) return "";
    return `${results.length} resultado${results.length === 1 ? "" : "s"}`;
  }, [loading, query, results.length]);

  const openFlow = (result: SearchResultRecord) => {
    setSelectedFlowId(result.flow_id);
    setActiveModule("proxy");
    setOpen(false);
    setQuery("");
    setResults([]);
  };

  return (
    <div ref={containerRef} className="relative">
      <label className="flex items-center gap-2 rounded border border-surface-700 bg-surface-850 px-2.5 py-1.5 text-zinc-400 focus-within:border-accent/70">
        <Search size={14} className="shrink-0 text-cyan-400" />
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          onFocus={() => {
            if (query.trim().length >= 2) setOpen(true);
          }}
          onKeyDown={(event) => {
            if (event.key === "Escape") setOpen(false);
          }}
          placeholder="Buscar en cuerpos…"
          aria-label="Buscar en cuerpos"
          className="w-28 bg-transparent font-mono text-xs text-zinc-200 outline-none placeholder:text-zinc-600 2xl:w-52"
        />
        {query && (
          <button
            type="button"
            onClick={() => {
              setQuery("");
              setOpen(false);
            }}
            aria-label="Limpiar búsqueda"
            className="rounded p-0.5 text-zinc-500 hover:text-zinc-200"
          >
            <X size={12} />
          </button>
        )}
      </label>

      {open && (
        <div className="absolute right-0 top-full z-50 mt-2 w-[30rem] max-w-[90vw] overflow-hidden rounded-xl border border-surface-700 bg-surface-900 shadow-2xl">
          <div className="flex items-center justify-between border-b border-surface-800 px-3 py-2 text-[10px] uppercase tracking-[0.14em] text-zinc-500">
            <span>{summary}</span>
            {loading && <Loader2 size={12} className="animate-spin text-accent" />}
          </div>
          {error ? (
            <p className="px-3 py-3 text-xs text-rose-300">{error}</p>
          ) : results.length === 0 && !loading ? (
            <p className="px-3 py-3 text-xs text-zinc-500">
              Sin coincidencias en cuerpos de peticiones o respuestas.
            </p>
          ) : (
            <div className="max-h-96 overflow-auto">
              {results.map((result, index) => (
                <button
                  key={`${result.flow_id}-${result.location}-${index}`}
                  type="button"
                  data-testid="search-result"
                  onClick={() => openFlow(result)}
                  className="block w-full border-b border-surface-800/70 px-3 py-2 text-left transition last:border-b-0 hover:bg-surface-850"
                >
                  <div className="flex items-center gap-2 font-mono text-[10px] text-zinc-500">
                    <span className="text-accent">#{result.flow_id}</span>
                    <span
                      className={[
                        "rounded border px-1 py-0.5 uppercase",
                        result.location === "response"
                          ? "border-cyan-500/40 text-cyan-300"
                          : "border-emerald-500/40 text-emerald-300",
                      ].join(" ")}
                    >
                      {result.location === "response" ? "Resp" : "Req"}
                    </span>
                    <span className="truncate">{result.method ?? "—"}</span>
                    <span className="ml-auto truncate text-zinc-600">
                      {result.url}
                    </span>
                  </div>
                  <p className="mt-1 line-clamp-2 font-mono text-[11px] text-zinc-300">
                    {result.snippet}
                  </p>
                </button>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
