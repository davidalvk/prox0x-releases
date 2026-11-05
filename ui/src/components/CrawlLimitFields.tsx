interface CrawlLimitFieldsProps {
  depth: number;
  maxPages: number;
  unlimited: boolean;
  onDepthChange: (value: number) => void;
  onMaxPagesChange: (value: number) => void;
  onUnlimitedChange: (value: boolean) => void;
  /** Versión compacta para formularios con poco espacio vertical. */
  compact?: boolean;
  maxPagesLimit?: number;
}

const DEFAULT_MAX_PAGES_LIMIT = 10_000;

/**
 * Controles compartidos de profundidad, páginas máximas e ilimitado para los
 * tres módulos que usan el Crawler (Full Site Scan, CVEs y Mapa de Rutas).
 */
export function CrawlLimitFields({
  depth,
  maxPages,
  unlimited,
  onDepthChange,
  onMaxPagesChange,
  onUnlimitedChange,
  compact = false,
  maxPagesLimit = DEFAULT_MAX_PAGES_LIMIT,
}: CrawlLimitFieldsProps) {
  const labelClass = compact
    ? "text-[10px] text-zinc-500"
    : "text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-400";
  const inputClass = [
    "rounded-lg border border-surface-700 bg-surface-950 font-mono text-zinc-200 outline-none focus:border-accent disabled:cursor-not-allowed disabled:opacity-40",
    compact ? "w-14 px-1.5 py-0.5 text-[11px]" : "w-full px-2.5 py-2 text-sm",
  ].join(" ");

  const fields = (
    <>
      <label className="flex items-center gap-1.5">
        <span className={labelClass}>Profundidad</span>
        <input
          type="number"
          min={1}
          max={100}
          aria-label="Profundidad"
          value={depth}
          disabled={unlimited}
          onChange={(event) => onDepthChange(Number(event.target.value) || 1)}
          className={inputClass}
        />
      </label>
      <label className="flex items-center gap-1.5">
        <span className={labelClass}>Páginas máximas</span>
        <input
          type="number"
          min={1}
          max={maxPagesLimit}
          aria-label="Páginas máximas"
          value={maxPages}
          disabled={unlimited}
          onChange={(event) =>
            onMaxPagesChange(Number(event.target.value) || 1)
          }
          className={inputClass}
        />
      </label>
      <label className="flex items-center gap-1.5">
        <input
          type="checkbox"
          aria-label="Ilimitado"
          checked={unlimited}
          onChange={(event) => onUnlimitedChange(event.target.checked)}
          className="h-3.5 w-3.5 accent-cyan-400"
        />
        <span className={compact ? "text-[10px] text-zinc-400" : "text-xs text-zinc-300"}>
          Ilimitado
        </span>
      </label>
    </>
  );

  return (
    <div className={compact ? "space-y-1" : "space-y-2"}>
      <div
        className={
          compact
            ? "flex flex-wrap items-center gap-x-3 gap-y-1"
            : "grid grid-cols-1 gap-3 sm:grid-cols-3 sm:items-end"
        }
      >
        {fields}
      </div>
      {unlimited && (
        <p className="text-[10px] leading-snug text-amber-300">
          Sin límite de profundidad ni de páginas (máximo de seguridad:{" "}
          {maxPagesLimit.toLocaleString("es-ES")} URLs). Puede tardar mucho.
        </p>
      )}
    </div>
  );
}
