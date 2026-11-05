import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { Loader2, Save, SlidersHorizontal, X } from "lucide-react";
import { fetchScope, saveScope } from "../lib/api";
import { useApp } from "../context/AppContext";
import { HelpTooltip } from "./HelpTooltip";

function parseRules(value: string): string[] {
  return value
    .split(/\r?\n/)
    .map((rule) => rule.trim())
    .filter((rule) => rule.length > 0);
}

export function ScopeButton() {
  const { currentProject, notifyScopeChanged } = useApp();
  const [open, setOpen] = useState(false);
  const [include, setInclude] = useState("");
  const [exclude, setExclude] = useState("");
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ kind: "ok" | "error"; text: string } | null>(
    null,
  );

  useEffect(() => {
    const openScope = () => setOpen(true);
    window.addEventListener("prox0x:open-scope", openScope);
    return () => window.removeEventListener("prox0x:open-scope", openScope);
  }, []);

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    setLoading(true);
    setMessage(null);
    fetchScope()
      .then((scope) => {
        if (cancelled) return;
        setInclude(scope.include.join("\n"));
        setExclude(scope.exclude.join("\n"));
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setMessage({
            kind: "error",
            text: err instanceof Error ? err.message : "No se pudo cargar el Alcance",
          });
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [open, currentProject]);

  const save = async () => {
    setSaving(true);
    setMessage(null);
    try {
      const scope = await saveScope({
        include: parseRules(include),
        exclude: parseRules(exclude),
      });
      setInclude(scope.include.join("\n"));
      setExclude(scope.exclude.join("\n"));
      setMessage({ kind: "ok", text: "Alcance guardado correctamente." });
      notifyScopeChanged();
    } catch (err: unknown) {
      setMessage({
        kind: "error",
        text: err instanceof Error ? err.message : "No se pudo guardar el Alcance",
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <div className="flex items-center gap-1">
        <button
          type="button"
          onClick={() => setOpen(true)}
          className="flex items-center gap-2 rounded-lg border border-surface-700 bg-surface-850 px-3 py-2 text-xs text-zinc-400 transition hover:border-surface-600 hover:text-zinc-100"
        >
          <SlidersHorizontal size={15} />
          Alcance
        </button>
        <HelpTooltip
          label="Alcance"
          text="Define qué dominios o IPs te interesan. El resto del tráfico se ignorará."
        />
      </div>

      {open &&
        createPortal(
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm"
            onClick={() => setOpen(false)}
            role="presentation"
          >
          <section
            className="terminal-modal w-full max-w-2xl rounded-2xl border border-surface-700 bg-surface-900 shadow-2xl"
            onClick={(event) => event.stopPropagation()}
            aria-label="Configuración de Alcance"
          >
            <header className="flex items-center justify-between border-b border-surface-800 px-5 py-4">
              <div>
                <h2 className="text-sm font-semibold text-zinc-100">Alcance de auditoría</h2>
                <p className="mt-0.5 text-[11px] text-zinc-500">
                  Regex por línea. Prefijo <code className="font-mono text-accent">!</code> para excluir.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setOpen(false)}
                className="rounded-lg border border-surface-700 p-2 text-zinc-400 hover:text-zinc-100"
                aria-label="Cerrar Alcance"
              >
                <X size={16} />
              </button>
            </header>

            {loading ? (
              <div className="grid h-52 place-items-center text-zinc-500">
                <Loader2 size={20} className="animate-spin text-accent" />
              </div>
            ) : (
              <div className="grid gap-4 p-5 md:grid-cols-2">
                <label className="flex flex-col gap-1.5">
                  <span className="text-[10px] font-semibold uppercase tracking-[0.16em] text-emerald-400">
                    Incluir
                  </span>
                  <textarea
                    value={include}
                    onChange={(event) => setInclude(event.target.value)}
                    spellCheck={false}
                    placeholder={" .*\\.miobjetivo\\.com\n .*target\\.local"}
                    className="h-48 resize-y rounded-lg border border-surface-800 bg-surface-950 p-3 font-mono text-[11px] leading-relaxed text-zinc-300 outline-none placeholder:text-zinc-700 focus:border-emerald-500/50"
                  />
                </label>
                <label className="flex flex-col gap-1.5">
                  <span className="text-[10px] font-semibold uppercase tracking-[0.16em] text-rose-400">
                    Excluir
                  </span>
                  <textarea
                    value={exclude}
                    onChange={(event) => setExclude(event.target.value)}
                    spellCheck={false}
                    placeholder={" .*\\.google\\.com\n .*/static/.*"}
                    className="h-48 resize-y rounded-lg border border-surface-800 bg-surface-950 p-3 font-mono text-[11px] leading-relaxed text-zinc-300 outline-none placeholder:text-zinc-700 focus:border-rose-500/50"
                  />
                </label>
              </div>
            )}

            {message && (
              <div
                className={[
                  "mx-5 mb-3 rounded-lg border px-3 py-2 text-xs",
                  message.kind === "ok"
                    ? "border-emerald-900/60 bg-emerald-950/30 text-emerald-300"
                    : "border-rose-900/60 bg-rose-950/30 text-rose-300",
                ].join(" ")}
              >
                {message.text}
              </div>
            )}

            <footer className="flex items-center justify-between border-t border-surface-800 px-5 py-3">
              <p className="text-[10px] text-zinc-600">
                Sin reglas de inclusión se incluye todo excepto las exclusiones.
              </p>
              <button
                type="button"
                onClick={() => void save()}
                disabled={saving || loading}
                className="flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-xs font-semibold text-surface-950 transition hover:bg-accent-soft disabled:opacity-50"
              >
                {saving ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
                Guardar Alcance
              </button>
            </footer>
          </section>
        </div>,
          document.body,
        )}
    </>
  );
}
