import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  Check,
  Loader2,
  Plus,
  RefreshCw,
  Replace,
  Trash2,
} from "lucide-react";
import type {
  MatchReplaceLocation,
  MatchReplaceRule,
  MatchReplaceTarget,
} from "../types";
import { fetchMatchReplace, saveMatchReplace } from "../lib/api";
import { DATA_TABLE, DATA_TABLE_HEAD } from "../lib/tableStyles";
import { useApp } from "../context/AppContext";
import { HelpTooltip } from "./HelpTooltip";

const TARGET_LABEL: Record<MatchReplaceTarget, string> = {
  request: "Request",
  response: "Response",
};

const LOCATION_LABEL: Record<MatchReplaceLocation, string> = {
  headers: "Headers",
  body: "Body",
  all: "All",
};

function errorMessage(err: unknown, fallback: string): string {
  return err instanceof Error ? err.message : fallback;
}

export function MatchReplaceView() {
  const { currentProject } = useApp();
  const [rules, setRules] = useState<MatchReplaceRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [target, setTarget] = useState<MatchReplaceTarget>("request");
  const [location, setLocation] = useState<MatchReplaceLocation>("headers");
  const [regex, setRegex] = useState(false);
  const [match, setMatch] = useState("");
  const [replace, setReplace] = useState("");

  const load = useCallback(async () => {
    setError(null);
    setLoading(true);
    try {
      setRules(await fetchMatchReplace());
    } catch (err: unknown) {
      setError(errorMessage(err, "No se pudieron cargar las reglas"));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load, currentProject]);

  const commit = async (
    next: MatchReplaceRule[],
    message: string,
  ): Promise<boolean> => {
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      setRules(await saveMatchReplace(next));
      setNotice(message);
      return true;
    } catch (err: unknown) {
      setError(errorMessage(err, "No se pudieron guardar las reglas"));
      return false;
    } finally {
      setSaving(false);
    }
  };

  const addRule = async () => {
    if (!match.trim()) {
      setError("Match no puede estar vacío.");
      return;
    }
    const rule: MatchReplaceRule = {
      id: "",
      target,
      location,
      regex,
      match: match.trim(),
      replace,
      enabled: true,
    };
    const saved = await commit([...rules, rule], "Regla añadida.");
    if (saved) {
      setMatch("");
      setReplace("");
      setRegex(false);
    }
  };

  const toggleRule = async (rule: MatchReplaceRule) => {
    await commit(
      rules.map((item) =>
        item.id === rule.id ? { ...item, enabled: !item.enabled } : item,
      ),
      rule.enabled ? "Regla desactivada." : "Regla activada.",
    );
  };

  const deleteRule = async (rule: MatchReplaceRule) => {
    await commit(
      rules.filter((item) => item.id !== rule.id),
      "Regla eliminada.",
    );
  };

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-3 border-b border-surface-800 bg-surface-900/40 px-5 py-3">
        <span className="flex items-center gap-2 rounded-full border border-surface-700 bg-surface-850 px-3 py-1.5 text-[11px] text-zinc-400">
          <Replace size={14} className="text-accent" />
          {rules.length} reglas
        </span>
        <p className="text-xs text-zinc-500">
          Se aplican automáticamente antes de enviar la petición o la respuesta.
        </p>
        <button
          type="button"
          onClick={() => void load()}
          disabled={loading || saving}
          className="ml-auto flex items-center gap-2 rounded-lg border border-surface-700 px-3 py-2 text-xs text-zinc-400 transition hover:border-surface-600 hover:text-zinc-100 disabled:opacity-40"
        >
          <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
          Recargar
        </button>
      </div>

      <form
        onSubmit={(event) => {
          event.preventDefault();
          void addRule();
        }}
        className="flex flex-wrap items-end gap-3 border-b border-surface-800 bg-surface-900/20 px-5 py-3"
      >
        <label className="flex flex-col gap-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
          Target
          <select
            value={target}
            onChange={(event) =>
              setTarget(event.target.value as MatchReplaceTarget)
            }
            disabled={saving}
            className="min-w-28 rounded-lg border border-surface-700 bg-surface-950 px-2.5 py-2 text-xs normal-case tracking-normal text-zinc-200 outline-none focus:border-accent/60"
          >
            <option value="request">Request</option>
            <option value="response">Response</option>
          </select>
        </label>

        <label className="flex flex-col gap-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
          Location
          <select
            value={location}
            onChange={(event) =>
              setLocation(event.target.value as MatchReplaceLocation)
            }
            disabled={saving}
            className="min-w-28 rounded-lg border border-surface-700 bg-surface-950 px-2.5 py-2 text-xs normal-case tracking-normal text-zinc-200 outline-none focus:border-accent/60"
          >
            <option value="headers">Headers</option>
            <option value="body">Body</option>
            <option value="all">All</option>
          </select>
        </label>

        <div className="flex items-center gap-1.5 rounded-lg border border-surface-700 bg-surface-850 px-3 py-2 text-[11px] text-zinc-400">
          <label className="flex cursor-pointer items-center gap-2">
            <input
              type="checkbox"
              checked={regex}
              onChange={(event) => setRegex(event.target.checked)}
              disabled={saving}
              className="h-3.5 w-3.5 accent-emerald-400"
            />
            Regex
          </label>
          <HelpTooltip
            label="Regex"
            text="Si está activo, 'Match' se tratará como una expresión regular en lugar de texto exacto."
          />
        </div>

        <label className="flex min-w-48 flex-1 flex-col gap-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
          Match
          <input
            value={match}
            onChange={(event) => setMatch(event.target.value)}
            disabled={saving}
            spellCheck={false}
            placeholder="texto exacto o expresión regular"
            className="w-full rounded-lg border border-surface-700 bg-surface-950 px-3 py-2 font-mono text-xs normal-case tracking-normal text-zinc-200 outline-none placeholder:text-zinc-600 focus:border-accent/60"
          />
        </label>

        <label className="flex min-w-48 flex-1 flex-col gap-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
          Replace
          <input
            value={replace}
            onChange={(event) => setReplace(event.target.value)}
            disabled={saving}
            spellCheck={false}
            placeholder="texto de reemplazo"
            className="w-full rounded-lg border border-surface-700 bg-surface-950 px-3 py-2 font-mono text-xs normal-case tracking-normal text-zinc-200 outline-none placeholder:text-zinc-600 focus:border-accent/60"
          />
        </label>

        <button
          type="submit"
          disabled={saving || loading}
          className="flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-xs font-semibold text-surface-950 transition hover:bg-accent-soft disabled:cursor-not-allowed disabled:opacity-40"
        >
          {saving ? (
            <Loader2 size={14} className="animate-spin" />
          ) : (
            <Plus size={14} />
          )}
          Add Rule
        </button>
      </form>

      {(error || notice) && (
        <div className="px-5 pt-3">
          {error ? (
            <div
              role="alert"
              className="flex items-start gap-2 rounded-lg border border-rose-900/60 bg-rose-950/30 px-3 py-2 text-xs text-rose-300"
            >
              <AlertTriangle size={14} className="mt-0.5 shrink-0" />
              <span>{error}</span>
            </div>
          ) : (
            <div
              role="status"
              className="flex items-center gap-2 rounded-lg border border-emerald-900/60 bg-emerald-950/30 px-3 py-2 text-xs text-emerald-300"
            >
              <Check size={14} />
              {notice}
            </div>
          )}
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-auto">
        {loading ? (
          <div className="flex h-full items-center justify-center text-sm text-zinc-500">
            <Loader2 size={20} className="mr-2 animate-spin text-accent" />
            Cargando reglas…
          </div>
        ) : rules.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-3 text-center text-zinc-500">
            <Replace size={32} className="text-zinc-700" />
            <div>
              <p className="text-sm text-zinc-400">Sin reglas todavía</p>
              <p className="mt-1 max-w-md text-xs text-zinc-600">
                Añade una regla para reemplazar cabeceras o cuerpos en las
                peticiones y respuestas que pasen por Interceptación.
              </p>
            </div>
          </div>
        ) : (
          <table className={DATA_TABLE}>
            <thead className={DATA_TABLE_HEAD}>
              <tr className="border-b border-surface-800">
                <th className="w-24 px-3 py-2.5 font-medium">Target</th>
                <th className="w-24 px-2 py-2.5 font-medium">Ubicación</th>
                <th className="w-16 px-2 py-2.5 font-medium">Regex</th>
                <th className="px-2 py-2.5 font-medium">Match</th>
                <th className="px-2 py-2.5 font-medium">Replace</th>
                <th className="w-20 px-2 py-2.5 text-center font-medium">Estado</th>
                <th className="w-16 px-3 py-2.5 text-right font-medium">Acciones</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr
                  key={rule.id}
                  className={rule.enabled ? "" : "opacity-60"}
                >
                  <td className="px-3 py-2.5">
                    <span
                      className={[
                        "rounded border px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide",
                        rule.target === "request"
                          ? "border-emerald-800/70 bg-emerald-950/40 text-emerald-300"
                          : "border-cyan-800/70 bg-cyan-950/40 text-cyan-300",
                      ].join(" ")}
                    >
                      {TARGET_LABEL[rule.target]}
                    </span>
                  </td>
                  <td className="px-2 py-2.5 text-zinc-400">
                    {LOCATION_LABEL[rule.location]}
                  </td>
                  <td className="px-2 py-2.5 text-zinc-500">
                    {rule.regex ? "Sí" : "No"}
                  </td>
                  <td
                    className="truncate px-2 py-2.5 text-zinc-300"
                    title={rule.match}
                  >
                    {rule.match}
                  </td>
                  <td
                    className="truncate px-2 py-2.5 text-emerald-300"
                    title={rule.replace}
                  >
                    {rule.replace || "—"}
                  </td>
                  <td className="px-2 py-2.5 text-center">
                    <button
                      type="button"
                      role="switch"
                      aria-checked={rule.enabled}
                      aria-label={`${
                        rule.enabled ? "Desactivar" : "Activar"
                      } regla ${rule.match}`}
                      disabled={saving}
                      onClick={() => void toggleRule(rule)}
                      className={[
                        "relative inline-flex h-5 w-9 items-center rounded-full border transition disabled:opacity-40",
                        "hover:!bg-surface-950 hover:!border-accent/70",
                        rule.enabled
                          ? "border-emerald-500/60 bg-emerald-950"
                          : "border-surface-700 bg-surface-900",
                      ].join(" ")}
                    >
                      <span
                        className={[
                          "absolute h-3.5 w-3.5 rounded-full transition-all",
                          rule.enabled
                            ? "left-[18px] bg-accent shadow-glow"
                            : "left-0.5 bg-zinc-600",
                        ].join(" ")}
                      />
                    </button>
                  </td>
                  <td className="px-3 py-2.5 text-right">
                    <button
                      type="button"
                      disabled={saving}
                      onClick={() => void deleteRule(rule)}
                      aria-label={`Eliminar regla ${rule.match}`}
                      title="Eliminar regla"
                      className="rounded-lg border border-surface-700 p-1.5 text-zinc-500 transition hover:border-rose-500 hover:text-rose-300 disabled:opacity-40"
                    >
                      <Trash2 size={13} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
