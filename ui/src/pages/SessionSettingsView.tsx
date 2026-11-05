import { useEffect, useMemo, useState } from "react";
import { KeyRound, Loader2, Save, ShieldCheck } from "lucide-react";
import type { FlowSummaryRecord } from "../types";
import { fetchFlows, fetchSession, flowPath, saveSession } from "../lib/api";
import { useApp } from "../context/AppContext";

export function SessionSettingsView() {
  const { currentProject } = useApp();
  const [flows, setFlows] = useState<FlowSummaryRecord[]>([]);
  const [loginFlowId, setLoginFlowId] = useState<string>("");
  const [tokenRegex, setTokenRegex] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{
    kind: "ok" | "error";
    text: string;
  } | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([fetchFlows(500), fetchSession()])
      .then(([flowList, config]) => {
        if (cancelled) return;
        setFlows(flowList);
        setLoginFlowId(
          config.login_flow_id === null ? "" : String(config.login_flow_id),
        );
        setTokenRegex(config.token_regex);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setMessage({
          kind: "error",
          text:
            err instanceof Error
              ? err.message
              : "No se pudo cargar la configuración",
        });
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [currentProject]);

  const options = useMemo(
    () =>
      flows.map((flow) => ({
        id: flow.id,
        label: `#${flow.id} · ${flow.request.method ?? "GET"} ${flowPath(flow)}`,
      })),
    [flows],
  );

  const save = async () => {
    setSaving(true);
    setMessage(null);
    try {
      const config = await saveSession({
        login_flow_id: loginFlowId ? Number(loginFlowId) : null,
        token_regex: tokenRegex,
      });
      setLoginFlowId(
        config.login_flow_id === null ? "" : String(config.login_flow_id),
      );
      setTokenRegex(config.token_regex);
      setMessage({
        kind: "ok",
        text: "Macro de login guardada para este proyecto.",
      });
    } catch (err: unknown) {
      setMessage({
        kind: "error",
        text:
          err instanceof Error
            ? err.message
            : "No se pudo guardar la macro de login",
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col overflow-auto bg-surface-950 p-5">
      <div className="mx-auto w-full max-w-4xl">
        <div className="flex items-start gap-3">
          <div className="grid h-11 w-11 place-items-center rounded-xl border border-accent/40 bg-accent/10 text-accent">
            <KeyRound size={20} />
          </div>
          <div>
            <h2 className="text-base font-bold text-zinc-100">
              Gestión de sesión
            </h2>
            <p className="mt-1 max-w-2xl text-xs text-zinc-500">
              Cuando Reenvío o Intrusión reciban un <strong>401</strong> o{" "}
              <strong>403</strong>, prox0x ejecutará esta macro de login,
              extraerá el token y reintentará la petición una vez.
            </p>
          </div>
        </div>

        {loading ? (
          <div className="mt-8 flex items-center text-sm text-zinc-500">
            <Loader2 size={18} className="mr-2 animate-spin text-accent" />
            Cargando configuración…
          </div>
        ) : (
          <div className="mt-6 space-y-5">
            <label className="block">
              <span className="mb-1 block text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
                Flujo de login
              </span>
              <select
                value={loginFlowId}
                onChange={(event) => setLoginFlowId(event.target.value)}
                aria-label="Flujo de login"
                className="w-full rounded-lg border border-surface-700 bg-surface-900 px-3 py-2.5 font-mono text-xs text-zinc-200 outline-none focus:border-accent/60"
              >
                <option value="">Sin macro de login</option>
                {options.map((option) => (
                  <option key={option.id} value={option.id}>
                    {option.label}
                  </option>
                ))}
              </select>
              <span className="mt-1 block text-[10px] text-zinc-600">
                Selecciona una petición de login guardada en el historial.
              </span>
            </label>

            <label className="block">
              <span className="mb-1 block text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
                Regex para extraer el token
              </span>
              <input
                value={tokenRegex}
                onChange={(event) => setTokenRegex(event.target.value)}
                spellCheck={false}
                aria-label="Regex para extraer el token"
                placeholder="(eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+)"
                className="w-full rounded-lg border border-surface-700 bg-surface-900 px-3 py-2.5 font-mono text-xs text-zinc-200 outline-none focus:border-accent/60"
              />
              <span className="mt-1 block text-[10px] text-zinc-600">
                Se busca primero en cabeceras Set-Cookie y después en el body.
                Si la regex tiene grupo de captura, se usa el grupo 1.
              </span>
            </label>

            <div className="rounded-lg border border-cyan-500/30 bg-cyan-950/20 p-4 text-xs text-cyan-200/80">
              <p className="flex items-center gap-2 font-semibold text-cyan-200">
                <ShieldCheck size={14} />
                Inyección automática
              </p>
              <p className="mt-1">
                Si el token viene de Set-Cookie se fusiona en la cabecera{" "}
                <code>Cookie</code>. Si viene del body se envía como{" "}
                <code>Authorization: Bearer …</code>. El reintento queda
                registrado en los logs como <code>session_renewed</code>.
              </p>
            </div>

            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={() => void save()}
                disabled={saving}
                className="flex items-center gap-2 rounded-lg bg-accent px-4 py-2.5 text-xs font-semibold text-surface-950 transition hover:bg-accent-soft disabled:opacity-60"
              >
                {saving ? (
                  <Loader2 size={14} className="animate-spin" />
                ) : (
                  <Save size={14} />
                )}
                Guardar macro
              </button>
              {message && (
                <span
                  role={message.kind === "error" ? "alert" : "status"}
                  className={
                    message.kind === "ok"
                      ? "text-xs text-emerald-300"
                      : "text-xs text-rose-300"
                  }
                >
                  {message.text}
                </span>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
