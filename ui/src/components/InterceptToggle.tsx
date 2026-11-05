import { useState } from "react";
import { Loader2, ShieldCheck, ShieldOff } from "lucide-react";
import { useIntercept } from "../context/InterceptContext";
import { HelpTooltip } from "./HelpTooltip";

export function InterceptToggle() {
  const { enabled, pending, connected, setEnabled, error } = useIntercept();
  const [busy, setBusy] = useState(false);

  const toggle = async () => {
    setBusy(true);
    try {
      await setEnabled(!enabled);
    } catch {
      // El hook ya expone el error; el botón vuelve a su estado anterior.
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex items-center gap-1">
      <button
        type="button"
        onClick={() => void toggle()}
        disabled={busy}
        title={
          error
            ? error
            : connected
              ? "Intercepción en pausa"
              : "Esperando al control plane de Interceptación…"
        }
        className={[
          "flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold transition disabled:opacity-60",
          enabled
            ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-300 shadow-[0_0_20px_-8px_rgba(16,185,129,0.8)]"
            : "border-surface-700 bg-surface-850 text-zinc-400 hover:text-zinc-200",
        ].join(" ")}
      >
        {busy ? (
          <Loader2 size={15} className="animate-spin" />
        ) : enabled ? (
          <ShieldCheck size={15} />
        ) : (
          <ShieldOff size={15} />
        )}
        <span>
          {enabled ? "Intercepción en pausa ON" : "Intercepción en pausa OFF"}
        </span>
        {pending.length > 0 && (
          <span className="grid h-5 min-w-5 place-items-center rounded-full bg-rose-500 px-1.5 font-mono text-[10px] font-bold text-white">
            {pending.length}
          </span>
        )}
        {!connected && (
          <span
            className="h-1.5 w-1.5 rounded-full bg-amber-400"
            title="WS desconectado"
          />
        )}
      </button>
      <HelpTooltip
        label="Intercepción en pausa"
        text="Pausa el tráfico en tiempo real. Si hay un Alcance definido, solo pausará las peticiones que estén dentro de él."
      />
    </div>
  );
}
