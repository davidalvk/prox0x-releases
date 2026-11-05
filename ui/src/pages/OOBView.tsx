import { useCallback, useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  ClipboardCopy,
  Loader2,
  RadioTower,
  Trash2,
  Wifi,
} from "lucide-react";
import type {
  OOBConnectivityResult,
  OOBInteraction,
  OOBMode,
  OOBStatus,
} from "../types";
import {
  OOB_WS_URL,
  deleteOOBInteractions,
  fetchOOBInteractions,
  fetchOOBStatus,
  formatTime,
  setOOBMode,
  testOOBConnectivity,
} from "../lib/api";
import { writeClipboard } from "../lib/clipboard";
import { DATA_TABLE, DATA_TABLE_HEAD } from "../lib/tableStyles";
import { useApp } from "../context/AppContext";
import { RawMessageDetail } from "../components/RawMessageDetail";
import { SplitPane } from "../components/SplitPane";

export function OOBView() {
  const { currentProject } = useApp();
  const [status, setStatus] = useState<OOBStatus | null>(null);
  const [interactions, setInteractions] = useState<OOBInteraction[]>([]);
  const [loading, setLoading] = useState(true);
  const [switching, setSwitching] = useState(false);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<OOBConnectivityResult | null>(
    null,
  );
  const [selectedInteractionId, setSelectedInteractionId] = useState<
    number | null
  >(null);
  const copyTimer = useRef<number | undefined>(undefined);

  const selectedInteraction =
    interactions.find(
      (interaction) => interaction.id === selectedInteractionId,
    ) ?? null;

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [nextStatus, items] = await Promise.all([
        fetchOOBStatus(),
        fetchOOBInteractions(),
      ]);
      setStatus(nextStatus);
      setInteractions(items);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "No se pudo cargar OOB");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load, currentProject]);

  useEffect(() => {
    setSelectedInteractionId(null);
  }, [currentProject]);

  useEffect(() => {
    let stopped = false;
    let socket: WebSocket | null = null;
    let reconnectTimer: number | undefined;

    const connect = () => {
      if (stopped) return;
      socket = new WebSocket(OOB_WS_URL);
      socket.onopen = () => setConnected(true);
      socket.onmessage = (event) => {
        try {
          const interaction = JSON.parse(
            event.data as string,
          ) as OOBInteraction;
          setInteractions((previous) =>
            previous.some((item) => item.id === interaction.id)
              ? previous
              : [interaction, ...previous],
          );
        } catch {
          // Ignora mensajes no JSON.
        }
      };
      socket.onerror = () => socket?.close();
      socket.onclose = () => {
        setConnected(false);
        if (!stopped) reconnectTimer = window.setTimeout(connect, 2_000);
      };
    };

    connect();
    return () => {
      stopped = true;
      if (reconnectTimer !== undefined) window.clearTimeout(reconnectTimer);
      socket?.close();
    };
  }, [currentProject]);

  const changeMode = async (mode: OOBMode) => {
    setSwitching(true);
    setError(null);
    setTestResult(null);
    try {
      setStatus(await setOOBMode(mode));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "No se pudo cambiar el modo");
    } finally {
      setSwitching(false);
    }
  };

  const testConnectivity = async () => {
    setTesting(true);
    setError(null);
    setTestResult(null);
    try {
      const result = await testOOBConnectivity();
      setTestResult(result);
    } catch (err: unknown) {
      setError(
        err instanceof Error
          ? err.message
          : "No se pudo probar la conectividad OOB",
      );
    } finally {
      setTesting(false);
    }
  };

  const copyUrl = async () => {
    if (!status?.callback_url) return;
    try {
      await writeClipboard(status.callback_url);
      setCopied(true);
      if (copyTimer.current !== undefined) window.clearTimeout(copyTimer.current);
      copyTimer.current = window.setTimeout(() => setCopied(false), 2_000);
    } catch {
      setError("No se pudo copiar la URL de callback");
    }
  };

  const clear = async () => {
    try {
      await deleteOOBInteractions();
      setInteractions([]);
      setSelectedInteractionId(null);
    } catch (err: unknown) {
      setError(
        err instanceof Error ? err.message : "No se pudieron borrar las interacciones",
      );
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col bg-surface-950">
      <div className="flex flex-wrap items-end justify-between gap-3 border-b border-surface-800 px-5 py-3">
        <div>
          <h2 className="flex items-center gap-2 text-sm font-bold text-zinc-100">
            <RadioTower size={16} className="text-accent" />
            Interacciones OOB
          </h2>
          <p className="mt-1 text-[11px] text-zinc-500">
            {connected ? "live · ws conectado" : "reconectando…"} ·{" "}
            {interactions.length} interacción{interactions.length === 1 ? "" : "es"}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="flex rounded-lg border border-surface-700 bg-surface-900 p-1">
            {(["local", "online"] as const).map((mode) => (
              <button
                key={mode}
                type="button"
                onClick={() => void changeMode(mode)}
                disabled={switching}
                className={[
                  "rounded px-3 py-1.5 text-[11px] font-semibold transition disabled:opacity-50",
                  status?.mode === mode
                    ? "bg-accent text-surface-950"
                    : "text-zinc-400 hover:text-zinc-100",
                ].join(" ")}
              >
                {mode === "local" ? "Local :9999" : "Online (Interactsh)"}
              </button>
            ))}
          </div>
          <button
            type="button"
            onClick={() => void testConnectivity()}
            disabled={
              status?.mode !== "online" ||
              !status?.callback_url ||
              testing ||
              switching
            }
            title={
              status?.mode === "online"
                ? "Genera un callback real y comprueba si llega al servidor"
                : "Cambia a modo Online para probar la conectividad"
            }
            className="flex items-center gap-2 rounded-lg border border-cyan-400/40 bg-cyan-950/30 px-3 py-2 text-xs font-semibold text-cyan-300 transition hover:border-accent hover:text-accent disabled:cursor-not-allowed disabled:opacity-40"
          >
            {testing ? (
              <Loader2 size={14} className="animate-spin" />
            ) : (
              <Wifi size={14} />
            )}
            {testing ? "Probando…" : "Probar Conectividad"}
          </button>
          <button
            type="button"
            onClick={() => void clear()}
            disabled={interactions.length === 0}
            className="flex items-center gap-2 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs font-semibold text-rose-300 transition hover:bg-rose-500/20 disabled:opacity-40"
          >
            <Trash2 size={14} />
            Limpiar
          </button>
        </div>
      </div>

      {(error || status?.error) && (
        <div
          role="alert"
          className="border-b border-rose-900/60 bg-rose-950/30 px-5 py-2 text-xs text-rose-300"
        >
          {error ?? status?.error}
        </div>
      )}

      {testResult && (
        <div
          role="alert"
          data-testid="oob-connectivity-result"
          className={[
            "flex items-start gap-2 border-b px-5 py-2 text-xs",
            testResult.ok
              ? "border-emerald-900/60 bg-emerald-950/30 text-emerald-300"
              : "border-amber-900/60 bg-amber-950/30 text-amber-300",
          ].join(" ")}
        >
          {testResult.ok ? (
            <CheckCircle2 size={15} className="mt-0.5 shrink-0" />
          ) : (
            <AlertTriangle size={15} className="mt-0.5 shrink-0" />
          )}
          <div>
            <p className="font-semibold">
              {testResult.ok
                ? "Conectividad OOB correcta"
                : "Prueba de conectividad fallida"}
            </p>
            <p className="mt-0.5 text-[11px] opacity-90">
              {testResult.ok
                ? `Callback verificado vía ${testResult.server ?? "Interactsh"}${
                    testResult.status_code
                      ? ` (HTTP ${testResult.status_code})`
                      : ""
                  }.`
                : testResult.detail}
            </p>
          </div>
        </div>
      )}

      <div className="border-b border-surface-800 bg-surface-900/40 px-5 py-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
            URL de callback
          </span>
          {switching ? (
            <Loader2 size={14} className="animate-spin text-accent" />
          ) : null}
          <input
            readOnly
            value={status?.callback_url ?? ""}
            aria-label="URL de callback OOB"
            placeholder="Cambiando de modo…"
            className="min-w-0 flex-1 rounded-lg border border-surface-700 bg-surface-950 px-3 py-2 font-mono text-xs text-cyan-300 outline-none"
          />
          <button
            type="button"
            onClick={() => void copyUrl()}
            disabled={!status?.callback_url}
            className="flex items-center gap-2 rounded-lg border border-surface-700 bg-surface-850 px-3 py-2 text-xs text-zinc-300 transition hover:border-accent hover:text-accent disabled:opacity-40"
          >
            {copied ? (
              <Check size={14} className="text-emerald-400" />
            ) : (
              <ClipboardCopy size={14} />
            )}
            {copied ? "Copiada" : "Copiar"}
          </button>
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-2 text-[10px]">
          <span className="font-semibold uppercase tracking-[0.16em] text-zinc-600">
            Servidor Interactsh
          </span>
          {status?.mode === "online" ? (
            <span className="rounded border border-cyan-500/40 bg-cyan-950/30 px-2 py-0.5 font-mono text-cyan-300">
              {status.server ?? "sin registrar"}
            </span>
          ) : (
            <span className="text-zinc-600">— modo local —</span>
          )}
        </div>
        <p className="mt-2 text-[10px] text-zinc-600">
          Usa esta URL en payloads SSRF, XXE, XSS ciego, SQLi OOB, etc. Las
          interacciones se guardan en el proyecto activo.
        </p>
      </div>

      <SplitPane
        orientation="vertical"
        label="Redimensionar interacciones y detalle OOB"
        initial={55}
        min={25}
        max={80}
        first={
          <div className="h-full min-h-0 overflow-auto">
            {loading ? (
              <div className="flex h-full items-center justify-center text-sm text-zinc-500">
                <Loader2 size={20} className="mr-2 animate-spin text-accent" />
                Cargando interacciones…
              </div>
            ) : interactions.length === 0 ? (
              <div className="flex h-full flex-col items-center justify-center gap-3 text-center text-zinc-500">
                <RadioTower size={34} className="text-zinc-700" />
                <div>
                  <p className="text-sm text-zinc-400">
                    Sin interacciones todavía
                  </p>
                  <p className="mt-1 max-w-md text-xs text-zinc-600">
                    Copia la URL de callback y úsala en un payload. Cualquier
                    DNS, HTTP o SMTP recibido aparecerá aquí.
                  </p>
                </div>
              </div>
            ) : (
              <table className={DATA_TABLE}>
                <thead className={DATA_TABLE_HEAD}>
                  <tr className="border-b border-surface-800">
                    <th className="w-20 px-4 py-2.5 font-medium">Protocolo</th>
                    <th className="w-40 px-2 py-2.5 font-medium">Origen</th>
                    <th className="w-64 px-2 py-2.5 font-medium">ID</th>
                    <th className="px-2 py-2.5 font-medium">Solicitud</th>
                    <th className="w-24 px-4 py-2.5 text-right font-medium">
                      Hora
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {interactions.map((interaction) => (
                    <tr
                      key={interaction.id}
                      onClick={() => setSelectedInteractionId(interaction.id)}
                      className={[
                        "cursor-pointer border-b border-surface-800/70 align-top transition",
                        selectedInteractionId === interaction.id
                          ? "bg-accent/10"
                          : "hover:bg-surface-850",
                      ].join(" ")}
                      title="Ver el detalle de la interacción"
                    >
                      <td className="px-4 py-2.5">
                        <span className="rounded border border-cyan-500/40 bg-cyan-950/30 px-1.5 py-0.5 text-[9px] font-bold uppercase text-cyan-300">
                          {interaction.protocol || "?"}
                        </span>
                      </td>
                      <td className="truncate px-2 py-2.5 text-zinc-300">
                        {interaction.remote_address || "—"}
                      </td>
                      <td
                        className="truncate px-2 py-2.5 text-zinc-500"
                        title={interaction.full_id}
                      >
                        {interaction.full_id || interaction.unique_id || "—"}
                      </td>
                      <td
                        className="truncate px-2 py-2.5 text-zinc-400"
                        title={interaction.raw_request ?? ""}
                      >
                        {interaction.raw_request
                          ? interaction.raw_request
                              .replace(/\s+/g, " ")
                              .slice(0, 300)
                          : "—"}
                      </td>
                      <td className="px-4 py-2.5 text-right text-zinc-500">
                        {formatTime(interaction.created_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        }
        second={
          selectedInteraction ? (
            <RawMessageDetail
              title={`${selectedInteraction.protocol || "?"} · ${
                selectedInteraction.full_id ||
                selectedInteraction.unique_id ||
                `#${selectedInteraction.id}`
              }`}
              requestRaw={selectedInteraction.raw_request}
              responseRaw={selectedInteraction.raw_response}
              onClose={() => setSelectedInteractionId(null)}
            />
          ) : (
            <div className="flex h-full flex-col items-center justify-center gap-2 border-t border-surface-800 bg-surface-900/40 text-center text-zinc-600">
              <RadioTower size={26} className="text-zinc-700" />
              <p className="text-[10px] uppercase tracking-[0.18em] text-zinc-500">
                Detalle de la interacción
              </p>
              <p className="max-w-md text-[11px]">
                Selecciona una interacción para ver la solicitud y la respuesta
                completas.
              </p>
            </div>
          )
        }
      />
    </div>
  );
}
