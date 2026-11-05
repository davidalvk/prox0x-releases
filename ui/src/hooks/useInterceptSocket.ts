import { useCallback, useEffect, useState } from "react";
import type { BreakpointMessage, BreakpointRecord } from "../types";
import {
  INTERCEPT_WS_URL,
  fetchInterceptPending,
  toggleIntercept,
} from "../lib/api";

type InterceptEvent =
  | { type: "breakpoint"; breakpoint: BreakpointRecord }
  | { type: "resolved"; id: string; action: string }
  | { type: "status"; enabled: boolean; points?: string[]; pending?: number }
  | { type: "error"; detail: string };

function isBreakpointKind(
  value: unknown,
): value is BreakpointMessage["kind"] {
  return value === "request" || value === "response" || value === "message";
}

/**
 * Normaliza un breakpoint llegado del backend o del WebSocket.
 *
 * Nunca confiamos en la forma del payload: un mensaje ausente o corrupto se
 * convierte en `raw: ""` para que el modal muestre un editor vacío y el
 * usuario pueda hacer Drop, en lugar de romper el render. Si ni siquiera hay
 * identificador, el breakpoint se ignora.
 */
export function normalizeBreakpoint(value: unknown): BreakpointRecord | null {
  if (value === null || typeof value !== "object") return null;
  const candidate = value as Partial<BreakpointRecord>;
  if (typeof candidate.id !== "string" || candidate.id.length === 0) {
    return null;
  }

  const incoming = candidate.message;
  const source =
    incoming !== null && typeof incoming === "object" ? incoming : null;

  const message: BreakpointMessage = {
    kind: isBreakpointKind(source?.kind) ? source.kind : "message",
    raw: typeof source?.raw === "string" ? source.raw : "",
    version: source?.version,
    headers: Array.isArray(source?.headers) ? source.headers : undefined,
    method: source?.method,
    target: source?.target,
    status: source?.status,
    reason: source?.reason,
  };

  return { ...(candidate as BreakpointRecord), message };
}

function normalizePending(items: unknown): BreakpointRecord[] {
  if (!Array.isArray(items)) return [];
  const normalized: BreakpointRecord[] = [];
  for (const item of items) {
    const breakpoint = normalizeBreakpoint(item);
    if (breakpoint) {
      normalized.push(breakpoint);
    } else {
      console.warn("[prox0x] breakpoint ignorado por datos inválidos", item);
    }
  }
  return normalized;
}

export interface InterceptSocketState {
  enabled: boolean;
  pending: BreakpointRecord[];
  connected: boolean;
  error: string | null;
  setEnabled: (enabled: boolean) => Promise<void>;
  refreshPending: () => Promise<void>;
}

export function useInterceptSocket(): InterceptSocketState {
  const [enabled, setEnabledState] = useState(false);
  const [pending, setPending] = useState<BreakpointRecord[]>([]);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refreshPending = useCallback(async () => {
    try {
      const items = await fetchInterceptPending();
      setPending(normalizePending(items));
    } catch (err: unknown) {
      // La API/Proxy puede estar arrancando; el WS reconectará. No dejes
      // modales de breakpoints que ya no podemos confirmar.
      setPending([]);
      setError(err instanceof Error ? err.message : "No se pudo leer la cola");
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    let socket: WebSocket | null = null;
    let reconnectTimer: number | undefined;

    const upsert = (breakpoint: BreakpointRecord) => {
      const normalized = normalizeBreakpoint(breakpoint);
      if (!normalized) {
        console.warn(
          "[prox0x] breakpoint del WebSocket ignorado por datos inválidos",
          breakpoint,
        );
        return;
      }
      setPending((previous) => {
        const index = previous.findIndex(
          (item) => item.id === normalized.id,
        );
        if (index >= 0) {
          const copy = [...previous];
          copy[index] = normalized;
          return copy;
        }
        return [...previous, normalized];
      });
    };

    const connect = () => {
      if (cancelled) return;
      socket = new WebSocket(INTERCEPT_WS_URL);
      socket.onopen = () => {
        if (cancelled) return;
        setConnected(true);
        setError(null);
        void refreshPending();
      };
      socket.onmessage = (event) => {
        if (cancelled) return;
        try {
          const parsed = JSON.parse(event.data as string) as InterceptEvent;
          if (parsed.type === "breakpoint") {
            upsert(parsed.breakpoint);
          } else if (parsed.type === "resolved") {
            setPending((previous) =>
              previous.filter((item) => item.id !== parsed.id),
            );
          } else if (parsed.type === "status") {
            setEnabledState(parsed.enabled);
          } else if (parsed.type === "error") {
            setError(parsed.detail);
          }
        } catch {
          // Ignora mensajes no JSON.
        }
      };
      socket.onerror = () => socket?.close();
      socket.onclose = () => {
        if (cancelled) return;
        setConnected(false);
        // Los breakpoints del servidor pueden haber cambiado de proyecto o
        // desaparecido: no mantengas modales huérfanos en la UI.
        setPending([]);
        reconnectTimer = window.setTimeout(connect, 2000);
      };
    };

    void refreshPending();
    connect();
    return () => {
      cancelled = true;
      if (reconnectTimer !== undefined) window.clearTimeout(reconnectTimer);
      socket?.close();
    };
  }, [refreshPending]);

  const setEnabled = useCallback(async (next: boolean) => {
    setError(null);
    try {
      const status = await toggleIntercept(next);
      setEnabledState(status.enabled);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "No se pudo cambiar Intercept");
      throw err;
    }
  }, []);

  return {
    enabled,
    pending,
    connected,
    error,
    setEnabled,
    refreshPending,
  };
}
