import type {
  ActiveScanAttempt,
  ActiveScanBatchPayload,
  ActiveScanStatus,
  FullSiteScanPayload,
  AttackResultDetail,
  BreakpointRecord,
  CrawlPayload,
  CrawlStatus,
  DashboardStats,
  FlowListResponse,
  FlowRecord,
  FlowSummaryRecord,
  FindingRecord,
  HeaderView,
  InterceptStatus,
  IntruderJob,
  IntruderStartPayload,
  MessageRecord,
  MessageView,
  MatchReplaceRule,
  OOBConnectivityResult,
  OOBInteraction,
  OOBMode,
  OOBStatus,
  ProjectsResponse,
  RepeaterSendOptions,
  RepeaterSendResponse,
  ScopeAddResponse,
  ScopeConfig,
  SearchResultRecord,
  ServiceRecord,
  SessionConfig,
  SitemapTree,
  TemplateInfo,
  TemplateScanPayload,
  TemplateScanStatus,
  TemplateUpdateResult,
  UpdateStatus,
} from "../types";
import { base64ToBytes } from "./binary";

const API_BASE = "/api";

function defaultWsUrl(path: string): string {
  if (typeof window !== "undefined" && window.location.host) {
    const scheme = window.location.protocol === "https:" ? "wss" : "ws";
    return `${scheme}://${window.location.host}${path}`;
  }
  return `ws://127.0.0.1:8000${path}`;
}

export const WS_URL =
  import.meta.env.VITE_WS_URL ?? defaultWsUrl("/api/ws");
export const INTERCEPT_WS_URL =
  import.meta.env.VITE_INTERCEPT_WS_URL ??
  defaultWsUrl("/api/ws/intercept");
export const FINDINGS_WS_URL =
  import.meta.env.VITE_FINDINGS_WS_URL ?? defaultWsUrl("/api/ws/findings");
export const OOB_WS_URL =
  import.meta.env.VITE_OOB_WS_URL ?? defaultWsUrl("/api/ws/oob");
export const SCAN_WS_URL =
  import.meta.env.VITE_SCAN_WS_URL ?? defaultWsUrl("/api/ws/scan");

/** Campos mínimos compartidos por el resumen de tabla y el flujo completo. */
type FlowLocation = {
  service: ServiceRecord;
  request: { target?: string };
};

async function getJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, init);
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return (await response.json()) as T;
}

export async function fetchFlows(
  limit = 200,
  includeScanFlows = false,
): Promise<FlowSummaryRecord[]> {
  const params = new URLSearchParams({
    limit: String(limit),
    include_scan_flows: String(includeScanFlows),
  });
  const data = await getJson<FlowListResponse>(`/flows?${params.toString()}`);
  return data.flows;
}

export async function checkForUpdates(): Promise<UpdateStatus> {
  return getJson<UpdateStatus>("/updates/check");
}

export async function searchFlows(
  query: string,
  signal?: AbortSignal,
): Promise<SearchResultRecord[]> {
  const params = new URLSearchParams({ q: query, limit: "100" });
  const data = await getJson<{ results: SearchResultRecord[] }>(
    `/search?${params.toString()}`,
    { signal },
  );
  return data.results;
}

export async function fetchDashboardStats(): Promise<DashboardStats> {
  return getJson<DashboardStats>("/stats");
}

export async function fetchFlow(
  flowId: number,
  signal?: AbortSignal,
): Promise<FlowRecord> {
  return getJson<FlowRecord>(`/flows/${flowId}`, { signal });
}

export async function deleteFlows(): Promise<{ deleted: number }> {
  const response = await fetch(`${API_BASE}/flows`, { method: "DELETE" });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return (await response.json()) as { deleted: number };
}

export async function fetchFindings(filters?: {
  severity?: string;
  kind?: string;
  limit?: number;
}): Promise<FindingRecord[]> {
  const params = new URLSearchParams();
  if (filters?.severity) params.set("severity", filters.severity);
  if (filters?.kind) params.set("kind", filters.kind);
  params.set("limit", String(filters?.limit ?? 500));
  const data = await getJson<{ findings: FindingRecord[] }>(
    `/findings?${params.toString()}`,
  );
  return data.findings;
}

export async function deleteFindings(): Promise<{ deleted: number }> {
  const response = await fetch(`${API_BASE}/findings`, { method: "DELETE" });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return (await response.json()) as { deleted: number };
}

export async function startBatchScan(
  payload: ActiveScanBatchPayload,
): Promise<ActiveScanStatus> {
  return postJson<ActiveScanStatus>("/scan/batch", payload);
}

export async function startFullScan(
  payload: FullSiteScanPayload,
): Promise<ActiveScanStatus> {
  return postJson<ActiveScanStatus>("/scan/full", payload);
}

export async function fetchLatestScan(): Promise<ActiveScanStatus | null> {
  return getJson<ActiveScanStatus | null>("/scan/status");
}

export async function stopScan(scanId: string): Promise<ActiveScanStatus> {
  return postJson<ActiveScanStatus>(
    `/scan/stop/${encodeURIComponent(scanId)}`,
    {},
  );
}

export async function fetchScanStatus(
  scanId: string,
): Promise<ActiveScanStatus> {
  return getJson<ActiveScanStatus>(`/scan/status/${scanId}`);
}

export async function fetchScanAttempts(
  limit = 1_000,
  scanId?: string,
): Promise<ActiveScanAttempt[]> {
  const params = new URLSearchParams({ limit: String(limit) });
  if (scanId) params.set("scan_id", scanId);
  const data = await getJson<{ attempts: ActiveScanAttempt[] }>(
    `/scan/attempts?${params.toString()}`,
  );
  return data.attempts;
}

export async function deleteScanAttempts(): Promise<{ deleted: number }> {
  const response = await fetch(`${API_BASE}/scan/attempts`, {
    method: "DELETE",
  });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return (await response.json()) as { deleted: number };
}

export async function startTemplateScan(
  payload: TemplateScanPayload,
): Promise<TemplateScanStatus> {
  return postJson<TemplateScanStatus>("/scan/templates", payload);
}

export async function fetchLatestTemplateScan(): Promise<TemplateScanStatus | null> {
  return getJson<TemplateScanStatus | null>("/scan/templates/status");
}

export async function fetchActiveTemplateScan(): Promise<TemplateScanStatus | null> {
  return getJson<TemplateScanStatus | null>("/scan/templates/active");
}

export async function fetchTemplateScanStatus(
  scanId: string,
): Promise<TemplateScanStatus> {
  return getJson<TemplateScanStatus>(
    `/scan/templates/status/${encodeURIComponent(scanId)}`,
  );
}

export async function stopTemplateScan(
  scanId: string,
): Promise<TemplateScanStatus> {
  return postJson<TemplateScanStatus>(
    `/scan/templates/stop/${encodeURIComponent(scanId)}`,
    {},
  );
}

export async function updateNucleiTemplates(): Promise<TemplateUpdateResult> {
  return postJson<TemplateUpdateResult>("/templates/update", {});
}

export async function fetchTemplateTags(): Promise<string[]> {
  return getJson<string[]>("/templates/tags");
}

export async function fetchTemplateInfo(): Promise<TemplateInfo> {
  return getJson<TemplateInfo>("/templates/info");
}

export async function fetchSession(): Promise<SessionConfig> {
  return getJson<SessionConfig>("/session");
}

export async function saveSession(config: SessionConfig): Promise<SessionConfig> {
  return postJson<SessionConfig>("/session", config);
}

export async function fetchOOBStatus(): Promise<OOBStatus> {
  return getJson<OOBStatus>("/oob");
}

export async function setOOBMode(mode: OOBMode): Promise<OOBStatus> {
  return postJson<OOBStatus>("/oob/mode", { mode });
}

export async function testOOBConnectivity(): Promise<OOBConnectivityResult> {
  return postJson<OOBConnectivityResult>("/oob/test", {});
}

export async function fetchOOBInteractions(
  limit = 500,
): Promise<OOBInteraction[]> {
  const data = await getJson<{ interactions: OOBInteraction[] }>(
    `/oob/interactions?limit=${limit}`,
  );
  return data.interactions;
}

export async function deleteOOBInteractions(): Promise<{ deleted: number }> {
  const response = await fetch(`${API_BASE}/oob/interactions`, {
    method: "DELETE",
  });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return (await response.json()) as { deleted: number };
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const parsed = (await response.json()) as { detail?: string };
      if (parsed.detail) detail = parsed.detail;
    } catch {
      // sin JSON de error
    }
    throw new Error(detail);
  }
  return (await response.json()) as T;
}

export async function sendRepeater(
  flowId: number,
  rawRequest: string,
  options: RepeaterSendOptions,
): Promise<RepeaterSendResponse> {
  return postJson<RepeaterSendResponse>("/repeater/send", {
    flow_id: flowId,
    raw_request: rawRequest,
    mode: options.mode,
    count: options.count,
    concurrency: options.concurrency,
    delay_ms: options.delayMs,
  });
}

export async function startIntruder(
  payload: IntruderStartPayload,
): Promise<IntruderJob> {
  return postJson<IntruderJob>("/intruder/start", payload);
}

export async function fetchIntruderJob(attackId: string): Promise<IntruderJob> {
  return getJson<IntruderJob>(`/intruder/${encodeURIComponent(attackId)}`);
}

export async function fetchIntruderResult(
  attackId: string,
  index: number,
): Promise<AttackResultDetail> {
  return getJson<AttackResultDetail>(
    `/intruder/${encodeURIComponent(attackId)}/results/${index}`,
  );
}

export async function fetchInterceptPending(): Promise<BreakpointRecord[]> {
  const data = await getJson<{ pending: BreakpointRecord[] }>(
    "/intercept/pending",
  );
  return data.pending ?? [];
}

export async function toggleIntercept(
  enabled: boolean,
  points?: string[],
): Promise<InterceptStatus> {
  const data = await postJson<{ status: InterceptStatus }>("/intercept/toggle", {
    enabled,
    ...(points ? { points } : {}),
  });
  return data.status;
}

export async function forwardBreakpoint(
  breakpointId: string,
  rawMessage: string,
): Promise<void> {
  await postJson(`/intercept/pending/${encodeURIComponent(breakpointId)}/forward`, {
    raw_message: rawMessage,
  });
}

export async function forwardFrameBreakpoint(
  breakpointId: string,
  payloadBase64: string,
): Promise<void> {
  await postJson(`/intercept/pending/${encodeURIComponent(breakpointId)}/forward`, {
    frame_payload: payloadBase64,
  });
}

export async function dropBreakpoint(breakpointId: string): Promise<void> {
  await postJson(`/intercept/pending/${encodeURIComponent(breakpointId)}/drop`, {});
}

export async function fetchScope(): Promise<ScopeConfig> {
  const data = await getJson<{ scope: ScopeConfig }>("/scope");
  return data.scope;
}

export async function saveScope(scope: ScopeConfig): Promise<ScopeConfig> {
  const data = await postJson<{ scope: ScopeConfig }>("/scope", scope);
  return data.scope;
}

export async function addScopeHost(host: string): Promise<ScopeAddResponse> {
  return postJson<ScopeAddResponse>("/scope/add", { host });
}

export async function fetchSitemap(): Promise<SitemapTree> {
  return getJson<SitemapTree>("/sitemap");
}

export async function startCrawl(payload: CrawlPayload): Promise<CrawlStatus> {
  return postJson<CrawlStatus>("/crawl", payload);
}

export async function fetchCrawlStatus(
  crawlId?: string,
): Promise<CrawlStatus | null> {
  const path = crawlId
    ? `/crawl/status/${encodeURIComponent(crawlId)}`
    : "/crawl/status";
  return getJson<CrawlStatus | null>(path);
}

export async function fetchMatchReplace(): Promise<MatchReplaceRule[]> {
  const data = await getJson<{ rules: MatchReplaceRule[] }>("/match-replace");
  return data.rules ?? [];
}

export async function saveMatchReplace(
  rules: MatchReplaceRule[],
): Promise<MatchReplaceRule[]> {
  const data = await postJson<{ rules: MatchReplaceRule[] }>("/match-replace", {
    rules,
  });
  return data.rules ?? [];
}

export async function fetchProjects(): Promise<ProjectsResponse> {
  return getJson<ProjectsResponse>("/projects");
}

export async function fetchCurrentProject(): Promise<string> {
  const data = await getJson<{ name: string; current: string }>(
    "/projects/current",
  );
  return data.current ?? data.name;
}

export async function createProject(name: string): Promise<ProjectsResponse> {
  return postJson<ProjectsResponse>("/projects", { name });
}

export async function loadProject(name: string): Promise<ProjectsResponse> {
  return postJson<ProjectsResponse>("/projects/load", { name });
}

export async function deleteProject(name: string): Promise<ProjectsResponse> {
  const response = await fetch(
    `${API_BASE}/projects/${encodeURIComponent(name)}`,
    { method: "DELETE" },
  );
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const parsed = (await response.json()) as { detail?: string };
      if (parsed.detail) detail = parsed.detail;
    } catch {
      // sin JSON de error
    }
    throw new Error(detail);
  }
  return (await response.json()) as ProjectsResponse;
}

export function flowPathOnly(flow: FlowLocation): string {
  const group = flow.request.target ?? "/";
  const withoutQuery = group.split("?", 1)[0] || "/";
  return withoutQuery.startsWith("http")
    ? (() => {
        try {
          return new URL(withoutQuery).pathname || "/";
        } catch {
          return withoutQuery;
        }
      })()
    : withoutQuery;
}

export function decodeBase64(value: string): string {
  try {
    const binary = atob(value);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch {
    return "";
  }
}

export function parseHeaders(rawHead: string): HeaderView[] {
  const lines = rawHead.split(/\r?\n/).slice(1);
  return lines
    .map((line) => {
      const separator = line.indexOf(":");
      if (separator === -1) return null;
      return {
        name: line.slice(0, separator).trim(),
        value: line.slice(separator + 1).trim(),
      };
    })
    .filter((header): header is HeaderView => header !== null);
}

export function decodeMessage(message: MessageRecord | null | undefined): MessageView {
  if (!message) {
    return {
      startLine: "",
      headers: [],
      body: "",
      contentType: null,
      bodyBytes: new Uint8Array(),
      originalBodyBytes: new Uint8Array(),
    };
  }
  const originalBodyBytes = base64ToBytes(message.raw);
  const displayBodyBytes =
    message.display_raw && message.display_raw !== message.raw
      ? base64ToBytes(message.display_raw)
      : originalBodyBytes;
  return parseRawMessageBytes(displayBodyBytes, originalBodyBytes);
}

export function messageRaw(message: MessageRecord): string {
  return decodeBase64(message.display_raw ?? message.raw);
}

function findBodyStart(bytes: Uint8Array): number {
  for (let index = 0; index < bytes.length - 3; index += 1) {
    if (
      bytes[index] === 13 &&
      bytes[index + 1] === 10 &&
      bytes[index + 2] === 13 &&
      bytes[index + 3] === 10
    ) {
      return index + 4;
    }
  }
  for (let index = 0; index < bytes.length - 1; index += 1) {
    if (bytes[index] === 10 && bytes[index + 1] === 10) {
      return index + 2;
    }
  }
  return bytes.length;
}

function parseRawMessageBytes(
  bytes: Uint8Array,
  originalBytes: Uint8Array = bytes,
): MessageView {
  const bodyStart = findBodyStart(bytes);
  const originalBodyStart = findBodyStart(originalBytes);
  const head = new TextDecoder("iso-8859-1").decode(bytes.subarray(0, bodyStart));
  const bodyBytes = bytes.subarray(bodyStart);
  const originalBodyBytes = originalBytes.subarray(originalBodyStart);
  const startLine = head.split(/\r?\n/, 1)[0] ?? "";
  const headers = parseHeaders(head);
  const contentType =
    headers.find((header) => header.name.toLowerCase() === "content-type")
      ?.value ?? null;
  return {
    startLine,
    headers,
    body: new TextDecoder("utf-8", { fatal: false }).decode(bodyBytes),
    contentType,
    bodyBytes,
    originalBodyBytes,
  };
}

export function parseRawMessage(raw: string): MessageView {
  return parseRawMessageBytes(new TextEncoder().encode(raw));
}

export function formatBody(body: string, contentType: string | null): string {
  if (!body) return "";
  const trimmed = body.trim();
  const looksJson =
    (contentType?.toLowerCase().includes("json") ?? false) ||
    trimmed.startsWith("{") ||
    trimmed.startsWith("[");
  if (looksJson) {
    try {
      return JSON.stringify(JSON.parse(trimmed), null, 2);
    } catch {
      // El cuerpo no es JSON válido: se muestra tal cual.
    }
  }
  return body;
}

export function flowPath(flow: FlowLocation): string {
  const target = flow.request.target ?? "";
  if (target.startsWith("http://") || target.startsWith("https://")) {
    try {
      const url = new URL(target);
      return `${url.pathname}${url.search}`;
    } catch {
      return target;
    }
  }
  if (target.startsWith("ws://") || target.startsWith("wss://")) {
    try {
      const url = new URL(target);
      return `${url.pathname}${url.search}`;
    } catch {
      return target;
    }
  }
  return target || "/";
}

export function flowHost(flow: FlowLocation): string {
  const { host, port, secure } = flow.service;
  const defaultPort = secure ? 443 : 80;
  return port === defaultPort ? host : `${host}:${port}`;
}

export function formatTime(value: string): string {
  try {
    return new Date(value).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return "—";
  }
}

export function formatMs(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return `${value.toFixed(1)} ms`;
}

export function methodTone(method: string | undefined): string {
  switch ((method ?? "").toUpperCase()) {
    case "GET":
      return "text-emerald-400";
    case "POST":
      return "text-cyan-400";
    case "PUT":
    case "PATCH":
      return "text-amber-400";
    case "DELETE":
      return "text-rose-400";
    case "OPTIONS":
    case "HEAD":
      return "text-zinc-400";
    default:
      return "text-zinc-300";
  }
}

export function statusTone(status: number | undefined): string {
  if (status === undefined) return "text-zinc-500";
  if (status >= 200 && status < 300) return "text-emerald-400";
  if (status >= 300 && status < 400) return "text-cyan-400";
  if (status >= 400 && status < 500) return "text-amber-400";
  if (status >= 500) return "text-rose-400";
  return "text-zinc-300";
}
