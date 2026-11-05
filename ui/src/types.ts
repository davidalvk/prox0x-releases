export type ModuleId =
  | "home"
  | "proxy"
  | "repeater"
  | "intruder"
  | "findings"
  | "active-scan"
  | "comparer"
  | "settings"
  | "oob"
  | "sitemap"
  | "decoder"
  | "match-replace";

export interface RouteFilter {
  host: string;
  path: string;
}

export interface ScopeConfig {
  include: string[];
  exclude: string[];
}

export interface ScopeAddResponse {
  scope: ScopeConfig;
  rule: string;
  added: boolean;
}

export interface ProjectsResponse {
  current: string;
  projects: string[];
  name?: string;
}

export interface SitemapEntry {
  methods: string[];
  count: number;
}

export type SitemapTree = Record<string, Record<string, SitemapEntry>>;

export interface MessageRecord {
  raw: string;
  display_raw?: string;
  content_encoding?: string;
  method?: string;
  target?: string;
  version?: string;
  status?: number;
  reason?: string;
  /** Cuerpo omitido por superar el límite de visualización. */
  body_too_large?: boolean;
  size?: number;
  download_url?: string;
}

export interface ServiceRecord {
  host: string;
  port: number;
  secure: boolean;
}

export interface TimingRecord {
  sent_at: string;
  first_byte_at: string | null;
  completed_at: string | null;
  ttfb_ms: number | null;
  total_ms: number | null;
}

export interface WebSocketFrameRecord {
  direction: string;
  opcode: number;
  name: string;
  size: number;
  at: string;
}

export interface MessageSummaryRecord {
  method?: string;
  target?: string;
  version?: string;
  status?: number;
  reason?: string;
  content_encoding?: string;
  size?: number;
}

export interface FlowRecordBase<RequestT, ResponseT> {
  id: number;
  at: string;
  listener_port: number;
  source_ip: string;
  dest_ip: string;
  service: ServiceRecord;
  request: RequestT;
  response: ResponseT | null;
  edited: boolean;
  modified_by_rule?: boolean;
  mime: string;
  timing?: TimingRecord;
  websocket_frames?: WebSocketFrameRecord[];
  dropped?: boolean;
  drop_reason?: string | null;
  status?: number | "DROPPED" | null;
  in_scope?: boolean;
  is_scan_flow?: boolean;
  request_size?: number;
  response_size?: number;
  body_truncated?: boolean;
}

/** Fila de la tabla y evento WebSocket: sin cuerpos Base64. */
export type FlowSummaryRecord = FlowRecordBase<
  MessageSummaryRecord,
  MessageSummaryRecord
>;

/** Flujo completo obtenido bajo demanda con ``GET /api/flows/{id}``. */
export interface FlowRecord extends FlowRecordBase<MessageRecord, MessageRecord> {
  final_request?: MessageRecord;
}

export interface FlowListResponse {
  count: number;
  flows: FlowSummaryRecord[];
}

export interface DashboardStats {
  flows: number;
  findings: number;
  routes: number;
  scan_flows: number;
}

export type FindingSeverity = "high" | "medium" | "info";

export interface FindingRecord {
  id: number;
  flow_id: number;
  url: string;
  kind: string;
  severity: FindingSeverity;
  evidence: string;
  at: string;
}

export type ActiveScanState = "running" | "completed" | "failed";

export type ActiveScanMode = "batch" | "full";
export type ScanIntensity = "low" | "medium" | "high";
export type ActiveScanPhase =
  | "crawling"
  | "analyzing"
  | "scanning"
  | "completed"
  | "failed";

export interface ActiveScanStatus {
  scan_id: string;
  flow_id: number | null;
  flow_ids: number[];
  host: string | null;
  status: ActiveScanState;
  mode?: ActiveScanMode;
  phase?: ActiveScanPhase;
  seed_url?: string | null;
  intensity?: ScanIntensity;
  max_depth?: number;
  max_urls?: number;
  urls_found?: number;
  forms_found?: number;
  pages_found?: number;
  total: number;
  completed: number;
  progress: number;
  total_attempts: number;
  vulnerable: number;
  errors: number;
  findings: FindingRecord[];
  error: string | null;
  started_at: string;
  finished_at: string | null;
}

export type ScanAttemptResult = "vulnerable" | "safe" | "error";

export interface ActiveScanAttempt {
  id: number;
  scan_id: string;
  flow_id: number;
  url: string;
  parameter: string;
  location: string;
  attack: string;
  payload: string;
  status_code: number | null;
  result: ScanAttemptResult;
  evidence: string;
  evidence_match?: string | null;
  evidence_offset?: number | null;
  request_raw: string | null;
  response_raw: string | null;
  created_at: string;
}

export interface ActiveScanBatchPayload {
  flow_ids?: number[];
  host?: string;
  intensity?: ScanIntensity;
}

export interface FullSiteScanPayload {
  url: string;
  intensity?: ScanIntensity;
  custom_headers?: string;
  max_depth?: number;
  max_urls?: number;
}

export type CrawlState = "running" | "completed" | "failed";
export type CrawlPhase = "crawling" | "saving" | "completed" | "failed";

export interface CrawlStatus {
  crawl_id: string;
  seed_url: string;
  host: string | null;
  status: CrawlState;
  phase: CrawlPhase;
  max_urls: number;
  max_depth: number;
  urls_found: number;
  pages_found: number;
  forms_found: number;
  routes_saved: number;
  errors: number;
  progress: number;
  error: string | null;
  started_at: string;
  finished_at: string | null;
}

export interface CrawlPayload {
  url: string;
  max_urls?: number;
  max_depth?: number;
}

export type TemplateScanState = "running" | "completed" | "failed";

export interface TemplateScanResult {
  template_id: string;
  name: string;
  severity: string;
  tags: string[];
  url: string;
  method: string;
  status_code: number;
  matcher: string;
  evidence: string;
  extracted: Record<string, string[]>;
  flow_id: number;
}

export interface TemplateScanStatus {
  scan_id: string;
  url: string;
  tags: string[];
  max_templates: number;
  concurrency: number;
  throttle_ms: number;
  status: TemplateScanState;
  phase: string;
  crawl: boolean;
  auto_tech: boolean;
  max_depth: number;
  max_urls: number;
  detected_technologies: string[];
  detected_tags: string[];
  effective_tags: string[];
  tech_evidence: string[];
  tech_error: string | null;
  templates_total: number;
  templates_run: number;
  templates_skipped: number;
  urls_found: number;
  urls_total: number;
  urls_scanned: number;
  attacks_total: number;
  attacks_run: number;
  matches: number;
  errors: number;
  progress: number;
  results: TemplateScanResult[];
  skipped: Array<{ path: string; reason: string }>;
  error: string | null;
  started_at: string;
  finished_at: string | null;
}

export interface TemplateScanPayload {
  url: string;
  tags?: string[];
  max_templates?: number;
  concurrency?: number;
  throttle_ms?: number;
  crawl?: boolean;
  auto_tech?: boolean;
  max_depth?: number;
  max_urls?: number;
}

export interface TemplateUpdateResult {
  path: string;
  cloned: boolean;
  updated: boolean;
  templates: number;
  duration_ms: number;
  error: string | null;
}

export interface TemplateInfo {
  total_available: number;
  skipped: number;
}

export interface UpdateStatus {
  update_available: boolean;
  current_version?: string;
  latest_version?: string | null;
  download_url?: string | null;
  error?: string;
}

export interface SearchResultRecord {
  flow_id: number;
  url: string;
  at: string;
  method: string | null;
  status: number | null;
  location: "request" | "response";
  snippet: string;
}

export interface SessionConfig {
  login_flow_id: number | null;
  token_regex: string;
}

export type OOBMode = "local" | "online";

export interface OOBStatus {
  mode: OOBMode;
  callback_url: string;
  running: boolean;
  error: string | null;
  server: string | null;
  local_port: number;
}

export interface OOBConnectivityResult {
  ok: boolean;
  server: string | null;
  callback_url: string;
  detail: string;
  status_code?: number | null;
}

export interface OOBInteraction {
  id: number;
  mode: string;
  protocol: string;
  unique_id: string;
  full_id: string;
  remote_address: string;
  raw_request: string | null;
  raw_response: string | null;
  created_at: string;
}

export interface AttemptRecord {
  index: number;
  label: string;
  status: string;
  status_code: number | null;
  length: number;
  response_bytes: number;
  ttfb_ms: number | null;
  total_ms: number | null;
  latency_ms: number;
  error: string | null;
  request?: MessageRecord | null;
  response: MessageRecord | null;
}

export interface RepeaterSendResponse {
  flow_id: number;
  tab_id: number;
  attempts: AttemptRecord[];
}

export type RepeaterSendMode = "single" | "sequential" | "parallel";

export interface RepeaterSendOptions {
  mode: RepeaterSendMode;
  count: number;
  concurrency: number;
  delayMs: number;
}

export type MatchReplaceTarget = "request" | "response";
export type MatchReplaceLocation = "headers" | "body" | "all";

export interface MatchReplaceRule {
  id: string;
  target: MatchReplaceTarget;
  match: string;
  replace: string;
  location: MatchReplaceLocation;
  regex: boolean;
  enabled: boolean;
}

export type IntruderMode =
  | "sniper"
  | "battering_ram"
  | "pitchfork"
  | "cluster_bomb";

export interface AttackResultRecord {
  index: number;
  combo: Record<string, string>;
  label: string;
  status: string;
  status_code: number | null;
  length: number;
  ttfb_ms: number | null;
  total_ms: number | null;
  error: string | null;
  request?: MessageRecord | null;
  response?: MessageRecord | null;
}

export interface AttackResultDetail {
  attack_id: string;
  index: number;
  request: MessageRecord | null;
  response: MessageRecord | null;
}

export interface IntruderJob {
  attack_id: string;
  status: "running" | "completed" | "failed";
  expected: number;
  skipped: number;
  error: string | null;
  results: AttackResultRecord[];
  started_at?: string;
  finished_at?: string | null;
}

export interface IntruderStartPayload {
  flow_id: number;
  mode: IntruderMode;
  positions?: string[];
  raw_request?: string;
  payloads?: string[];
  payload_sets?: string[][];
  concurrency: number;
  throttle_ms: number;
  background: boolean;
}

export interface BreakpointMessage {
  kind: "request" | "response" | "message";
  raw: string;
  version?: string;
  headers?: HeaderView[];
  method?: string;
  target?: string;
  status?: number;
  reason?: string;
}

export interface BreakpointFrame {
  payload: string;
  size: number;
  opcode: number;
  opcode_name: string;
  direction: string;
  fin: boolean;
  masked: boolean;
}

export interface BreakpointRecord {
  id: string;
  flow_id: number;
  point: string;
  kind: string;
  service: string;
  listener_port: number;
  source_ip: string;
  dest_ip: string;
  created_at: string;
  size: number;
  method?: string;
  target?: string;
  status?: number;
  reason?: string;
  /**
   * La API/WS siempre envía un mensaje válido, pero toleramos `null` en la
   * frontera para que un backend antiguo o una carrera no rompa la UI.
   */
  message?: BreakpointMessage | null;
  frame?: BreakpointFrame | null;
}

export interface InterceptStatus {
  enabled: boolean;
  points: string[];
  pending: number;
  timeout_s: number;
  max_pending: number;
}

export interface HeaderView {
  name: string;
  value: string;
}

export interface MessageView {
  startLine: string;
  headers: HeaderView[];
  body: string;
  contentType: string | null;
  /** Cuerpo mostrado (descomprimido si había ``display_raw``). */
  bodyBytes: Uint8Array;
  /** Cuerpo original exacto, para descargar sin alterar nada. */
  originalBodyBytes: Uint8Array;
}
