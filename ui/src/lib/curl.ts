import type { FlowRecord, MessageRecord } from "../types";
import { bytesToBase64 } from "./binary";

export interface CurlService {
  host: string;
  port: number;
  secure: boolean;
}

interface ParsedRequest {
  method: string;
  target: string;
  headers: Array<{ name: string; value: string }>;
  body: Uint8Array;
}

/** Cabeceras que curl genera o gestiona por su cuenta. */
const SKIPPED_HEADERS = new Set([
  "host",
  "content-length",
  "transfer-encoding",
  "connection",
  "proxy-connection",
  "keep-alive",
]);

function decodeBase64Bytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function splitHeadAndBody(bytes: Uint8Array): {
  head: Uint8Array;
  body: Uint8Array;
} {
  for (let index = 0; index < bytes.length - 3; index += 1) {
    if (
      bytes[index] === 0x0d &&
      bytes[index + 1] === 0x0a &&
      bytes[index + 2] === 0x0d &&
      bytes[index + 3] === 0x0a
    ) {
      return {
        head: bytes.slice(0, index),
        body: bytes.slice(index + 4),
      };
    }
  }
  for (let index = 0; index < bytes.length - 1; index += 1) {
    if (bytes[index] === 0x0a && bytes[index + 1] === 0x0a) {
      return {
        head: bytes.slice(0, index),
        body: bytes.slice(index + 2),
      };
    }
  }
  return { head: bytes, body: new Uint8Array() };
}

/** Token HTTP válido según RFC 9110 §5.6.2 (tchar). */
const HTTP_TOKEN_RE = /^[!#$%&'*+\-.^_|~0-9A-Za-z]+$/;

function sanitizeMethod(raw: string): string {
  const trimmed = raw.trim().toUpperCase();
  return HTTP_TOKEN_RE.test(trimmed) ? trimmed : "GET";
}

function parseRequest(bytes: Uint8Array): ParsedRequest {
  const { head, body } = splitHeadAndBody(bytes);
  const lines = new TextDecoder("utf-8", { fatal: false })
    .decode(head)
    .split(/\r?\n/);
  const requestLine = (lines[0]?.trim() ?? "").replace(/\s+HTTP\/[\d.]+$/i, "");
  const lastSpace = requestLine.search(/\s+\S+$/);
  const rawMethod =
    lastSpace >= 0 ? requestLine.slice(0, lastSpace) : requestLine || "GET";
  const rawTarget =
    lastSpace >= 0 ? requestLine.slice(lastSpace).trim() : "/";
  const method = sanitizeMethod(rawMethod);
  const target = rawTarget || "/";

  const headers: Array<{ name: string; value: string }> = [];
  for (const line of lines.slice(1)) {
    if (!line) continue;
    const separator = line.indexOf(":");
    if (separator <= 0) continue;
    const name = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    if (!name || name.startsWith(":")) continue;
    headers.push({ name, value });
  }

  return { method, target, headers, body };
}

function formatAuthority(service: CurlService): string {
  const host =
    service.host.includes(":") && !service.host.startsWith("[")
      ? `[${service.host}]`
      : service.host;
  const defaultPort = service.secure ? 443 : 80;
  return service.port === defaultPort ? host : `${host}:${service.port}`;
}

function absoluteUrl(target: string, service: CurlService): string {
  if (/^(?:https?|wss?):\/\//i.test(target)) return target;
  const scheme = service.secure ? "https" : "http";
  const path = target.startsWith("/") ? target : `/${target}`;
  return `${scheme}://${formatAuthority(service)}${path}`;
}

/** Comillas simples de Bash: cierra, escapa y reabre para cada `'`. */
function shellQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

/** Cuerpo binario como $'...' con bytes no imprimibles en hexadecimal. */
function ansiCQuote(bytes: Uint8Array): string {
  let output = "$'";
  for (const byte of bytes) {
    if (byte === 0x5c) {
      output += "\\\\";
    } else if (byte === 0x27) {
      output += "\\'";
    } else if (byte === 0x0a) {
      output += "\\n";
    } else if (byte === 0x0d) {
      output += "\\r";
    } else if (byte === 0x09) {
      output += "\\t";
    } else if (byte >= 0x20 && byte <= 0x7e) {
      output += String.fromCharCode(byte);
    } else {
      output += `\\x${byte.toString(16).padStart(2, "0")}`;
    }
  }
  return `${output}'`;
}

function isTextBody(body: Uint8Array): boolean {
  for (const byte of body) {
    const isAllowedControl = byte === 0x09 || byte === 0x0a || byte === 0x0d;
    if ((byte < 0x20 && !isAllowedControl) || byte === 0x7f) return false;
  }
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(body);
    return true;
  } catch {
    return false;
  }
}

function buildFromParsed(parsed: ParsedRequest, service: CurlService): string {
  const lines: string[] = [];
  const method = sanitizeMethod(parsed.method || "GET");
  const url = absoluteUrl(parsed.target || "/", service);

  let firstLine = "curl";
  if (method !== "GET") firstLine += ` -X ${shellQuote(method)}`;
  firstLine += ` --url ${shellQuote(url)}`;
  lines.push(firstLine);

  for (const header of parsed.headers) {
    if (SKIPPED_HEADERS.has(header.name.toLowerCase())) continue;
    lines.push(`-H ${shellQuote(`${header.name}: ${header.value}`)}`);
  }

  if (parsed.body.length > 0) {
    if (isTextBody(parsed.body)) {
      const body = new TextDecoder("utf-8", { fatal: false }).decode(parsed.body);
      lines.push(`--data-raw ${shellQuote(body)}`);
    } else {
      lines.push(`--data-binary ${ansiCQuote(parsed.body)}`);
    }
  }

  return lines.join(" \\\n  ");
}

function buildFetchFromParsed(
  parsed: ParsedRequest,
  service: CurlService,
): string {
  const method = sanitizeMethod(parsed.method || "GET");
  const url = absoluteUrl(parsed.target || "/", service);
  const headers = parsed.headers.filter(
    (header) => !SKIPPED_HEADERS.has(header.name.toLowerCase()),
  );

  const lines: string[] = [
    `fetch(${JSON.stringify(url)}, {`,
    `  method: ${JSON.stringify(method)},`,
    "  headers: {",
  ];
  for (const header of headers) {
    lines.push(
      `    ${JSON.stringify(header.name)}: ${JSON.stringify(header.value)},`,
    );
  }
  lines.push("  },");

  if (parsed.body.length > 0) {
    if (isTextBody(parsed.body)) {
      const body = new TextDecoder("utf-8", { fatal: false }).decode(
        parsed.body,
      );
      lines.push(`  body: ${JSON.stringify(body)},`);
    } else {
      lines.push(
        `  body: Uint8Array.from(atob(${JSON.stringify(
          bytesToBase64(parsed.body),
        )}), (char) => char.charCodeAt(0)),`,
      );
    }
  }
  lines.push("})");
  return lines.join("\n");
}

/** Genera código ``fetch`` desde una petición HTTP cruda. */
export function buildFetchFromRaw(raw: string, service: CurlService): string {
  return buildFetchFromParsed(parseRequest(new TextEncoder().encode(raw)), service);
}

/** Genera código ``fetch`` desde un mensaje serializado por la API. */
export function buildFetchFromMessage(
  message: MessageRecord,
  service: CurlService,
): string {
  return buildFetchFromParsed(parseRequest(decodeBase64Bytes(message.raw)), service);
}

/** Genera código ``fetch`` para replicar la petición final del flujo. */
export function buildFetchFromFlow(flow: FlowRecord): string {
  return buildFetchFromMessage(
    flow.final_request ?? flow.request,
    flow.service,
  );
}

/** Genera el comando a partir de una petición HTTP cruda y su servicio. */
export function buildCurlFromRaw(raw: string, service: CurlService): string {
  return buildFromParsed(parseRequest(new TextEncoder().encode(raw)), service);
}

/** Genera el comando desde un mensaje serializado por la API (raw base64). */
export function buildCurlFromMessage(
  message: MessageRecord,
  service: CurlService,
): string {
  return buildFromParsed(parseRequest(decodeBase64Bytes(message.raw)), service);
}

/**
 * Usa la petición final si fue editada y, si no, la original. Es la misma
 * semántica que Repeater: replicar exactamente lo que salió hacia el origen.
 */
export function buildCurlFromFlow(flow: FlowRecord): string {
  return buildCurlFromMessage(
    flow.final_request ?? flow.request,
    flow.service,
  );
}
