import type { HeaderView } from "../types";

/** Tope de bytes que se vuelcan en la vista hexadecimal / Base64. */
export const BINARY_VIEW_LIMIT = 1024 * 1024;

const TEXT_TYPES = new Set([
  "application/ecmascript",
  "application/graphql",
  "application/javascript",
  "application/json",
  "application/ld+json",
  "application/x-httpd-php",
  "application/x-javascript",
  "application/x-www-form-urlencoded",
  "application/xhtml+xml",
  "application/xml",
  "application/yaml",
]);

const EXTENSIONS: Record<string, string> = {
  "application/gzip": "gz",
  "application/javascript": "js",
  "application/json": "json",
  "application/octet-stream": "bin",
  "application/pdf": "pdf",
  "application/wasm": "wasm",
  "application/xml": "xml",
  "application/zip": "zip",
  "font/otf": "otf",
  "font/ttf": "ttf",
  "font/woff": "woff",
  "font/woff2": "woff2",
  "image/gif": "gif",
  "image/jpeg": "jpg",
  "image/png": "png",
  "image/svg+xml": "svg",
  "image/webp": "webp",
  "text/css": "css",
  "text/csv": "csv",
  "text/html": "html",
  "text/javascript": "js",
  "text/plain": "txt",
  "text/xml": "xml",
};

export function contentTypeEssence(contentType: string | null): string {
  return (contentType ?? "").split(";", 1)[0].trim().toLowerCase();
}

export function isImageContentType(contentType: string | null): boolean {
  return contentTypeEssence(contentType).startsWith("image/");
}

export function isHtmlContentType(contentType: string | null): boolean {
  const essence = contentTypeEssence(contentType);
  return essence === "text/html" || essence === "application/xhtml+xml";
}

function escapeAttribute(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;");
}

/**
 * Inyecta ``<base href>`` para que recursos relativos del HTML renderizado
 * apunten al sitio original dentro del iframe aislado.
 */
export function injectBaseHref(html: string, baseUrl?: string): string {
  if (!baseUrl) return html;
  const base = `<base href="${escapeAttribute(baseUrl)}">`;
  if (/<head[^>]*>/i.test(html)) {
    return html.replace(/<head([^>]*)>/i, `<head$1>${base}`);
  }
  if (/<html[^>]*>/i.test(html)) {
    return html.replace(/<html([^>]*)>/i, `<html$1><head>${base}</head>`);
  }
  return `${base}${html}`;
}

function startsWith(bytes: Uint8Array, signature: number[]): boolean {
  if (bytes.length < signature.length) return false;
  return signature.every((byte, index) => bytes[index] === byte);
}

/** Identifica imágenes por magic numbers cuando el MIME falta o miente. */
export function sniffImageMime(bytes: Uint8Array): string | null {
  // WebP: contenedor RIFF con la marca ``WEBP`` en el offset 8.
  if (
    bytes.length >= 12 &&
    startsWith(bytes, [0x52, 0x49, 0x46, 0x46]) &&
    bytes[8] === 0x57 &&
    bytes[9] === 0x45 &&
    bytes[10] === 0x42 &&
    bytes[11] === 0x50
  ) {
    return "image/webp";
  }
  if (startsWith(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) {
    return "image/png";
  }
  if (startsWith(bytes, [0xff, 0xd8, 0xff])) return "image/jpeg";
  if (
    startsWith(bytes, [0x47, 0x49, 0x46, 0x38, 0x37, 0x61]) ||
    startsWith(bytes, [0x47, 0x49, 0x46, 0x38, 0x39, 0x61])
  ) {
    return "image/gif";
  }
  if (startsWith(bytes, [0x42, 0x4d])) return "image/bmp";
  if (startsWith(bytes, [0x00, 0x00, 0x01, 0x00])) return "image/x-icon";
  // AVIF: caja ``ftyp`` con marca ``avif`` o ``avis``.
  if (
    bytes.length >= 12 &&
    String.fromCharCode(...bytes.subarray(4, 8)) === "ftyp" &&
    ["avif", "avis"].includes(String.fromCharCode(...bytes.subarray(8, 12)))
  ) {
    return "image/avif";
  }
  return null;
}

/** MIME de imagen efectivo: primero el declarado, luego los bytes mágicos. */
export function resolveImageMime(
  contentType: string | null,
  bytes: Uint8Array,
): string | null {
  const essence = contentTypeEssence(contentType);
  if (essence.startsWith("image/")) {
    if (essence === "image/jpg") return "image/jpeg";
    if (essence === "image/x-png") return "image/png";
    return essence;
  }
  return sniffImageMime(bytes);
}

/** PDF por MIME o por la firma ``%PDF-``. */
export function isPdfContent(
  contentType: string | null,
  bytes: Uint8Array,
): boolean {
  if (contentTypeEssence(contentType) === "application/pdf") return true;
  return startsWith(bytes, [0x25, 0x50, 0x44, 0x46, 0x2d]);
}

export function isTextContentType(contentType: string | null): boolean {
  const essence = contentTypeEssence(contentType);
  if (!essence) return true;
  if (essence.startsWith("text/")) return true;
  if (essence.endsWith("+json") || essence.endsWith("+xml")) return true;
  return TEXT_TYPES.has(essence);
}

export function isBinaryBody(
  contentType: string | null,
  body: string,
): boolean {
  if (isImageContentType(contentType)) return true;
  if (!isTextContentType(contentType)) return true;
  return body.includes("\u0000");
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(
      ...bytes.subarray(offset, offset + chunkSize),
    );
  }
  return btoa(binary);
}

export function base64ToBytes(value: string): Uint8Array {
  try {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  } catch {
    return new Uint8Array();
  }
}

export function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / (1024 * 1024)).toFixed(2)} MiB`;
}

export interface HexDump {
  text: string;
  shown: number;
  total: number;
  truncated: boolean;
}

/** Volcado estilo ``xxd``: offset, 16 bytes en hex y ASCII imprimible. */
export function hexDump(
  bytes: Uint8Array,
  limit: number = BINARY_VIEW_LIMIT,
): HexDump {
  const shown = Math.max(0, Math.min(bytes.length, limit));
  const lines: string[] = [];
  for (let offset = 0; offset < shown; offset += 16) {
    const chunk = bytes.subarray(offset, Math.min(offset + 16, shown));
    const hex: string[] = [];
    for (let index = 0; index < 16; index += 1) {
      hex.push(
        index < chunk.length
          ? chunk[index].toString(16).padStart(2, "0")
          : "  ",
      );
      if (index === 7) hex.push("");
    }
    let ascii = "";
    for (const byte of chunk) {
      ascii += byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : ".";
    }
    lines.push(
      `${offset.toString(16).padStart(8, "0")}  ${hex.join(" ").padEnd(48)}  |${ascii}|`,
    );
  }
  return {
    text: lines.join("\n"),
    shown,
    total: bytes.length,
    truncated: shown < bytes.length,
  };
}

export interface Latin1Dump {
  text: string;
  shown: number;
  total: number;
  truncated: boolean;
}

/**
 * Decodifica bytes como ISO-8859-1 (Latin-1) para extraer strings visibles.
 *
 * Los caracteres de control se sustituyen por ``·`` para que no rompan el
 * layout; el resto de bytes conserva su representación Latin-1.
 */
export function latin1Dump(
  bytes: Uint8Array,
  limit: number = BINARY_VIEW_LIMIT,
): Latin1Dump {
  const shown = Math.max(0, Math.min(bytes.length, limit));
  let text = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < shown; offset += chunkSize) {
    text += String.fromCharCode(
      ...bytes.subarray(offset, Math.min(offset + chunkSize, shown)),
    );
  }
  text = text.replace(
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g,
    "·",
  );
  return {
    text,
    shown,
    total: bytes.length,
    truncated: shown < bytes.length,
  };
}

export function downloadBytes(bytes: Uint8Array, filename: string): void {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  const blob = new Blob([buffer], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.rel = "noopener";
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function extensionFor(contentType: string | null): string | null {
  const essence = contentTypeEssence(contentType);
  if (!essence) return null;
  const known = EXTENSIONS[essence];
  if (known) return known;
  const subtype = essence.split("/", 2)[1]?.split("+", 1)[0];
  return subtype && /^[a-z0-9]+$/i.test(subtype) ? subtype : null;
}

/** Nombre de descarga a partir de ``Content-Disposition`` o del MIME. */
export function suggestDownloadName(
  contentType: string | null,
  headers: HeaderView[],
  fallback: string,
): string {
  const disposition = headers.find(
    (header) => header.name.toLowerCase() === "content-disposition",
  )?.value;

  let name = "";
  if (disposition) {
    const encoded =
      /filename\*\s*=\s*(?:UTF-8'')?([^;]+)/i.exec(disposition)?.[1] ??
      /filename\s*=\s*"?([^";]+)"?/i.exec(disposition)?.[1];
    if (encoded) {
      const cleaned = encoded.trim().replace(/^"|"$/g, "");
      try {
        name = decodeURIComponent(cleaned);
      } catch {
        name = cleaned;
      }
    }
  }

  name = (name.split(/[\\/]/).pop() ?? "")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim();
  if (!name) name = fallback;
  if (!/\.[a-z0-9]{1,8}$/i.test(name)) {
    const extension = extensionFor(contentType);
    if (extension) name = `${name}.${extension}`;
  }
  return name || "prox0x-body.bin";
}
