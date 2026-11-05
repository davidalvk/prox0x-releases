import Prism from "prismjs";
import "prismjs/components/prism-json";
import "prismjs/components/prism-markup";
import "prismjs/components/prism-css";
import "prismjs/components/prism-javascript";

export type HighlightLanguage = "json" | "markup" | "css" | "javascript" | "plain";

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function detectLanguage(
  contentType: string | null,
  body: string,
): HighlightLanguage {
  const essence = (contentType ?? "").split(";", 1)[0].trim().toLowerCase();
  if (essence.endsWith("+json") || essence.includes("json")) return "json";
  if (
    essence.endsWith("+xml") ||
    essence.includes("html") ||
    essence.includes("xml") ||
    essence === "image/svg+xml"
  ) {
    return "markup";
  }
  if (essence.includes("css")) return "css";
  if (essence.includes("javascript") || essence.includes("ecmascript")) {
    return "javascript";
  }

  const trimmed = body.trimStart();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      JSON.parse(trimmed);
      return "json";
    } catch {
      // No es JSON válido: se trata como texto plano.
    }
  }
  if (trimmed.startsWith("<")) return "markup";
  return "plain";
}

export function highlightBody(body: string, language: HighlightLanguage): string {
  if (!body) return "";
  if (language === "plain") return escapeHtml(body);
  const grammar = Prism.languages[language];
  if (!grammar) return escapeHtml(body);
  return Prism.highlight(body, grammar, language);
}

/**
 * Resalta un rango de texto dentro del cuerpo sin romper el resaltado de
 * Prism. Se insertan dos centinelas privados antes de tokenizar y se sustituyen
 * por ``<mark>`` después, de modo que el HTML generado por Prism no se mezcla
 * con etiquetas introducidas a mano.
 */
export function highlightBodyWithMark(
  body: string,
  language: HighlightLanguage,
  start: number,
  end: number,
): string {
  if (!body || start < 0 || end <= start || start >= body.length) {
    return highlightBody(body, language);
  }
  const safeEnd = Math.min(end, body.length);
  const startMarker = "\uE000";
  const endMarker = "\uE001";
  const marked =
    body.slice(0, start) +
    startMarker +
    body.slice(start, safeEnd) +
    endMarker +
    body.slice(safeEnd);
  return highlightBody(marked, language)
    .replaceAll(
      startMarker,
      '<mark class="evidence-mark" data-testid="evidence-mark">',
    )
    .replaceAll(endMarker, "</mark>");
}
