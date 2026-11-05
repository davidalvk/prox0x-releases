import beautify from "js-beautify";
import { contentTypeEssence, isImageContentType } from "./binary";

/** Tope de tamaño para formatear sin bloquear el hilo principal. */
export const MAX_BEAUTIFY_BYTES = 1024 * 1024;

export type BeautifyKind = "json" | "js" | "css" | "html" | "xml";

export function beautifyKind(contentType: string | null): BeautifyKind | null {
  const essence = contentTypeEssence(contentType);
  if (!essence || isImageContentType(contentType)) return null;
  if (essence.includes("json")) return "json";
  if (
    essence.includes("javascript") ||
    essence.includes("ecmascript") ||
    essence.endsWith("+js")
  ) {
    return "js";
  }
  if (essence.includes("css")) return "css";
  if (essence.includes("html")) return "html";
  if (essence.includes("xml")) return "xml";
  return null;
}

export function isBeautifiable(contentType: string | null): boolean {
  return beautifyKind(contentType) !== null;
}

const OPTIONS = {
  indent_size: 2,
  indent_char: " ",
  preserve_newlines: true,
  max_preserve_newlines: 2,
  end_with_newline: false,
  wrap_line_length: 0,
};

/** Devuelve el texto formateado o ``null`` si no se puede procesar. */
export function beautifyText(
  text: string,
  contentType: string | null,
): string | null {
  const kind = beautifyKind(contentType);
  if (!kind || !text) return null;
  try {
    if (kind === "json") {
      try {
        return JSON.stringify(JSON.parse(text), null, 2);
      } catch {
        // JSON inválido: probamos el formateador de JavaScript.
        return beautify.js(text, OPTIONS);
      }
    }
    if (kind === "js") return beautify.js(text, OPTIONS);
    if (kind === "css") return beautify.css(text, OPTIONS);
    return beautify.html(text, {
      ...OPTIONS,
      indent_inner_html: true,
    });
  } catch {
    return null;
  }
}
