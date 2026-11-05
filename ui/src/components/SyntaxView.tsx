import { useEffect, useMemo, useRef, useState } from "react";
import { Code2, Download, Eye, Wand2 } from "lucide-react";
import type { HeaderView } from "../types";
import {
  detectLanguage,
  highlightBody,
  highlightBodyWithMark,
} from "../lib/highlight";
import {
  MAX_BEAUTIFY_BYTES,
  beautifyText,
  isBeautifiable,
} from "../lib/beautify";
import {
  BINARY_VIEW_LIMIT,
  bytesToBase64,
  contentTypeEssence,
  downloadBytes,
  formatBytes,
  hexDump,
  injectBaseHref,
  isBinaryBody,
  isHtmlContentType,
  isPdfContent,
  latin1Dump,
  resolveImageMime,
} from "../lib/binary";

interface SyntaxViewProps {
  startLine: string;
  headers: HeaderView[];
  body: string;
  contentType: string | null;
  bodyBytes?: Uint8Array;
  originalBodyBytes?: Uint8Array;
  downloadName?: string;
  /** Origen/ruta original para resolver recursos relativos del HTML. */
  baseUrl?: string;
  /** Identifica el mensaje para reiniciar el modo imagen al cambiar de flujo. */
  viewKey?: string | number;
  /** Fragmento exacto de evidencia que debe resaltarse en el cuerpo. */
  evidenceMatch?: string | null;
  /** Offset opcional de la evidencia dentro del cuerpo. */
  evidenceOffset?: number | null;
  className?: string;
}

/**
 * Vista de solo lectura de un mensaje HTTP.
 *
 * - Texto: cabeceras tácticas y cuerpo con resaltado Prism.
 * - Imágenes (por MIME o magic numbers): previsualización ``<img>`` con
 *   alternativa Base64.
 * - PDF: visor nativo con ``<iframe>`` y alternativa Base64.
 * - Otros binarios: volcado hexadecimal o texto crudo ISO-8859-1 (máximo 1 MiB).
 */
export function SyntaxView({
  startLine,
  headers,
  body,
  contentType,
  bodyBytes,
  originalBodyBytes,
  downloadName = "prox0x-body.bin",
  baseUrl,
  viewKey,
  evidenceMatch,
  evidenceOffset,
  className = "",
}: SyntaxViewProps) {
  const [imageAsText, setImageAsText] = useState(false);
  const [pdfAsBase64, setPdfAsBase64] = useState(false);
  const [htmlRendered, setHtmlRendered] = useState(false);
  const [binaryMode, setBinaryMode] = useState<"hex" | "text">("hex");
  const [formattedText, setFormattedText] = useState<string | null>(null);
  const [formatError, setFormatError] = useState<string | null>(null);
  const bodyRef = useRef<HTMLPreElement>(null);

  const bytes = useMemo(
    () => bodyBytes ?? new TextEncoder().encode(body),
    [bodyBytes, body],
  );
  const imageMime = useMemo(
    () => resolveImageMime(contentType, bytes),
    [contentType, bytes],
  );
  const image = imageMime !== null;
  const pdf = useMemo(
    () => !image && isPdfContent(contentType, bytes),
    [image, contentType, bytes],
  );
  const essence =
    imageMime ?? (contentTypeEssence(contentType) || "application/octet-stream");
  const binary = isBinaryBody(contentType, body);
  const formatAvailable =
    isBeautifiable(contentType) && !image && !pdf && !binary;
  const tooLarge = bytes.length > MAX_BEAUTIFY_BYTES;
  const shownBody = formattedText ?? body;
  const html = isHtmlContentType(contentType) && !binary;
  const htmlSrcDoc = useMemo(
    () =>
      html && htmlRendered
        ? injectBaseHref(shownBody, baseUrl)
        : "",
    [html, htmlRendered, shownBody, baseUrl],
  );
  const language = useMemo(
    () => (binary ? "plain" : detectLanguage(contentType, shownBody)),
    [binary, contentType, shownBody],
  );
  const evidenceRange = useMemo(() => {
    if (binary || htmlRendered || !evidenceMatch || !shownBody) return null;
    const needle = evidenceMatch.toLowerCase();
    if (!needle) return null;
    let start =
      typeof evidenceOffset === "number" && evidenceOffset >= 0
        ? evidenceOffset
        : -1;
    const matchesOffset =
      start >= 0 &&
      shownBody.slice(start, start + needle.length).toLowerCase() === needle;
    if (!matchesOffset) {
      start = shownBody.toLowerCase().indexOf(needle);
    }
    if (start < 0) return null;
    return { start, end: start + evidenceMatch.length };
  }, [
    binary,
    htmlRendered,
    evidenceMatch,
    evidenceOffset,
    shownBody,
  ]);
  useEffect(() => {
    if (!evidenceRange) return;
    const mark = bodyRef.current?.querySelector(
      'mark[data-testid="evidence-mark"]',
    );
    if (mark instanceof HTMLElement) {
      mark.scrollIntoView({ block: "center", behavior: "smooth" });
    }
  }, [evidenceRange]);

  const highlightedBody = useMemo(() => {
    if (binary) return "";
    if (evidenceRange) {
      return highlightBodyWithMark(
        shownBody,
        language,
        evidenceRange.start,
        evidenceRange.end,
      );
    }
    return highlightBody(shownBody, language);
  }, [binary, evidenceRange, shownBody, language]);
  const previewBase64 = useMemo(
    () => (image || pdf ? bytesToBase64(bytes) : ""),
    [image, pdf, bytes],
  );
  const base64Text = useMemo(() => {
    if (!((image && imageAsText) || (pdf && pdfAsBase64))) return "";
    const encoded = bytesToBase64(bytes.subarray(0, BINARY_VIEW_LIMIT));
    return encoded.replace(/(.{76})/g, "$1\n");
  }, [image, imageAsText, pdf, pdfAsBase64, bytes]);
  const dump = useMemo(
    () => (!image && !pdf && binary ? hexDump(bytes) : null),
    [image, pdf, binary, bytes],
  );
  const rawText = useMemo(
    () => (!image && !pdf && binary ? latin1Dump(bytes) : null),
    [image, pdf, binary, bytes],
  );

  useEffect(() => {
    setImageAsText(false);
    setPdfAsBase64(false);
    setHtmlRendered(false);
    setBinaryMode("hex");
    setFormattedText(null);
    setFormatError(null);
  }, [viewKey, contentType, body]);

  const toggleFormat = () => {
    if (formattedText !== null) {
      setFormattedText(null);
      setFormatError(null);
      return;
    }
    if (tooLarge || !formatAvailable) return;
    const result = beautifyText(body, contentType);
    if (result === null) {
      setFormatError("No se pudo formatear este contenido.");
      return;
    }
    setFormatError(null);
    setFormattedText(result);
  };

  const downloadBody = originalBodyBytes ?? bodyBytes ?? bytes;

  return (
    <div
      data-testid="syntax-view"
      data-language={language}
      className={[
        "syntax-view font-mono text-[11px] leading-relaxed",
        className,
      ].join(" ")}
    >
      <pre className="whitespace-pre">
        <code>
          <span className="syntax-start">{startLine || "—"}</span>
          {"\n"}
          {headers.map((header, index) => (
            <span key={`${header.name}-${index}`}>
              <span className="syntax-header-name">{header.name}</span>
              <span className="syntax-punct">:</span>
              <span className="syntax-header-value"> {header.value}</span>
              {"\n"}
            </span>
          ))}
        </code>
      </pre>

      {(image || pdf || dump || formatAvailable) && (
        <div className="my-2 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-surface-800 bg-surface-950/60 px-2 py-1.5">
          <div className="flex flex-wrap items-center gap-1">
            {html && (
              <button
                type="button"
                aria-pressed={htmlRendered}
                onClick={() => setHtmlRendered((value) => !value)}
                title={
                  htmlRendered
                    ? "Volver al código fuente"
                    : "Renderizar el HTML de forma aislada"
                }
                className={[
                  "flex items-center gap-1.5 rounded border px-2 py-1 text-[10px] font-semibold transition",
                  htmlRendered
                    ? "border-accent/60 bg-accent/15 text-accent"
                    : "border-surface-700 text-zinc-300 hover:border-accent hover:text-accent",
                ].join(" ")}
              >
                {htmlRendered ? <Code2 size={12} /> : <Eye size={12} />}
                {htmlRendered ? "Vista Código" : "Renderizar"}
              </button>
            )}
            {image ? (
              <>
                <button
                  type="button"
                  aria-pressed={!imageAsText}
                  onClick={() => setImageAsText(false)}
                  className={[
                    "rounded px-2 py-1 text-[10px] font-semibold transition",
                    !imageAsText
                      ? "bg-accent text-surface-950"
                      : "text-zinc-400 hover:bg-surface-800 hover:text-zinc-100",
                  ].join(" ")}
                >
                  Vista de Imagen
                </button>
                <button
                  type="button"
                  aria-pressed={imageAsText}
                  onClick={() => setImageAsText(true)}
                  className={[
                    "rounded px-2 py-1 text-[10px] font-semibold transition",
                    imageAsText
                      ? "bg-accent text-surface-950"
                      : "text-zinc-400 hover:bg-surface-800 hover:text-zinc-100",
                  ].join(" ")}
                >
                  Vista de Texto (Base64)
                </button>
              </>
            ) : pdf ? (
              <>
                <button
                  type="button"
                  aria-pressed={!pdfAsBase64}
                  onClick={() => setPdfAsBase64(false)}
                  className={[
                    "rounded px-2 py-1 text-[10px] font-semibold transition",
                    !pdfAsBase64
                      ? "bg-accent text-surface-950"
                      : "text-zinc-400 hover:bg-surface-800 hover:text-zinc-100",
                  ].join(" ")}
                >
                  Vista PDF
                </button>
                <button
                  type="button"
                  aria-pressed={pdfAsBase64}
                  onClick={() => setPdfAsBase64(true)}
                  className={[
                    "rounded px-2 py-1 text-[10px] font-semibold transition",
                    pdfAsBase64
                      ? "bg-accent text-surface-950"
                      : "text-zinc-400 hover:bg-surface-800 hover:text-zinc-100",
                  ].join(" ")}
                >
                  Vista Base64
                </button>
              </>
            ) : dump ? (
              <>
                <button
                  type="button"
                  aria-pressed={binaryMode === "hex"}
                  onClick={() => setBinaryMode("hex")}
                  className={[
                    "rounded px-2 py-1 text-[10px] font-semibold transition",
                    binaryMode === "hex"
                      ? "bg-amber-400 text-surface-950"
                      : "text-zinc-400 hover:bg-surface-800 hover:text-zinc-100",
                  ].join(" ")}
                >
                  Volcado Hexadecimal
                </button>
                <button
                  type="button"
                  aria-pressed={binaryMode === "text"}
                  onClick={() => setBinaryMode("text")}
                  className={[
                    "rounded px-2 py-1 text-[10px] font-semibold transition",
                    binaryMode === "text"
                      ? "bg-amber-400 text-surface-950"
                      : "text-zinc-400 hover:bg-surface-800 hover:text-zinc-100",
                  ].join(" ")}
                >
                  Texto en crudo
                </button>
                <span className="px-1 text-[10px] text-zinc-600">
                  {formatBytes(bytes.length)}
                </span>
              </>
            ) : !htmlRendered ? (
              <button
                type="button"
                onClick={toggleFormat}
                disabled={tooLarge || !formatAvailable}
                aria-pressed={formattedText !== null}
                title={
                  tooLarge
                    ? "Formatear está desactivado para cuerpos de más de 1 MiB."
                    : formattedText !== null
                      ? "Volver al texto original"
                      : "Formatear código minificado"
                }
                className={[
                  "flex items-center gap-1.5 rounded border px-2 py-1 text-[10px] font-semibold transition",
                  formattedText !== null
                    ? "border-accent/60 bg-accent/15 text-accent"
                    : "border-surface-700 text-zinc-300 hover:border-accent hover:text-accent",
                  tooLarge ? "cursor-not-allowed opacity-40" : "",
                ].join(" ")}
              >
                <Wand2 size={12} />
                {formattedText !== null ? "Original" : "Formatear"}
              </button>
            ) : null}
            {formatError && (
              <span role="alert" className="px-1 text-[10px] text-rose-300">
                {formatError}
              </span>
            )}
          </div>
          <button
            type="button"
            onClick={() => downloadBytes(downloadBody, downloadName)}
            className="flex items-center gap-1.5 rounded border border-surface-700 px-2 py-1 text-[10px] font-semibold text-zinc-300 transition hover:border-accent hover:text-accent"
          >
            <Download size={12} />
            Descargar archivo
          </button>
        </div>
      )}

      {image && !imageAsText && (
        <div className="mt-2 flex max-h-[60vh] justify-center overflow-auto rounded-lg border border-surface-800 bg-[repeating-conic-gradient(#18181b_0%_25%,#0b0b0d_0%_50%)] bg-[length:16px_16px] p-3">
          <img
            data-testid="image-preview"
            src={`data:${essence};base64,${previewBase64}`}
            alt={`Previsualización de imagen ${essence}`}
            className="max-h-full max-w-full object-contain"
          />
        </div>
      )}

      {pdf && !pdfAsBase64 && (
        <div className="mt-2 max-h-[70vh] overflow-hidden rounded-lg border border-surface-800 bg-surface-950">
          <iframe
            data-testid="pdf-preview"
            title="Previsualización del PDF"
            src={`data:application/pdf;base64,${previewBase64}`}
            className="h-[65vh] w-full"
          />
        </div>
      )}

      {((image && imageAsText) || (pdf && pdfAsBase64)) && (
        <div className="mt-2">
          <pre
            data-testid="base64-view"
            className="max-h-[60vh] overflow-auto whitespace-pre-wrap break-all rounded-lg border border-surface-800 bg-surface-950 p-3 text-[10px] text-zinc-400"
          >
            {base64Text || "—"}
          </pre>
          {bytes.length > BINARY_VIEW_LIMIT && (
            <p className="mt-1 text-[10px] text-amber-300">
              Mostrando los primeros {formatBytes(BINARY_VIEW_LIMIT)} de{" "}
              {formatBytes(bytes.length)}. Usa «Descargar archivo» para el
              contenido completo.
            </p>
          )}
        </div>
      )}

      {dump && binaryMode === "hex" && (
        <div className="mt-2">
          <pre
            data-testid="hex-dump"
            className="max-h-[60vh] overflow-auto whitespace-pre rounded-lg border border-surface-800 bg-surface-950 p-3 text-[10px] text-zinc-400"
          >
            {dump.text || "—"}
          </pre>
          {dump.truncated && (
            <p className="mt-1 text-[10px] text-amber-300">
              Mostrando los primeros {formatBytes(dump.shown)} de{" "}
              {formatBytes(dump.total)}. Usa «Descargar archivo» para el
              contenido completo.
            </p>
          )}
        </div>
      )}

      {rawText && binaryMode === "text" && (
        <div className="mt-2">
          <pre
            data-testid="raw-text"
            className="max-h-[60vh] overflow-auto whitespace-pre-wrap break-all rounded-lg border border-surface-800 bg-surface-950 p-3 text-[10px] text-zinc-400"
          >
            {rawText.text || "—"}
          </pre>
          <p className="mt-1 text-[10px] text-zinc-600">
            Decodificación ISO-8859-1 (Latin-1); los caracteres de control se
            muestran como «·».
          </p>
          {rawText.truncated && (
            <p className="mt-1 text-[10px] text-amber-300">
              Mostrando los primeros {formatBytes(rawText.shown)} de{" "}
              {formatBytes(rawText.total)}. Usa «Descargar archivo» para el
              contenido completo.
            </p>
          )}
        </div>
      )}

      {html && htmlRendered && (
        <iframe
          data-testid="html-preview"
          title="Previsualización HTML"
          sandbox=""
          referrerPolicy="no-referrer"
          srcDoc={htmlSrcDoc}
          className="mt-2 h-[70vh] w-full rounded-lg border border-surface-800 bg-white"
        />
      )}

      {!image && !pdf && !dump && !(html && htmlRendered) && (
        <pre ref={bodyRef} className="whitespace-pre">
          <code>
            <span
              data-testid="syntax-body"
              className="syntax-body"
              // Prism escapa el texto antes de envolverlo en tokens.
              dangerouslySetInnerHTML={{ __html: highlightedBody || "—" }}
            />
          </code>
        </pre>
      )}
    </div>
  );
}
