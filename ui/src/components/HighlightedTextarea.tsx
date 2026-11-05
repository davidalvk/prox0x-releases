import { Fragment, useMemo, useRef, type KeyboardEventHandler } from "react";
import { detectLanguage, highlightBody } from "../lib/highlight";

interface HighlightedTextareaProps {
  value: string;
  onChange: (value: string) => void;
  className?: string;
  ariaLabel?: string;
  textareaRef?: (element: HTMLTextAreaElement | null) => void;
  onKeyDown?: KeyboardEventHandler<HTMLTextAreaElement>;
}

function splitRaw(value: string): { head: string; body: string; hasBody: boolean } {
  const divider = value.includes("\r\n\r\n")
    ? "\r\n\r\n"
    : value.includes("\n\n")
      ? "\n\n"
      : null;
  if (!divider) return { head: value, body: "", hasBody: false };
  const [head, body = ""] = value.split(divider, 2);
  return { head, body, hasBody: true };
}

function contentTypeFromHead(head: string): string | null {
  for (const line of head.split(/\r?\n/)) {
    const colon = line.indexOf(":");
    if (colon === -1) continue;
    if (line.slice(0, colon).trim().toLowerCase() === "content-type") {
      return line.slice(colon + 1).trim();
    }
  }
  return null;
}

function renderHeadLine(line: string, index: number) {
  if (index === 0) {
    return <span className="syntax-start">{line}</span>;
  }
  const colon = line.indexOf(":");
  if (colon === -1) {
    return <span className="syntax-dim">{line}</span>;
  }
  return (
    <>
      <span className="syntax-header-name">{line.slice(0, colon)}</span>
      <span className="syntax-punct">:</span>
      <span className="syntax-header-value">{line.slice(colon + 1)}</span>
    </>
  );
}

/**
 * ``<textarea>`` editable con una capa de resaltado debajo.
 *
 * El texto del textarea es transparente; el ``<pre>`` pinta exactamente el
 * mismo contenido con los mismos estilos y se sincroniza al hacer scroll. Así
 * se conservan los selectores E2E (``textarea``) y el cursor nativo.
 */
export function HighlightedTextarea({
  value,
  onChange,
  className = "",
  ariaLabel,
  textareaRef,
  onKeyDown,
}: HighlightedTextareaProps) {
  const preRef = useRef<HTMLPreElement>(null);
  const localRef = useRef<HTMLTextAreaElement | null>(null);

  const setTextareaRef = (element: HTMLTextAreaElement | null) => {
    localRef.current = element;
    textareaRef?.(element);
  };

  const { head, body, hasBody } = useMemo(() => splitRaw(value), [value]);
  const contentType = useMemo(() => contentTypeFromHead(head), [head]);
  const language = useMemo(
    () => detectLanguage(contentType, body),
    [contentType, body],
  );
  const highlightedBody = useMemo(
    () => highlightBody(body, language),
    [body, language],
  );
  const headLines = useMemo(() => head.split(/\r?\n/), [head]);

  const syncScroll = () => {
    const textarea = localRef.current;
    const pre = preRef.current;
    if (!textarea || !pre) return;
    pre.scrollTop = textarea.scrollTop;
    pre.scrollLeft = textarea.scrollLeft;
  };

  return (
    <div className={["syntax-editor relative", className].join(" ")}>
      <pre
        ref={preRef}
        aria-hidden="true"
        data-testid="syntax-overlay"
        data-language={language}
        className="syntax-overlay pointer-events-none absolute inset-0 m-0 overflow-hidden whitespace-pre p-4 font-mono text-xs leading-relaxed"
      >
        {headLines.map((line, index) => (
          <Fragment key={index}>
            {index > 0 ? "\n" : null}
            {renderHeadLine(line, index)}
          </Fragment>
        ))}
        {hasBody ? (
          <>
            {"\n\n"}
            <span
              className="syntax-body"
              dangerouslySetInnerHTML={{ __html: highlightedBody }}
            />
          </>
        ) : null}
      </pre>
      <textarea
        ref={setTextareaRef}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        onScroll={syncScroll}
        onKeyDown={onKeyDown}
        aria-label={ariaLabel}
        spellCheck={false}
        autoCapitalize="off"
        autoCorrect="off"
        wrap="off"
        className="syntax-textarea absolute inset-0 h-full w-full resize-none overflow-auto p-4 font-mono text-xs leading-relaxed outline-none"
      />
    </div>
  );
}
