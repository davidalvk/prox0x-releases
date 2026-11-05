import { useId, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { HelpCircle } from "lucide-react";

interface HelpTooltipProps {
  text: string;
  label?: string;
  className?: string;
}

interface Coords {
  top: number;
  left: number;
}

const TOOLTIP_WIDTH = 260;

export function HelpTooltip({ text, label, className = "" }: HelpTooltipProps) {
  const [open, setOpen] = useState(false);
  const [coords, setCoords] = useState<Coords>({ top: 0, left: 0 });
  const triggerRef = useRef<HTMLSpanElement>(null);
  const tooltipId = useId();

  const updatePosition = () => {
    const rect = triggerRef.current?.getBoundingClientRect();
    if (!rect) return;
    const viewportW = window.innerWidth;
    const viewportH = window.innerHeight;

    let left = rect.left + rect.width / 2 - TOOLTIP_WIDTH / 2;
    left = Math.max(10, Math.min(viewportW - TOOLTIP_WIDTH - 10, left));

    const preferBelow = rect.bottom + 96 < viewportH;
    const top = preferBelow ? rect.bottom + 8 : Math.max(10, rect.top - 76);

    setCoords({ top, left });
  };

  const show = () => {
    updatePosition();
    setOpen(true);
  };

  const hide = () => {
    setOpen(false);
  };

  return (
    <>
      <span
        ref={triggerRef}
        tabIndex={0}
        data-testid={label ? `help-${label}` : "help"}
        aria-label="?"
        aria-describedby={open ? tooltipId : undefined}
        onMouseEnter={show}
        onMouseLeave={hide}
        onFocus={show}
        onBlur={hide}
        onClick={(event) => {
          event.stopPropagation();
          event.preventDefault();
          if (open) {
            hide();
          } else {
            show();
          }
        }}
        onKeyDown={(event) => {
          if (event.key === "Escape") {
            hide();
          }
        }}
        className={[
          "inline-flex h-4 w-4 shrink-0 cursor-help items-center justify-center rounded-full text-cyan-400/80 transition hover:scale-110 hover:text-accent focus:text-accent focus:outline-none",
          className,
        ].join(" ")}
      >
        <HelpCircle size={13} />
      </span>

      {open &&
        createPortal(
          <div
            id={tooltipId}
            role="tooltip"
            style={{
              position: "fixed",
              top: `${coords.top}px`,
              left: `${coords.left}px`,
              width: `${TOOLTIP_WIDTH}px`,
              zIndex: 9995,
            }}
            className="pointer-events-none rounded-lg border border-accent bg-[#0a0a0a] px-3 py-2 font-mono text-[11px] leading-relaxed text-zinc-200 shadow-[0_0_20px_rgba(57,255,20,0.35)]"
          >
            {label && (
              <p className="mb-0.5 text-[10px] font-bold uppercase tracking-wider text-cyan-400">
                [?] {label}
              </p>
            )}
            <p className="text-zinc-200">{text}</p>
          </div>,
          document.body,
        )}
    </>
  );
}
