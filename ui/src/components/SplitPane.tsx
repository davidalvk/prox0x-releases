import { useEffect, useRef, useState, type ReactNode } from "react";

type Orientation = "horizontal" | "vertical";

interface SplitPaneProps {
  orientation: Orientation;
  first: ReactNode;
  second: ReactNode;
  /** Porcentaje inicial del primer panel (20–80). */
  initial?: number;
  min?: number;
  max?: number;
  label: string;
  className?: string;
  firstClassName?: string;
  secondClassName?: string;
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

/**
 * Paneles divisibles estilo terminal, sin dependencias externas.
 *
 * ``horizontal`` reparte en columnas (izquierda/derecha) y ``vertical`` en
 * filas (arriba/abajo). El separador se arrastra con el ratón o se mueve con
 * las flechas del teclado.
 */
export function SplitPane({
  orientation,
  first,
  second,
  initial = 50,
  min = 20,
  max = 80,
  label,
  className = "",
  firstClassName = "",
  secondClassName = "",
}: SplitPaneProps) {
  const [percent, setPercent] = useState(() => clamp(initial, min, max));
  const [dragging, setDragging] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!dragging) return;

    const onMove = (event: PointerEvent) => {
      const rect = containerRef.current?.getBoundingClientRect();
      if (!rect) return;
      const value =
        orientation === "horizontal"
          ? ((event.clientX - rect.left) / rect.width) * 100
          : ((event.clientY - rect.top) / rect.height) * 100;
      setPercent(clamp(value, min, max));
    };
    const stop = () => setDragging(false);

    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", stop);
    window.addEventListener("pointercancel", stop);
    document.body.style.cursor =
      orientation === "horizontal" ? "col-resize" : "row-resize";
    document.body.style.userSelect = "none";
    return () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", stop);
      window.removeEventListener("pointercancel", stop);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
  }, [dragging, max, min, orientation]);

  const move = (delta: number) => {
    setPercent((value) => clamp(value + delta, min, max));
  };

  const horizontal = orientation === "horizontal";

  return (
    <div
      ref={containerRef}
      className={[
        "flex min-h-0 min-w-0 flex-1",
        horizontal ? "flex-row" : "flex-col",
        className,
      ].join(" ")}
    >
      <div
        className={["min-h-0 min-w-0 overflow-hidden", firstClassName].join(" ")}
        style={{ flexGrow: percent, flexBasis: 0 }}
      >
        {first}
      </div>

      <div
        role="separator"
        aria-orientation={horizontal ? "vertical" : "horizontal"}
        aria-label={label}
        aria-valuemin={min}
        aria-valuemax={max}
        aria-valuenow={Math.round(percent)}
        tabIndex={0}
        onPointerDown={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onKeyDown={(event) => {
          const negative = horizontal ? "ArrowLeft" : "ArrowUp";
          const positive = horizontal ? "ArrowRight" : "ArrowDown";
          if (event.key === negative) {
            event.preventDefault();
            move(-2);
          } else if (event.key === positive) {
            event.preventDefault();
            move(2);
          }
        }}
        title={
          horizontal
            ? "Arrastra para redimensionar las columnas"
            : "Arrastra para redimensionar las filas"
        }
        className={[
          "relative shrink-0 bg-surface-800 transition hover:bg-accent/60 focus:bg-accent focus:outline-none",
          horizontal ? "w-1.5 cursor-col-resize" : "h-1.5 cursor-row-resize",
        ].join(" ")}
      >
        <span
          className={
            horizontal
              ? "pointer-events-none absolute inset-y-1/4 left-1/2 w-px -translate-x-1/2 bg-accent/40"
              : "pointer-events-none absolute inset-x-1/4 top-1/2 h-px -translate-y-1/2 bg-accent/40"
          }
        />
      </div>

      <div
        className={["min-h-0 min-w-0 overflow-hidden", secondClassName].join(" ")}
        style={{ flexGrow: 100 - percent, flexBasis: 0 }}
      >
        {second}
      </div>
    </div>
  );
}
