import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

/**
 * Red de seguridad de renderizado: si un componente lanza durante el render,
 * muestra una pantalla de recuperación en lugar de dejar el `<body>` en negro.
 */
interface PageErrorBoundaryProps {
  children: ReactNode;
  pageName: string;
}

/**
 * Aisla el fallo de una página concreta: el layout, la Sidebar y el resto de
 * módulos siguen funcionando aunque una tabla reciba datos corruptos.
 */
export class PageErrorBoundary extends Component<
  PageErrorBoundaryProps,
  ErrorBoundaryState
> {
  state: ErrorBoundaryState = { hasError: false, error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error(
      `prox0x UI error en ${this.props.pageName}`,
      error,
      info.componentStack,
    );
  }

  private retry = (): void => {
    this.setState({ hasError: false, error: null });
  };

  render(): ReactNode {
    if (!this.state.hasError) return this.props.children;

    return (
      <div className="flex h-full min-h-0 items-center justify-center bg-surface-950 p-6">
        <section
          role="alert"
          aria-label={`Error en ${this.props.pageName}`}
          className="w-full max-w-lg rounded-xl border border-rose-500/60 bg-surface-900 p-5 shadow-2xl"
        >
          <div className="flex items-center gap-3">
            <div className="grid h-9 w-9 place-items-center rounded-lg bg-rose-500/15 text-rose-300">
              <AlertTriangle size={18} />
            </div>
            <div>
              <h2 className="text-sm font-bold text-rose-300">
                Error en {this.props.pageName}
              </h2>
              <p className="mt-0.5 text-[11px] text-zinc-500">
                Esta vista se ha aislado para no tumbar el resto de la interfaz.
              </p>
            </div>
          </div>
          {this.state.error?.message && (
            <pre className="mt-4 max-h-28 overflow-auto rounded-lg border border-surface-800 bg-surface-950 p-3 text-[10px] text-zinc-500">
              {this.state.error.message}
            </pre>
          )}
          <div className="mt-4 flex justify-end">
            <button
              type="button"
              onClick={this.retry}
              className="flex items-center gap-2 rounded-lg border border-accent/50 bg-accent/10 px-3 py-2 text-xs font-semibold text-accent transition hover:bg-accent/20"
            >
              <RefreshCw size={14} />
              Reintentar vista
            </button>
          </div>
        </section>
      </div>
    );
  }
}

export class ErrorBoundary extends Component<
  ErrorBoundaryProps,
  ErrorBoundaryState
> {
  state: ErrorBoundaryState = { hasError: false, error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // La consola queda como pista de diagnóstico sin exponerla en la UI.
    console.error("prox0x UI error", error, info.componentStack);
  }

  private reload = (): void => {
    window.location.reload();
  };

  render(): ReactNode {
    if (!this.state.hasError) return this.props.children;

    return (
      <div className="flex min-h-screen items-center justify-center bg-surface-950 p-6 font-mono text-zinc-200">
        <section
          role="alert"
          aria-label="Error de la interfaz"
          className="terminal-modal w-full max-w-xl rounded-2xl border border-rose-500/60 bg-surface-900 p-6 shadow-2xl"
        >
          <div className="flex items-center gap-3">
            <div className="grid h-10 w-10 place-items-center rounded-lg bg-rose-500/15 text-rose-300">
              <AlertTriangle size={20} />
            </div>
            <div>
              <h1 className="text-base font-bold text-rose-300">
                Algo ha ido mal
              </h1>
              <p className="mt-0.5 text-[11px] text-zinc-500">
                La interfaz encontró un estado inesperado.
              </p>
            </div>
          </div>

          <p className="mt-4 text-xs leading-relaxed text-zinc-400">
            Puede ocurrir al cambiar de proyecto o al recibir tráfico mientras
            hay breakpoints pendientes. Recarga para volver a un estado limpio;
            tus proyectos, CA e historial siguen guardados en{" "}
            <code className="text-cyan-300">~/.prox0x</code>.
          </p>

          {this.state.error?.message && (
            <pre className="mt-3 max-h-24 overflow-auto rounded-lg border border-surface-800 bg-surface-950 p-3 text-[10px] text-zinc-500">
              {this.state.error.message}
            </pre>
          )}

          <div className="mt-5 flex flex-wrap items-center justify-end gap-2">
            <button
              type="button"
              onClick={this.reload}
              className="flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-xs font-semibold text-surface-950 transition hover:bg-accent-soft"
            >
              <RefreshCw size={14} />
              Recargar prox0x
            </button>
          </div>
        </section>
      </div>
    );
  }
}
