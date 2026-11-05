import {
  Activity,
  ArrowUpCircle,
  Bug,
  Code2,
  Crosshair,
  Download,
  FolderTree,
  GitCompare,
  Home,
  PanelLeftClose,
  PanelLeftOpen,
  RadioTower,
  Replace,
  ScanSearch,
  Send,
  Settings,
  X,
  type LucideIcon,
} from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import type { ModuleId, UpdateStatus } from "../types";
import { checkForUpdates } from "../lib/api";
import { useApp } from "../context/AppContext";
import { BreakpointModal } from "./BreakpointModal";
import { CertificateModal } from "./CertificateModal";
import { GlobalSearch } from "./GlobalSearch";
import { InterceptToggle } from "./InterceptToggle";
import { ProjectSelector } from "./ProjectSelector";
import { ScopeButton } from "./ScopeButton";
import { Sidebar } from "./Sidebar";

const SIDEBAR_STORAGE_KEY = "prox0x.sidebarOpen";

const TITLES: Record<
  ModuleId,
  { title: string; subtitle: string; icon: LucideIcon }
> = {
  home: {
    title: "Inicio",
    subtitle: "Panel de control del proyecto y operaciones en curso",
    icon: Home,
  },
  proxy: {
    title: "Interceptación",
    subtitle: "Historial de tráfico HTTP/1.1, HTTP/2 y WebSocket",
    icon: Activity,
  },
  repeater: {
    title: "Reenvío",
    subtitle: "Edita la petición y reenvíala al origen",
    icon: Send,
  },
  intruder: {
    title: "Intrusión",
    subtitle:
      "Envío masivo manual de payloads (Sniper, Pitchfork, Cluster Bomb)",
    icon: Crosshair,
  },
  findings: {
    title: "Hallazgos",
    subtitle: "Tokens, PII, recon y posible XSS detectados en el tráfico",
    icon: Bug,
  },
  "active-scan": {
    title: "Escáner Web",
    subtitle: "Fuzzing XSS/SQLi y CVEs con plantillas Nuclei",
    icon: ScanSearch,
  },
  comparer: {
    title: "Comparador",
    subtitle: "Diff línea a línea entre dos peticiones o respuestas",
    icon: GitCompare,
  },
  settings: {
    title: "Ajustes",
    subtitle: "Macro de login y renovación automática de sesión",
    icon: Settings,
  },
  oob: {
    title: "OOB",
    subtitle: "Servidor local o Interactsh online para callbacks ciegos",
    icon: RadioTower,
  },
  sitemap: {
    title: "Mapa de Rutas",
    subtitle: "Endpoints descubiertos agrupados por host y ruta",
    icon: FolderTree,
  },
  decoder: {
    title: "Codificación",
    subtitle: "Codifica, decodifica y hashea datos en el navegador",
    icon: Code2,
  },
  "match-replace": {
    title: "Transformación",
    subtitle: "Reemplaza cabeceras y cuerpos automáticamente",
    icon: Replace,
  },
};

function readInitialSidebarState(): boolean {
  try {
    const raw = window.localStorage.getItem(SIDEBAR_STORAGE_KEY);
    if (raw === "false") return false;
    if (raw === "true") return true;
  } catch {
    // localStorage no disponible
  }
  return true;
}

export function Layout({ children }: { children: ReactNode }) {
  const { activeModule } = useApp();
  const [sidebarOpen, setSidebarOpen] = useState<boolean>(readInitialSidebarState);
  const [update, setUpdate] = useState<UpdateStatus | null>(null);
  const [updateDismissed, setUpdateDismissed] = useState(false);
  const heading = TITLES[activeModule];
  const HeadingIcon = heading.icon;

  useEffect(() => {
    let cancelled = false;
    void checkForUpdates()
      .then((result) => {
        if (!cancelled && result.update_available) setUpdate(result);
      })
      .catch(() => {
        // El chequeo es best-effort: no debe afectar al arranque.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    try {
      window.localStorage.setItem(SIDEBAR_STORAGE_KEY, String(sidebarOpen));
    } catch {
      // ignora errores de cuota o privacidad
    }
  }, [sidebarOpen]);

  return (
    <div className="flex h-screen overflow-hidden bg-surface-950 text-zinc-200">
      <Sidebar open={sidebarOpen} />
      <main className="flex min-w-0 flex-1 flex-col">
        <header className="relative z-30 flex h-16 shrink-0 items-center justify-between gap-3 overflow-hidden border-b border-surface-700 bg-surface-900/80 px-5">
          <div className="flex min-w-[10rem] flex-1 items-center gap-3">
            <button
              type="button"
              onClick={() => setSidebarOpen((prev) => !prev)}
              aria-label={
                sidebarOpen ? "Ocultar barra lateral" : "Mostrar barra lateral"
              }
              title={
                sidebarOpen ? "Ocultar barra lateral" : "Mostrar barra lateral"
              }
              className="rounded-lg border border-surface-700 bg-surface-850 p-2 text-zinc-300 transition hover:border-accent/60 hover:text-accent"
            >
              {sidebarOpen ? (
                <PanelLeftClose size={16} />
              ) : (
                <PanelLeftOpen size={16} />
              )}
            </button>
            <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-surface-700 bg-surface-850 text-accent">
              <HeadingIcon size={16} />
            </span>
            <div className="min-w-0">
              <div className="flex min-w-0 items-baseline gap-2">
                <h1 className="min-w-[6rem] truncate text-base font-bold tracking-wide text-accent">
                  {heading.title}
                  <span aria-hidden="true" className="terminal-cursor">
                    _
                  </span>
                </h1>
                <span className="hidden font-mono text-[10px] uppercase tracking-[0.18em] text-cyan-400 2xl:inline">
                  / {heading.title}
                </span>
              </div>
              <p
                key={activeModule}
                className="terminal-typewriter truncate text-xs text-zinc-400"
              >
                {heading.subtitle}
              </p>
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <GlobalSearch />
            <ProjectSelector />
            <CertificateModal />
            <ScopeButton />
            <InterceptToggle />
            <div className="hidden items-center gap-2 rounded border border-surface-700 bg-surface-850 px-3 py-1.5 text-[11px] text-cyan-300 2xl:flex">
              <Activity size={14} className="text-accent" />
              API local · 127.0.0.1:8000
            </div>
          </div>
        </header>
        {update?.update_available && !updateDismissed && (
          <div
            role="status"
            data-testid="update-banner"
            className="flex flex-wrap items-center gap-3 border-b border-amber-400/40 bg-amber-950/30 px-5 py-2 text-xs text-amber-200"
          >
            <ArrowUpCircle size={15} className="shrink-0 text-amber-300" />
            <span>
              Nueva versión disponible{" "}
              <strong className="font-mono text-amber-100">
                ({update.latest_version})
              </strong>
              .
            </span>
            <a
              href={
                update.download_url ??
                "https://github.com/davidalvk/prox0x-releases/releases/latest"
              }
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 rounded border border-amber-400/50 bg-amber-400/10 px-2 py-1 font-semibold text-amber-200 transition hover:bg-amber-400/20"
            >
              <Download size={12} />
              Descargar actualización
            </a>
            <button
              type="button"
              onClick={() => setUpdateDismissed(true)}
              aria-label="Descartar aviso de actualización"
              title="Descartar aviso"
              className="ml-auto rounded p-1 text-amber-300/70 transition hover:bg-amber-400/10 hover:text-amber-100"
            >
              <X size={14} />
            </button>
          </div>
        )}
        <div className="min-h-0 flex-1 overflow-hidden">{children}</div>
      </main>
      <BreakpointModal />
    </div>
  );
}
