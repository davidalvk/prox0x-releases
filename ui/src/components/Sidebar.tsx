import { Github, Terminal } from "lucide-react";
import type { ModuleId } from "../types";
import { useApp } from "../context/AppContext";
import { HelpTooltip } from "./HelpTooltip";

interface SidebarProps {
  open: boolean;
}

interface NavItem {
  kind: "module";
  id: ModuleId;
  label: string;
  hint: string;
  glyph: string;
  help: string;
}

interface NavAction {
  kind: "scope";
  label: string;
  hint: string;
  glyph: string;
  help: string;
}

type NavEntry = NavItem | NavAction;

interface NavGroup {
  title: string;
  items: NavEntry[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    title: "Principal",
    items: [
      {
        kind: "module",
        id: "home",
        label: "Inicio",
        hint: "Panel de control",
        glyph: "H",
        help: "Resumen del proyecto: estadísticas, operaciones en curso, últimos hallazgos y accesos rápidos.",
      },
      {
        kind: "module",
        id: "proxy",
        label: "Interceptación",
        hint: "Historial en vivo",
        glyph: ">",
        help: "Captura y muestra todo el tráfico HTTP/HTTPS que pasa por tu navegador.",
      },
      {
        kind: "module",
        id: "repeater",
        label: "Reenvío",
        hint: "Editar y reenviar",
        glyph: "-",
        help: "Modifica peticiones a mano y vuelve a enviarlas al servidor para probar cosas.",
      },
      {
        kind: "module",
        id: "intruder",
        label: "Intrusión",
        hint: "Envío masivo manual",
        glyph: "!",
        help: "Fuzzing manual con diccionarios: Sniper, Pitchfork, Cluster Bomb y más.",
      },
    ],
  },
  {
    title: "Análisis Automático",
    items: [
      {
        kind: "module",
        id: "active-scan",
        label: "Escáner Web",
        hint: "Fuzzing y CVEs",
        glyph: "ZAP",
        help: "Fuzzing XSS/SQLi y ejecución de CVEs con plantillas Nuclei, con evidencia y progreso en vivo.",
      },
      {
        kind: "module",
        id: "sitemap",
        label: "Mapa de Rutas",
        hint: "Endpoints descubiertos",
        glyph: "T",
        help: "Muestra un árbol con todas las rutas y métodos HTTP descubiertos en la web.",
      },
      {
        kind: "module",
        id: "findings",
        label: "Hallazgos",
        hint: "Tokens, PII y XSS",
        glyph: "?",
        help: "Hallazgos pasivos detectados en el tráfico: tokens, datos personales, endpoints y posible XSS reflejado.",
      },
    ],
  },
  {
    title: "Herramientas",
    items: [
      {
        kind: "module",
        id: "oob",
        label: "OOB",
        hint: "Interacciones ciegas",
        glyph: "OOB",
        help: "Servidor Out-of-Band local o Interactsh online para detectar SSRF, XXE, XSS ciego y más.",
      },
      {
        kind: "module",
        id: "match-replace",
        label: "Transformación",
        hint: "Reglas automáticas",
        glyph: "<>",
        help: "Reglas automáticas para modificar cabeceras o cuerpos sin tocar el tráfico a mano.",
      },
      {
        kind: "module",
        id: "decoder",
        label: "Codificación",
        hint: "Codificar y decodificar",
        glyph: "{}",
        help: "Herramienta para codificar/decodificar Base64, URL, Hex y calcular hashes.",
      },
      {
        kind: "module",
        id: "comparer",
        label: "Comparador",
        hint: "Diff de textos",
        glyph: "A/B",
        help: "Compara dos peticiones o respuestas y resalta las líneas añadidas y eliminadas.",
      },
    ],
  },
  {
    title: "Sistema",
    items: [
      {
        kind: "module",
        id: "settings",
        label: "Ajustes",
        hint: "Macro de login",
        glyph: "S",
        help: "Configura la petición de login y la regex para renovar la sesión tras un 401/403.",
      },
      {
        kind: "scope",
        label: "Alcance",
        hint: "Dominios permitidos",
        glyph: "[]",
        help: "Define qué dominios o IPs te interesan. El resto del tráfico se ignorará.",
      },
    ],
  },
];

export function Sidebar({ open }: SidebarProps) {
  const { activeModule, setActiveModule } = useApp();

  const openItem = (item: NavEntry) => {
    if (item.kind === "scope") {
      window.dispatchEvent(new Event("prox0x:open-scope"));
      return;
    }
    setActiveModule(item.id);
  };

  return (
    <aside
      aria-label="Menú principal"
      aria-hidden={!open}
      style={{
        transform: open ? "translateX(0)" : "translateX(-100%)",
      }}
      className={[
        "flex shrink-0 flex-col overflow-hidden bg-surface-950/95 transition-[width,transform] duration-200 ease-out",
        open
          ? "w-16 border-r border-surface-700 lg:w-64"
          : "pointer-events-none w-0 border-r-0",
      ].join(" ")}
    >
      <div className="flex h-16 w-16 items-center gap-3 border-b border-surface-700 bg-surface-900/70 px-4 lg:w-64">
        <div className="grid h-9 w-9 shrink-0 place-items-center rounded border border-accent/60 bg-accent/10 font-mono text-sm font-bold text-accent shadow-glow">
          <Terminal size={17} />
        </div>
        <div className="hidden min-w-0 lg:block">
          <div className="flex items-center gap-1.5">
            <p className="font-mono text-sm font-bold tracking-wider text-accent">
              PROX0X
            </p>
            <span className="rounded border border-cyan-400/50 bg-cyan-950/50 px-1 py-0.2 font-mono text-[9px] text-cyan-400">
              SYS//01
            </span>
          </div>
          <p className="truncate font-mono text-[9px] uppercase tracking-[0.18em] text-zinc-500">
            ┌─[ TACTICAL PROXY ]─┐
          </p>
        </div>
      </div>

      <nav className="flex min-h-0 w-16 flex-1 flex-col overflow-y-auto p-2 lg:w-64 lg:p-3">
        {NAV_GROUPS.map((group) => (
          <div
            key={group.title}
            role="group"
            aria-label={group.title}
            className="mt-3 first:mt-0"
          >
            <p className="hidden px-3 pb-1 font-mono text-[9px] font-semibold uppercase tracking-[0.22em] text-zinc-600 lg:block">
              {group.title}
            </p>
            <div className="mx-2 mb-2 border-t border-surface-800 lg:hidden" />
            <div className="space-y-1.5">
              {group.items.map((item) => {
                const selected =
                  item.kind === "module" && activeModule === item.id;
                return (
                  <div
                    key={`${group.title}-${item.label}`}
                    className="flex items-center gap-1.5"
                  >
                    <button
                      type="button"
                      onClick={() => openItem(item)}
                      aria-current={selected ? "page" : undefined}
                      className={[
                        "group flex min-w-0 flex-1 items-center gap-3 rounded border px-3 py-2.5 text-left transition",
                        selected
                          ? "border-accent bg-accent/15 text-accent shadow-glow"
                          : "border-surface-800/80 bg-surface-900/40 text-zinc-400 hover:border-accent/60 hover:bg-surface-850 hover:text-zinc-100",
                      ].join(" ")}
                      title={item.label}
                    >
                      <span
                        aria-hidden="true"
                        className={[
                          "w-7 shrink-0 text-center font-mono text-xs font-bold",
                          selected ? "text-cyan-400" : "text-accent",
                        ].join(" ")}
                      >
                        [{item.glyph}]
                      </span>
                      <span className="hidden min-w-0 flex-1 lg:block">
                        <span className="block text-xs font-semibold tracking-wide">
                          {item.label}
                        </span>
                        <span className="block truncate text-[10px] text-zinc-500">
                          {item.hint}
                        </span>
                      </span>
                    </button>
                    <HelpTooltip
                      label={item.label}
                      text={item.help}
                      className="hidden lg:inline-flex"
                    />
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      <footer className="hidden w-64 border-t border-surface-700 bg-surface-900/50 px-4 py-3 lg:block">
        <div className="flex items-center justify-between text-[10px] text-zinc-500">
          <span className="flex items-center gap-1.5 font-mono">
            <span aria-hidden="true" className="text-cyan-400">
              [*]
            </span>
            <span>LOOPBACK // SECURE</span>
          </span>
          <span className="font-mono text-[10px] text-amber-400">v1.2.0</span>
        </div>
        <p className="mt-2 border-t border-surface-800 pt-2 font-mono text-[10px] leading-relaxed text-zinc-400">
          Creado por <span className="font-semibold text-accent">Davidal VK</span>
          {" | "}
          <a
            href="https://davidalvk.com"
            target="_blank"
            rel="noopener noreferrer"
            className="text-cyan-400 underline decoration-cyan-400/40 underline-offset-2 transition hover:text-accent"
          >
            Web
          </a>
          {" | "}
          <a
            href="https://www.linkedin.com/in/davidalvk/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-cyan-400 underline decoration-cyan-400/40 underline-offset-2 transition hover:text-accent"
          >
            LinkedIn
          </a>
          {" | "}
          <a
            href="https://github.com/davidalvk/prox0x-releases"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="Repositorio público de prox0x en GitHub"
            className="inline-flex items-center gap-1 text-cyan-400 underline decoration-cyan-400/40 underline-offset-2 transition hover:text-accent"
          >
            <Github size={11} aria-hidden="true" />
            GitHub
          </a>
        </p>
      </footer>
    </aside>
  );
}
