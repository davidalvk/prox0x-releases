import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  FolderOpen,
  Loader2,
  Plus,
  Terminal,
  Trash2,
} from "lucide-react";
import {
  createProject,
  deleteProject,
  fetchProjects,
  loadProject,
} from "../lib/api";
import { useApp } from "../context/AppContext";
import { CertificateModal } from "./CertificateModal";

export function WelcomeScreen() {
  const { setCurrentProject } = useApp();
  const [projects, setProjects] = useState<string[]>(["Temporal"]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [newName, setNewName] = useState("");
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchProjects();
      setProjects(data.projects);
    } catch {
      // Mantiene Temporal si la API aún está iniciando.
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const handleSelect = async (name: string) => {
    setBusy(true);
    setError(null);
    try {
      const data = await loadProject(name);
      setProjects(data.projects);
      setCurrentProject(data.current);
    } catch (err: unknown) {
      setError(
        err instanceof Error ? err.message : "No se pudo cargar el proyecto",
      );
    } finally {
      setBusy(false);
    }
  };

  const handleCreate = async () => {
    const trimmed = newName.trim();
    if (!trimmed) {
      setError("Escribe un nombre para el proyecto.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await createProject(trimmed);
      const loaded = await loadProject(trimmed);
      setProjects(loaded.projects);
      setNewName("");
      setCurrentProject(loaded.current);
    } catch (err: unknown) {
      setError(
        err instanceof Error ? err.message : "No se pudo crear el proyecto",
      );
    } finally {
      setBusy(false);
    }
  };

  const handleDelete = async (name: string) => {
    setBusy(true);
    setError(null);
    try {
      const data = await deleteProject(name);
      setProjects(data.projects);
      setConfirmDelete(null);
    } catch (err: unknown) {
      setError(
        err instanceof Error ? err.message : "No se pudo eliminar el proyecto",
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-surface-950 p-6 text-zinc-200">
      <section
        aria-label="Bienvenida de prox0x"
        className="terminal-modal w-full max-w-2xl overflow-hidden rounded-2xl border border-accent bg-surface-900 shadow-2xl"
      >
        <header className="flex items-center justify-between border-b border-surface-700 bg-surface-900/90 px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="grid h-10 w-10 place-items-center rounded border border-accent/60 bg-accent/10 text-accent shadow-glow">
              <Terminal size={20} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-base font-bold tracking-wider text-accent">
                  PROX0X
                </span>
                <span className="rounded border border-cyan-400/50 bg-cyan-950/50 px-1.5 py-0.5 font-mono text-[10px] text-cyan-400">
                  SYS//01
                </span>
              </div>
              <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-zinc-500">
                ┌─[ CONSOLA DE AUDITORÍA WEB ]─┐
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <CertificateModal showTooltip={false} />
            <span className="font-mono text-xs text-amber-400">v1.2.0</span>
          </div>
        </header>

        <div className="space-y-6 p-6">
          <div>
            <h1 className="terminal-typewriter text-lg font-bold text-accent">
              Selecciona un proyecto o crea uno nuevo
              <span aria-hidden="true" className="terminal-cursor">
                _
              </span>
            </h1>
            <p className="mt-1 text-xs text-zinc-400">
              Cada proyecto aísla su propio historial de Interceptación, reglas
              de Alcance y Transformación en una base de datos independiente.
            </p>
          </div>

          {error && (
            <div
              role="alert"
              className="flex items-center gap-2 rounded-lg border border-rose-900/60 bg-rose-950/30 px-4 py-2.5 text-xs text-rose-300"
            >
              <AlertTriangle size={14} className="shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div className="grid gap-5 md:grid-cols-2">
            <div className="flex flex-col rounded-xl border border-surface-700 bg-surface-950/70">
              <div className="border-b border-surface-800 px-4 py-2.5">
                <h2 className="text-[11px] font-semibold uppercase tracking-[0.16em] text-cyan-400">
                  Proyectos disponibles
                </h2>
              </div>

              {loading ? (
                <div className="grid h-44 place-items-center text-zinc-500">
                  <Loader2 size={18} className="animate-spin text-accent" />
                </div>
              ) : (
                <ul className="max-h-56 divide-y divide-surface-800/80 overflow-auto">
                  {projects.map((project) => {
                    const isTemporal = project === "Temporal";
                    return (
                      <li
                        key={project}
                        className="flex items-center justify-between gap-2 px-4 py-2.5 text-xs"
                      >
                        <div className="min-w-0">
                          <span
                            title={
                              isTemporal
                                ? "Proyecto temporal. Su historial se borra al reiniciar prox0x."
                                : undefined
                            }
                            className="flex min-w-0 items-center gap-2 truncate font-mono text-zinc-200"
                          >
                            <FolderOpen
                              size={14}
                              className="shrink-0 text-accent"
                            />
                            <span className="truncate">{project}</span>
                          </span>
                          {isTemporal && (
                            <p className="mt-0.5 pl-6 text-[10px] text-amber-400/90">
                              Proyecto temporal. Su historial se borra al
                              reiniciar prox0x.
                            </p>
                          )}
                        </div>

                        {confirmDelete === project ? (
                          <div className="flex items-center gap-1.5">
                            <span className="font-mono text-[10px] text-amber-400">
                              ¿Seguro?
                            </span>
                            <button
                              type="button"
                              disabled={busy}
                              onClick={() => void handleDelete(project)}
                              aria-label={`Confirmar eliminar ${project}`}
                              className="rounded border border-rose-500/60 bg-rose-950/60 px-2 py-1 text-[10px] font-semibold text-rose-300"
                            >
                              Sí
                            </button>
                            <button
                              type="button"
                              disabled={busy}
                              onClick={() => setConfirmDelete(null)}
                              aria-label={`Cancelar eliminar ${project}`}
                              className="rounded border border-surface-700 px-2 py-1 text-[10px] text-zinc-400"
                            >
                              No
                            </button>
                          </div>
                        ) : (
                          <div className="flex items-center gap-1.5">
                            <button
                              type="button"
                              disabled={busy}
                              onClick={() => void handleSelect(project)}
                              aria-label={`Cargar ${project}`}
                              className="rounded border border-accent/50 bg-accent/10 px-2.5 py-1 text-[11px] font-semibold text-accent transition hover:bg-accent hover:text-surface-950 disabled:opacity-40"
                            >
                              Cargar
                            </button>
                            <button
                              type="button"
                              disabled={busy || isTemporal}
                              onClick={() => setConfirmDelete(project)}
                              aria-label={`Eliminar ${project}`}
                              title={
                                isTemporal
                                  ? "Proyecto del sistema, no se puede eliminar"
                                  : `Eliminar proyecto ${project}`
                              }
                              className={[
                                "inline-flex items-center gap-1 rounded border px-2 py-1 text-[11px] font-medium transition",
                                isTemporal
                                  ? "cursor-not-allowed border-surface-800 bg-surface-900/40 text-zinc-600 opacity-50"
                                  : "border-rose-500/50 bg-rose-950/35 text-rose-300 hover:border-rose-400 hover:text-rose-200",
                              ].join(" ")}
                            >
                              <Trash2 size={12} />
                              <span>Eliminar</span>
                            </button>
                          </div>
                        )}
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>

            <form
              onSubmit={(event) => {
                event.preventDefault();
                void handleCreate();
              }}
              className="flex flex-col justify-between rounded-xl border border-surface-700 bg-surface-950/70 p-4"
            >
              <div className="space-y-3">
                <h2 className="text-[11px] font-semibold uppercase tracking-[0.16em] text-cyan-400">
                  + Nuevo Proyecto
                </h2>
                <p className="text-[11px] text-zinc-500">
                  Crea un entorno aislado para una máquina, objetivo o auditoría
                  específica.
                </p>
                <label className="block space-y-1">
                  <span className="text-[10px] uppercase tracking-[0.14em] text-zinc-400">
                    Nombre del proyecto
                  </span>
                  <input
                    value={newName}
                    onChange={(event) => setNewName(event.target.value)}
                    disabled={busy}
                    spellCheck={false}
                    aria-label="Nombre del proyecto"
                    placeholder="Auditoria-Web"
                    className="w-full rounded-lg border border-surface-700 bg-surface-950 px-3 py-2 font-mono text-xs text-zinc-200 outline-none placeholder:text-zinc-600"
                  />
                </label>
              </div>

              <button
                type="submit"
                disabled={busy}
                className="mt-4 flex w-full items-center justify-center gap-2 rounded-lg bg-accent px-4 py-2.5 text-xs font-semibold text-surface-950 transition hover:bg-accent-soft disabled:opacity-50"
              >
                {busy ? (
                  <Loader2 size={14} className="animate-spin" />
                ) : (
                  <Plus size={14} />
                )}
                Crear
              </button>
            </form>
          </div>
        </div>

        <footer className="flex flex-wrap items-center justify-between gap-2 border-t border-surface-700 bg-surface-900/60 px-6 py-3 font-mono text-[11px] text-zinc-400">
          <span>[*] LOOPBACK // 127.0.0.1:8080</span>
          <span>
            Creado por <span className="font-semibold text-accent">Davidal VK</span>
            {" | "}
            <a
              href="https://davidalvk.com"
              target="_blank"
              rel="noopener noreferrer"
              className="text-cyan-400 underline decoration-cyan-400/40 underline-offset-2"
            >
              Web
            </a>
            {" | "}
            <a
              href="https://www.linkedin.com/in/davidalvk/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-cyan-400 underline decoration-cyan-400/40 underline-offset-2"
            >
              LinkedIn
            </a>
          </span>
        </footer>
      </section>
    </div>
  );
}
