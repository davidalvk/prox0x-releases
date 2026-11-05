import { useCallback, useEffect, useRef, useState } from "react";
import {
  Check,
  ChevronDown,
  FolderOpen,
  Loader2,
  Plus,
  Trash2,
} from "lucide-react";
import {
  createProject,
  deleteProject,
  fetchProjects,
  loadProject,
} from "../lib/api";
import { useApp } from "../context/AppContext";

export function ProjectSelector() {
  const { currentProject, setCurrentProject } = useApp();
  const [open, setOpen] = useState(false);
  const [projects, setProjects] = useState<string[]>(["Temporal"]);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState("");
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const refresh = useCallback(async () => {
    try {
      const data = await fetchProjects();
      setProjects(data.projects);
    } catch {
      // Si la API aún está levantando, mantiene el estado local.
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (!open) return;
    void refresh();
    const onPointerDown = (event: MouseEvent) => {
      if (
        containerRef.current &&
        !containerRef.current.contains(event.target as Node)
      ) {
        setOpen(false);
        setCreating(false);
        setConfirmDelete(null);
        setError(null);
      }
    };
    window.addEventListener("mousedown", onPointerDown);
    return () => window.removeEventListener("mousedown", onPointerDown);
  }, [open, refresh]);

  const handleLoad = async (name: string) => {
    setBusy(true);
    setError(null);
    try {
      const data = await loadProject(name);
      setProjects(data.projects);
      setCurrentProject(data.current);
      setOpen(false);
      setCreating(false);
      setConfirmDelete(null);
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
      setCurrentProject(loaded.current);
      setNewName("");
      setCreating(false);
      setOpen(false);
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
      if (currentProject === name) {
        setCurrentProject(data.current);
      }
    } catch (err: unknown) {
      setError(
        err instanceof Error ? err.message : "No se pudo eliminar el proyecto",
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div ref={containerRef} className="relative">
      <button
        type="button"
        onClick={() => {
          setOpen((prev) => !prev);
          setConfirmDelete(null);
          setError(null);
        }}
        aria-label="Selector de proyecto"
        aria-expanded={open}
        className="flex items-center gap-2 rounded-lg border border-surface-700 bg-surface-850 px-3 py-2 text-xs text-zinc-300 transition hover:border-surface-600 hover:text-zinc-100"
      >
        <FolderOpen size={14} className="text-accent" />
        <span className="font-mono text-xs">{currentProject ?? "Temporal"}</span>
        <ChevronDown size={13} className="text-zinc-500" />
      </button>

      {open && (
        <section
          aria-label="Proyectos"
          className="terminal-modal absolute right-0 top-full z-50 mt-2 w-80 overflow-hidden rounded-xl border border-surface-700 bg-surface-900 shadow-2xl"
        >
          <div className="border-b border-surface-800 px-3.5 py-2.5">
            <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
              Proyectos disponibles
            </p>
          </div>

          <ul className="max-h-56 divide-y divide-surface-800/70 overflow-auto">
            {projects.map((project) => {
              const active = project === currentProject;
              const isTemporal = project === "Temporal";
              return (
                <li
                  key={project}
                  className="flex items-center justify-between gap-2 px-3.5 py-2 text-xs"
                >
                  <span
                    title={
                      isTemporal
                        ? "Proyecto temporal. Su historial se borra al reiniciar prox0x."
                        : undefined
                    }
                    className={[
                      "truncate font-mono",
                      active ? "font-semibold text-accent" : "text-zinc-300",
                    ].join(" ")}
                  >
                    {project}
                  </span>

                  {confirmDelete === project ? (
                    <div className="flex items-center gap-1">
                      <span className="font-mono text-[10px] text-amber-400">
                        ¿Seguro?
                      </span>
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => void handleDelete(project)}
                        aria-label={`Confirmar eliminar ${project}`}
                        className="rounded border border-rose-500/60 bg-rose-950/50 px-2 py-0.5 text-[10px] font-semibold text-rose-300"
                      >
                        Sí
                      </button>
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => setConfirmDelete(null)}
                        aria-label={`Cancelar eliminar ${project}`}
                        className="rounded border border-surface-700 px-2 py-0.5 text-[10px] text-zinc-400"
                      >
                        No
                      </button>
                    </div>
                  ) : (
                    <div className="flex items-center gap-1.5">
                      {active ? (
                        <span className="inline-flex items-center gap-1 rounded border border-emerald-800/60 bg-emerald-950/40 px-2 py-0.5 text-[10px] text-emerald-300">
                          <Check size={11} />
                          Activo
                        </span>
                      ) : (
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => void handleLoad(project)}
                          aria-label={`Cargar ${project}`}
                          className="rounded border border-surface-700 bg-surface-850 px-2.5 py-1 text-[11px] font-medium text-zinc-300 transition hover:border-accent/50 hover:text-accent disabled:opacity-40"
                        >
                          Cargar
                        </button>
                      )}
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
                          "rounded border p-1 transition",
                          isTemporal
                            ? "cursor-not-allowed border-surface-800 bg-surface-900/40 text-zinc-600 opacity-50"
                            : "border-rose-500/50 bg-rose-950/35 text-rose-300 hover:border-rose-400 hover:text-rose-200",
                        ].join(" ")}
                      >
                        <Trash2 size={12} />
                      </button>
                    </div>
                  )}
                </li>
              );
            })}
          </ul>

          {error && (
            <div
              role="alert"
              className="border-t border-rose-900/60 bg-rose-950/30 px-3.5 py-2 text-[11px] text-rose-300"
            >
              {error}
            </div>
          )}

          <div className="border-t border-surface-800 bg-surface-950/60 p-3">
            {!creating ? (
              <button
                type="button"
                disabled={busy}
                onClick={() => {
                  setCreating(true);
                  setError(null);
                }}
                className="flex w-full items-center justify-center gap-1.5 rounded-lg border border-accent/40 bg-accent/10 px-3 py-2 text-xs font-semibold text-accent transition hover:bg-accent/20"
              >
                <Plus size={14} />
                + Nuevo Proyecto
              </button>
            ) : (
              <form
                onSubmit={(event) => {
                  event.preventDefault();
                  void handleCreate();
                }}
                className="space-y-2"
              >
                <input
                  value={newName}
                  onChange={(event) => setNewName(event.target.value)}
                  disabled={busy}
                  autoFocus
                  spellCheck={false}
                  aria-label="Nombre del proyecto"
                  placeholder="Auditoria-Web"
                  className="w-full rounded-lg border border-surface-700 bg-surface-950 px-2.5 py-1.5 font-mono text-xs text-zinc-200 outline-none placeholder:text-zinc-600 focus:border-accent/60"
                />
                <div className="flex items-center justify-end gap-2">
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => {
                      setCreating(false);
                      setNewName("");
                      setError(null);
                    }}
                    className="rounded-lg border border-surface-700 px-2.5 py-1 text-[11px] text-zinc-400 hover:text-zinc-200"
                  >
                    Cancelar
                  </button>
                  <button
                    type="submit"
                    disabled={busy}
                    className="flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1 text-[11px] font-semibold text-surface-950 transition hover:bg-accent-soft disabled:opacity-50"
                  >
                    {busy ? (
                      <Loader2 size={12} className="animate-spin" />
                    ) : (
                      <Plus size={12} />
                    )}
                    Crear
                  </button>
                </div>
              </form>
            )}
          </div>
        </section>
      )}
    </div>
  );
}
