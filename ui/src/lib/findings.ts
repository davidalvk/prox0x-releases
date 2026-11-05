export const SEVERITY_LABELS: Record<string, string> = {
  critical: "Crítica",
  high: "Alta",
  medium: "Media",
  low: "Baja",
  info: "Info",
  unknown: "Desconocida",
};

export const SEVERITY_CLASSES: Record<string, string> = {
  critical:
    "border-rose-400/80 bg-rose-500/15 text-rose-200 shadow-[0_0_10px_rgba(244,63,94,0.45)]",
  high: "border-rose-500/50 bg-rose-950/40 text-rose-300",
  medium: "border-amber-500/50 bg-amber-950/40 text-amber-300",
  low: "border-cyan-500/50 bg-cyan-950/40 text-cyan-300",
  info: "border-cyan-500/50 bg-cyan-950/40 text-cyan-300",
  unknown: "border-surface-700 bg-surface-850 text-zinc-400",
};

export const KIND_LABELS: Record<string, string> = {
  token: "Token",
  email: "Email",
  phone: "Teléfono",
  password: "Password",
  url: "URL",
  endpoint: "Endpoint",
  subdomain: "Subdominio",
  xss: "XSS",
  active_xss: "Active XSS",
  active_sqli: "Active SQLi",
  active_command: "Active Command Injection",
  active_traversal: "Path Traversal",
  nuclei_template: "Nuclei Template",
  interesting_route: "Ruta Interesante Encontrada",
};

export function severityLabel(value: string): string {
  return SEVERITY_LABELS[value] ?? value;
}

export function severityClass(value: string): string {
  return (
    SEVERITY_CLASSES[value] ??
    "border-surface-700 bg-surface-850 text-zinc-400"
  );
}

export function kindLabel(value: string): string {
  return KIND_LABELS[value] ?? value;
}
