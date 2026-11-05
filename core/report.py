"""Generación del informe HTML autocontenido de prox0x."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from html import escape

_SEVERITY_LABELS = {
    "high": "Alta",
    "medium": "Media",
    "info": "Info",
}
_SEVERITY_ORDER = ("high", "medium", "info")
_KIND_LABELS = {
    "token": "Token",
    "email": "Email",
    "phone": "Teléfono",
    "password": "Password",
    "url": "URL",
    "endpoint": "Endpoint",
    "subdomain": "Subdominio",
    "xss": "XSS reflejado",
}


def render_report(
    project: str,
    findings: list[dict],
    flow_count: int,
    *,
    generated_at: datetime | None = None,
) -> str:
    """Devuelve un documento HTML completo con CSS embebido."""
    now = generated_at or datetime.now(timezone.utc)
    counts = Counter(str(item.get("severity", "info")) for item in findings)
    summary_cards = "".join(
        (
            '<div class="card">'
            f'<span class="label">{_SEVERITY_LABELS[severity]}</span>'
            f'<strong class="value {severity}">{counts.get(severity, 0)}</strong>'
            "</div>"
        )
        for severity in _SEVERITY_ORDER
    )

    rows: list[str] = []
    for finding in findings:
        severity = str(finding.get("severity", "info"))
        rows.append(
            "<tr>"
            f'<td><span class="badge {escape(severity)}">'
            f"{escape(_SEVERITY_LABELS.get(severity, severity))}</span></td>"
            f"<td>{escape(_KIND_LABELS.get(str(finding.get('kind')), str(finding.get('kind', ''))))}</td>"
            f"<td class=\"evidence\">{escape(str(finding.get('evidence', '')))}</td>"
            f"<td class=\"url\">{escape(str(finding.get('url', '')))}</td>"
            f"<td class=\"mono\">#{escape(str(finding.get('flow_id', '')))}</td>"
            "</tr>"
        )
    if not rows:
        rows.append(
            '<tr><td colspan="5" class="empty">No se detectaron hallazgos.</td></tr>'
        )

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe prox0x · {escape(project)}</title>
<style>
:root {{ color-scheme: dark; }}
* {{ box-sizing: border-box; }}
body {{
  margin: 0; padding: 32px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  background: #050706; color: #d8f5d0;
}}
h1, h2 {{ margin: 0 0 8px; }}
h1 {{ color: #6fff6a; font-size: 26px; letter-spacing: .04em; }}
h2 {{ color: #7ee787; font-size: 16px; margin-top: 32px; }}
.sub {{ color: #7f9a7b; font-size: 12px; }}
.grid {{ display: flex; flex-wrap: wrap; gap: 12px; margin-top: 20px; }}
.card {{
  min-width: 150px; padding: 14px 18px; border: 1px solid #1d3320;
  border-radius: 10px; background: #0b120d;
}}
.label {{ display: block; color: #7f9a7b; font-size: 10px; text-transform: uppercase; }}
.value {{ display: block; margin-top: 6px; font-size: 26px; }}
.value.high {{ color: #ff7b72; }}
.value.medium {{ color: #f2cc60; }}
.value.info {{ color: #79c0ff; }}
table {{ width: 100%; margin-top: 14px; border-collapse: collapse; font-size: 12px; }}
th, td {{ border-bottom: 1px solid #17251a; padding: 9px 10px; text-align: left; vertical-align: top; }}
th {{ color: #8bdc86; font-size: 10px; text-transform: uppercase; letter-spacing: .08em; }}
.badge {{
  display: inline-block; padding: 2px 7px; border-radius: 999px;
  border: 1px solid currentColor; font-size: 10px; font-weight: 700;
}}
.badge.high {{ color: #ff7b72; }}
.badge.medium {{ color: #f2cc60; }}
.badge.info {{ color: #79c0ff; }}
.evidence {{ color: #d8f5d0; word-break: break-word; }}
.url {{ color: #79c0ff; word-break: break-all; }}
.mono {{ color: #8bdc86; white-space: nowrap; }}
.empty {{ color: #7f9a7b; text-align: center; padding: 24px; }}
footer {{ margin-top: 32px; color: #55705a; font-size: 10px; }}
</style>
</head>
<body>
<h1>prox0x · Informe de auditoría</h1>
<p class="sub">Proyecto: <strong>{escape(project)}</strong> · Generado: {escape(now.isoformat())}</p>
<div class="grid">
  <div class="card"><span class="label">Flujos interceptados</span><strong class="value">{flow_count}</strong></div>
  <div class="card"><span class="label">Hallazgos</span><strong class="value">{len(findings)}</strong></div>
  {summary_cards}
</div>
<h2>Resumen por severidad</h2>
<p class="sub">Alta: {counts.get('high', 0)} · Media: {counts.get('medium', 0)} · Info: {counts.get('info', 0)}</p>
<h2>Hallazgos detallados</h2>
<table>
<thead><tr><th>Severidad</th><th>Tipo</th><th>Evidencia</th><th>URL</th><th>Flow</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
<footer>Informe generado localmente por prox0x. Herramienta para auditorías éticas.</footer>
</body>
</html>
"""
