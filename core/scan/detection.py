"""Firmas, contextos y reglas de evidencia del Escáner Activo (Fase 2).

La firma SQL reproduce una cadena de errores común en motores comerciales. Para reducir falsos
positivos se separa en marcadores fuertes y débiles: un marcador fuerte basta;
los débiles solo cuentan si el baseline no los tenía y la respuesta es 5xx.
"""

from __future__ import annotations

import re

# Firma exacta recuperada de wvsc.exe.
SQL_ERROR_SIGNATURE = (
    "error|failed|exception|invalid|warning|stack|pg_query|mysql_query|"
    "sql syntax|divisor|divide|ora-|division|infinity"
)
SQL_ERROR_RE = re.compile(SQL_ERROR_SIGNATURE, re.IGNORECASE)

# Frases que el escáner anterior ya reconocía y que la firma SQL base no
# cubre literalmente. Se mantienen como marcadores fuertes para no perder
# cobertura; las palabras genéricas ``mysql``/``postgresql`` se omiten porque
# aparecen en páginas normales y producían falsos positivos.
SQL_EXTRA_STRONG_MARKERS = frozenset(
    {
        "unclosed quotation mark",
        "odbc sql server driver",
        "microsoft ole db",
        "you have an error in your sql syntax",
        "syntax error",
        "syntax error at or near",
        "sqlite error",
        "unrecognized token",
        "no such table",
        "no such column",
    }
)

SQL_STRONG_MARKERS = frozenset(
    {
        "pg_query",
        "mysql_query",
        "sql syntax",
        "divisor",
        "divide",
        "ora-",
        "division",
        "infinity",
    }
) | SQL_EXTRA_STRONG_MARKERS
SQL_WEAK_MARKERS = frozenset(
    {"error", "failed", "exception", "invalid", "warning", "stack"}
)

_TRAVERSAL_MARKERS: tuple[str, ...] = (
    "root:x:0:0:",
    "root:*:0:0:",
    "[fonts]",
    "[extensions]",
    "for 16-bit app support",
)

_URL_ATTRIBUTES = frozenset(
    {
        "href",
        "src",
        "action",
        "formaction",
        "poster",
        "data",
        "srcset",
        "cite",
        "background",
    }
)


def sql_markers(text: str) -> frozenset[str]:
    """Marcadores de la firma SQL y de las frases extra presentes en ``text``."""

    if not text:
        return frozenset()
    markers = {match.group(0).lower() for match in SQL_ERROR_RE.finditer(text)}
    lower = text.lower()
    markers.update(
        phrase for phrase in SQL_EXTRA_STRONG_MARKERS if phrase in lower
    )
    return frozenset(markers)


def sql_candidate(
    body: str,
    baseline_markers: frozenset[str],
    status_code: int,
) -> tuple[bool, str, str]:
    """Decide si una respuesta es evidencia SQLi.

    Devuelve ``(es_candidato, severidad, marcadores)``. Los marcadores que ya
    aparecían en el baseline se descartan, que es el control negativo que evita
    marcar páginas que siempre muestran "error".

    Un marcador fuerte (``sql syntax``, ``pg_query``, ``ora-``...) confirma el
    hallazgo con severidad alta. Un marcador débil (``error``, ``failed``...)
    que no estaba en el baseline se acepta como severidad media solo si la
    respuesta es 5xx; así una validación 400/422 no se confunde con SQLi.
    """

    markers = sql_markers(body)
    new_markers = markers - baseline_markers
    strong = new_markers & SQL_STRONG_MARKERS
    if strong:
        return True, "high", ", ".join(sorted(strong))

    weak = new_markers & SQL_WEAK_MARKERS
    if weak and status_code >= 500:
        return True, "medium", ", ".join(sorted(weak))

    return False, "", ""


def traversal_marker(body: str, baseline_body: str | None) -> str | None:
    """Devuelve el marcador de fichero encontrado y ausente en el baseline."""

    for marker in _TRAVERSAL_MARKERS:
        if marker in body and (baseline_body is None or marker not in baseline_body):
            return marker
    return None


_COMMAND_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+"),
    re.compile(r"root:x:0:0:"),
    re.compile(r"(?i)nt authority\\(system|network service|local service)"),
    re.compile(r"(?i)(www-data|nobody|daemon|apache|nginx|tomcat):"),
    re.compile(r"(?i)bytes from \d+\.\d+\.\d+\.\d+"),
    re.compile(r"(?i)Linux \S+ \d+\.\d+"),
)


def command_marker(body: str, baseline_body: str | None) -> str | None:
    """Devuelve una salida típica de comando ausente en el baseline."""

    for pattern in _COMMAND_PATTERNS:
        match = pattern.search(body)
        if match is None:
            continue
        value = match.group(0)
        if baseline_body is None or value not in baseline_body:
            return value
    return None


def time_based_candidate(
    latency_ms: float | None,
    baseline_ms: float | None,
    *,
    threshold_ms: float = 4_000.0,
    baseline_limit_ms: float = 1_500.0,
) -> bool:
    """Confirma un delay si supera el umbral y el baseline era rápido."""

    if latency_ms is None or latency_ms < threshold_ms:
        return False
    return baseline_ms is None or baseline_ms < baseline_limit_ms


def boolean_candidate(
    baseline_length: int,
    baseline_status: int,
    true_length: int,
    true_status: int,
    false_length: int,
    false_status: int,
) -> bool:
    """Compara la respuesta verdadera/falsa contra el baseline.

    La señal principal es que la condición verdadera y la falsa produzcan
    cuerpos distintos. Además, al menos una de las dos debe parecerse al
    baseline, para descartar páginas que cambian por contenido dinámico. Un
    cambio de código HTTP entre ambas también cuenta como evidencia.

    El umbral relativo es bajo (1 %, mínimo 100 B) porque las páginas reales
    suelen tener mucho HTML estático alrededor de una lista de resultados
    pequeña; exigir un 20 % ocultaba inyecciones booleanas reales.
    """

    if true_status != false_status:
        return baseline_status in (true_status, false_status)

    if true_status != baseline_status or false_status != baseline_status:
        return False

    largest = max(baseline_length, true_length, false_length, 1)
    tolerance = max(100, round(largest * 0.15))
    significant = max(100, round(largest * 0.01))

    resembles_baseline = (
        abs(true_length - baseline_length) <= tolerance
        or abs(false_length - baseline_length) <= tolerance
    )
    if not resembles_baseline:
        return False
    return abs(true_length - false_length) >= significant


def xss_contexts(body: str, canary: str) -> tuple[str, ...]:
    """Clasifica el contexto HTML/JS en el que se refleja ``canary``.

    Contextos: ``html``, ``attr_double``, ``attr_single``, ``attr_unquoted``,
    ``url``, ``script``, ``style`` y ``comment``. Se devuelven sin duplicados.
    """

    if not body or not canary:
        return ()
    lower = body.lower()
    seen: list[str] = []

    for match in re.finditer(re.escape(canary), body):
        pos = match.start()

        # Comentario HTML: el payload no ejecuta salvo que rompa el comentario.
        if lower.rfind("<!--", 0, pos) > lower.rfind("-->", 0, pos):
            context = "comment"

        else:
            last_lt = lower.rfind("<", 0, pos)
            last_gt = lower.rfind(">", 0, pos)

            if last_lt > last_gt:
                # Dentro de una etiqueta de apertura: atributo.
                tag_prefix = lower[last_lt:pos]
                double_quotes = tag_prefix.count('"')
                single_quotes = tag_prefix.count("'")
                attr_match = re.search(
                    r'([:\w-]+)\s*=\s*["\']?[^"\'>]*$', tag_prefix
                )
                attr_name = attr_match.group(1) if attr_match else ""

                if double_quotes % 2 == 1:
                    context = "attr_double"
                elif single_quotes % 2 == 1:
                    context = "attr_single"
                else:
                    context = "attr_unquoted"

                if attr_name in _URL_ATTRIBUTES:
                    context = "url"

            elif lower.rfind("<script", 0, pos) > lower.rfind("</script", 0, pos):
                context = "script"

            elif lower.rfind("<style", 0, pos) > lower.rfind("</style", 0, pos):
                context = "style"

            else:
                context = "html"

        if context not in seen:
            seen.append(context)

    return tuple(seen)


def xss_payloads(context: str, canary: str) -> tuple[str, ...]:
    """Payloads específicos para el contexto detectado.

    Todos incluyen el canary para que la evidencia sea inequívoca y para no
    confundir el reflejo con un script legítimo de la página.
    """

    if context == "script":
        return (
            f";alert('{canary}');//",
            f'";alert(\'{canary}\');//',
            f"</script><svg/onload=alert('{canary}')>",
        )
    if context == "attr_double":
        return (
            f'" onmouseover=alert(\'{canary}\') x="',
            f'"><svg/onload=alert(\'{canary}\')>',
        )
    if context == "attr_single":
        return (
            f"' onmouseover=alert(\"{canary}\") x='",
            f"'><svg/onload=alert(\"{canary}\")>",
        )
    if context == "attr_unquoted":
        return (f" onmouseover=alert('{canary}') x=",)
    if context == "url":
        return (f"javascript:alert('{canary}')",)
    if context == "style":
        return (f"</style><svg/onload=alert('{canary}')>",)
    if context == "comment":
        return (f"--><svg/onload=alert('{canary}')>",)
    return (
        f"<script>alert('{canary}')</script>",
        f"<svg/onload=alert('{canary}')>",
    )


def xss_executable(body: str, payload: str) -> bool:
    """El payload aparece literalmente y, por tanto, sin escapar."""

    return bool(payload) and payload in body
