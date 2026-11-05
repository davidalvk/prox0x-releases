#!/usr/bin/env bash
# Construye el binario unico de prox0x con PyInstaller.
#
# Uso:
#   ./build-binary.sh
#
# Requisitos de BUILD (no del usuario final): Python 3.12+ y Node.js 20+.
# El binario resultante incluye Python, FastAPI/Uvicorn y la UI React; no
# necesita Python ni Node para ejecutarse.

set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

log() { printf '\033[1;32m[build]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[build] AVISO:\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[build] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# ------------------------------------------------------------------ Python
if [[ -n "${PYTHON:-}" ]]; then
  PYTHON_BIN="$PYTHON"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  fail "no se encontro Python 3.12+. Instalalo para compilar el binario."
fi

"$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)' \
  || fail "se requiere Python 3.12 o superior (encontrado: $("$PYTHON_BIN" --version 2>&1))."

command -v npm >/dev/null 2>&1 || fail "no se encontro npm. Instala Node.js 20+ para compilar la UI."

# --------------------------------------------------------------- entorno build
VENV="$ROOT/tmp/build-venv"
if [[ ! -x "$VENV/bin/python" && ! -x "$VENV/Scripts/python.exe" ]]; then
  log "Creando entorno de build en ${VENV}..."
  "$PYTHON_BIN" -m venv "$VENV"
fi
if [[ -x "$VENV/bin/python" ]]; then
  PY="$VENV/bin/python"
else
  PY="$VENV/Scripts/python.exe"
fi

log "Instalando dependencias de build (prox0x + PyInstaller)..."
"$PY" -m pip install --upgrade pip >/dev/null
"$PY" -m pip install -e ".[dev]" pyinstaller >/dev/null

# --------------------------------------------------------------------- UI
log "Compilando la UI React..."
if [[ -f ui/package-lock.json ]]; then
  (cd ui && npm ci)
else
  (cd ui && npm install)
fi

# npm 12 bloquea los postinstall no aprobados. La aprobacion vive en
# ui/package.json (allowScripts); estos comandos la reparan/verifican tambien
# en entornos con un npm mas nuevo y son no fatales si no estan disponibles.
log "Revisando scripts de instalacion y auditoria de npm..."
(cd ui && npm install-scripts approve --no-allow-scripts-pin esbuild || true)
(cd ui && npm audit fix || true)

(cd ui && npm run build)

[[ -f ui/dist/index.html ]] || fail "la build de Vite no genero ui/dist/index.html"

log "Copiando la UI a api/ui_dist..."
rm -rf api/ui_dist
mkdir -p api/ui_dist
cp -R ui/dist/. api/ui_dist/
[[ -f api/ui_dist/index.html ]] || fail "no se pudo copiar la UI a api/ui_dist"

# -------------------------------------------------------------- PyInstaller
log "Empaquetando el binario con PyInstaller..."
rm -rf build/pyinstaller dist
mkdir -p build

case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN*)
    SEP=";"
    EXE=".exe"
    ARTIFACT="prox0x-windows.exe"
    ;;
  Darwin)
    SEP=":"
    EXE=""
    ARTIFACT="prox0x-macos"
    ;;
  Linux)
    SEP=":"
    EXE=""
    ARTIFACT="prox0x-linux"
    ;;
  *)
    SEP=":"
    EXE=""
    ARTIFACT="prox0x-$(uname -s | tr '[:upper:]' '[:lower:]')"
    ;;
esac

# PyInstaller es un programa nativo: en Windows Git Bash hay que pasarle rutas
# con formato Windows para --paths y --add-data.
if command -v cygpath >/dev/null 2>&1; then
  ROOT_FOR_PYINSTALLER="$(cygpath -w "$ROOT")"
  UI_FOR_PYINSTALLER="$(cygpath -w "$ROOT/api/ui_dist")"
else
  ROOT_FOR_PYINSTALLER="$ROOT"
  UI_FOR_PYINSTALLER="$ROOT/api/ui_dist"
fi

HIDDEN_IMPORTS=(
  "uvicorn.logging"
  "uvicorn.loops.auto"
  "uvicorn.loops.asyncio"
  "uvicorn.protocols.http.auto"
  "uvicorn.protocols.http.h11_impl"
  "uvicorn.protocols.websockets.auto"
  "uvicorn.protocols.websockets.websockets_impl"
  "uvicorn.protocols.websockets.websockets_sansio_impl"
  "uvicorn.lifespan.on"
  "websockets"
  "websockets.legacy"
  "websockets.legacy.server"
  "h11"
  "h2"
  "hpack"
  "hyperframe"
  "anyio._backends._asyncio"
  "brotli"
  "typer"
  "click"
  "structlog"
)

HIDDEN_ARGS=()
while IFS= read -r module; do
  [[ -n "$module" ]] && HIDDEN_ARGS+=("--hidden-import=$module")
done < <(
  "$PY" - "${HIDDEN_IMPORTS[@]}" <<'PY'
import importlib.util
import sys

for name in sys.argv[1:]:
    if importlib.util.find_spec(name) is not None:
        print(name)
    else:
        print(f"[build] hidden import no disponible: {name}", file=sys.stderr)
PY
)

"$PY" -m PyInstaller \
  --noconfirm \
  --clean \
  --onefile \
  --name prox0x \
  --paths "$ROOT_FOR_PYINSTALLER" \
  --add-data "$UI_FOR_PYINSTALLER${SEP}api/ui_dist" \
  --collect-submodules websockets \
  --collect-data certifi \
  "${HIDDEN_ARGS[@]}" \
  --distpath dist \
  --workpath build/pyinstaller \
  --specpath build \
  --log-level INFO \
  prox0x_entry.py

[[ -f "dist/prox0x$EXE" ]] || fail "PyInstaller no genero dist/prox0x$EXE"

cp "dist/prox0x$EXE" "dist/$ARTIFACT"
chmod +x "dist/$ARTIFACT" 2>/dev/null || true

log "Binario listo: dist/$ARTIFACT"
log "Pruebalo con: ./dist/$ARTIFACT --help"
