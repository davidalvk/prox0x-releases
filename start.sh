#!/usr/bin/env bash
# Arranque unificado de prox0x: Proxy + API + UI.
# Uso: ./start.sh
# Ctrl+C detiene los tres servicios de forma limpia.

set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

VENV="$ROOT/tmp/prox0x-venv"
PROX0X="$VENV/bin/prox0x"
UVICORN="$VENV/bin/uvicorn"
API_PORT=8000
UI_PORT=5173

log() {
  printf '[start] %s\n' "$*"
}

fail() {
  printf '[start] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ -x "$PROX0X" ]] || fail "no existe $PROX0X. Crea el entorno con: python3 -m venv ./tmp/prox0x-venv && ./tmp/prox0x-venv/bin/pip install -e '.[dev]'"
[[ -x "$UVICORN" ]] || fail "no existe $UVICORN. Reinstala el entorno con pip install -e '.[dev]'."
command -v npm >/dev/null 2>&1 || fail "npm no está instalado o no está en el PATH."

CA_DIR="${PROX0X_CA_DIR:-$HOME/.prox0x/ca}"

if [[ -z "${PROX0X_CA_PASSPHRASE:-}" ]]; then
  if [[ -t 0 ]]; then
    read -r -s -p "[start] Frase de paso de la CA: " PROX0X_CA_PASSPHRASE
    printf '\n'
  else
    fail "define PROX0X_CA_PASSPHRASE para arrancar sin terminal interactiva."
  fi
fi
export PROX0X_CA_PASSPHRASE

if [[ ! -f "$CA_DIR/ca.pem" || ! -f "$CA_DIR/ca.key.enc" ]]; then
  log "no hay CA en $CA_DIR; generándola automáticamente…"
  "$PROX0X" ca init --ca-dir "$CA_DIR"
fi

if [[ ! -d "$ROOT/ui/node_modules" ]]; then
  log "ui/node_modules no existe; instalando dependencias del frontend…"
  (cd "$ROOT/ui" && npm install)
fi

PIDS=()
NAMES=()
CLEANING=0

start_service() {
  local name="$1"
  shift
  local pid

  if command -v setsid >/dev/null 2>&1; then
    # Cada servicio en su propio grupo de procesos: Ctrl+C los mata todos,
    # incluidos los hijos de npm/Vite.
    setsid "$@" > >(sed -u "s/^/[$name] /") 2>&1 &
  else
    "$@" > >(sed -u "s/^/[$name] /") 2>&1 &
  fi
  pid=$!
  PIDS+=("$pid")
  NAMES+=("$name")
  log "$name arrancado (pid $pid)"
}

cleanup() {
  local status="${1:-0}"
  if [[ "$CLEANING" -eq 1 ]]; then
    return
  fi
  CLEANING=1
  trap - INT TERM EXIT

  printf '\n'
  log "parando servicios…"
  if [[ ${#PIDS[@]} -gt 0 ]]; then
    for pid in "${PIDS[@]}"; do
      if command -v setsid >/dev/null 2>&1; then
        kill -TERM -- "-$pid" 2>/dev/null || true
      else
        kill -TERM "$pid" 2>/dev/null || true
      fi
    done
    sleep 1
    for pid in "${PIDS[@]}"; do
      if command -v setsid >/dev/null 2>&1; then
        kill -KILL -- "-$pid" 2>/dev/null || true
      else
        kill -KILL "$pid" 2>/dev/null || true
      fi
    done
  fi
  wait 2>/dev/null || true
  log "parado."
  exit "$status"
}

trap 'cleanup 130' INT
trap 'cleanup 143' TERM
trap 'cleanup $?' EXIT

# Limpia el proyecto efímero Temporal antes de arrancar los servicios.
STATE_DIR="${PROX0X_STATE_DIR:-$HOME/.prox0x}"
PROJECTS_DIR="${PROX0X_PROJECTS_DIR:-$STATE_DIR/projects}"
rm -rf "$PROJECTS_DIR/Temporal"

log "proxy   → http://127.0.0.1:8080"
log "API     → http://127.0.0.1:${API_PORT} (docs: /docs)"
log "UI      → http://127.0.0.1:${UI_PORT}"
log "Ctrl+C para detener todo."

# Proxy: logs y CA resueltos por la CLI (hereda PROX0X_CA_PASSPHRASE del entorno).
start_service proxy "$PROX0X" proxy start

# API FastAPI/uvicorn.
start_service api "$UVICORN" api.main:app --host 127.0.0.1 --port "$API_PORT"

# Vite. El subshell entra en ui/ y exec reemplaza al shell por npm.
start_service ui bash -c 'cd "$1" && exec npm run dev -- --host 127.0.0.1' _ "$ROOT/ui"

log "servicios arriba. Esperando…"

# Si cualquiera muere, se para el resto. Ctrl+C ejecuta cleanup vía trap.
set +e
wait -n "${PIDS[@]}"
STATUS=$?
set -e
log "un servicio terminó (status $STATUS); cerrando el resto."
cleanup "$STATUS"
