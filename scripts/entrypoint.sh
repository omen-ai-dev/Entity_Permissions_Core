#!/usr/bin/env bash
set -euo pipefail

APP_MODULE=${APP_MODULE:-"app.main:app"}
HOST=${HOST:-"0.0.0.0"}
PORT=${PORT:-"8080"}
WORKERS=${WORKERS:-"4"}

log() {
  # Uniform log prefix so CloudWatch can filter by container role.
  echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [entrypoint] $*"
}

if [[ $# -gt 0 ]]; then
  log "Custom command detected: $*"
  exec "$@"
fi

log "No custom command provided; starting Uvicorn (module=${APP_MODULE}, workers=${WORKERS})"
exec uvicorn "${APP_MODULE}" --host "${HOST}" --port "${PORT}" --workers "${WORKERS}"
