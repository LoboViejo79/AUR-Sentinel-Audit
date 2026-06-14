#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
  echo "No existe entorno .venv. Ejecutando install.sh..."
  ./install.sh
fi

source .venv/bin/activate
python aur_sentinel.py
