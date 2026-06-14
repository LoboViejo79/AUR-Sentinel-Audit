#!/usr/bin/env bash
set -euo pipefail

echo "=========================================="
echo " AUR Sentinel Audit - Instalador"
echo "=========================================="

if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERROR] Python 3 no está instalado."
  exit 1
fi

if ! command -v pacman >/dev/null 2>&1; then
  echo "[ADVERTENCIA] No se detectó pacman. Esta herramienta está pensada para Arch Linux y derivadas."
fi

echo "[OK] Python detectado: $(python3 --version)"

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt

chmod +x aur_sentinel.py

echo
echo "Instalación terminada."
echo "Ejecuta:"
echo "  ./run.sh"
echo
