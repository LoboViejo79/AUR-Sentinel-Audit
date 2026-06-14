#!/usr/bin/env bash
# ==========================================================
# AUR Sentinel Audit - Autorun Portable GUI
# Este archivo levanta la INTERFAZ GRÁFICA por defecto.
# No instala librerías Python globalmente.
# ==========================================================

set -euo pipefail

APP_NAME="AUR Sentinel Audit"
VENV_DIR=".venv"
LOG_DIR="logs"
LOG_FILE="$LOG_DIR/autorun_gui_$(date '+%Y%m%d_%H%M%S').log"

cd "$(dirname "$0")"
mkdir -p "$LOG_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

clear
echo "=================================================="
echo "      🛡️  $APP_NAME - GUI Portable"
echo "=================================================="
echo
echo "Este lanzador abre la interfaz gráfica."
echo "Las librerías se instalan dentro de .venv"
echo

if [ ! -f "aur_sentinel_gui.py" ]; then
    echo "[ERROR] No se encontró aur_sentinel_gui.py"
    echo "Verifica que descargaste la versión GUI Portable."
    exit 1
fi

if [ ! -f "requirements.txt" ]; then
    echo "[ERROR] No se encontró requirements.txt"
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "[ERROR] Python 3 no está instalado."
    echo
    echo "En Arch/CachyOS/EndeavourOS:"
    echo "sudo pacman -S python"
    exit 1
fi

log "Python detectado: $(python3 --version 2>&1)"

# Verificar que exista soporte venv
if ! python3 -m venv --help >/dev/null 2>&1; then
    echo "[ERROR] Tu Python no tiene soporte venv."
    echo "En Arch/CachyOS normalmente viene incluido con python."
    exit 1
fi

if [ ! -d "$VENV_DIR" ]; then
    log "Creando entorno virtual local"
    python3 -m venv "$VENV_DIR"
else
    log "Entorno virtual local detectado"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

log "Actualizando pip"
python -m pip install --upgrade pip wheel setuptools | tee -a "$LOG_FILE"

log "Instalando librerías desde requirements.txt"
pip install -r requirements.txt | tee -a "$LOG_FILE"

echo
echo "=================================================="
echo " Herramientas opcionales para auditoría completa"
echo "=================================================="
echo
echo "Estas herramientas son del sistema y mejoran el análisis:"
echo "arch-audit, bind-tools, whois, lsof, nmap, curl, git"
echo

if command -v pacman >/dev/null 2>&1; then
    read -r -p "¿Instalar herramientas opcionales del sistema con pacman? [s/N]: " RESP
    if [[ "$RESP" =~ ^[sS]$ ]]; then
        log "Instalando herramientas opcionales"
        sudo pacman -S --needed arch-audit bind-tools whois lsof nmap curl git | tee -a "$LOG_FILE"
    else
        log "Instalación opcional omitida"
    fi
fi

# Comprobar entorno gráfico
if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
    echo
    echo "[ERROR] No se detectó DISPLAY ni WAYLAND_DISPLAY."
    echo "Ejecuta este autorun desde tu sesión gráfica de KDE/Plasma."
    exit 1
fi

log "Ejecutando interfaz gráfica aur_sentinel_gui.py"
python aur_sentinel_gui.py
