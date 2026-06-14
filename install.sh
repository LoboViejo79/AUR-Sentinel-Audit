#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

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

chmod +x aur_sentinel.py aur_sentinel_gui.py autorun.sh autorun_gui.sh run.sh install_guard_wrappers.sh

echo
echo "=========================================="
echo " Integración con GNOME/KDE"
echo "=========================================="

mkdir -p "$HOME/.local/share/applications" "$HOME/.config/autostart" "$HOME/.local/bin"

DESKTOP_FILE="$HOME/.local/share/applications/aur-sentinel-audit.desktop"
AUTOSTART_FILE="$HOME/.config/autostart/aur-sentinel-guard.desktop"
ICON_PATH="$ROOT/assets/aur_sentinel.svg"
LAUNCHER_GUI="$HOME/.local/bin/aur-sentinel-audit"
LAUNCHER_GUARD="$HOME/.local/bin/aur-sentinel-guard"

cat > "$LAUNCHER_GUI" <<EOF
#!/usr/bin/env bash
cd "$ROOT"
exec "$ROOT/autorun.sh" "\$@"
EOF

cat > "$LAUNCHER_GUARD" <<EOF
#!/usr/bin/env bash
cd "$ROOT"
exec "$ROOT/autorun.sh" --tray
EOF

chmod +x "$LAUNCHER_GUI" "$LAUNCHER_GUARD"

cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Name=AUR Sentinel Audit
Comment=Auditoría defensiva AUR para Arch Linux y derivadas
Exec=$LAUNCHER_GUI
Icon=$ICON_PATH
Terminal=false
Categories=System;Security;
StartupNotify=true
EOF

cat > "$AUTOSTART_FILE" <<EOF
[Desktop Entry]
Type=Application
Name=AUR Sentinel Guard
Comment=Guardia AUR en segundo plano
Exec=$LAUNCHER_GUARD
Icon=$ICON_PATH
Terminal=false
X-GNOME-Autostart-enabled=true
X-KDE-autostart-after=panel
StartupNotify=false
EOF

chmod +x "$DESKTOP_FILE" "$AUTOSTART_FILE"

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$HOME/.local/share/applications" >/dev/null 2>&1 || true
fi

echo "[OK] Acceso instalado: $DESKTOP_FILE"
echo "[OK] Autoinicio instalado: $AUTOSTART_FILE"

echo
echo "=========================================="
echo " Guardia AUR para yay/paru"
echo "=========================================="

./install_guard_wrappers.sh --yes

if command -v pacman >/dev/null 2>&1; then
  echo
  echo "Herramientas recomendadas para notificaciones e integración:"
  echo "  libnotify, python-pyside6, arch-audit, bind-tools, whois, lsof, nmap, curl, git"
  read -r -p "¿Instalar herramientas opcionales del sistema con pacman? [s/N]: " RESP_TOOLS
  if [[ "$RESP_TOOLS" =~ ^[sS]$ ]]; then
    sudo pacman -S --needed libnotify arch-audit bind-tools whois lsof nmap curl git
  fi
fi

echo
echo "Instalación terminada."
echo "Ejecuta:"
echo "  ./autorun.sh"
echo
echo "La Guardia AUR queda configurada para iniciar con GNOME/KDE."
echo "En GNOME, si no ves icono de bandeja, el guardia igual queda activo y mostrará popups/notificaciones."
echo
