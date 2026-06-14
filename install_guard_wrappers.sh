#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
ASSUME_YES=0

for arg in "$@"; do
  case "$arg" in
    -y|--yes|--aliases)
      ASSUME_YES=1
      ;;
  esac
done

mkdir -p "$HOME/.local/bin"
cp "$ROOT/tools/aur-guard" "$ROOT/tools/aur-guard-yay" "$ROOT/tools/aur-guard-paru" "$ROOT/tools/aur_guard_preinstall.py" "$HOME/.local/bin/"
chmod +x "$HOME/.local/bin/aur-guard" "$HOME/.local/bin/aur-guard-yay" "$HOME/.local/bin/aur-guard-paru" "$HOME/.local/bin/aur_guard_preinstall.py"
echo "Wrappers instalados en ~/.local/bin"

if [[ "$ASSUME_YES" -eq 1 ]]; then
  RESP="s"
else
  read -r -p "¿Agregar alias para que yay/paru pasen por Guardia AUR? [s/N]: " RESP
fi

if [[ "$RESP" =~ ^[sS]$ ]]; then
  for file in "$HOME/.bashrc" "$HOME/.zshrc"; do
    touch "$file"
    grep -Fq "alias yay=" "$file" || echo "alias yay='$HOME/.local/bin/aur-guard-yay'" >> "$file"
    grep -Fq "alias paru=" "$file" || echo "alias paru='$HOME/.local/bin/aur-guard-paru'" >> "$file"
  done
  mkdir -p "$HOME/.config/fish/conf.d"
  printf 'alias yay="%s/.local/bin/aur-guard-yay"\nalias paru="%s/.local/bin/aur-guard-paru"\n' "$HOME" "$HOME" > "$HOME/.config/fish/conf.d/aur-sentinel-guard.fish"
  echo "Alias agregados. Reinicia la terminal."
fi
