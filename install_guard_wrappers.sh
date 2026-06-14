#!/usr/bin/env bash
set -euo pipefail

mkdir -p "$HOME/.local/bin"
cp tools/aur-guard tools/aur-guard-yay tools/aur-guard-paru "$HOME/.local/bin/"
chmod +x "$HOME/.local/bin/aur-guard" "$HOME/.local/bin/aur-guard-yay" "$HOME/.local/bin/aur-guard-paru"

echo "Wrappers instalados en ~/.local/bin"
echo
echo "Uso:"
echo "  aur-guard-yay paquete"
echo "  aur-guard-paru paquete"
echo
echo "Asegúrate de tener ~/.local/bin en tu PATH."
