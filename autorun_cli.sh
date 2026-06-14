#!/usr/bin/env bash
# AUR Sentinel Audit - CLI Portable
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi

source .venv/bin/activate
pip install -r requirements.txt

python aur_sentinel.py
