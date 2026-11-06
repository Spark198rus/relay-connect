#!/usr/bin/env bash
# Локальная сборка Relay Connect на macOS или Linux (на Windows — build.bat).
# Нужен Python 3.10+ с tkinter:
#   Ubuntu/Debian: sudo apt install python3-tk python3-venv
#   macOS: Python с python.org (tkinter уже внутри) или `brew install python-tk`
set -euo pipefail
cd "$(dirname "$0")"

python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install -r requirements.txt

if [[ "$(uname)" == "Darwin" ]]; then
    python -m PyInstaller --noconfirm --clean --windowed --name RelayConnect --paths src app.py
    echo "Готово: dist/RelayConnect.app"
else
    python -m PyInstaller --noconfirm --clean --onefile --windowed --name RelayConnect --paths src app.py
    echo "Готово: dist/RelayConnect"
fi
