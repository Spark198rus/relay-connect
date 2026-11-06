@echo off
rem Build RelayConnect.exe (needs Python 3.10+)
cd /d "%~dp0"
python -m pip install -r requirements.txt || exit /b 1
python -m PyInstaller --noconfirm --clean --onefile --windowed --name RelayConnect --paths src app.py || exit /b 1
echo.
echo Done: dist\RelayConnect.exe
