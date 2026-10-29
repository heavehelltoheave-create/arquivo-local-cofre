@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo Execute Instalar_e_Abrir.bat antes.
    pause
    exit /b 1
)
".venv\Scripts\python.exe" -m pip install "pyinstaller>=6,<8"
if errorlevel 1 (
    echo Falha ao instalar PyInstaller.
    pause
    exit /b 1
)
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile --windowed --name "ArquivoLocal" --collect-all argon2 --hidden-import win32crypt app.py
if errorlevel 1 (
    echo Falha ao criar o executavel.
    pause
    exit /b 1
)
echo.
echo Executavel disponivel em dist\ArquivoLocal.exe
pause
