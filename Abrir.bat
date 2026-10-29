@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo Instale primeiro pelo arquivo Instalar_e_Abrir.bat.
    pause
    exit /b 1
)
".venv\Scripts\python.exe" app.py
if errorlevel 1 pause
