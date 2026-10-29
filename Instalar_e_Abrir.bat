@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if %errorlevel%==0 (
    py -3 -m venv .venv
) else (
    python -m venv .venv
)
if errorlevel 1 (
    echo ERRO: Instale Python 3.11+ do site python.org e marque Add Python to PATH.
    pause
    exit /b 1
)
call ".venv\Scripts\activate.bat"
python -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 (
    echo ERRO: Nao foi possivel instalar dependencias.
    pause
    exit /b 1
)
python app.py
if errorlevel 1 pause
endlocal
