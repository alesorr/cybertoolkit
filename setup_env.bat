@echo off
SET VENV_NAME=venv
echo ================================
echo Creazione virtual environment...
echo ================================
python -m venv %VENV_NAME%
IF ERRORLEVEL 1 (
   echo ERRORE: Python non trovato o errore nella creazione del venv
   pause
   exit /b 1
)
echo.
echo ================================
echo Attivazione virtual environment
echo ================================
call %VENV_NAME%\Scripts\activate.bat
echo.
echo ================================
echo Aggiornamento pip
echo ================================
python -m pip install --upgrade pip
echo.
echo ================================
echo Installazione dipendenze
echo ================================
pip install -r requirements.txt
echo.
echo ================================
echo Ambiente pronto!
echo ================================
pause