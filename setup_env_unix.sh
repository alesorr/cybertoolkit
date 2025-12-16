#!/bin/bash

VENV_NAME="venv"

echo "================================"
echo "Creazione virtual environment..."
echo "================================"

python3 -m venv "$VENV_NAME"
if [ $? -ne 0 ]; then
    echo "ERRORE: Python3 non trovato o errore nella creazione del venv"
    exit 1
fi

echo
echo "================================"
echo "Attivazione virtual environment"
echo "================================"

source "$VENV_NAME/bin/activate"

echo
echo "================================"
echo "Aggiornamento pip"
echo "================================"

python -m pip install --upgrade pip

echo
echo "================================"
echo "Installazione dipendenze"
echo "================================"

pip install -r requirements.txt

echo
echo "================================"
echo "Ambiente pronto!"
echo "================================"

source venv/bin/activate