#!/bin/bash

VENV_DIR="/home/kali/working_dir/venv"
PY_SCRIPT="/home/kali/working_dir/chirp_attack_scapy_ver05.py"

if [ ! -d "$VENV_DIR" ]; then
    echo "Hiba: A virtuális környezet ($VENV_DIR) nem található."
    exit 1
fi

source "$VENV_DIR/bin/activate"

# Elindítjuk a Python scriptet
"$VENV_DIR/bin/python" "$PY_SCRIPT"

# Deaktiváljuk a virtuális környezetet
deactivate
