#!/bin/bash

# munkakönyvtár létrehozása
mkdir -p ~/working_dir
# python virtuális környezet létrehozása
cd ~/working_dir && virtualenv venv
# környezet aktiválása és scapy telepítése
source venv/bin/activate && pip install scapy
