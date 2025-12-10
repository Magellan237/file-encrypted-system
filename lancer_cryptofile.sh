#!/bin/bash
echo "🔐 CryptoFile Launch..."
cd "C:\Users\Magellan\Documents\Studium\file-encrypted-system"
"C:\Users\Magellan\AppData\Local\Programs\Python\Python313\python.exe" -c "
import sys
sys.path.append('C:\Users\Magellan\Documents\Studium\file-encrypted-system')
from src.gui.app import run_gui
run_gui()
"
