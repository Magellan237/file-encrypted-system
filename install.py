#!/usr/bin/env python3
"""
Simplified automatic installer for CryptoFile
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path

def print_colored(text, color):
    """Displays colored text in the console"""
    colors = {
        'green': '\033[92m',
        'yellow': '\033[93m', 
        'red': '\033[91m',
        'blue': '\033[94m',
        'reset': '\033[0m'
    }
    print(f"{colors.get(color, '')}{text}{colors['reset']}")

def check_python_version():
    """Check the Python version"""
    version = sys.version_info
    print_colored(f"🐍 Python {version.major}.{version.minor}.{version.micro}", "blue")
    
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print_colored("❌ Python 3.8 or higher required", "red")
        return False
    return True

def install_dependencies():
    """Installs dependencies automatically"""
    print_colored("📦 Installing dependencies...", "blue")
    
    dependencies = [
        "cryptography>=41.0.0",
        "argon2-cffi>=23.1.0", 
        "rich>=13.0.0"
    ]
    
    for package in dependencies:
        try:
            print_colored(f"  Installation of {package}...", "yellow")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print_colored(f"  ✅ {package} installed", "green")
        except subprocess.CalledProcessError as e:
            print_colored(f"  ❌ Installation failed {package}: {e}", "red")
            return False
    
    return True

def install_gui_dependencies():
    """Installs optional dependencies for the graphical interface"""
    print_colored("🖥️  Installing the graphical interface...", "blue")
    
    gui_dependencies = []
    
    # Prüfen Sie, ob tkinter verfügbar ist.
    try:
        import tkinter
        print_colored("  ✅ tkinter already available", "green")
    except ImportError:
        print_colored("  ℹ️  tkinter not available - the graphical interface will be limited", "yellow")
    
    # Installieren Sie Pillow für bessere Bilder (optional).
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pillow"])
        print_colored("  ✅ Pillow set up for the pictures", "green")
    except:
        print_colored("  ⚠️  Pillow not installed (optional)", "yellow")
    
    return True

def create_launch_scripts():
    """Create launch scripts for all systems"""
    print_colored("🚀 Creating the launch scripts...", "blue")
    
    current_dir = os.getcwd()
    
    # Script Windows
    if platform.system() == "Windows":
        bat_content = f'''@echo off
chcp 65001 
echo 🔐 CryptoFile Launch...
"{sys.executable}" -m src.gui.app
pause
'''
        with open("Lancer_CryptoFile.bat", "w", encoding="utf-8") as f:
            f.write(bat_content)
        print_colored("  ✅ Windows script created: 'Lancer_CryptoFile.bat'", "green")
    
    # Script Unix/Linux/macOS
    sh_content = f'''#!/bin/bash
echo "🔐 CryptoFile Launch..."
cd "{current_dir}"
"{sys.executable}" -c "
import sys
sys.path.append('{current_dir}')
from src.gui.app import run_gui
run_gui()
"
'''
    with open("lancer_cryptofile.sh", "w", encoding="utf-8") as f:
        f.write(sh_content)
    
    # Rendre le script executable sur Unix
    if platform.system() != "Windows":
        os.chmod("lancer_cryptofile.sh", 0o755)
        print_colored("  ✅ Unix script created: 'lancer_cryptofile.sh'", "green")

def create_config_files():
    """Creates the default configuration files"""
    print_colored("⚙️  Application configuration...", "blue")
    
    config_dir = Path.home() / '.cryptofile'
    config_dir.mkdir(exist_ok=True)
    
    # Standardkonfiguration
    config_content = '''{
    "auto_backup": true,
    "theme": "light",
    "language": "fr",
    "clear_logs_on_exit": true
}'''
    
    config_file = config_dir / 'config.json'
    with open(config_file, 'w', encoding='utf-8') as f:
        f.write(config_content)
    
    print_colored("  ✅ Configuration created", "green")
"""
# def create_example_files():
#    Create sample files for testing
    print_colored("📝 Creating sample files...", "blue")
    
    examples_dir = Path("exemples")
    examples_dir.mkdir(exist_ok=True)
    
    # Fichier texte d'exemple
    with open(examples_dir / "test_secret.txt", "w", encoding="utf-8") as f:
        f.write("This is a secret test file! 🔐\n")
        f.write("You can encrypt it to practice..\n")
    
    # Guide rapide
    guide_content = '''# 🎯 CryptoFile Quick Guide

## Pour chiffrer un fichier :
1. Launch CryptoFile
2. Click "Browse"
3. Select a file
4. Enter a password
5. Click "Encrypt"

## To decrypt:
1. Select an .encrypted file
2. Enter the password
3. Click on "🔓 Decrypt"

## 💡 Tip:
Use the "test_secret.txt" file to practice!
'''
    with open(examples_dir / "LISEZ_MOI.txt", "w", encoding="utf-8") as f:
        f.write(guide_content)
    
    print_colored("  ✅ Example files created in 'examples/'", "green")

def test_installation():
    #Testen Sie, ob die Installation funktioniert
    print_colored("🧪 Testen der Installation...", "blue")
    
    try:
        # Importe testen
        import cryptography
        import argon2
        import rich
        
        print_colored("  ✅ Wichtigste importierte Abhängigkeiten", "green")
        
        # Testen unseres Codes
        sys.path.append('.')
        from src.core.crypto_manager import CryptoManager
        
        crypto_manager = CryptoManager()
        print_colored("  ✅ CryptoFile erfolgreich importiert", "green")
        
        # Einfacher Verschlüsselungstest
        test_content = b"Test de chiffrement"
        test_file = "test_install.txt"
        encrypted_file = test_file + ".encrypted"
        decrypted_file = test_file + ".decrypted"
        
        with open(test_file, 'wb') as f:
            f.write(test_content)
        
        # Verschlüsselung
        success = crypto_manager.encrypt_file_v2(test_file, encrypted_file, "test_password")
        
        if success and os.path.exists(encrypted_file):
            # Entschlüsselung
            success = crypto_manager.decrypt_file_v2(encrypted_file, decrypted_file, "test_password")
            
            if success and os.path.exists(decrypted_file):
                with open(decrypted_file, 'rb') as f:
                    if f.read() == test_content:
                        print_colored("  ✅ Verschlüsselungs-/Entschlüsselungstest erfolgreich!", "green")
                    else:
                        print_colored("  ⚠️  Verschlüsselungstest: Daten beschädigt", "yellow")
            else:
                print_colored("  ⚠️  Testentschlüsselung fehlgeschlagen", "yellow")
        else:
            print_colored("  ⚠️  Die Testverschlüsselung ist fehlgeschlagen", "yellow")
        
        # Reinigung
        for f in [test_file, encrypted_file, decrypted_file]:
            if os.path.exists(f):
                os.remove(f)
                
    except Exception as e:
        print_colored(f"  Installationstest: {e}", "yellow")
"""
def show_final_instructions():
    """Zeigt die endgültigen Anweisungen an"""
    print_colored("\n Die Installation wurde erfolgreich abgeschlossen!", "green")
    print_colored("=" * 50, "blue")
    
    system = platform.system()
    
    if system == "Windows":
        print_colored("   Um CryptoFile zu starten :", "yellow")
        print_colored("   Doppelklicken Sie auf 'Lancer_CryptoFile.bat'", "green")
        print_colored("   ODER", "blue")
        print_colored("   Tippen: python CryptoFile.py oder py CryptoFile.py", "green")
    
    elif system == "Darwin":
        print_colored("   Um CryptoFile zu starten :", "yellow") 
        print_colored("   Doppelklicken Sie auf 'lancer_cryptofile.sh'", "green")
        print_colored("   ODER", "blue")
        print_colored("   Tippen: ./lancer_cryptofile.sh", "green")
    
    else:  # Linux/Unix
        print_colored("   Um CryptoFile zu starten  :", "yellow")
        print_colored("   Tippen : ./lancer_cryptofile.sh", "green")
        print_colored("   ODER", "blue") 
        print_colored("   Tippen: python CryptoFile.py", "green")
    
    print_colored("\n Im Problemfall :", "yellow")
    print_colored("   Führen Sie dieses Skript erneut aus.: python install.py oder py install.py", "green")
    print_colored("   Oder schauen Sie sich die Datei an: GUIDE.md", "green")

def main():
    """Hauptinstallationsfunktion"""
    print_colored("🔐 CryptoFile installieren", "blue")
    print_colored("=" * 50, "blue")
    
    # Grundlegende Kontrollen
    if not check_python_version():
        return
    
    # Abhängigkeiten installieren
    if not install_dependencies():
        print_colored("❌ Installation der Abhängigkeiten fehlgeschlagen", "red")
        return
    
    # Optionale GUI-Abhängigkeiten
    install_gui_dependencies()
    
    # Erstellung von Skripten
    create_launch_scripts()
    
    # Konfiguration
    create_config_files()
    
    # Beispieldateien
    #create_example_files()
    
    # Abschlusstest
    #test_installation()
    
    # Anweisungen   
    show_final_instructions()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_colored("\n❌ Installation vom Benutzer abgebrochen", "red")
    except Exception as e:
        print_colored(f"\n💥 Fehler bei der Installation: {e}", "red")