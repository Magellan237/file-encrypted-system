#!/usr/bin/env python3
"""
Installateur automatique simplifié pour CryptoFile
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path

def print_colored(text, color):
    """Affiche du texte coloré dans la console"""
    colors = {
        'green': '\033[92m',
        'yellow': '\033[93m', 
        'red': '\033[91m',
        'blue': '\033[94m',
        'reset': '\033[0m'
    }
    print(f"{colors.get(color, '')}{text}{colors['reset']}")

def check_python_version():
    """Vérifie la version de Python"""
    version = sys.version_info
    print_colored(f"🐍 Python {version.major}.{version.minor}.{version.micro}", "blue")
    
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print_colored("❌ Python 3.8 ou supérieur requis", "red")
        return False
    return True

def install_dependencies():
    """Installe les dépendances automatiquement"""
    print_colored("📦 Installation des dépendances...", "blue")
    
    dependencies = [
        "cryptography>=41.0.0",
        "argon2-cffi>=23.1.0", 
        "rich>=13.0.0"
    ]
    
    for package in dependencies:
        try:
            print_colored(f"  Installation de {package}...", "yellow")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print_colored(f"  ✅ {package} installé", "green")
        except subprocess.CalledProcessError as e:
            print_colored(f"  ❌ Échec installation de {package}: {e}", "red")
            return False
    
    return True

def install_gui_dependencies():
    """Installe les dépendances optionnelles pour l'interface graphique"""
    print_colored("🖥️  Installation de l'interface graphique...", "blue")
    
    gui_dependencies = []
    
    # Vérifier si tkinter est disponible
    try:
        import tkinter
        print_colored("  ✅ tkinter déjà disponible", "green")
    except ImportError:
        print_colored("  ℹ️  tkinter non disponible - l'interface graphique sera limitée", "yellow")
    
    # Installer pillow pour de meilleures images (optionnel)
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pillow"])
        print_colored("  ✅ Pillow installé pour les images", "green")
    except:
        print_colored("  ⚠️  Pillow non installé (optionnel)", "yellow")
    
    return True

def create_launch_scripts():
    """Crée des scripts de lancement pour tous les systèmes"""
    print_colored("🚀 Création des scripts de lancement...", "blue")
    
    current_dir = os.getcwd()
    
    # Script Windows
    if platform.system() == "Windows":
        bat_content = f'''@echo off
chcp 65001 > nul
echo 🔐 Lancement de CryptoFile...
echo.
"{sys.executable}" -c "
import sys
sys.path.append('{current_dir}')
from src.gui.app import run_gui
run_gui()
"
pause
'''
        with open("Lancer_CryptoFile.bat", "w", encoding="utf-8") as f:
            f.write(bat_content)
        print_colored("  ✅ Script Windows créé: 'Lancer_CryptoFile.bat'", "green")
    
    # Script Unix/Linux/macOS
    sh_content = f'''#!/bin/bash
echo "🔐 Lancement de CryptoFile..."
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
        print_colored("  ✅ Script Unix créé: 'lancer_cryptofile.sh'", "green")

def create_config_files():
    """Crée les fichiers de configuration par défaut"""
    print_colored("⚙️  Configuration de l'application...", "blue")
    
    config_dir = Path.home() / '.cryptofile'
    config_dir.mkdir(exist_ok=True)
    
    # Configuration par défaut
    config_content = '''{
    "auto_backup": true,
    "theme": "light",
    "language": "fr",
    "clear_logs_on_exit": true
}'''
    
    config_file = config_dir / 'config.json'
    with open(config_file, 'w', encoding='utf-8') as f:
        f.write(config_content)
    
    print_colored("  ✅ Configuration créée", "green")

def create_example_files():
    """Crée des fichiers d'exemple pour tester"""
    print_colored("📝 Création de fichiers d'exemple...", "blue")
    
    examples_dir = Path("exemples")
    examples_dir.mkdir(exist_ok=True)
    
    # Fichier texte d'exemple
    with open(examples_dir / "test_secret.txt", "w", encoding="utf-8") as f:
        f.write("Ceci est un fichier secret de test ! 🔐\n")
        f.write("Vous pouvez le chiffrer pour vous entraîner.\n")
    
    # Guide rapide
    guide_content = '''# 🎯 Guide Rapide CryptoFile

## Pour chiffrer un fichier :
1. Lancez CryptoFile
2. Cliquez sur "Parcourir"
3. Sélectionnez un fichier
4. Entrez un mot de passe
5. Cliquez sur "🔒 Chiffrer"

## Pour déchiffrer :
1. Sélectionnez un fichier .encrypted
2. Entrez le mot de passe
3. Cliquez sur "🔓 Déchiffrer"

## 💡 Conseil :
Utilisez le fichier "test_secret.txt" pour vous entraîner !
'''
    with open(examples_dir / "LISEZ_MOI.txt", "w", encoding="utf-8") as f:
        f.write(guide_content)
    
    print_colored("  ✅ Fichiers d'exemple créés dans 'exemples/'", "green")

def test_installation():
    """Teste que l'installation fonctionne"""
    print_colored("🧪 Test de l'installation...", "blue")
    
    try:
        # Test des imports
        import cryptography
        import argon2
        import rich
        
        print_colored("  ✅ Dépendances principales importées", "green")
        
        # Test de notre code
        sys.path.append('.')
        from src.core.crypto_manager import CryptoManager
        
        crypto_manager = CryptoManager()
        print_colored("  ✅ CryptoFile importé avec succès", "green")
        
        # Test de chiffrement simple
        test_content = b"Test de chiffrement"
        test_file = "test_install.txt"
        encrypted_file = test_file + ".encrypted"
        decrypted_file = test_file + ".decrypted"
        
        with open(test_file, 'wb') as f:
            f.write(test_content)
        
        # Chiffrement
        success = crypto_manager.encrypt_file_v2(test_file, encrypted_file, "test_password")
        
        if success and os.path.exists(encrypted_file):
            # Déchiffrement
            success = crypto_manager.decrypt_file_v2(encrypted_file, decrypted_file, "test_password")
            
            if success and os.path.exists(decrypted_file):
                with open(decrypted_file, 'rb') as f:
                    if f.read() == test_content:
                        print_colored("  ✅ Test de chiffrement/déchiffrement réussi!", "green")
                    else:
                        print_colored("  ⚠️  Test de chiffrement: données corrompues", "yellow")
            else:
                print_colored("  ⚠️  Échec du déchiffrement de test", "yellow")
        else:
            print_colored("  ⚠️  Échec du chiffrement de test", "yellow")
        
        # Nettoyage
        for f in [test_file, encrypted_file, decrypted_file]:
            if os.path.exists(f):
                os.remove(f)
                
    except Exception as e:
        print_colored(f"  ⚠️  Test d'installation: {e}", "yellow")

def show_final_instructions():
    """Affiche les instructions finales"""
    print_colored("\n🎉 Installation terminée avec succès!", "green")
    print_colored("=" * 50, "blue")
    
    system = platform.system()
    
    if system == "Windows":
        print_colored("🚀 Pour lancer CryptoFile :", "yellow")
        print_colored("   Double-cliquez sur 'Lancer_CryptoFile.bat'", "green")
        print_colored("   OU", "blue")
        print_colored("   Exécutez: python CryptoFile.py", "green")
    
    elif system == "Darwin":
        print_colored("🚀 Pour lancer CryptoFile :", "yellow") 
        print_colored("   Double-cliquez sur 'lancer_cryptofile.sh'", "green")
        print_colored("   OU", "blue")
        print_colored("   Exécutez: ./lancer_cryptofile.sh", "green")
    
    else:  # Linux/Unix
        print_colored("🚀 Pour lancer CryptoFile :", "yellow")
        print_colored("   Exécutez: ./lancer_cryptofile.sh", "green")
        print_colored("   OU", "blue") 
        print_colored("   Exécutez: python CryptoFile.py", "green")
    
    print_colored("\n📚 Pour vous entraîner :", "yellow")
    print_colored("   Des fichiers d'exemple sont dans le dossier 'exemples/'", "green")
    
    print_colored("\n🆘 En cas de problème :", "yellow")
    print_colored("   Réexécutez ce script: python install.py", "green")
    print_colored("   Ou consultez le fichier: GUIDE.md", "green")

def main():
    """Fonction principale d'installation"""
    print_colored("🔐 Installation de CryptoFile", "blue")
    print_colored("=" * 50, "blue")
    
    # Vérifications de base
    if not check_python_version():
        return
    
    # Installation des dépendances
    if not install_dependencies():
        print_colored("❌ Échec de l'installation des dépendances", "red")
        return
    
    # Dépendances GUI optionnelles
    install_gui_dependencies()
    
    # Création des scripts
    create_launch_scripts()
    
    # Configuration
    create_config_files()
    
    # Fichiers d'exemple
    create_example_files()
    
    # Test final
    test_installation()
    
    # Instructions
    show_final_instructions()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_colored("\n❌ Installation annulée par l'utilisateur", "red")
    except Exception as e:
        print_colored(f"\n💥 Erreur during installation: {e}", "red")