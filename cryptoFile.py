#!/usr/bin/env python3
"""
Universal launcher for CryptoFile
"""

import os
import sys
import platform

def can_run_gui():
    """Check if the graphical interface can be launched"""
    try:
        import tkinter
        return True
    except ImportError:
        return False

def setup_paths():
    """Configures import paths"""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_dir = os.path.join(current_dir, 'src')
    
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)
    
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)

def main():
    """Main function"""
    print("🔐 CryptoFile - Launch...")
    
    # Configuration des chemins
    setup_paths()
    
    # Vérification des dépendances
    try:
        import cryptography
        import argon2
    except ImportError as e:
        print(f"❌ Missing dependencies: {e}")
        print("💡 Run: python install.py")
        return
    
    # Arguments de ligne de commande
    args = sys.argv[1:]
    
    # Mode ligne de commande forcé
    if '--cli' in args or '-c' in args:
        print("💻 Command line mode")
        try:
            from main import cli
            cli()
        except ImportError as e:
            print(f"❌ Unable to load the CLI interface:{e}")
        return
    """    
    # Mode web
    if '--web' in args or '-w' in args:
        print("🌐 Lancement de l'interface web...")
        try:
            from src.web.app import app
            app.run(debug=False, host='127.0.0.1', port=5000)
        except ImportError as e:
            print(f"❌ Interface web non disponible: {e}")
        return
    """    
    # Mode graphique (par défaut si disponible)
    if can_run_gui():
        print("🖥️  GUI mode")
        try:
            from src.gui.app import run_gui
            run_gui()
        except ImportError as e:
            print(f"❌ Graphical interface not available: {e}")
            fallback_to_cli()
    else:
        print("❌ GUI not available")
        fallback_to_cli()

def fallback_to_cli():
    """Returns to the command-line interface"""
    print("🔄 Return to the command line interface...")
    try:
        from main import cli
        cli()
    except ImportError as e:
        print(f"❌ No interface available:{e}")
        print("💡 Recommended installation: python install.py")

if __name__ == "__main__":
    main()