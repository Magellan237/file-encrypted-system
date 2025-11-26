#!/usr/bin/env python3
"""
Lanceur universel pour CryptoFile
"""

import os
import sys
import platform

def can_run_gui():
    """Vérifie si l'interface graphique peut être lancée"""
    try:
        import tkinter
        return True
    except ImportError:
        return False

def setup_paths():
    """Configure les chemins d'importation"""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_dir = os.path.join(current_dir, 'src')
    
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)
    
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)

def main():
    """Fonction principale"""
    print("🔐 CryptoFile - Lancement...")
    
    # Configuration des chemins
    setup_paths()
    
    # Vérification des dépendances
    try:
        import cryptography
        import argon2
    except ImportError as e:
        print(f"❌ Dépendances manquantes: {e}")
        print("💡 Exécutez: python install.py")
        return
    
    # Arguments de ligne de commande
    args = sys.argv[1:]
    
    # Mode ligne de commande forcé
    if '--cli' in args or '-c' in args:
        print("💻 Mode ligne de commande")
        try:
            from main import cli
            cli()
        except ImportError as e:
            print(f"❌ Impossible de charger l'interface CLI: {e}")
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
        print("🖥️  Mode interface graphique")
        try:
            from src.gui.app import run_gui
            run_gui()
        except ImportError as e:
            print(f"❌ Interface graphique non disponible: {e}")
            fallback_to_cli()
    else:
        print("❌ Interface graphique non disponible")
        fallback_to_cli()

def fallback_to_cli():
    """Retourne vers l'interface ligne de commande"""
    print("🔄 Retour à l'interface ligne de commande...")
    try:
        from main import cli
        cli()
    except ImportError as e:
        print(f"❌ Aucune interface disponible: {e}")
        print("💡 Installation recommandée: python install.py")

if __name__ == "__main__":
    main()