#!/usr/bin/env python3
"""
Script de test et correction immédiate
"""

import os
import sys
sys.path.append('src')

def test_encryption_decryption():
    """Test complet du système"""
    print("🧪 Test complet du système de chiffrement...")
    
    # Création fichier test
    test_content = b"Hello World! Ceci est un test de chiffrement. " * 10
    test_file = "test_file.txt"
    encrypted_file = "test_file.txt.encrypted"
    decrypted_file = "test_file.txt.decrypted"
    
    with open(test_file, 'wb') as f:
        f.write(test_content)
    
    print(f"📁 Fichier test créé: {test_file} ({len(test_content)} bytes)")
    
    try:
        from core.crypto_manager import CryptoManager
        crypto_manager = CryptoManager()
        
        # Chiffrement V2
        print("\n🔒 Chiffrement V2...")
        success_encrypt = crypto_manager.encrypt_file_v2(test_file, encrypted_file, "test")
        
        if success_encrypt and os.path.exists(encrypted_file):
            print(f"✅ Fichier chiffré: {encrypted_file}")
            
            # Déchiffrement V2
            print("\n🔓 Déchiffrement V2...")
            success_decrypt = crypto_manager.decrypt_file_v2(encrypted_file, decrypted_file, "test")
            
            if success_decrypt and os.path.exists(decrypted_file):
                with open(decrypted_file, 'rb') as f:
                    decrypted_content = f.read()
                
                if decrypted_content == test_content:
                    print("🎉 Test réussi! Les fichiers sont identiques.")
                else:
                    print("❌ Les fichiers sont différents!")
                    print(f"Original: {len(test_content)} bytes")
                    print(f"Déchiffré: {len(decrypted_content)} bytes")
            else:
                print("❌ Échec du déchiffrement V2")
                
                # Test automatique
                print("\n🔄 Déchiffrement automatique...")
                success_auto = crypto_manager.decrypt_file_auto(encrypted_file, decrypted_file + ".auto", "test")
                if success_auto:
                    print("✅ Déchiffrement automatique réussi!")
        else:
            print("❌ Échec du chiffrement V2")
    
    except Exception as e:
        print(f"💥 Erreur: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Nettoyage
        for f in [test_file, encrypted_file, decrypted_file, decrypted_file + ".auto"]:
            if os.path.exists(f):
                os.remove(f)
                print(f"🧹 Fichier supprimé: {f}")

def fix_existing_file():
    """Corrige le fichier existant"""
    print("\n🔧 Correction du fichier existant...")
    
    input_file = "testing.txt.encrypted"
    output_file = "testing.txt.fixed"
    password = "test"
    
    if not os.path.exists(input_file):
        print(f"❌ Fichier introuvable: {input_file}")
        return
    
    try:
        from core.crypto_manager import CryptoManager
        crypto_manager = CryptoManager()
        
        print(f"🔄 Tentative de déchiffrement automatique...")
        success = crypto_manager.decrypt_file_auto(input_file, output_file, password)
        
        if success:
            print(f"✅ Fichier déchiffré: {output_file}")
            size = os.path.getsize(output_file)
            print(f"📏 Taille: {size} bytes")
        else:
            print("❌ Impossible de déchiffrer le fichier")
            
    except Exception as e:
        print(f"💥 Erreur: {e}")

if __name__ == "__main__":
    print("🔐 Système de Correction de Chiffrement")
    print("=" * 50)
    
    test_encryption_decryption()
    fix_existing_file()