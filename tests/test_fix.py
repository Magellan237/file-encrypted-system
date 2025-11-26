#!/usr/bin/env python3
#
# -*- coding: utf-8 -*-

"""
Script de test pour vérifier les corrections
"""

import os
import tempfile
from src.core.crypto import AESCipher
from src.core.key_manager import KeyManager

def test_basic_encryption():
    """Test basique de chiffrement/déchiffrement"""
    print("🔒 Test de chiffrement basique...")
    
    cipher = AESCipher()
    key_manager = KeyManager()
    
    # Test avec génération de clé
    password = "mon_mot_de_passe_securise"
    key, salt, encoded_hash = key_manager.derive_key_from_password(password)
    
    print(f"✅ Clé dérivée: {len(key)} bytes")
    print(f"✅ Sel généré: {len(salt)} bytes")
    print(f"✅ Hash Argon2: {encoded_hash[:50]}...")
    
    # Test de vérification
    is_valid = key_manager.verify_password(password, encoded_hash)
    print(f"✅ Vérification mot de passe: {is_valid}")
    
    # Test chiffrement simple
    test_data = b"Test de donnees secretes " * 10
    iv, encrypted = cipher.encrypt(test_data, key)
    
    print(f"✅ IV généré: {len(iv)} bytes")
    print(f"✅ Données chiffrées: {len(encrypted)} bytes")
    
    # Test déchiffrement
    decrypted = cipher.decrypt(encrypted, key, iv)
    
    if decrypted == test_data:
        print("✅ Chiffrement/déchiffrement réussi!")
    else:
        print("❌ Échec du chiffrement/déchiffrement")
        return False
    
    return True

def test_file_encryption():
    """Test de chiffrement de fichier"""
    print("\n📁 Test de chiffrement de fichier...")
    
    cipher = AESCipher()
    key_manager = KeyManager()
    
    # Création fichier test
    with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
        test_content = b"Contenu secret du fichier PDF de test " * 100
        f.write(test_content)
        input_file = f.name
    
    output_file = input_file + '.enc'
    decrypted_file = input_file + '.dec'
    
    try:
        # Dérivation de clé
        password = "test_password_123"
        key, _, _ = key_manager.derive_key_from_password(password)
        
        # Chiffrement
        cipher.encrypt_file(input_file, output_file, key)
        print(f"✅ Fichier chiffré: {output_file}")
        
        # Vérification que le fichier chiffré est différent
        with open(input_file, 'rb') as f:
            original = f.read()
        with open(output_file, 'rb') as f:
            encrypted = f.read()
        
        if original != encrypted:
            print("✅ Fichier correctement chiffré")
        else:
            print("❌ Le fichier n'a pas été chiffré")
            return False
        
        # Déchiffrement
        cipher.decrypt_file(output_file, decrypted_file, key)
        print(f"✅ Fichier déchiffré: {decrypted_file}")
        
        # Vérification
        with open(decrypted_file, 'rb') as f:
            decrypted = f.read()
        
        if original == decrypted:
            print("✅ Déchiffrement réussi - fichiers identiques")
        else:
            print("❌ Échec du déchiffrement - fichiers différents")
            return False
            
        return True
        
    except Exception as e:
        print(f"❌ Erreur lors du test: {e}")
        return False
    finally:
        # Nettoyage
        for file in [input_file, output_file, decrypted_file]:
            if os.path.exists(file):
                os.unlink(file)

if __name__ == "__main__":
    print("🧪 Démarrage des tests de correction...")
    
    success1 = test_basic_encryption()
    success2 = test_file_encryption()
    
    if success1 and success2:
        print("\n🎉 Tous les tests passent avec succès!")
        print("➡️ Vous pouvez maintenant utiliser le système de chiffrement")
    else:
        print("\n💥 Certains tests ont échoué")