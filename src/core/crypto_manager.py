import os
import struct
from typing import Tuple
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from .crypto import AESCipher
from .key_manager import KeyManager
from src.utils.security import secure_erase

class CryptoManager:
    """Gestionnaire unifié pour le chiffrement/déchiffrement"""
    
    def __init__(self):
        self.cipher = AESCipher()
        self.key_manager = KeyManager()
    
    def encrypt_file_v2(self, input_path: str, output_path: str, password: str, key_file: str = None) -> bool:
        """
        Chiffre un fichier avec le format V2 (standardisé)
        Format: [FENC][IV][SIZE][SALT][DATA]
        """
        try:
            print(f"🔒 Chiffrement V2: {input_path}")
            
            # Lecture du fichier
            with open(input_path, 'rb') as f:
                plaintext = f.read()
            
            # Gestion de la clé
            if key_file and os.path.exists(key_file):
                print(f"🔑 Chargement de la clé depuis: {key_file}")
                key = self.key_manager.load_key_for_crypto(key_file, password)
            else:
                # Génération du sel et dérivation de la clé
                salt = os.urandom(16)
                key, _, key_hash = self.key_manager.derive_key_from_password(password, salt)
            
            # Chiffrement
            iv, ciphertext = self.cipher.encrypt(plaintext, key)
            
            # Écriture avec format V2
            with open(output_path, 'wb') as f:
                f.write(b'FENC')  # Magic bytes
                f.write(iv)       # 16 bytes IV
                f.write(struct.pack('<I', len(plaintext)))  # Taille originale
                if not key_file:
                    f.write(salt)     # 16 bytes salt (seulement si pas de fichier de clé)
                else:
                    f.write(b'\x00' * 16)  # Salt nul si fichier de clé utilisé
                f.write(ciphertext)  # Données chiffrées
            
            secure_erase(plaintext)
            print(f"✅ Chiffrement V2 réussi: {output_path}")
            return True
            
        except Exception as e:
            print(f"❌ Erreur chiffrement V2: {e}")
            return False
    
    def decrypt_file_v2(self, input_path: str, output_path: str, password: str, key_file: str = None) -> bool:
        """
        Déchiffre un fichier avec le format V2
        """
        try:
            print(f"🔓 Déchiffrement V2: {input_path}")
            
            with open(input_path, 'rb') as f:
                # Lecture de l'en-tête
                magic = f.read(4)
                if magic != b'FENC':
                    raise ValueError("Format V2 invalide - magic bytes incorrects")
                
                iv = f.read(16)
                if len(iv) != 16:
                    raise ValueError("IV invalide")
                
                size_bytes = f.read(4)
                original_size = struct.unpack('<I', size_bytes)[0]
                
                salt = f.read(16)
                
                ciphertext = f.read()
            
            # Gestion de la clé
            if key_file and os.path.exists(key_file):
                print(f"🔑 Chargement de la clé depuis: {key_file}")
                key = self.key_manager.load_key_for_crypto(key_file, password)
            else:
                # Dérivation de la clé avec le sel
                if salt == b'\x00' * 16:
                    raise ValueError("Fichier chiffré avec clé externe - utilisez --key-file")
                key, _, _ = self.key_manager.derive_key_from_password(password, salt)
            
            # Déchiffrement
            plaintext = self.cipher.decrypt(ciphertext, key, iv)
            
            # Vérification de la taille
            if len(plaintext) != original_size:
                print(f"⚠️  Taille différente: attendu {original_size}, obtenu {len(plaintext)}")
            
            # Écriture du fichier déchiffré
            with open(output_path, 'wb') as f:
                f.write(plaintext)
            
            secure_erase(plaintext)
            print(f"✅ Déchiffrement V2 réussi: {output_path}")
            return True
            
        except Exception as e:
            print(f"❌ Erreur déchiffrement V2: {e}")
            return False
    
    def decrypt_file_auto(self, input_path: str, output_path: str, password: str, key_file: str = None) -> bool:
        """
        Tente automatiquement tous les formats de déchiffrement
        """
        print(f"🔄 Déchiffrement automatique: {input_path}")
        
        # Essai 1: Format V2
        try:
            if self.decrypt_file_v2(input_path, output_path, password, key_file):
                print("✅ Succès avec format V2")
                return True
        except Exception as e:
            print(f"❌ Échec format V2: {e}")
        
        # Essai 2: Format V1 (avec en-tête simple)
        try:
            if self._decrypt_v1(input_path, output_path, password, key_file):
                print("✅ Succès avec format V1")
                return True
        except Exception as e:
            print(f"❌ Échec format V1: {e}")
        
        # Essai 3: Format legacy (IV + données)
        try:
            if self._decrypt_legacy(input_path, output_path, password, key_file):
                print("✅ Succès avec format legacy")
                return True
        except Exception as e:
            print(f"❌ Échec format legacy: {e}")
        
        print("💥 Aucun format reconnu")
        return False
    
    def _decrypt_v1(self, input_path: str, output_path: str, password: str, key_file: str = None) -> bool:
        """Déchiffrement format V1"""
        with open(input_path, 'rb') as f:
            magic = f.read(4)
            if magic != b'FENC':
                return False
            
            iv = f.read(16)
            ciphertext = f.read()
        
        # Gestion de la clé
        if key_file and os.path.exists(key_file):
            key = self.key_manager.load_key_for_crypto(key_file, password)
        else:
            key, _, _ = self.key_manager.derive_key_from_password(password)
        
        plaintext = self.cipher.decrypt(ciphertext, key, iv)
        
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        secure_erase(plaintext)
        return True
    
    def _decrypt_legacy(self, input_path: str, output_path: str, password: str, key_file: str = None) -> bool:
        """Déchiffrement format legacy (IV + données)"""
        with open(input_path, 'rb') as f:
            data = f.read()
        
        if len(data) < 16:
            return False
        
        iv = data[:16]
        ciphertext = data[16:]
        
        # Gestion de la clé
        if key_file and os.path.exists(key_file):
            key = self.key_manager.load_key_for_crypto(key_file, password)
        else:
            key, _, _ = self.key_manager.derive_key_from_password(password)
        
        try:
            plaintext = self.cipher.decrypt(ciphertext, key, iv)
        except Exception as e:
            print(f"❌ Échec déchiffrement legacy: {e}")
            return False
        
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        secure_erase(plaintext)
        return True