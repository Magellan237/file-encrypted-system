import os
import base64
import secrets
from typing import Optional, Tuple
import argon2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import struct

from src.utils.security import secure_erase

class KeyManager:
    """Gestion sécurisée des clés de chiffrement avec Argon2"""
    
    def __init__(self):
        self.ph = argon2.PasswordHasher(
            time_cost=3,          # Nombre d'itérations
            memory_cost=65536,    # Mémoire en KiB
            parallelism=1,        # Parallélisme
            hash_len=32,          # Longueur du hash (32 bytes = 256 bits)
            salt_len=16           # Longueur du sel
        )

    def derive_key_from_password(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes, str]:
        """
        Dérive une clé sécurisée à partir d'un mot de passe avec Argon2
        """
        if salt is None:
            salt = secrets.token_bytes(16)

        try:
            # Méthode SIMPLIFIÉE et plus robuste
            password_bytes = password.encode('utf-8')
            
            # Utilisation directe d'Argon2
            raw_hash = argon2.low_level.hash_secret(
                secret=password_bytes,
                salt=salt,
                time_cost=3,
                memory_cost=65536,
                parallelism=1,
                hash_len=32,
                type=argon2.low_level.Type.ID
            )
            
            # Extraction de la partie hash
            hash_parts = raw_hash.decode('utf-8').split('$')
            if len(hash_parts) < 6:
                raise ValueError("Format de hash Argon2 invalide")
            
            hash_b64 = hash_parts[-1]
            
            # Décodage base64 avec padding correct
            padding_needed = len(hash_b64) % 4
            if padding_needed:
                hash_b64 += '=' * (4 - padding_needed)
            
            try:
                key_bytes = base64.b64decode(hash_b64)
            except Exception:
                # Fallback vers PBKDF2 si Argon2 échoue
                import hashlib
                key_bytes = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 100000, 32)
            
            # Assurer que la clé fait exactement 32 bytes
            if len(key_bytes) < 32:
                key_bytes = key_bytes.ljust(32, b'\0')
            elif len(key_bytes) > 32:
                key_bytes = key_bytes[:32]
            
            encoded_hash = raw_hash.decode('utf-8')
            return key_bytes, salt, encoded_hash
            
        except Exception as e:
            # Fallback vers PBKDF2
            import hashlib
            password_bytes = password.encode('utf-8')
            key_bytes = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 100000, 32)
            encoded_hash = f"pbkdf2_sha256${base64.b64encode(salt).decode()}${base64.b64encode(key_bytes).decode()}"
            return key_bytes, salt, encoded_hash

    def verify_password(self, password: str, encoded_hash: str) -> bool:
        """
        Vérifie un mot de passe contre le hash stocké
        """
        try:
            if encoded_hash.startswith('pbkdf2_sha256'):
                # Fallback PBKDF2
                parts = encoded_hash.split('$')
                if len(parts) != 3:
                    return False
                salt = base64.b64decode(parts[1])
                stored_key = base64.b64decode(parts[2])
                
                import hashlib
                password_bytes = password.encode('utf-8')
                derived_key = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 100000, 32)
                return derived_key == stored_key
            else:
                # Argon2
                return self.ph.verify(encoded_hash, password)
        except Exception as e:
            print(f"❌ Erreur de vérification: {e}")
            return False

    def generate_secure_key(self) -> bytes:
        """Génère une clé cryptographiquement sécurisée"""
        return secrets.token_bytes(32)

    def save_key_to_file(self, key: bytes, file_path: str, password: str) -> None:
        """
        Sauvegarde une clé chiffrée dans un fichier
        """
        salt = secrets.token_bytes(16)
        encryption_key, _, encoded_hash = self.derive_key_from_password(password, salt)
        
        # Chiffrement XOR simple
        if len(encryption_key) < len(key):
            encryption_key = encryption_key.ljust(len(key), b'\0')
        
        xor_key = encryption_key[:len(key)]
        encrypted_data = bytes(a ^ b for a, b in zip(key, xor_key))
        
        with open(file_path, 'wb') as f:
            f.write(salt)
            f.write(struct.pack('>I', len(encrypted_data)))
            f.write(encrypted_data)
        
        # Sauvegarde du hash
        hash_file = file_path + '.hash'
        with open(hash_file, 'w', encoding='utf-8') as f:
            f.write(encoded_hash)

    def load_key_from_file(self, file_path: str, password: str) -> bytes:
        """
        Charge une clé depuis un fichier chiffré
        """
        try:
            with open(file_path, 'rb') as f:
                salt = f.read(16)
                if len(salt) != 16:
                    raise ValueError("Salt invalide")
                
                data_size_bytes = f.read(4)
                if len(data_size_bytes) != 4:
                    raise ValueError("Taille de données invalide")
                
                data_size = struct.unpack('>I', data_size_bytes)[0]
                encrypted_data = f.read(data_size)
                
                if len(encrypted_data) != data_size:
                    raise ValueError("Données chiffrées incomplètes")
            
            # Chargement du hash
            hash_file = file_path + '.hash'
            if not os.path.exists(hash_file):
                raise ValueError("Fichier de hash manquant")
                
            with open(hash_file, 'r', encoding='utf-8') as f:
                encoded_hash = f.read().strip()
            
            # Vérification du mot de passe
            if not self.verify_password(password, encoded_hash):
                raise ValueError("Mot de passe incorrect")
            
            # Régénération de la clé de dérivation
            derived_key, _, _ = self.derive_key_from_password(password, salt)
            
            # Ajustement de la taille
            if len(derived_key) < len(encrypted_data):
                derived_key = derived_key.ljust(len(encrypted_data), b'\0')
            else:
                derived_key = derived_key[:len(encrypted_data)]
            
            # Déchiffrement
            key = bytes(a ^ b for a, b in zip(encrypted_data, derived_key))
            
            return key
            
        except Exception as e:
            raise ValueError(f"Erreur lors du chargement de la clé: {str(e)}")

    def load_key_for_crypto(self, key_file: str, password: str) -> bytes:
        """
        Charge une clé pour utilisation cryptographique
        Version simplifiée pour la compatibilité
        """
        if not os.path.exists(key_file):
            raise ValueError(f"Fichier de clé introuvable: {key_file}")
        
        return self.load_key_from_file(key_file, password)