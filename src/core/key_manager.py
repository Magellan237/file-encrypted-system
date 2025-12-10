import os
import base64
import secrets
from typing import Optional, Tuple
import argon2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import struct

from datetime import datetime

from src.utils.security import secure_erase

class KeyManager:
    """Secure management of encryption keys with Argon2"""
    
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
        Derive a secure key from a password with Argon2
        """
        if salt is None:
            salt = secrets.token_bytes(16)

        try:
            # SIMPLIFIED and more robust method
            password_bytes = password.encode('utf-8')
            
            # Direct use of Argon2
            raw_hash = argon2.low_level.hash_secret(
                secret=password_bytes,
                salt=salt,
                time_cost=3,
                memory_cost=65536,
                parallelism=1,
                hash_len=32,
                type=argon2.low_level.Type.ID
            )
            
            # Extracting the hash part
            hash_parts = raw_hash.decode('utf-8').split('$')
            if len(hash_parts) < 6:
                raise ValueError("Format de hash Argon2 invalide")
            
            hash_b64 = hash_parts[-1]
            
            # Base64 decoding with correct padding
            padding_needed = len(hash_b64) % 4
            if padding_needed:
                hash_b64 += '=' * (4 - padding_needed)
            
            try:
                key_bytes = base64.b64decode(hash_b64)
            except Exception:
                # Fallback to PBKDF2 if Argon2 fails
                import hashlib
                key_bytes = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 100000, 32)
            
            # Ensure that the key is exactly 32 bytes long.
            if len(key_bytes) < 32:
                key_bytes = key_bytes.ljust(32, b'\0')
            elif len(key_bytes) > 32:
                key_bytes = key_bytes[:32]
            
            encoded_hash = raw_hash.decode('utf-8')
            return key_bytes, salt, encoded_hash
            
        except Exception as e:
            # Fallback to PBKDF2
            import hashlib
            password_bytes = password.encode('utf-8')
            key_bytes = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 100000, 32)
            encoded_hash = f"pbkdf2_sha256${base64.b64encode(salt).decode()}${base64.b64encode(key_bytes).decode()}"
            return key_bytes, salt, encoded_hash

    def verify_password(self, password: str, encoded_hash: str) -> bool:
        """
        Verifies a password against the stored hash
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
            print(f"❌ Verification error: {e}")
            return False

    def generate_secure_key(self) -> bytes:
        """Generates a cryptographically secure key"""
        return secrets.token_bytes(32)

    def save_key_to_file(self, key: bytes, file_path: str, password: str) -> None:
        """
        Saves an encrypted key to a file
        """
        salt = secrets.token_bytes(16)
        encryption_key, _, encoded_hash = self.derive_key_from_password(password, salt)
        
        # Simple XOR encryption
        if len(encryption_key) < len(key):
            encryption_key = encryption_key.ljust(len(key), b'\0')
        
        xor_key = encryption_key[:len(key)]
        encrypted_data = bytes(a ^ b for a, b in zip(key, xor_key))
        
        with open(file_path, 'wb') as f:
            f.write(salt)
            f.write(struct.pack('>I', len(encrypted_data)))
            f.write(encrypted_data)
        
        # Saving the hash
        hash_file = file_path + '.hash'
        with open(hash_file, 'w', encoding='utf-8') as f:
            f.write(encoded_hash)

    def load_key_from_file(self, file_path: str, password: str) -> bytes:
        """
        Load a key from an encrypted file
        """
        try:
            with open(file_path, 'rb') as f:
                salt = f.read(16)
                if len(salt) != 16:
                    raise ValueError("Salt invalid")
                
                data_size_bytes = f.read(4)
                if len(data_size_bytes) != 4:
                    raise ValueError("Invalid data size")
                
                data_size = struct.unpack('>I', data_size_bytes)[0]
                encrypted_data = f.read(data_size)
                
                if len(encrypted_data) != data_size:
                    raise ValueError("Incomplete numerical data")
            
            # Laden des Hashs
            hash_file = file_path + '.hash'
            if not os.path.exists(hash_file):
                raise ValueError("Missing hash file")
                
            with open(hash_file, 'r', encoding='utf-8') as f:
                encoded_hash = f.read().strip()
            
            # Passwortüberprüfung
            if not self.verify_password(password, encoded_hash):
                raise ValueError("Mot de passe incorrect")
            
            # Regeneration of the bypass key
            derived_key, _, _ = self.derive_key_from_password(password, salt)
            
            # Größenanpassung
            if len(derived_key) < len(encrypted_data):
                derived_key = derived_key.ljust(len(encrypted_data), b'\0')
            else:
                derived_key = derived_key[:len(encrypted_data)]
            
            # Entschlüsselung
            key = bytes(a ^ b for a, b in zip(encrypted_data, derived_key))
            
            return key
            
        except Exception as e:
            raise ValueError(f"Error loading key: {str(e)}")

    def load_key_for_crypto(self, key_file: str, password: str) -> bytes:
        """
        Loads a key for cryptographic use
        Simplified version for compatibility
        """
        if not os.path.exists(key_file):
            raise ValueError(f"Fkey file not found: {key_file}")
        
        return self.load_key_from_file(key_file, password)