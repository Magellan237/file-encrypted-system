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
    """Unified manager for encryption/decryption operations."""
    
    def __init__(self):
        self.cipher = AESCipher()
        self.key_manager = KeyManager()
    
    def encrypt_with_key(self, input_path: str, output_path: str, key: bytes) -> bool:
        """
        Encrypts a file using a provided key.
        Format: [KENC][IV][SIZE][KEY_ID][DATA]
        """
        try:
            if len(key) != 32:
                raise ValueError("Key must be 32 bytes.")

            # Read file
            with open(input_path, 'rb') as f:
                plaintext = f.read()

            # Generate key ID (first 8 bytes of SHA256 hash)
            import hashlib
            key_id = hashlib.sha256(key).digest()[:8]

            # Encryption
            iv, ciphertext = self.cipher.encrypt(plaintext, key)

            # Write encrypted file
            with open(output_path, 'wb') as f:
                f.write(b'KENC')
                f.write(iv)
                f.write(struct.pack('<I', len(plaintext)))
                f.write(key_id)
                f.write(ciphertext)

            secure_erase(plaintext)
            return True

        except Exception as e:
            print(f"Encryption with key failed: {e}")
            return False
    
    def decrypt_with_key(self, input_path: str, output_path: str, key: bytes) -> bool:
        """
        Decrypts a file encrypted with a direct key.
        Validates the stored key ID before decrypting.
        """
        try:
            if len(key) != 32:
                raise ValueError("Key must be 32 bytes.")

            with open(input_path, 'rb') as f:
                magic = f.read(4)
                if magic != b'KENC':
                    print("Invalid KENC format.")
                    return False

                iv = f.read(16)
                size_bytes = f.read(4)
                original_size = struct.unpack('<I', size_bytes)[0]
                stored_key_id = f.read(8)
                ciphertext = f.read()

            # Validate key ID
            import hashlib
            current_key_id = hashlib.sha256(key).digest()[:8]

            if stored_key_id != current_key_id:
                print("Incorrect key ID.")
                return False

            plaintext = self.cipher.decrypt(ciphertext, key, iv)

            if len(plaintext) != original_size:
                print("Warning: size mismatch after decryption.")

            with open(output_path, 'wb') as f:
                f.write(plaintext)

            secure_erase(plaintext)
            return True

        except Exception as e:
            print(f"Decryption with key failed: {e}")
            return False
    
    def encrypt_file_v2(self, input_path: str, output_path: str, password: str) -> bool:
        """
        Encrypts a file using the V2 password-based format.
        Format: [FENC][IV][SIZE][SALT][DATA]
        """
        try:
            with open(input_path, 'rb') as f:
                plaintext = f.read()

            salt = os.urandom(16)
            key, _, _ = self.key_manager.derive_key_from_password(password, salt)

            iv, ciphertext = self.cipher.encrypt(plaintext, key)

            with open(output_path, 'wb') as f:
                f.write(b'FENC')
                f.write(iv)
                f.write(struct.pack('<I', len(plaintext)))
                f.write(salt)
                f.write(ciphertext)

            secure_erase(plaintext)
            return True

        except Exception as e:
            print(f"V2 encryption failed: {e}")
            return False
    
    def decrypt_file_v2(self, input_path: str, output_path: str, password: str) -> bool:
        """
        Decrypts a file using the V2 password-based format.
        """
        try:
            with open(input_path, 'rb') as f:
                magic = f.read(4)
                if magic != b'FENC':
                    raise ValueError("Invalid V2 format.")

                iv = f.read(16)
                size_bytes = f.read(4)
                original_size = struct.unpack('<I', size_bytes)[0]
                salt = f.read(16)
                ciphertext = f.read()

            key, _, _ = self.key_manager.derive_key_from_password(password, salt)
            plaintext = self.cipher.decrypt(ciphertext, key, iv)

            if len(plaintext) != original_size:
                print("Warning: size mismatch after decryption.")

            with open(output_path, 'wb') as f:
                f.write(plaintext)

            secure_erase(plaintext)
            return True

        except Exception as e:
            print(f"V2 decryption failed: {e}")
            return False
    
    def detect_file_format(self, input_path: str) -> str:
        """Detects the encryption format of a file."""
        try:
            with open(input_path, 'rb') as f:
                magic = f.read(4)

                if magic == b'KENC':
                    return 'key_encrypted'
                elif magic == b'FENC':
                    return 'password_encrypted'
                else:
                    f.seek(0)
                    if len(f.read()) >= 16:
                        return 'legacy'
                    else:
                        return 'unknown'
        except Exception:
            return 'unknown'
    
    def decrypt_file_auto(self, input_path: str, output_path: str, password: str) -> bool:
        """
        Automatically attempts all supported decryption formats.
        """
        format_type = self.detect_file_format(input_path)

        if format_type == 'key_encrypted':
            print("This file requires a direct key (use --key-file).")
            return False
            
        elif format_type == 'password_encrypted':
            return self.decrypt_file_v2(input_path, output_path, password)

        elif format_type == 'legacy':
            return self._decrypt_legacy(input_path, output_path, password)

        print("Could not decrypt: unknown format or incorrect password.")
        return False
    
    def _decrypt_legacy(self, input_path: str, output_path: str, password: str) -> bool:
        """Legacy decryption: [IV][DATA], no salt."""
        with open(input_path, 'rb') as f:
            data = f.read()
        
        if len(data) < 16:
            return False
        
        iv = data[:16]
        ciphertext = data[16:]

        key, _, _ = self.key_manager.derive_key_from_password(password)

        try:
            plaintext = self.cipher.decrypt(ciphertext, key, iv)
        except Exception:
            return False
        
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        secure_erase(plaintext)
        return True