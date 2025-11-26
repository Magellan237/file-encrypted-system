import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
from typing import Tuple, Optional
import secrets
import struct

from src.utils.security import secure_erase

class AESCipher:
    """AES-256 implementation with secure management"""
    
    def __init__(self):
        self.backend = default_backend()
        self.iv_size = 16  # 128-bit for AES
        self.key_size = 32  # 256 bits
        self.block_size = 128  # bits

    def generate_iv(self) -> bytes:
        """Generates a secure initialization vector"""
        return secrets.token_bytes(self.iv_size)

    def encrypt(self, plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypts data with AES-256 in CBC mode
        
        Args:
            plaintext: Data to encrypt
            key: Encryption key (32 bytes)
            
        Returns:
            Tuple (iv, ciphertext)
        """
        # Schlüsselvalidierung
        if len(key) != self.key_size:
            raise ValueError(f"La clé doit faire {self.key_size} bytes")

        # Erzeugen einer sicheren IV
        iv = self.generate_iv()

        # Data padding
        padder = padding.PKCS7(self.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        # Verschlüsselung
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return iv, ciphertext

    def decrypt(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Déchiffre les données avec AES-256
        
        Args:
            ciphertext: Données chiffrées
            key: Clé de déchiffrement
            iv: Vecteur d'initialisation
            
        Returns:
            Données déchiffrées
        """
        # Parametervalidierung
        if len(key) != self.key_size:
            raise ValueError(f"La clé doit faire {self.key_size} bytes")
        if len(iv) != self.iv_size:
            raise ValueError(f"L'IV doit faire {self.iv_size} bytes")

        try:
            # Entschlüsselung
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # Entfernung von Padding mit Fehlerbehandlung
            unpadder = padding.PKCS7(self.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

            return plaintext
            
        except ValueError as e:
            # Spezielle Behandlung von Padding-Fehlern
            if "padding" in str(e).lower():
                raise ValueError("Padding error - the key or data may be corrupted")
            raise e

    def encrypt_file(self, input_path: str, output_path: str, key: bytes) -> None:
        """Encrypts an entire file with a custom header"""
        with open(input_path, 'rb') as f:
            plaintext = f.read()

        iv, ciphertext = self.encrypt(plaintext, key)

        # Enhanced encrypted file format:
        # [4 bytes: magic number] + [16 bytes: IV] + [4 bytes: data size] + [encrypted data]
        magic = b'FENC'  # File ENCryption
        data_size = len(ciphertext)
        
        with open(output_path, 'wb') as f:
            f.write(magic)
            f.write(iv)
            f.write(struct.pack('>I', data_size))  # Taille en big-endian
            f.write(ciphertext)

        # Sichere Speicherbereinigung
        secure_erase(plaintext)

    def decrypt_file(self, input_path: str, output_path: str, key: bytes) -> None:
        """Decrypts an entire file with a custom header"""
        with open(input_path, 'rb') as f:
            # Den Header lesen
            magic = f.read(4)
            if magic != b'FENC':
                raise ValueError("Invalid file format - magic number incorrect")
            
            iv = f.read(16)
            if len(iv) != 16:
                raise ValueError("IV invalid")
            
            data_size_bytes = f.read(4)
            if len(data_size_bytes) != 4:
                raise ValueError("Invalid data size")
            
            data_size = struct.unpack('>I', data_size_bytes)[0]
            ciphertext = f.read(data_size)
            
            if len(ciphertext) != data_size:
                raise ValueError(f"Incorrect data size: expected {data_size}, got {len(ciphertext)}")

        plaintext = self.decrypt(ciphertext, key, iv)

        with open(output_path, 'wb') as f:
            f.write(plaintext)

        # Sichere Reinigung
        secure_erase(plaintext)