import ctypes
import sys
from typing import Any

def secure_erase(data: Any) -> None:
    """
    Effacement sécurisé des données en mémoire
    
    Cette fonction tente de nettoyer les données sensibles de la mémoire
    pour prévenir les attaques par lecture de mémoire.
    """
    if isinstance(data, bytes):
        # Pour les bytes, on écrase avec des zéros
        if hasattr(data, 'buffer'):
            # Pour les bytes et bytearray
            buffer = data.buffer if hasattr(data, 'buffer') else data
            ctypes.memset(ctypes.addressof(buffer), 0, len(data))
        else:
            # Méthode alternative pour bytes
            data = b'\x00' * len(data)
    
    elif isinstance(data, str):
        # Pour les strings, conversion en bytes puis effacement
        data_bytes = data.encode('utf-8')
        if hasattr(data_bytes, 'buffer'):
            buffer = data_bytes.buffer
            ctypes.memset(ctypes.addressof(buffer), 0, len(data_bytes))
    
    elif isinstance(data, bytearray):
        # Effacement direct pour bytearray
        ctypes.memset(ctypes.addressof(data), 0, len(data))
    
    # Forcer le garbage collection
    import gc
    gc.collect()

class SecureString:
    """Classe pour stocker des strings de manière sécurisée"""
    
    def __init__(self, text: str):
        self._data = bytearray(text.encode('utf-8'))
        self._length = len(self._data)
    
    def get(self) -> str:
        """Récupère la string (attention: copie en mémoire non sécurisée)"""
        return self._data.decode('utf-8')
    
    def erase(self) -> None:
        """Effacement sécurisé"""
        secure_erase(self._data)
        self._length = 0
    
    def __del__(self):
        self.erase()