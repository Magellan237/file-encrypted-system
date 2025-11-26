import os
import hashlib
from typing import Optional
from pathlib import Path

from src.utils.security import secure_erase

class FileHandler:
    """Gestion sécurisée des opérations sur les fichiers"""
    
    @staticmethod
    def validate_file_path(file_path: str) -> bool:
        """Valide l'existence et l'accessibilité d'un fichier"""
        path = Path(file_path)
        return path.exists() and path.is_file() and os.access(file_path, os.R_OK)

    @staticmethod
    def get_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
        """Calcule le hash d'un fichier"""
        hash_func = getattr(hashlib, algorithm)()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()

    @staticmethod
    def secure_delete(file_path: str, passes: int = 3) -> bool:
        """
        Suppression sécurisée d'un fichier par écrasement multiple
        """
        try:
            if not os.path.exists(file_path):
                return False
            
            file_size = os.path.getsize(file_path)
            
            with open(file_path, 'rb+') as f:
                for _ in range(passes):
                    # Écriture de données aléatoires
                    f.seek(0)
                    random_data = os.urandom(file_size)
                    f.write(random_data)
                    f.flush()
                    os.fsync(f.fileno())
            
            # Suppression finale du fichier
            os.remove(file_path)
            return True
            
        except Exception:
            return False

    @staticmethod
    def create_backup(file_path: str) -> Optional[str]:
        """Crée une sauvegarde d'un fichier"""
        if not FileHandler.validate_file_path(file_path):
            return None
        
        backup_path = file_path + '.backup'
        try:
            import shutil
            shutil.copy2(file_path, backup_path)
            return backup_path
        except Exception:
            return None