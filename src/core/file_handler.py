import os
import hashlib
from typing import Optional
from pathlib import Path
from src.utils.security import secure_erase

class FileHandler:
    """Secure file operation management"""
    
    @staticmethod
    def validate_file_path(file_path: str) -> bool:
        """Validates the existence and accessibility of a file"""
        path = Path(file_path)
        return path.exists() and path.is_file() and os.access(file_path, os.R_OK)

    @staticmethod
    def get_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
        """Berechnet den Hashwert einer Datei"""
        hash_func = getattr(hashlib, algorithm)()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()

    @staticmethod
    def secure_delete(file_path: str, passes: int = 3) -> bool:
        """
        Securely delete a file by overwriting multiple files
        """
        try:
            if not os.path.exists(file_path):
                return False
            
            file_size = os.path.getsize(file_path)
            
            with open(file_path, 'rb+') as f:
                for _ in range(passes):
                    # Writing random data
                    f.seek(0)
                    random_data = os.urandom(file_size)
                    f.write(random_data)
                    f.flush()
                    os.fsync(f.fileno())
            
            # Endgültige Löschung der Datei
            os.remove(file_path)
            return True
            
        except Exception:
            return False

    @staticmethod
    def create_backup(file_path: str) -> Optional[str]:
        """Erstellt eine Sicherungskopie einer Datei"""
        if not FileHandler.validate_file_path(file_path):
            return None
        
        backup_path = file_path + '.backup'
        try:
            import shutil
            shutil.copy2(file_path, backup_path)
            return backup_path
        except Exception:
            return None