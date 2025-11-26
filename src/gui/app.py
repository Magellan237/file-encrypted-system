import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import sys
from pathlib import Path

# Ajouter le chemin pour les imports
current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

try:
    from core.crypto_manager import CryptoManager
    from core.file_handler import FileHandler
except ImportError as e:
    print(f"❌ Erreur d'importation: {e}")
    sys.exit(1)

class CryptoFileApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 CryptoFile - Chiffrement Simple et Sécurisé")
        self.root.geometry("700x600")
        self.root.minsize(600, 500)
        
        # Variables d'instance
        self.current_file = None
        self.current_key_file = None
        self.use_key_var = tk.BooleanVar(value=False)
        
        self.crypto_manager = CryptoManager()
        self.setup_ui()
    
    def setup_ui(self):
        # Style moderne
        self.setup_styles()
        
        # Frame principale avec scrollbar
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configuration du grid pour le redimensionnement
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(5, weight=1)
        
        # En-tête
        self.create_header(main_frame)
        
        # Sélection de fichier
        self.create_file_section(main_frame)
        
        # Section clé (optionnelle)
        self.create_key_section(main_frame)
        
        # Mot de passe
        self.create_password_section(main_frame)
        
        # Actions
        self.create_action_section(main_frame)
        
        # Progress bar
        self.create_progress_section(main_frame)
        
        # Journal d'activité
        self.create_log_section(main_frame)
        
        # Pied de page
        self.create_footer(main_frame)
    
    def setup_styles(self):
        style = ttk.Style()
        
        # Styles personnalisés
        style.configure('Title.TLabel', font=('Arial', 18, 'bold'))
        style.configure('Subtitle.TLabel', font=('Arial', 11))
        style.configure('Action.TButton', font=('Arial', 12, 'bold'))
        style.configure('Success.TLabel', foreground='green')
        style.configure('Error.TLabel', foreground='red')
    
    def create_header(self, parent):
        """Crée l'en-tête de l'application"""
        header_frame = ttk.Frame(parent)
        header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 20))
        header_frame.columnconfigure(0, weight=1)
        
        title = ttk.Label(header_frame, text="🔐 CryptoFile", style='Title.TLabel')
        title.grid(row=0, column=0, pady=(0, 5))
        
        subtitle = ttk.Label(header_frame, 
                           text="Chiffrement et déchiffrement sécurisé de fichiers - Simple et Rapide",
                           style='Subtitle.TLabel')
        subtitle.grid(row=1, column=0)
    
    def create_file_section(self, parent):
        """Section de sélection de fichier"""
        file_frame = ttk.LabelFrame(parent, text="📁 1. Sélection du fichier", padding="12")
        file_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 12))
        file_frame.columnconfigure(0, weight=1)
        
        # Affichage du fichier sélectionné
        self.file_label = ttk.Label(file_frame, text="Aucun fichier sélectionné")
        self.file_label.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 8))
        
        # Boutons
        btn_frame = ttk.Frame(file_frame)
        btn_frame.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        self.browse_btn = ttk.Button(btn_frame, text="Parcourir...", command=self.select_file)
        self.browse_btn.grid(row=0, column=0, padx=(0, 10))
        
        self.clear_btn = ttk.Button(btn_frame, text="Effacer", command=self.clear_file, state=tk.DISABLED)
        self.clear_btn.grid(row=0, column=1)
        
        # Info fichier
        self.file_info = ttk.Label(file_frame, text="", style='Subtitle.TLabel')
        self.file_info.grid(row=2, column=0, sticky=tk.W)
    
    def create_key_section(self, parent):
        """Section de gestion des clés (optionnelle)"""
        key_frame = ttk.LabelFrame(parent, text="🗝️ 2. Clé externe (optionnel)", padding="10")
        key_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 12))
        key_frame.columnconfigure(0, weight=1)
        
        key_check = ttk.Checkbutton(key_frame, text="Utiliser un fichier de clé", 
                                   variable=self.use_key_var, command=self.toggle_key_file)
        key_check.grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        self.key_file_frame = ttk.Frame(key_frame)
        self.key_file_frame.grid(row=1, column=0, sticky=(tk.W, tk.E))
        self.key_file_frame.columnconfigure(0, weight=1)
        
        self.key_file_label = ttk.Label(self.key_file_frame, text="Aucun fichier de clé sélectionné")
        self.key_file_label.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        self.key_browse_btn = ttk.Button(self.key_file_frame, text="Parcourir clé...", 
                                       command=self.select_key_file, state=tk.DISABLED)
        self.key_browse_btn.grid(row=0, column=1, padx=(10, 0))
        
        # Cacher initialement
        self.key_file_frame.grid_remove()
    
    def create_password_section(self, parent):
        """Section de saisie du mot de passe"""
        password_frame = ttk.LabelFrame(parent, text="🔑 3. Mot de passe", padding="12")
        password_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(0, 12))
        password_frame.columnconfigure(1, weight=1)
        
        # Mot de passe
        ttk.Label(password_frame, text="Mot de passe:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.password_entry = ttk.Entry(password_frame, show="•", width=30)
        self.password_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        # Confirmation
        ttk.Label(password_frame, text="Confirmation:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(8, 0))
        self.confirm_entry = ttk.Entry(password_frame, show="•", width=30)
        self.confirm_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(0, 10), pady=(8, 0))
        
        # Indicateur de force du mot de passe
        self.password_strength = ttk.Label(password_frame, text="")
        self.password_strength.grid(row=2, column=1, sticky=tk.W, pady=(5, 0))
        
        # Lier les événements de saisie
        self.password_entry.bind('<KeyRelease>', self.check_password_strength)
        self.confirm_entry.bind('<KeyRelease>', self.check_password_match)
    
    def create_action_section(self, parent):
        """Section des boutons d'action"""
        action_frame = ttk.LabelFrame(parent, text="⚡ 4. Action", padding="12")
        action_frame.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=(0, 12))
        
        # Boutons centrés
        btn_container = ttk.Frame(action_frame)
        btn_container.grid(row=0, column=0)
        
        self.encrypt_btn = ttk.Button(btn_container, text="🔒 CHIFFRER", 
                                     command=self.encrypt_file, 
                                     state=tk.DISABLED,
                                     style='Action.TButton')
        self.encrypt_btn.grid(row=0, column=0, padx=(0, 20))
        
        self.decrypt_btn = ttk.Button(btn_container, text="🔓 DÉCHIFFRER", 
                                     command=self.decrypt_file, 
                                     state=tk.DISABLED,
                                     style='Action.TButton')
        self.decrypt_btn.grid(row=0, column=1)
    
    def create_progress_section(self, parent):
        """Section de progression"""
        self.progress_frame = ttk.Frame(parent)
        self.progress_frame.grid(row=5, column=0, sticky=(tk.W, tk.E), pady=(0, 12))
        self.progress_frame.columnconfigure(0, weight=1)
        
        self.progress = ttk.Progressbar(self.progress_frame, mode='indeterminate')
        self.progress.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        self.progress_label = ttk.Label(self.progress_frame, text="")
        self.progress_label.grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        
        # Cacher initialement
        self.hide_progress()
    
    def create_log_section(self, parent):
        """Section du journal d'activité"""
        log_frame = ttk.LabelFrame(parent, text="📋 Journal d'activité", padding="12")
        log_frame.grid(row=6, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 12))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        # Zone de texte avec scrollbar
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, wrap=tk.WORD)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Boutons de contrôle du journal
        log_controls = ttk.Frame(log_frame)
        log_controls.grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        
        ttk.Button(log_controls, text="Effacer le journal", 
                  command=self.clear_log).grid(row=0, column=0, padx=(0, 10))
        
        ttk.Button(log_controls, text="Copier le journal", 
                  command=self.copy_log).grid(row=0, column=1)
    
    def create_footer(self, parent):
        """Pied de page"""
        footer_frame = ttk.Frame(parent)
        footer_frame.grid(row=7, column=0, sticky=(tk.W, tk.E))
        footer_frame.columnconfigure(0, weight=1)
        
        footer_text = "✅ CryptoFile - Sécurisez vos fichiers facilement"
        footer = ttk.Label(footer_frame, text=footer_text, style='Subtitle.TLabel')
        footer.grid(row=0, column=0)
    
    def select_file(self):
        """Sélectionne un fichier"""
        filename = filedialog.askopenfilename(
            title="Sélectionnez un fichier à chiffrer/déchiffrer",
            filetypes=[
                ("Tous les fichiers", "*.*"),
                ("Documents PDF", "*.pdf"),
                ("Images", "*.jpg *.jpeg *.png *.gif"),
                ("Documents", "*.doc *.docx *.txt"),
                ("Archives", "*.zip *.rar *.7z")
            ]
        )
        
        if filename:
            self.current_file = filename
            file_path = Path(filename)
            self.file_label.config(text=file_path.name)
            self.clear_btn.config(state=tk.NORMAL)
            
            # Afficher les informations du fichier
            file_size = file_path.stat().st_size
            size_text = self.format_file_size(file_size)
            self.file_info.config(text=f"Taille: {size_text}")
            
            # Déterminer l'action possible
            if filename.endswith('.encrypted'):
                self.encrypt_btn.config(state=tk.DISABLED)
                self.decrypt_btn.config(state=tk.NORMAL)
                self.log("📁 Fichier chiffré sélectionné - Prêt pour le déchiffrement")
            else:
                self.encrypt_btn.config(state=tk.NORMAL)
                self.decrypt_btn.config(state=tk.DISABLED)
                self.log("📁 Fichier normal sélectionné - Prêt pour le chiffrement")
    
    def clear_file(self):
        """Efface la sélection de fichier"""
        self.current_file = None
        self.file_label.config(text="Aucun fichier sélectionné")
        self.file_info.config(text="")
        self.clear_btn.config(state=tk.DISABLED)
        self.encrypt_btn.config(state=tk.DISABLED)
        self.decrypt_btn.config(state=tk.DISABLED)
        self.log("🗑️ Sélection de fichier effacée")
    
    def toggle_key_file(self):
        """Active/désactive la sélection de fichier de clé"""
        if self.use_key_var.get():
            self.key_file_frame.grid()
            self.key_browse_btn.config(state=tk.NORMAL)
            self.log("🗝️  Mode fichier de clé activé")
        else:
            self.key_file_frame.grid_remove()
            self.key_browse_btn.config(state=tk.DISABLED)
            self.current_key_file = None
            self.key_file_label.config(text="Aucun fichier de clé sélectionné")
            self.log("🗝️  Mode fichier de clé désactivé")
    
    def select_key_file(self):
        """Sélectionne un fichier de clé"""
        filename = filedialog.askopenfilename(
            title="Sélectionnez un fichier de clé",
            filetypes=[("Fichiers de clé", "*.key"), ("Tous les fichiers", "*.*")]
        )
        
        if filename:
            self.current_key_file = filename
            self.key_file_label.config(text=Path(filename).name)
            self.log(f"🗝️  Fichier de clé sélectionné: {Path(filename).name}")
    
    def check_password_strength(self, event=None):
        """Vérifie la force du mot de passe"""
        password = self.password_entry.get()
        
        if len(password) == 0:
            self.password_strength.config(text="")
        elif len(password) < 4:
            self.password_strength.config(text="❌ Trop court (min 4 caractères)", style='Error.TLabel')
        elif len(password) < 8:
            self.password_strength.config(text="⚠️  Faible", style='Subtitle.TLabel')
        else:
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            
            if has_upper and has_lower and has_digit:
                self.password_strength.config(text="✅ Fort", style='Success.TLabel')
            else:
                self.password_strength.config(text="⚠️  Moyen", style='Subtitle.TLabel')
    
    def check_password_match(self, event=None):
        """Vérifie si les mots de passe correspondent"""
        password = self.password_entry.get()
        confirm = self.confirm_entry.get()
        
        if confirm and password != confirm:
            self.password_strength.config(text="❌ Les mots de passe ne correspondent pas", style='Error.TLabel')
        elif confirm and password == confirm:
            self.password_strength.config(text="✅ Mots de passe identiques", style='Success.TLabel')
    
    def encrypt_file(self):
        """Chiffre le fichier sélectionné"""
        if not self.validate_inputs():
            return
        
        def encrypt_thread():
            try:
                self.show_progress("Chiffrement en cours...")
                
                input_path = self.current_file
                output_path = input_path + '.encrypted'
                
                key_file = self.current_key_file if self.use_key_var.get() else None
                
                self.log(f"🔒 Début du chiffrement: {Path(input_path).name}")
                if key_file:
                    self.log(f"🗝️  Utilisation du fichier de clé: {Path(key_file).name}")
                
                success = self.crypto_manager.encrypt_file_v2(
                    input_path, output_path, self.password_entry.get(), key_file
                )
                
                if success:
                    output_size = Path(output_path).stat().st_size
                    self.log(f"✅ Chiffrement réussi! Taille: {self.format_file_size(output_size)}")
                    messagebox.showinfo("Succès", 
                                      f"Fichier chiffré avec succès!\n\n"
                                      f"📁 Fichier: {Path(output_path).name}\n"
                                      f"📏 Taille: {self.format_file_size(output_size)}")
                else:
                    self.log("❌ Échec du chiffrement")
                    messagebox.showerror("Erreur", "Le chiffrement a échoué. Vérifiez le fichier et réessayez.")
                    
            except Exception as e:
                error_msg = f"Erreur lors du chiffrement: {str(e)}"
                self.log(f"💥 {error_msg}")
                messagebox.showerror("Erreur", error_msg)
            finally:
                self.hide_progress()
        
        threading.Thread(target=encrypt_thread, daemon=True).start()
    
    def decrypt_file(self):
        """Déchiffre le fichier sélectionné"""
        if not self.validate_inputs():
            return
        
        def decrypt_thread():
            try:
                self.show_progress("Déchiffrement en cours...")
                
                input_path = self.current_file
                key_file = self.current_key_file if self.use_key_var.get() else None
                
                if input_path.endswith('.encrypted'):
                    output_path = input_path[:-10]  # Retire .encrypted
                else:
                    output_path = input_path + '.decrypted'
                
                self.log(f"🔓 Début du déchiffrement: {Path(input_path).name}")
                if key_file:
                    self.log(f"🗝️  Utilisation du fichier de clé: {Path(key_file).name}")
                
                success = self.crypto_manager.decrypt_file_auto(
                    input_path, output_path, self.password_entry.get(), key_file
                )
                
                if success:
                    output_size = Path(output_path).stat().st_size
                    self.log(f"✅ Déchiffrement réussi! Taille: {self.format_file_size(output_size)}")
                    messagebox.showinfo("Succès", 
                                      f"Fichier déchiffré avec succès!\n\n"
                                      f"📁 Fichier: {Path(output_path).name}\n"
                                      f"📏 Taille: {self.format_file_size(output_size)}")
                else:
                    self.log("❌ Échec du déchiffrement - Mauvais mot de passe ou clé?")
                    messagebox.showerror("Erreur", 
                                       "Le déchiffrement a échoué.\n\n"
                                       "Raisons possibles:\n"
                                       "• Mot de passe incorrect\n"
                                       "• Clé incorrecte\n"
                                       "• Fichier corrompu\n"
                                       "• Format non supporté")
                
            except Exception as e:
                error_msg = f"Erreur lors du déchiffrement: {str(e)}"
                self.log(f"💥 {error_msg}")
                messagebox.showerror("Erreur", error_msg)
            finally:
                self.hide_progress()
        
        threading.Thread(target=decrypt_thread, daemon=True).start()
    
    def validate_inputs(self):
        """Valide les entrées utilisateur"""
        if not self.current_file:
            messagebox.showwarning("Attention", "Veuillez sélectionner un fichier")
            return False
        
        password = self.password_entry.get()
        confirm = self.confirm_entry.get()
        
        if not password:
            messagebox.showwarning("Attention", "Veuillez entrer un mot de passe")
            return False
        
        if password != confirm:
            messagebox.showwarning("Attention", "Les mots de passe ne correspondent pas")
            return False
        
        if len(password) < 4:
            messagebox.showwarning("Attention", "Le mot de passe doit faire au moins 4 caractères")
            return False
        
        # Vérification du fichier de clé si activé
        if self.use_key_var.get() and not self.current_key_file:
            messagebox.showwarning("Attention", "Veuillez sélectionner un fichier de clé")
            return False
        
        return True
    
    def show_progress(self, message):
        """Affiche la barre de progression"""
        self.progress_frame.grid()
        self.progress.start()
        self.progress_label.config(text=message)
    
    def hide_progress(self):
        """Cache la barre de progression"""
        self.progress.stop()
        self.progress_frame.grid_remove()
        self.progress_label.config(text="")
    
    def log(self, message):
        """Ajoute un message au journal"""
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
        self.root.update()
    
    def clear_log(self):
        """Efface le journal"""
        self.log_text.delete(1.0, tk.END)
        self.log("🗑️ Journal effacé")
    
    def copy_log(self):
        """Copie le journal dans le presse-papier"""
        log_content = self.log_text.get(1.0, tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(log_content)
        self.log("📋 Journal copié dans le presse-papiers")
    
    def format_file_size(self, size_bytes):
        """Formate la taille du fichier en unités lisibles"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"

def run_gui():
    """Lance l'interface graphique"""
    try:
        root = tk.Tk()
        app = CryptoFileApp(root)
        root.mainloop()
    except Exception as e:
        print(f"❌ Erreur lors du lancement de l'interface: {e}")
        input("Appuyez sur Entrée pour quitter...")

if __name__ == "__main__":
    run_gui()