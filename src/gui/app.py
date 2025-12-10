import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import sys
from pathlib import Path
import hashlib

# Pfad für Imports hinzufügen
current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

try:
    from core.crypto_manager import CryptoManager
    from core.file_handler import FileHandler
    from core.key_manager import KeyManager
except ImportError as e:
    print(f"❌ Importfehler: {e}")
    sys.exit(1)

class CryptoFileApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 CryptoFile - Einfache und sichere Verschlüsselung")
        self.root.geometry("700x600")
        self.root.minsize(600, 500)
        
        # Instanzvariablen
        self.current_file = None
        self.current_key_file = None
        self.use_key_var = tk.BooleanVar(value=False)
        
        self.crypto_manager = CryptoManager()
        self.key_manager = KeyManager()
        self.setup_ui()
    
    def setup_ui(self):
        # Modernes Design
        self.setup_styles()
        
        # Hauptframe mit Scrollbar
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Grid-Konfiguration für Anpassung
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(5, weight=1)
        
        # Header
        self.create_header(main_frame)
        
        # Dateiauswahl
        self.create_file_section(main_frame)
        
        # Schlüsselbereich (optional)
        self.create_key_section(main_frame)
        
        # Passwort
        self.create_password_section(main_frame)
        
        # Aktionen
        self.create_action_section(main_frame)
        
        # Fortschrittsbalken
        self.create_progress_section(main_frame)
        
        # Aktivitätsprotokoll
        self.create_log_section(main_frame)
        
        # Footer
        self.create_footer(main_frame)
    
    def setup_styles(self):
        style = ttk.Style()
        
        # Benutzerdefinierte Stile
        style.configure('Title.TLabel', font=('Arial', 18, 'bold'))
        style.configure('Subtitle.TLabel', font=('Arial', 11))
        style.configure('Action.TButton', font=('Arial', 12, 'bold'))
        style.configure('Success.TLabel', foreground='green')
        style.configure('Error.TLabel', foreground='red')
    
    def create_header(self, parent):
        """Erstellt den Anwendungsheader"""
        header_frame = ttk.Frame(parent)
        header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 20))
        header_frame.columnconfigure(0, weight=1)
        
        title = ttk.Label(header_frame, text="🔐 CryptoFile", style='Title.TLabel')
        title.grid(row=0, column=0, pady=(0, 5))
        
        subtitle = ttk.Label(header_frame, 
                           text="Sichere Dateiverschlüsselung und -entschlüsselung - Einfach und Schnell",
                           style='Subtitle.TLabel')
        subtitle.grid(row=1, column=0)
    
    def create_file_section(self, parent):
        """Dateiauswahlbereich"""
        file_frame = ttk.LabelFrame(parent, text="📁 1. Dateiauswahl", padding="12")
        file_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 12))
        file_frame.columnconfigure(0, weight=1)
        
        # Anzeige der ausgewählten Datei
        self.file_label = ttk.Label(file_frame, text="Keine Datei ausgewählt")
        self.file_label.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 8))
        
        # Buttons
        btn_frame = ttk.Frame(file_frame)
        btn_frame.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        self.browse_btn = ttk.Button(btn_frame, text="Durchsuchen...", command=self.select_file)
        self.browse_btn.grid(row=0, column=0, padx=(0, 10))
        
        self.clear_btn = ttk.Button(btn_frame, text="Löschen", command=self.clear_file, state=tk.DISABLED)
        self.clear_btn.grid(row=0, column=1)
        
        # Dateiinfo
        self.file_info = ttk.Label(file_frame, text="", style='Subtitle.TLabel')
        self.file_info.grid(row=2, column=0, sticky=tk.W)
    
    def create_key_section(self, parent):
        """Schlüsselverwaltung (optional)"""
        key_frame = ttk.LabelFrame(parent, text="🗝️ 2. Externer Schlüssel (optional)", padding="10")
        key_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 12))
        key_frame.columnconfigure(0, weight=1)
        
        key_check = ttk.Checkbutton(key_frame, text="Schlüsseldatei verwenden", 
                                   variable=self.use_key_var, command=self.toggle_key_file)
        key_check.grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        self.key_file_frame = ttk.Frame(key_frame)
        self.key_file_frame.grid(row=1, column=0, sticky=(tk.W, tk.E))
        self.key_file_frame.columnconfigure(0, weight=1)
        
        self.key_file_label = ttk.Label(self.key_file_frame, text="Keine Schlüsseldatei ausgewählt")
        self.key_file_label.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        self.key_browse_btn = ttk.Button(self.key_file_frame, text="Schlüssel durchsuchen...", 
                                       command=self.select_key_file, state=tk.DISABLED)
        self.key_browse_btn.grid(row=0, column=1, padx=(10, 0))
        
        self.generate_key_btn = ttk.Button(key_frame, text="Neuen Schlüssel generieren", 
                                         command=self.generate_key_dialog)
        self.generate_key_btn.grid(row=2, column=0, sticky=tk.W, pady=(10, 0))
        
        # Initial ausblenden
        self.key_file_frame.grid_remove()
    
    def create_password_section(self, parent):
        """Passworteingabebereich"""
        password_frame = ttk.LabelFrame(parent, text="🔑 3. Passwort", padding="12")
        password_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(0, 12))
        password_frame.columnconfigure(1, weight=1)
        
        # Passwort
        ttk.Label(password_frame, text="Passwort:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.password_entry = ttk.Entry(password_frame, show="•", width=30)
        self.password_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        # Bestätigung
        ttk.Label(password_frame, text="Bestätigung:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(8, 0))
        self.confirm_entry = ttk.Entry(password_frame, show="•", width=30)
        self.confirm_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(0, 10), pady=(8, 0))
        
        # Passwortstärke-Anzeige
        self.password_strength = ttk.Label(password_frame, text="")
        self.password_strength.grid(row=2, column=1, sticky=tk.W, pady=(5, 0))
        
        # Tastatureingabe-Ereignisse binden
        self.password_entry.bind('<KeyRelease>', self.check_password_strength)
        self.confirm_entry.bind('<KeyRelease>', self.check_password_match)
    
    def create_action_section(self, parent):
        """Aktionsbuttons"""
        action_frame = ttk.LabelFrame(parent, text="⚡ 4. Aktion", padding="12")
        action_frame.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=(0, 12))
        
        # Zentrierte Buttons
        btn_container = ttk.Frame(action_frame)
        btn_container.grid(row=0, column=0)
        
        self.encrypt_btn = ttk.Button(btn_container, text="🔒 VERSCHLÜSSELN", 
                                     command=self.encrypt_file, 
                                     state=tk.DISABLED,
                                     style='Action.TButton')
        self.encrypt_btn.grid(row=0, column=0, padx=(0, 20))
        
        self.decrypt_btn = ttk.Button(btn_container, text="🔓 ENTSCHLÜSSELN", 
                                     command=self.decrypt_file, 
                                     state=tk.DISABLED,
                                     style='Action.TButton')
        self.decrypt_btn.grid(row=0, column=1)
    
    def create_progress_section(self, parent):
        """Fortschrittsbereich"""
        self.progress_frame = ttk.Frame(parent)
        self.progress_frame.grid(row=5, column=0, sticky=(tk.W, tk.E), pady=(0, 12))
        self.progress_frame.columnconfigure(0, weight=1)
        
        self.progress = ttk.Progressbar(self.progress_frame, mode='indeterminate')
        self.progress.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        self.progress_label = ttk.Label(self.progress_frame, text="")
        self.progress_label.grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        
        # Initial ausblenden
        self.hide_progress()
    
    def create_log_section(self, parent):
        """Aktivitätsprotokoll"""
        log_frame = ttk.LabelFrame(parent, text="📋 Aktivitätsprotokoll", padding="12")
        log_frame.grid(row=6, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 12))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        # Textbereich mit Scrollbar
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, wrap=tk.WORD)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Protokollsteuerung
        log_controls = ttk.Frame(log_frame)
        log_controls.grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        
        ttk.Button(log_controls, text="Protokoll löschen", 
                  command=self.clear_log).grid(row=0, column=0, padx=(0, 10))
        
        ttk.Button(log_controls, text="Protokoll kopieren", 
                  command=self.copy_log).grid(row=0, column=1)
    
    def create_footer(self, parent):
        """Footer"""
        footer_frame = ttk.Frame(parent)
        footer_frame.grid(row=7, column=0, sticky=(tk.W, tk.E))
        footer_frame.columnconfigure(0, weight=1)
        
        footer_text = "✅ CryptoFile - Sichern Sie Ihre Dateien einfach"
        footer = ttk.Label(footer_frame, text=footer_text, style='Subtitle.TLabel')
        footer.grid(row=0, column=0)
    
    def select_file(self):
        """Wählt eine Datei aus"""
        filename = filedialog.askopenfilename(
            title="Datei zum Verschlüsseln/Entschlüsseln wählen",
            filetypes=[
                ("Alle Dateien", "*.*"),
                ("PDF-Dokumente", "*.pdf"),
                ("Bilder", "*.jpg *.jpeg *.png *.gif"),
                ("Dokumente", "*.doc *.docx *.txt"),
                ("Archive", "*.zip *.rar *.7z")
            ]
        )
        
        if filename:
            self.current_file = filename
            file_path = Path(filename)
            self.file_label.config(text=file_path.name)
            self.clear_btn.config(state=tk.NORMAL)
            
            # Dateiinformationen anzeigen
            file_size = file_path.stat().st_size
            size_text = self.format_file_size(file_size)
            self.file_info.config(text=f"Größe: {size_text}")
            
            # Mögliche Aktion bestimmen
            if filename.endswith('.encrypted'):
                self.encrypt_btn.config(state=tk.DISABLED)
                self.decrypt_btn.config(state=tk.NORMAL)
                self.log("📁 Verschlüsselte Datei ausgewählt - Bereit zum Entschlüsseln")
            else:
                self.encrypt_btn.config(state=tk.NORMAL)
                self.decrypt_btn.config(state=tk.DISABLED)
                self.log("📁 Normale Datei ausgewählt - Bereit zum Verschlüsseln")
    
    def clear_file(self):
        """Löscht die Dateiauswahl"""
        self.current_file = None
        self.file_label.config(text="Keine Datei ausgewählt")
        self.file_info.config(text="")
        self.clear_btn.config(state=tk.DISABLED)
        self.encrypt_btn.config(state=tk.DISABLED)
        self.decrypt_btn.config(state=tk.DISABLED)
        self.log("🗑️ Dateiauswahl gelöscht")
    
    def toggle_key_file(self):
        """Aktiviert/Deaktiviert Schlüsseldateiauswahl"""
        if self.use_key_var.get():
            self.key_file_frame.grid()
            self.key_browse_btn.config(state=tk.NORMAL)
            self.log("🗝️  Schlüsseldatei-Modus aktiviert")
        else:
            self.key_file_frame.grid_remove()
            self.key_browse_btn.config(state=tk.DISABLED)
            self.current_key_file = None
            self.key_file_label.config(text="Keine Schlüsseldatei ausgewählt")
            self.log("🗝️  Schlüsseldatei-Modus deaktiviert")
    
    def select_key_file(self):
        """Wählt eine Schlüsseldatei aus"""
        filename = filedialog.askopenfilename(
            title="Schlüsseldatei wählen",
            filetypes=[("Schlüsseldateien", "*.key"), ("Alle Dateien", "*.*")]
        )
        
        if filename:
            self.current_key_file = filename
            self.key_file_label.config(text=Path(filename).name)
            self.log(f"🗝️  Schlüsseldatei ausgewählt: {Path(filename).name}")
    
    def generate_key_dialog(self):
        """Dialog zum Generieren eines neuen Schlüssels"""
        dialog = tk.Toplevel(self.root)
        dialog.title("🔑 Neuen Schlüssel generieren")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Hauptframe
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(main_frame, text="Neuen Schlüssel generieren", font=('Arial', 14, 'bold')).grid(row=0, column=0, pady=(0, 15))
        
        # Passwort
        ttk.Label(main_frame, text="Passwort zum Schutz des Schlüssels:").grid(row=1, column=0, sticky=tk.W)
        password_entry = ttk.Entry(main_frame, show="•", width=30)
        password_entry.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(main_frame, text="Bestätigung:").grid(row=3, column=0, sticky=tk.W)
        confirm_entry = ttk.Entry(main_frame, show="•", width=30)
        confirm_entry.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        
        # Ausgabedatei
        ttk.Label(main_frame, text="Ausgabedatei:").grid(row=5, column=0, sticky=tk.W)
        file_frame = ttk.Frame(main_frame)
        file_frame.grid(row=6, column=0, sticky=(tk.W, tk.E), pady=(0, 20))
        
        output_var = tk.StringVar(value="mein_schluessel.key")
        output_entry = ttk.Entry(file_frame, textvariable=output_var, width=25)
        output_entry.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        def browse_output():
            filename = filedialog.asksaveasfilename(
                title="Schlüssel speichern unter",
                defaultextension=".key",
                filetypes=[("Schlüsseldateien", "*.key"), ("Alle Dateien", "*.*")]
            )
            if filename:
                output_var.set(filename)
        
        ttk.Button(file_frame, text="Durchsuchen...", command=browse_output).grid(row=0, column=1, padx=(10, 0))
        
        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=7, column=0, sticky=tk.E)
        
        def generate():
            password = password_entry.get()
            confirm = confirm_entry.get()
            output_file = output_var.get()
            
            if not password or not confirm:
                messagebox.showerror("Fehler", "Bitte geben Sie ein Passwort ein")
                return
            
            if password != confirm:
                messagebox.showerror("Fehler", "Passwörter stimmen nicht überein")
                return
            
            if len(password) < 4:
                messagebox.showerror("Fehler", "Passwort muss mindestens 4 Zeichen lang sein")
                return
            
            if not output_file:
                messagebox.showerror("Fehler", "Bitte geben Sie eine Ausgabedatei an")
                return
            
            try:
                # Schlüssel generieren
                key = self.key_manager.generate_secure_key()
                self.key_manager.save_key_to_file(key, output_file, password)
                
                self.log(f"🗝️  Neuer Schlüssel generiert: {output_file}")
                messagebox.showinfo("Erfolg", f"Schlüssel erfolgreich generiert!\n\nDatei: {output_file}")
                dialog.destroy()
                
            except Exception as e:
                messagebox.showerror("Fehler", f"Fehler bei der Generierung: {str(e)}")
        
        def cancel():
            dialog.destroy()
        
        ttk.Button(btn_frame, text="Generieren", command=generate).grid(row=0, column=0, padx=(0, 10))
        ttk.Button(btn_frame, text="Abbrechen", command=cancel).grid(row=0, column=1)
        
        # Grid-Konfiguration
        main_frame.columnconfigure(0, weight=1)
        file_frame.columnconfigure(0, weight=1)
    
    def check_password_strength(self, event=None):
        """Überprüft die Passwortstärke"""
        password = self.password_entry.get()
        
        if len(password) == 0:
            self.password_strength.config(text="")
        elif len(password) < 4:
            self.password_strength.config(text="❌ Zu kurz (min. 4 Zeichen)", style='Error.TLabel')
        elif len(password) < 8:
            self.password_strength.config(text="⚠️  Schwach", style='Subtitle.TLabel')
        else:
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            
            if has_upper and has_lower and has_digit:
                self.password_strength.config(text="✅ Stark", style='Success.TLabel')
            else:
                self.password_strength.config(text="⚠️  Mittel", style='Subtitle.TLabel')
    
    def check_password_match(self, event=None):
        """Überprüft Passwortübereinstimmung"""
        password = self.password_entry.get()
        confirm = self.confirm_entry.get()
        
        if confirm and password != confirm:
            self.password_strength.config(text="❌ Passwörter stimmen nicht überein", style='Error.TLabel')
        elif confirm and password == confirm:
            self.password_strength.config(text="✅ Passwörter übereinstimmend", style='Success.TLabel')
    
    def encrypt_file(self):
        """Verschlüsselt die ausgewählte Datei"""
        if not self.validate_inputs():
            return
        
        def encrypt_thread():
            try:
                self.show_progress("Verschlüsselung läuft...")
                
                input_path = self.current_file
                output_path = input_path + '.encrypted'
                
                password = self.password_entry.get()
                
                self.log(f"🔒 Beginn der Verschlüsselung: {Path(input_path).name}")
                
                if self.use_key_var.get() and self.current_key_file:
                    # Externer Schlüsselmodus
                    self.log(f"🗝️  Verwende Schlüsseldatei: {Path(self.current_key_file).name}")
                    
                    # Schlüssel laden
                    encryption_key = self.key_manager.load_key_from_file(self.current_key_file, password)
                    
                    # Mit Schlüssel verschlüsseln
                    success = self.crypto_manager.encrypt_with_key(input_path, output_path, encryption_key)
                    
                else:
                    # Passwortmodus
                    self.log("🔑 Passwortmodus (Schlüsselableitung)")
                    success = self.crypto_manager.encrypt_file_v2(input_path, output_path, password)
                
                if success:
                    output_size = Path(output_path).stat().st_size
                    mode = "mit externem Schlüssel" if (self.use_key_var.get() and self.current_key_file) else "mit Passwort"
                    self.log(f"✅ Verschlüsselung erfolgreich! ({mode})")
                    self.log(f"📦 Größe: {self.format_file_size(output_size)}")
                    
                    messagebox.showinfo("Erfolg", 
                                      f"Datei erfolgreich verschlüsselt!\n\n"
                                      f"📁 Datei: {Path(output_path).name}\n"
                                      f"📏 Größe: {self.format_file_size(output_size)}\n"
                                      f"🔐 Modus: {mode}")
                else:
                    self.log("❌ Verschlüsselung fehlgeschlagen")
                    messagebox.showerror("Fehler", "Verschlüsselung fehlgeschlagen. Datei überprüfen und erneut versuchen.")
                    
            except Exception as e:
                error_msg = f"Fehler bei der Verschlüsselung: {str(e)}"
                self.log(f"💥 {error_msg}")
                messagebox.showerror("Fehler", error_msg)
            finally:
                self.hide_progress()
        
        threading.Thread(target=encrypt_thread, daemon=True).start()
    
    def decrypt_file(self):
        """Entschlüsselt die ausgewählte Datei"""
        if not self.validate_inputs():
            return
        
        def decrypt_thread():
            try:
                self.show_progress("Entschlüsselung läuft...")
                
                input_path = self.current_file
                password = self.password_entry.get()
                
                if input_path.endswith('.encrypted'):
                    output_path = input_path[:-10]  # Entfernt .encrypted
                else:
                    output_path = input_path + '.decrypted'
                
                self.log(f"🔓 Beginn der Entschlüsselung: {Path(input_path).name}")
                
                # Dateiformat erkennen
                format_type = self.crypto_manager.detect_file_format(input_path)
                
                success = False
                
                if format_type == 'key_encrypted':
                    # Mit Schlüssel verschlüsselte Datei
                    if self.use_key_var.get() and self.current_key_file:
                        self.log(f"🗝️  KENC-Format erkannt - verwende Schlüsseldatei")
                        
                        # Schlüssel laden
                        decryption_key = self.key_manager.load_key_from_file(self.current_key_file, password)
                        
                        # Mit Schlüssel entschlüsseln
                        success = self.crypto_manager.decrypt_with_key(input_path, output_path, decryption_key)
                        
                        if not success:
                            self.log("❌ Fehlgeschlagen - Falsches Passwort oder Schlüssel?")
                    else:
                        self.log("❌ Mit Schlüssel verschlüsselt - Bitte Schlüsseldatei wählen")
                        messagebox.showerror("Fehler", 
                                           "Diese Datei wurde mit einem Schlüssel verschlüsselt.\n\n"
                                           "Bitte:\n"
                                           "1. 'Schlüsseldatei verwenden' aktivieren\n"
                                           "2. Richtige Schlüsseldatei wählen\n"
                                           "3. Schlüsselpasswort eingeben")
                        return
                
                elif format_type == 'password_encrypted':
                    # Mit Passwort verschlüsselte Datei
                    self.log("🔑 FENC-Format erkannt - Entschlüsselung mit Passwort")
                    success = self.crypto_manager.decrypt_file_v2(input_path, output_path, password)
                
                else:
                    # Unbekanntes Format, automatischer Versuch
                    self.log("🔄 Unbekanntes Format - automatischer Versuch")
                    success = self.crypto_manager.decrypt_file_auto(input_path, output_path, password)
                
                if success and os.path.exists(output_path):
                    output_size = Path(output_path).stat().st_size
                    self.log(f"✅ Entschlüsselung erfolgreich!")
                    self.log(f"📦 Größe: {self.format_file_size(output_size)}")
                    
                    messagebox.showinfo("Erfolg", 
                                      f"Datei erfolgreich entschlüsselt!\n\n"
                                      f"📁 Datei: {Path(output_path).name}\n"
                                      f"📏 Größe: {self.format_file_size(output_size)}")
                else:
                    self.log("❌ Entschlüsselung fehlgeschlagen")
                    messagebox.showerror("Fehler", 
                                       "Entschlüsselung fehlgeschlagen.\n\n"
                                       "Mögliche Gründe:\n"
                                       "• Falsches Passwort\n"
                                       "• Falscher Schlüssel\n"
                                       "• Beschädigte Datei\n"
                                       "• Nicht unterstütztes Format")
                
            except Exception as e:
                error_msg = f"Fehler bei der Entschlüsselung: {str(e)}"
                self.log(f"💥 {error_msg}")
                messagebox.showerror("Fehler", error_msg)
            finally:
                self.hide_progress()
        
        threading.Thread(target=decrypt_thread, daemon=True).start()
    
    def validate_inputs(self):
        """Validiert Benutzereingaben"""
        if not self.current_file:
            messagebox.showwarning("Hinweis", "Bitte wählen Sie eine Datei")
            return False
        
        password = self.password_entry.get()
        confirm = self.confirm_entry.get()
        
        if not password:
            messagebox.showwarning("Hinweis", "Bitte geben Sie ein Passwort ein")
            return False
        
        if password != confirm:
            messagebox.showwarning("Hinweis", "Passwörter stimmen nicht überein")
            return False
        
        if len(password) < 4:
            messagebox.showwarning("Hinweis", "Passwort muss mindestens 4 Zeichen lang sein")
            return False
        
        # Schlüsseldatei-Überprüfung wenn aktiviert
        if self.use_key_var.get() and not self.current_key_file:
            messagebox.showwarning("Hinweis", "Bitte wählen Sie eine Schlüsseldatei")
            return False
        
        return True
    
    def show_progress(self, message):
        """Zeigt Fortschrittsbalken"""
        self.progress_frame.grid()
        self.progress.start()
        self.progress_label.config(text=message)
    
    def hide_progress(self):
        """Versteckt Fortschrittsbalken"""
        self.progress.stop()
        self.progress_frame.grid_remove()
        self.progress_label.config(text="")
    
    def log(self, message):
        """Fügt Nachricht zum Protokoll hinzu"""
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
    
    def clear_log(self):
        """Löscht das Protokoll"""
        self.log_text.delete(1.0, tk.END)
        self.log("🗑️ Protokoll gelöscht")
    
    def copy_log(self):
        """Kopiert Protokoll in Zwischenablage"""
        log_content = self.log_text.get(1.0, tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(log_content)
        self.log("📋 Protokoll in Zwischenablage kopiert")
    
    def format_file_size(self, size_bytes):
        """Formatiert Dateigröße in lesbare Einheiten"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"

def run_gui():
    """Startet die grafische Oberfläche"""
    try:
        root = tk.Tk()
        app = CryptoFileApp(root)
        root.mainloop()
    except Exception as e:
        print(f"❌ Fehler beim Start der Oberfläche: {e}")

if __name__ == "__main__":
    run_gui()