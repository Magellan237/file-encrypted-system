import click
import os
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich.table import Table

from src.core.crypto import AESCipher
from src.core.key_manager import KeyManager
from src.core.file_handler import FileHandler

console = Console()

@click.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--output', '-o', help='Fichier de sortie')
@click.option('--key-file', '-k', help='Fichier contenant la clé')
@click.option('--password', '-p', help='Mot de passe pour dériver la clé', prompt=True, hide_input=True)
def encrypt_file(input_file, output, key_file, password):
    """Chiffre un fichier avec AES-256"""
    
    if not output:
        output = input_file + '.encrypted'
    
    try:
        # Validation du fichier d'entrée
        if not FileHandler.validate_file_path(input_file):
            console.print(f"[red]❌ Fichier d'entrée invalide: {input_file}[/red]")
            return
        
        # Gestion de la clé
        key_manager = KeyManager()
        
        if key_file:
            # Chargement de la clé depuis un fichier
            key = key_manager.load_key_from_file(key_file, password)
        else:
            # Dérivation de la clé depuis le mot de passe
            key, _, _ = key_manager.derive_key_from_password(password)
        
        # Chiffrement
        cipher = AESCipher()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            
            task = progress.add_task("Chiffrement en cours...", total=100)
            
            # Création de sauvegarde
            backup_path = FileHandler.create_backup(input_file)
            if backup_path:
                console.print(f"[yellow]📂 Sauvegarde créée: {backup_path}[/yellow]")
            
            # Chiffrement du fichier
            cipher.encrypt_file(input_file, output, key)
            
            progress.update(task, completed=100)
        
        # Calcul des hashs
        original_hash = FileHandler.get_file_hash(input_file)
        encrypted_hash = FileHandler.get_file_hash(output)
        
        # Affichage des résultats
        table = Table(title="Résultats du Chiffrement")
        table.add_column("Paramètre", style="cyan")
        table.add_column("Valeur", style="white")
        
        table.add_row("Fichier source", input_file)
        table.add_row("Fichier chiffré", output)
        table.add_row("Hash original", original_hash)
        table.add_row("Hash chiffré", encrypted_hash)
        table.add_row("Taille clé", "256 bits (AES-256)")
        
        console.print(table)
        console.print("[green]✅ Chiffrement terminé avec succès![/green]")
        
    except Exception as e:
        console.print(f"[red]❌ Erreur lors du chiffrement: {str(e)}[/red]")

@click.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--output', '-o', help='Fichier de sortie')
@click.option('--key-file', '-k', help='Fichier contenant la clé')
@click.option('--password', '-p', help='Mot de passe pour dériver la clé', prompt=True, hide_input=True)
def decrypt_file(input_file, output, key_file, password):
    """Déchiffre un fichier avec AES-256"""
    
    if not output:
        if input_file.endswith('.encrypted'):
            output = input_file[:-10]  # Retire '.encrypted'
        else:
            output = input_file + '.decrypted'
    
    try:
        # Validation du fichier d'entrée
        if not FileHandler.validate_file_path(input_file):
            console.print(f"[red]❌ Fichier d'entrée invalide: {input_file}[/red]")
            return
        
        # Gestion de la clé
        key_manager = KeyManager()
        
        if key_file:
            # Chargement de la clé depuis un fichier
            key = key_manager.load_key_from_file(key_file, password)
        else:
            # Dérivation de la clé depuis le mot de passe
            key, _, _ = key_manager.derive_key_from_password(password)
        
        # Déchiffrement
        cipher = AESCipher()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            
            task = progress.add_task("Déchiffrement en cours...", total=100)
            cipher.decrypt_file(input_file, output, key)
            progress.update(task, completed=100)
        
        console.print(f"[green]✅ Déchiffrement terminé: {output}[/green]")
        
    except Exception as e:
        console.print(f"[red]❌ Erreur lors du déchiffrement: {str(e)}[/red]")

@click.command()
@click.option('--output', '-o', help='Fichier de sortie pour la clé', required=True)
@click.option('--password', '-p', help='Mot de passe pour protéger la clé', prompt=True, hide_input=True, confirmation_prompt=True)
def generate_key(output, password):
    """Génère une nouvelle clé sécurisée et la sauvegarde"""
    
    try:
        key_manager = KeyManager()
        
        # Génération d'une clé sécurisée
        key = key_manager.generate_secure_key()
        
        # Sauvegarde de la clé
        key_manager.save_key_to_file(key, output, password)
        
        console.print(Panel.fit(
            f"[green]✅ Clé générée et sauvegardée avec succès!\n"
            f"Fichier: {output}\n"
            f"Taille: 256 bits\n"
            f"Algorithme: AES-256[/green]",
            title="Génération de Clé"
        ))
        
    except Exception as e:
        console.print(f"[red]❌ Erreur lors de la génération de la clé: {str(e)}[/red]")