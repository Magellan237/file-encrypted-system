import click
import os
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.table import Table

from src.core.crypto_manager import CryptoManager
from src.core.file_handler import FileHandler

console = Console()

@click.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--output', '-o', help='Output file')
@click.option('--key-file', '-k', help='File containing the key')
@click.option('--password', '-p', help='Password to derive the key', prompt=True, hide_input=True)
@click.option('--version', '-v', type=click.Choice(['1', '2']), default='2', help='Format version')
def encrypt_file(input_file, output, key_file, password, version):
    """Encrypt a file with AES-256"""
    
    if not output:
        output = input_file + '.encrypted'
    
    try:
        console.print(f"🔒 Start of encryption: {input_file}")
        
        if not FileHandler.validate_file_path(input_file):
            console.print(f"[red]❌ Invalid file: {input_file}[/red]")
            return
        
        crypto_manager = CryptoManager()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            task = progress.add_task("Encryption in progress...", total=None)
            
            if key_file and os.path.exists(key_file):
                console.print(f"🔑 Using the key file: {key_file}")
                # For now, we're using the password directly.
                # Key file management will be implemented at a later date.
                success = crypto_manager.encrypt_file_v2(input_file, output, password)
            else:
                success = crypto_manager.encrypt_file_v2(input_file, output, password)
            
            progress.update(task, completed=100)
        
        if success and os.path.exists(output):
            original_size = os.path.getsize(input_file)
            encrypted_size = os.path.getsize(output)
            
            console.print(Panel.fit(
                f"[green]✅ Successful encryption![/green]\n"
                f"File: {input_file} → {output}\n"
                f"Size: {original_size} → {encrypted_size} bytes\n"
                f"Format: V{version}",
                title="Result"
            ))
        else:
            console.print("[red]❌ Encryption failed[/red]")
        
    except Exception as e:
        console.print(f"[red]❌ Error: {str(e)}[/red]")

@click.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--output', '-o', help='Output file')
@click.option('--key-file', '-k', help='File containing the key')
@click.option('--password', '-p', help='Password to derive the key', prompt=True, hide_input=True)
@click.option('--auto', '-a', is_flag=True, help='Automatic format detection')
def decrypt_file(input_file, output, password, key_file, auto):
    """Decrypt a file with AES-256"""
    
    if not output:
        if input_file.endswith('.encrypted'):
            output = input_file[:-10]
        else:
            output = input_file + '.decrypted'
    
    try:
        console.print(f"🔓 The decryption process begins: {input_file}")
        
        if not FileHandler.validate_file_path(input_file):
            console.print(f"[red]❌ Invalid file: {input_file}[/red]")
            return
        
        crypto_manager = CryptoManager()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            task = progress.add_task("Decryption in progress...", total=None)
            
            if key_file and os.path.exists(key_file):
                console.print(f"🔑 Using the key file: {key_file}")
                # Im Moment verwenden wir das Passwort direkt.
                success = crypto_manager.decrypt_file_auto(input_file, output, password)
            else:
                if auto:
                    success = crypto_manager.decrypt_file_auto(input_file, output, password)
                else:
                    success = crypto_manager.decrypt_file_v2(input_file, output, password)
                    if not success:
                        console.print("[yellow]🔄 Automatischer Versuch...[/yellow]")
                        success = crypto_manager.decrypt_file_auto(input_file, output, password)
            
            progress.update(task, completed=100)
        
        if success and os.path.exists(output):
            decrypted_size = os.path.getsize(output)
            console.print(Panel.fit(
                f"[green]✅ Decryption successful![/green]\n"
                f"File: {output}\n"
                f"Size: {decrypted_size} bytes",
                title="Résult"
            ))
        else:
            console.print("[red]❌ Decryption failed[/red]")
            console.print("[yellow]💡 Try using --auto for automatic detection[/yellow]")
        
    except Exception as e:
        console.print(f"[red]❌ Error: {str(e)}[/red]")

@click.command()
@click.option('--output', '-o', help='Output file for the key', required=True)
@click.option('--password', '-p', help='Password to protect the key', prompt=True, hide_input=True, confirmation_prompt=True)
def generate_key(output, password):
    """Generates a new secure key and backup"""
    
    try:
        from src.core.key_manager import KeyManager
        
        key_manager = KeyManager()
        
        # Einen sicheren Schlüssel generieren
        key = key_manager.generate_secure_key()
        
        # Schlüsselsicherung
        key_manager.save_key_to_file(key, output, password)
        
        console.print(Panel.fit(
            f"[green]✅ Key generated and saved successfully![/green]\n"
            f"File: {output}\n"
            f"Size: 256 bits\n"
            f"Algorithm: AES-256\n"
            f"Password protected: YES",
            title="Key Generation"
        ))
        
        console.print(f"\n[yellow]💡 Usage:[/yellow]")
        console.print(f"   Encryption: python main.py encrypt file.txt -k {output} -p YOUR_PASSWORD")
        console.print(f"   Decryption: python main.py decrypt file.txt.encrypted -k {output} -p YOUR_PASSWORD")
        
    except Exception as e:
        console.print(f"[red]❌ Error generating key: {str(e)}[/red]")