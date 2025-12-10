import click
import os
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel

from src.core.crypto_manager import CryptoManager
from src.core.file_handler import FileHandler

console = Console()


# =====================================================================
# ENCRYPTION COMMAND
# =====================================================================
@click.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--output', '-o', help='Output file path')
@click.option('--key-file', '-k', help='File containing the encryption key')
@click.option('--password', '-p', help='Password used to unlock the key', prompt=True, hide_input=True)
@click.option('--version', '-v', type=click.Choice(['1', '2']), default='2', help='Encryption format version')
def encrypt_file(input_file, output, key_file, password, version):
    """Encrypt a file using AES-256."""
    
    if not output:
        output = input_file + '.encrypted'
    
    try:
        console.print(f"🔒 Starting encryption: {input_file}")
        
        if not FileHandler.validate_file_path(input_file):
            console.print(f"[red]❌ Invalid file: {input_file}[/red]")
            return
        
        crypto_manager = CryptoManager()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            
            task = progress.add_task("Encrypting...", total=None)
            
            # --- Using external key file ---
            if key_file and os.path.exists(key_file):
                console.print(f"🔑 Loading key file: {key_file}")
                
                from src.core.key_manager import KeyManager
                key_manager = KeyManager()
                
                encryption_key = key_manager.load_key_from_file(key_file, password)
                console.print(f"✅ Key loaded ({len(encryption_key)} bytes)")
                
                success = crypto_manager.encrypt_with_key(input_file, output, encryption_key)
            
            # --- Using password-based V2 format ---
            else:
                console.print("🔑 Deriving key from password...")
                success = crypto_manager.encrypt_file_v2(input_file, output, password)
            
            progress.update(task, completed=100)

        if success and os.path.exists(output):
            console.print(Panel.fit(
                f"[green]✅ Encryption successful![/green]\n"
                f"Input: {input_file}\n"
                f"Output: {output}",
                title="Result"
            ))
        else:
            console.print("[red]❌ Encryption failed[/red]")
        
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")


# =====================================================================
# DECRYPTION COMMAND
# =====================================================================
@click.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--output', '-o', help='Output file path')
@click.option('--key-file', '-k', help='File containing the decryption key')
@click.option('--password', '-p', help='Password used to unlock the key', prompt=True, hide_input=True)
@click.option('--auto', '-a', is_flag=True, help='Automatically detects the format')
def decrypt_file(input_file, output, key_file, password, auto):
    """Decrypt a file using AES-256."""
    
    if not output:
        output = input_file[:-10] if input_file.endswith('.encrypted') else input_file + '.decrypted'
    
    try:
        console.print(f"🔓 Starting decryption: {input_file}")
        
        if not FileHandler.validate_file_path(input_file):
            console.print(f"[red]❌ Invalid file: {input_file}[/red]")
            return
        
        crypto_manager = CryptoManager()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            
            task = progress.add_task("Decrypting...", total=None)
            
            # --- Using key file ---
            if key_file and os.path.exists(key_file):
                console.print(f"🔑 Loading key file: {key_file}")
                
                from src.core.key_manager import KeyManager
                key_manager = KeyManager()
                
                decryption_key = key_manager.load_key_from_file(key_file, password)
                console.print(f"✅ Key loaded ({len(decryption_key)} bytes)")
                
                success = crypto_manager.decrypt_with_key(input_file, output, decryption_key)

                if not success and auto:
                    console.print("[yellow]🔄 Trying automatic detection...[/yellow]")
                    success = crypto_manager.decrypt_file_auto(input_file, output, password)
            
            # --- Using password-based methods ---
            else:
                success = (
                    crypto_manager.decrypt_file_auto(input_file, output, password)
                    if auto
                    else crypto_manager.decrypt_file_v2(input_file, output, password)
                )

                if not success and not auto:
                    console.print("[yellow]🔄 Trying automatic detection...[/yellow]")
                    success = crypto_manager.decrypt_file_auto(input_file, output, password)
            
            progress.update(task, completed=100)
        
        if success and os.path.exists(output):
            console.print(Panel.fit(
                f"[green]✅ Decryption successful![/green]\n"
                f"Output: {output}",
                title="Result"
            ))
        else:
            console.print("[red]❌ Decryption failed[/red]")
            if key_file:
                console.print("[yellow]💡 Incorrect key or password[/yellow]")
            else:
                console.print("[yellow]💡 Try using --auto for format detection[/yellow]")
        
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")


# =====================================================================
# KEY GENERATION COMMAND
# =====================================================================
@click.command()
@click.option('--output', '-o', help='Output key filename', required=True)
@click.option('--password', '-p', prompt=True, hide_input=True, confirmation_prompt=True, help='Password to protect the key')
@click.option('--strength', '-s', type=click.Choice(['medium', 'high', 'maximum']), default='high', help='Security level')
def generate_key(output, password, strength):
    """Generate a new AES-256 key and save it securely."""
    
    try:
        from src.core.key_manager import KeyManager
        
        key_manager = KeyManager()
        key = key_manager.generate_secure_key()
        key_manager.save_key_to_file(key, output, password)

        console.print(Panel.fit(
            f"[green]✅ Key generated and saved successfully![/green]\n"
            f"File: {output}\n"
            f"Size: 256 bits\n"
            f"Security: {strength}\n"
            f"Password protected: YES",
            title="Key Generation"
        ))

        console.print("\n[yellow]Usage:[/yellow]")
        console.print(f"  Encrypt: python main.py encrypt file.txt -k {output} -p YOUR_PASSWORD")
        console.print(f"  Decrypt: python main.py decrypt file.txt.encrypted -k {output} -p YOUR_PASSWORD")

        console.print("\n[red]⚠️ WARNING:[/red] Losing the key file or its password makes decryption impossible.")

    except Exception as e:
        console.print(f"[red]❌ Key generation error: {e}[/red]")