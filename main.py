#!/usr/bin/env python3
"""
File Encryption System with Key Management
AES-256 with Argon2 for key derivation
"""

import click
from rich.console import Console
from rich.panel import Panel

from src.cli.commands import encrypt_file, decrypt_file, generate_key

console = Console()

@click.group()
@click.version_option(version="1.0.0")
def cli():
    """🔐 File Encryption System - AES-256 with Argon2"""
    pass

# Adding commands
cli.add_command(encrypt_file, name="encrypt")
cli.add_command(decrypt_file, name="decrypt") 
cli.add_command(generate_key, name="generate-key")

if __name__ == "__main__":
    console.print(Panel.fit(
        "🔐 AES-256 File Encryption System with Secure Key Management",
        style="bold blue"
    ))
    cli()