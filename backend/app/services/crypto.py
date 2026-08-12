"""
ERROR-PANEL — Encryption Service.
Handles encryption and decryption of backups using Fernet (symmetric authenticated cryptography).
"""
import os
from cryptography.fernet import Fernet
from backend.core.paths import DATA_DIR

KEY_FILE = DATA_DIR / "secret.key"

def get_or_create_key() -> bytes:
    """Load the encryption key, or generate a new one if it doesn't exist."""
    if not KEY_FILE.exists():
        key = Fernet.generate_key()
        KEY_FILE.write_bytes(key)
    return KEY_FILE.read_bytes()

def encrypt_data(data: bytes) -> bytes:
    """Encrypt binary data."""
    f = Fernet(get_or_create_key())
    return f.encrypt(data)

def decrypt_data(data: bytes) -> bytes:
    """Decrypt binary data."""
    f = Fernet(get_or_create_key())
    return f.decrypt(data)
