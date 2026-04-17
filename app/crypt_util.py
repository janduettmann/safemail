import hashlib
import base64
from cryptography.fernet import Fernet
import secrets
from typing import Any

def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from a password and salt using PBKDF2-HMAC-SHA256.

    Args:
        password: The user's raw password bytes.
        salt: Random salt bytes for key derivation.

    Returns:
        A URL-safe base64-encoded 32-byte key suitable for Fernet.
    """
    key = hashlib.pbkdf2_hmac(hash_name="sha256", password=password, salt=salt, iterations=600_000)
    return base64.urlsafe_b64encode(key)

def generate_salt() -> bytes:
    """Generate a cryptographically secure 16-byte random salt."""
    return secrets.token_bytes(16)

def generate_data_key() -> bytes:
    """Generate a new random Fernet data key for encrypting user data."""
    return Fernet.generate_key() 

def encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt data using Fernet symmetric encryption.

    Args:
        data: The plaintext bytes to encrypt.
        key: Fernet key bytes.

    Returns:
        The encrypted ciphertext bytes.
    """
    fn: Fernet = Fernet(key=key)
    return fn.encrypt(data=data)

def decrypt(chiffre: bytes, key: bytes) -> Any:
    """Decrypt Fernet-encrypted ciphertext.

    Args:
        chiffre: The encrypted ciphertext bytes.
        key: Fernet key bytes.

    Returns:
        The decrypted plaintext bytes.
    """
    fn: Fernet = Fernet(key=key)
    return fn.decrypt(token=chiffre)
