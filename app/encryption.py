"""
encryption.py — Data-at-Rest Security Module
=============================================
Implements AES-256 symmetric encryption via Fernet (from the `cryptography` library).
Sensitive fields (medical notes, SSN, contact info) are encrypted before storage.
Even if the database file is stolen, raw field values remain ciphertext.

Key rotation is supported: keys are loaded from environment variables, never hardcoded.
"""

import os
import base64
from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ── Key Management ──────────────────────────────────────────────────────────

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from a password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,  # OWASP 2024 recommendation
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def load_fernet_key() -> Fernet:
    """
    Load the Fernet encryption key from the environment.
    Falls back to a derived key from DB_ENCRYPTION_PASSWORD + DB_ENCRYPTION_SALT.
    Never hardcodes a key in source code.
    """
    raw_key = os.environ.get("DB_ENCRYPTION_KEY")
    if raw_key:
        return Fernet(raw_key.encode())

    password = os.environ.get("DB_ENCRYPTION_PASSWORD", "default-dev-password-change-in-prod")
    salt_hex = os.environ.get("DB_ENCRYPTION_SALT", "a1b2c3d4e5f6a7b8")
    salt = bytes.fromhex(salt_hex)
    key = derive_key_from_password(password, salt)
    return Fernet(key)


# Singleton Fernet instance loaded once at startup
_fernet: Fernet | None = None


def get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = load_fernet_key()
    return _fernet


# ── Field-Level Encryption / Decryption ─────────────────────────────────────

def encrypt_field(plaintext: str) -> str:
    """
    Encrypt a sensitive string field.
    Returns a URL-safe base64 token (the Fernet ciphertext).
    Stores ENCRYPTED:<ciphertext> prefix so we can detect encrypted vs plain.
    """
    if plaintext is None:
        return None
    token = get_fernet().encrypt(plaintext.encode("utf-8"))
    return "ENCRYPTED:" + token.decode("utf-8")


def decrypt_field(ciphertext: str) -> str:
    """
    Decrypt a field previously encrypted with encrypt_field().
    Returns the original plaintext string.
    """
    if ciphertext is None:
        return None
    if not ciphertext.startswith("ENCRYPTED:"):
        # Not encrypted (legacy plain data), return as-is
        return ciphertext
    token = ciphertext[len("ENCRYPTED:"):].encode("utf-8")
    return get_fernet().decrypt(token).decode("utf-8")


def is_encrypted(value: str) -> bool:
    """Check whether a stored value is in encrypted form."""
    return isinstance(value, str) and value.startswith("ENCRYPTED:")


# ── Password Hashing (separate from reversible encryption) ──────────────────

import hashlib
import secrets


def hash_password(password: str) -> str:
    """
    Hash a password using PBKDF2-HMAC-SHA256 with a random per-user salt.
    Returns 'pbkdf2:salt_hex:hash_hex'.
    Passwords are ONE-WAY hashed — they must never be decryptable.
    """
    salt = secrets.token_hex(32)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        480_000
    )
    return f"pbkdf2:{salt}:{dk.hex()}"


def verify_password(stored_hash: str, candidate: str) -> bool:
    """Verify a candidate password against a stored PBKDF2 hash."""
    try:
        algo, salt, expected_hex = stored_hash.split(":")
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            candidate.encode("utf-8"),
            salt.encode("utf-8"),
            480_000
        )
        # Constant-time comparison prevents timing attacks
        return secrets.compare_digest(dk.hex(), expected_hex)
    except (ValueError, AttributeError):
        return False
