"""
CyberGuard — Cryptographic Service
Implements envelope encryption using Fernet (AES-128-CBC + HMAC-SHA256)
as a local KMS stand-in for Phase 1.

Interface is designed to be swapped for AWS KMS or Azure Key Vault:
  - encrypt_token(plaintext, tenant_id) -> EncryptedBlob
  - decrypt_token(blob) -> str

The encrypted ciphertext is stored in the DB. The Fernet key is NEVER stored.
"""
import base64
from dataclasses import dataclass
from cryptography.fernet import Fernet, InvalidToken
from app.config import get_settings

settings = get_settings()


@dataclass
class EncryptedBlob:
    """Represents an encrypted token + its key metadata."""
    ciphertext: str      # Fernet token (URL-safe base64)
    kms_key_id: str      # Logical key identifier (for future KMS lookup)


def _get_fernet() -> Fernet:
    """Instantiate Fernet cipher from the configured key."""
    try:
        return Fernet(settings.fernet_encryption_key.encode())
    except Exception as e:
        raise ValueError(
            "FERNET_ENCRYPTION_KEY is invalid. "
            "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        ) from e


def encrypt_token(plaintext: str, tenant_id: str) -> EncryptedBlob:
    """
    Encrypts a plaintext token (e.g., M365 refresh token).
    
    Args:
        plaintext: The raw token string to encrypt.
        tenant_id: Tenant context (used for audit; will be used for KMS context in Phase 2).
    
    Returns:
        EncryptedBlob with ciphertext and key ID.
    
    Security note:
        The plaintext is held in memory only for the duration of this call.
        Python GC handles cleanup; for hyper-sensitive contexts, use bytearray 
        and explicit zeroing (Phase 2 hardening).
    """
    fernet = _get_fernet()
    token_bytes = plaintext.encode("utf-8")
    ciphertext_bytes = fernet.encrypt(token_bytes)
    ciphertext = ciphertext_bytes.decode("utf-8")
    
    # Explicit cleanup of sensitive data
    del token_bytes
    
    return EncryptedBlob(
        ciphertext=ciphertext,
        kms_key_id=settings.kms_key_id,
    )


def decrypt_token(blob: EncryptedBlob) -> str:
    """
    Decrypts an EncryptedBlob back to plaintext.
    
    Args:
        blob: The EncryptedBlob from the database.
    
    Returns:
        The plaintext token string.
    
    Raises:
        ValueError: If decryption fails (wrong key, tampered ciphertext).
    
    Security note:
        The returned string should be used immediately and not stored.
        Callers are responsible for not logging or persisting the return value.
    """
    fernet = _get_fernet()
    try:
        plaintext_bytes = fernet.decrypt(blob.ciphertext.encode("utf-8"))
        plaintext = plaintext_bytes.decode("utf-8")
        del plaintext_bytes
        return plaintext
    except InvalidToken as e:
        raise ValueError(
            f"Token decryption failed for key_id={blob.kms_key_id}. "
            "The token may be corrupted or the encryption key has changed."
        ) from e
