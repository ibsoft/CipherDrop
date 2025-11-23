import base64
import os
import secrets
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def load_master_key(env_var: str) -> bytes:
    """Load and decode a base64-encoded 32-byte key from an environment variable."""
    encoded = os.getenv(env_var)
    if not encoded:
        raise RuntimeError(f"{env_var} is not set; refusing to start without encryption key")
    try:
        key = base64.urlsafe_b64decode(encoded)
    except Exception as exc:
        raise RuntimeError(f"{env_var} is not valid base64") from exc
    if len(key) != 32:
        raise RuntimeError(f"{env_var} must decode to 32 bytes (256-bit AES key)")
    return key


def generate_data_key() -> bytes:
    return secrets.token_bytes(32)


def encrypt_payload(plaintext: bytes, data_key: bytes) -> Tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)
    cipher = AESGCM(data_key)
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    return ciphertext, nonce


def decrypt_payload(ciphertext: bytes, nonce: bytes, data_key: bytes) -> bytes:
    cipher = AESGCM(data_key)
    return cipher.decrypt(nonce, ciphertext, None)


def wrap_key(data_key: bytes, master_key: bytes) -> Tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)
    cipher = AESGCM(master_key)
    wrapped = cipher.encrypt(nonce, data_key, None)
    return wrapped, nonce


def unwrap_key(wrapped: bytes, nonce: bytes, master_key: bytes) -> bytes:
    cipher = AESGCM(master_key)
    return cipher.decrypt(nonce, wrapped, None)
