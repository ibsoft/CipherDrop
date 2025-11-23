import json
import secrets
from pathlib import Path
from typing import Any, Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto_utils import load_master_key

CONFIG_PATH = Path("config/encrypted_config.bin")
DEFAULT_CONFIG = {
    "max_upload_mb": 5,
    "allowed_mime_types": [
        "text/plain",
        "application/json",
        "application/pdf",
        "image/png",
        "image/jpeg",
        "application/octet-stream",
    ],
    "blocked_extensions": [
        "exe",
        "bat",
        "cmd",
        "sh",
        "ps1",
        "js",
        "msi",
        "vbs",
        "jar",
        "dll",
        "html",
        "php",
    ],
}


def _encrypt_config(payload: Dict[str, Any], key: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    cipher = AESGCM(key)
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ciphertext = cipher.encrypt(nonce, raw, None)
    return nonce + ciphertext


def _decrypt_config(blob: bytes, key: bytes) -> Dict[str, Any]:
    if len(blob) < 13:
        raise RuntimeError("Encrypted config file is too small or corrupted")
    nonce, ciphertext = blob[:12], blob[12:]
    cipher = AESGCM(key)
    decoded = cipher.decrypt(nonce, ciphertext, None)
    return json.loads(decoded.decode("utf-8"))


def load_secure_config() -> Dict[str, Any]:
    """Decrypt the local config file, creating a default encrypted version if missing."""
    key = load_master_key("CONFIG_MASTER_KEY")
    if not CONFIG_PATH.exists():
        encrypted = _encrypt_config(DEFAULT_CONFIG, key)
        CONFIG_PATH.write_bytes(encrypted)
    blob = CONFIG_PATH.read_bytes()
    return _decrypt_config(blob, key)
