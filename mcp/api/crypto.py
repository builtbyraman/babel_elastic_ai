"""
AES-GCM encryption for secret values stored in Postgres.

Key material comes from the SECRETS_KEY env var (base64-encoded 32 bytes).
Generate with: python -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"

In dev with no SECRETS_KEY set, uses a zero-byte key with a startup warning.
"""

import base64
import json
import logging
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

_NONCE_LEN = 12


def _key() -> bytes:
    raw = os.getenv('SECRETS_KEY', '')
    if not raw:
        logger.warning('SECRETS_KEY not set — using insecure dev key. Set this in production.')
        return b'\x00' * 32
    return base64.b64decode(raw)


def encrypt(data: dict) -> str:
    """Encrypt a dict to a base64-encoded nonce||ciphertext string."""
    aesgcm = AESGCM(_key())
    nonce = os.urandom(_NONCE_LEN)
    plaintext = json.dumps(data).encode()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ciphertext).decode()


def decrypt(blob: str) -> dict:
    """Decrypt a base64-encoded nonce||ciphertext string back to a dict."""
    aesgcm = AESGCM(_key())
    raw = base64.b64decode(blob)
    nonce, ciphertext = raw[:_NONCE_LEN], raw[_NONCE_LEN:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext)
