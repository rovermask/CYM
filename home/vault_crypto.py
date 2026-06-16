"""
Vault Encryption Helpers — CryptYourMind
=========================================
Key derivation:
    Each user has a random 256-bit salt stored in UserVaultProfile (created
    automatically via post_save signal on User creation).

    Fernet key = HMAC-SHA256( settings.SECRET_KEY, salt + ":" + str(user_id) )
    → urlsafe-base64 encoded (32 bytes → 44-char Fernet key)

Why HMAC + random salt:
    • Unique per user  — one leaked key cannot decrypt another user's data.
    • Salt never transmitted — only stored server-side in the DB.
    • Deterministic re-derivation — no need to store the raw key.
    • Key fingerprint (first 8 hex chars of salt) shown to users for
      awareness — demonstrates the cryptographic key concept educationally.

Disclosure shown in the UI:
    "Notes are encrypted at rest with AES-128 (Fernet). Because the key is
     derived server-side, an admin with DB + SECRET_KEY access could
     theoretically decrypt your notes. This is the server-side model —
     suitable for a learning platform, not for storing highly sensitive data."
"""

import hmac
import hashlib
import base64

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings


def _get_salt(user_id: int) -> str:
    """Fetch the user's salt from UserVaultProfile. Raises if missing."""
    # Import here to avoid circular imports at module load
    from home.models import UserVaultProfile
    profile = UserVaultProfile.objects.get(user_id=user_id)
    return profile.salt


def _derive_key(user_id: int) -> bytes:
    """
    Derive a 32-byte Fernet key:
        HMAC-SHA256( SECRET_KEY, "<salt>:<user_id>" )
    """
    salt    = _get_salt(user_id)
    secret  = settings.SECRET_KEY.encode('utf-8')
    message = f"{salt}:{user_id}".encode('utf-8')
    digest  = hmac.new(secret, message, hashlib.sha256).digest()   # 32 bytes
    return base64.urlsafe_b64encode(digest)                         # Fernet requires urlsafe b64


def encrypt(user_id: int, plaintext: str) -> str:
    """Encrypt plaintext string → Fernet token string."""
    f = Fernet(_derive_key(user_id))
    return f.encrypt(plaintext.encode('utf-8')).decode('utf-8')


def decrypt(user_id: int, token: str) -> str:
    """Decrypt Fernet token string → plaintext. Raises InvalidToken on failure."""
    f = Fernet(_derive_key(user_id))
    return f.decrypt(token.encode('utf-8')).decode('utf-8')


def get_key_fingerprint(user_id: int) -> str:
    """Return first 8 uppercase hex chars of the salt — shown in the UI."""
    salt = _get_salt(user_id)
    return salt[:8].upper()