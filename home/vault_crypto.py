"""
Vault encryption helpers — CryptYourMind
========================================
Each user has a random 256-bit salt stored in their Firestore profile
(created on first sign-in).

    Fernet key = HMAC-SHA256( settings.SECRET_KEY, "<salt>:<uid>" )  → urlsafe-base64

• Unique per user — one leaked key cannot decrypt another user's data.
• The salt is never sent to the browser; only a short fingerprint is shown.
• Notes are encrypted at rest with AES-128 (Fernet). Because the key is derived
  server-side, an operator with database + SECRET_KEY access could decrypt them —
  suitable for a learning platform, not for highly sensitive secrets.
"""

import base64
import hashlib
import hmac

from cryptography.fernet import Fernet
from django.conf import settings


def _key(uid: str, salt: str) -> bytes:
    digest = hmac.new(settings.SECRET_KEY.encode(), f"{salt}:{uid}".encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt(uid: str, salt: str, plaintext: str) -> str:
    return Fernet(_key(uid, salt)).encrypt(plaintext.encode()).decode()


def decrypt(uid: str, salt: str, token: str) -> str:
    """Raises cryptography.fernet.InvalidToken on failure."""
    return Fernet(_key(uid, salt)).decrypt(token.encode()).decode()


def fingerprint(salt: str) -> str:
    return salt[:8].upper()
