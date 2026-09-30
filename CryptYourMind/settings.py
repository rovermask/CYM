"""
Django settings for CryptYourMind.

No SQL database: identity is Firebase Auth, data is Firestore (see home/backends.py).
Configuration comes from environment variables; for local work copy `.env.example` to `.env`.
"""

import json
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv(path):
    """Tiny .env reader (KEY=VALUE per line) so no extra dependency is needed."""
    if not path.exists():
        return
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_dotenv(BASE_DIR / '.env')

# NOTE: vault entries are encrypted with keys derived from this value. Changing it makes
# existing entries undecryptable, so set DJANGO_SECRET_KEY in production and never rotate it lightly.
SECRET_KEY = os.environ.get(
    'DJANGO_SECRET_KEY',
    'django-insecure-2au^2k^49(_ds%%id0jbc%%4sjj!cj-ei*_sje)-eje6fx^$*m',
)

# On Vercel debug is off by default; locally it is on. Override with DJANGO_DEBUG=0/1.
ON_VERCEL = bool(os.environ.get('VERCEL'))
DEBUG = os.environ.get('DJANGO_DEBUG', '0' if ON_VERCEL else '1') == '1'

# Custom domains: set DJANGO_ALLOWED_HOSTS="example.com,www.example.com" (comma-separated).
_extra_hosts = [h.strip() for h in os.environ.get('DJANGO_ALLOWED_HOSTS', '').split(',') if h.strip()]
ALLOWED_HOSTS = [".vercel.app", "127.0.0.1", "localhost", "[::1]"] + _extra_hosts
CSRF_TRUSTED_ORIGINS = ["https://*.vercel.app"] + [f"https://{h.lstrip('.')}" for h in _extra_hosts]

# Vercel terminates TLS at its proxy.
if ON_VERCEL:
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")


# ── Firebase ──────────────────────────────────────────────────────────────────
# 'firebase' (default) or 'memory' (tests / offline UI work; only honoured with DEBUG or in tests).
CYM_BACKEND = os.environ.get('CYM_BACKEND', 'firebase')

# Public web config from Firebase console → Project settings → Your apps → Web app.
# Provide as one JSON object in FIREBASE_WEB_CONFIG.
try:
    FIREBASE_WEB_CONFIG = json.loads(os.environ.get('FIREBASE_WEB_CONFIG', '') or 'null')
except ValueError:
    FIREBASE_WEB_CONFIG = None


# ── Application definition ────────────────────────────────────────────────────

INSTALLED_APPS = [
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'home',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'CryptYourMind.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, "templates")],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.messages.context_processors.messages',
                'home.context.vault_user',
                'home.context.firebase_config',
            ],
        },
    },
]

WSGI_APPLICATION = 'CryptYourMind.wsgi.application'

# No SQL database is used.
DATABASES = {}

# Sessions live in a signed cookie, so nothing is stored server-side.
SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'
SESSION_COOKIE_AGE = 60 * 60 * 12          # 12 hours
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
MESSAGE_STORAGE = 'django.contrib.messages.storage.cookie.CookieStorage'


# ── Internationalization ──────────────────────────────────────────────────────

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True


# ── Static files ──────────────────────────────────────────────────────────────

STATIC_URL = 'static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_DIRS = [os.path.join(BASE_DIR, "static")]
# Templates reference /static/... directly, so no hashed-manifest storage (it needs collectstatic
# and breaks lookups otherwise). WhiteNoise serves straight from STATICFILES_DIRS.
STATICFILES_STORAGE = 'whitenoise.storage.CompressedStaticFilesStorage'
WHITENOISE_USE_FINDERS = True

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
