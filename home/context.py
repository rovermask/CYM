import json

from django.conf import settings


class SessionUser:
    """Lightweight stand-in for request.user, backed by the signed session cookie."""

    def __init__(self, data):
        data = data or {}
        self.uid = data.get('uid')
        self.email = data.get('email', '')
        self.username = data.get('username') or (self.email.split('@')[0] if self.email else '')
        self.is_admin = bool(data.get('is_admin'))
        self.is_authenticated = bool(self.uid)


def vault_user(request):
    user = SessionUser(request.session.get('vault_user'))
    request.vault_user = user
    return {'user': user}


def firebase_config(request):
    cfg = getattr(settings, 'FIREBASE_WEB_CONFIG', None)
    return {'firebase_web_config': cfg, 'firebase_configured': bool(cfg and cfg.get('apiKey'))}
