"""
Storage/auth backends for the Vault and the admin panel.

* FirebaseBackend — production: Firebase Auth (identity, admin claim) + Firestore (data).
* MemoryBackend   — tests / local UI work only (never enabled unless DEBUG or running tests).

Firestore layout
    vault_users/{uid}                      {salt, email, username, created_at}
    vault_users/{uid}/entries/{entry_id}   {title, content_encrypted, created_at, updated_at}

Both backends expose the same small API so views never touch Firebase directly.
"""

import json
import os
import sys
import uuid
from datetime import datetime, timezone

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


class BackendError(Exception):
    """Raised for any auth / storage failure the UI should report politely."""


def _now():
    return datetime.now(timezone.utc)


def _new_salt():
    return os.urandom(32).hex()


# ── Firebase ──────────────────────────────────────────────────────────────────

class FirebaseBackend:
    def __init__(self):
        import firebase_admin
        from firebase_admin import credentials

        if not firebase_admin._apps:
            raw = os.environ.get('FIREBASE_SERVICE_ACCOUNT_JSON')
            path = os.environ.get('FIREBASE_SERVICE_ACCOUNT_FILE')
            if raw:
                cred = credentials.Certificate(json.loads(raw))
            elif path:
                cred = credentials.Certificate(path)
            else:
                raise ImproperlyConfigured(
                    'Set FIREBASE_SERVICE_ACCOUNT_JSON or FIREBASE_SERVICE_ACCOUNT_FILE.')
            firebase_admin.initialize_app(cred)

        from firebase_admin import auth, firestore
        self.auth = auth
        self.db = firestore.client()
        self._firestore = firestore

    # -- auth --
    def verify_token(self, id_token):
        try:
            d = self.auth.verify_id_token(id_token, check_revoked=True)
        except Exception as e:
            raise BackendError('Your sign-in could not be verified. Please try again.') from e
        return {
            'uid': d['uid'],
            'email': d.get('email', ''),
            'name': d.get('name', ''),
            'is_admin': bool(d.get('admin')),
        }

    def is_admin(self, uid):
        try:
            return bool((self.auth.get_user(uid).custom_claims or {}).get('admin'))
        except Exception:
            return False

    def set_admin(self, email, value=True):
        user = self.auth.get_user_by_email(email)
        claims = dict(user.custom_claims or {})
        claims['admin'] = bool(value)
        self.auth.set_custom_user_claims(user.uid, claims)
        return user.uid

    # -- profile --
    def _profile_ref(self, uid):
        return self.db.collection('vault_users').document(uid)

    def get_profile(self, uid, email='', username=''):
        ref = self._profile_ref(uid)
        snap = ref.get()
        if snap.exists:
            return snap.to_dict()
        profile = {'salt': _new_salt(), 'email': email, 'username': username, 'created_at': _now()}
        ref.set(profile)
        return profile

    # -- entries --
    def _entries(self, uid):
        return self._profile_ref(uid).collection('entries')

    def list_entries(self, uid):
        q = self._entries(uid).order_by('updated_at', direction=self._firestore.Query.DESCENDING)
        return [{'id': d.id, **d.to_dict()} for d in q.stream()]

    def get_entry(self, uid, eid):
        snap = self._entries(uid).document(eid).get()
        return {'id': snap.id, **snap.to_dict()} if snap.exists else None

    def create_entry(self, uid, title, content_encrypted):
        now = _now()
        ref = self._entries(uid).document()
        ref.set({'title': title, 'content_encrypted': content_encrypted, 'created_at': now, 'updated_at': now})
        return ref.id

    def update_entry(self, uid, eid, title, content_encrypted):
        self._entries(uid).document(eid).update(
            {'title': title, 'content_encrypted': content_encrypted, 'updated_at': _now()})

    def delete_entry(self, uid, eid):
        self._entries(uid).document(eid).delete()

    def count_entries(self, uid):
        return sum(1 for _ in self._entries(uid).select([]).stream())

    # -- admin --
    def list_users(self):
        users = []
        for u in self.auth.list_users().iterate_all():
            meta = u.user_metadata
            prof = self._profile_ref(u.uid).get()
            users.append({
                'uid': u.uid,
                'email': u.email or '',
                'username': u.display_name or '',
                'disabled': u.disabled,
                'is_admin': bool((u.custom_claims or {}).get('admin')),
                'created_at': datetime.fromtimestamp(meta.creation_timestamp / 1000, timezone.utc)
                              if meta.creation_timestamp else None,
                'last_login': datetime.fromtimestamp(meta.last_sign_in_timestamp / 1000, timezone.utc)
                              if meta.last_sign_in_timestamp else None,
                'entry_count': self.count_entries(u.uid) if prof.exists else 0,
                'key_id': (prof.to_dict().get('salt', '')[:8].upper() if prof.exists else '—'),
            })
        return users

    def set_disabled(self, uid, disabled):
        self.auth.update_user(uid, disabled=bool(disabled))
        if disabled:
            self.auth.revoke_refresh_tokens(uid)

    def delete_user(self, uid):
        for d in self._entries(uid).stream():
            d.reference.delete()
        self._profile_ref(uid).delete()
        self.auth.delete_user(uid)


# ── Memory (tests / offline UI work) ──────────────────────────────────────────

class MemoryBackend:
    """Token format: 'uid|email|name[|admin]'. Data lives in process memory only."""

    def __init__(self):
        self.users = {}     # uid -> dict
        self.profiles = {}  # uid -> dict
        self.entries = {}   # uid -> {eid: dict}

    def verify_token(self, id_token):
        parts = (id_token or '').split('|')
        if len(parts) < 3 or not parts[0]:
            raise BackendError('Your sign-in could not be verified. Please try again.')
        uid, email, name = parts[:3]
        user = self.users.setdefault(uid, {
            'uid': uid, 'email': email, 'username': name, 'disabled': False,
            'is_admin': False, 'created_at': _now(), 'last_login': None})
        if user['disabled']:
            raise BackendError('Your sign-in could not be verified. Please try again.')
        if len(parts) > 3 and parts[3] == 'admin':
            user['is_admin'] = True
        user['last_login'] = _now()
        return {'uid': uid, 'email': email, 'name': name, 'is_admin': user['is_admin']}

    def is_admin(self, uid):
        return bool(self.users.get(uid, {}).get('is_admin'))

    def set_admin(self, email, value=True):
        for u in self.users.values():
            if u['email'] == email:
                u['is_admin'] = bool(value)
                return u['uid']
        raise BackendError('No such user.')

    def get_profile(self, uid, email='', username=''):
        return self.profiles.setdefault(
            uid, {'salt': _new_salt(), 'email': email, 'username': username, 'created_at': _now()})

    def list_entries(self, uid):
        items = [{'id': k, **v} for k, v in self.entries.get(uid, {}).items()]
        return sorted(items, key=lambda e: e['updated_at'], reverse=True)

    def get_entry(self, uid, eid):
        e = self.entries.get(uid, {}).get(eid)
        return {'id': eid, **e} if e else None

    def create_entry(self, uid, title, content_encrypted):
        eid, now = uuid.uuid4().hex[:20], _now()
        self.entries.setdefault(uid, {})[eid] = {
            'title': title, 'content_encrypted': content_encrypted, 'created_at': now, 'updated_at': now}
        return eid

    def update_entry(self, uid, eid, title, content_encrypted):
        self.entries[uid][eid].update(title=title, content_encrypted=content_encrypted, updated_at=_now())

    def delete_entry(self, uid, eid):
        self.entries.get(uid, {}).pop(eid, None)

    def count_entries(self, uid):
        return len(self.entries.get(uid, {}))

    def list_users(self):
        out = []
        for u in self.users.values():
            prof = self.profiles.get(u['uid'])
            out.append({**u, 'entry_count': self.count_entries(u['uid']),
                        'key_id': prof['salt'][:8].upper() if prof else '—'})
        return sorted(out, key=lambda u: u['created_at'], reverse=True)

    def set_disabled(self, uid, disabled):
        self.users[uid]['disabled'] = bool(disabled)

    def delete_user(self, uid):
        self.users.pop(uid, None)
        self.profiles.pop(uid, None)
        self.entries.pop(uid, None)


# ── Factory ───────────────────────────────────────────────────────────────────

_backend = None


def get_backend():
    global _backend
    if _backend is None:
        kind = getattr(settings, 'CYM_BACKEND', 'firebase')
        if kind == 'memory':
            if not (settings.DEBUG or 'test' in sys.argv):
                raise ImproperlyConfigured('The memory backend is only allowed with DEBUG or in tests.')
            _backend = MemoryBackend()
        else:
            _backend = FirebaseBackend()
    return _backend


def reset_backend():
    """Used by tests to start each case with clean state."""
    global _backend
    _backend = None
