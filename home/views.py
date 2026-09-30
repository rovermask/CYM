from functools import wraps

from cryptography.fernet import InvalidToken
from django.contrib import messages
from django.http import Http404, JsonResponse
from django.shortcuts import redirect, render
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

import encryption_algorithms.rsa_algo          as ra
import encryption_algorithms.substitution_cipher as sc
import encryption_algorithms.swapping_algo       as sa
import encryption_algorithms.vigenere_cipher     as vc
import encryption_algorithms.atbash_rot13        as ar
from home import vault_crypto
from home.backends import BackendError, get_backend
from home.context import SessionUser


# ── Algorithm config ──────────────────────────────────────────────────────────

# id -> (label, needs_key)
ALGORITHMS = {
    '1': ('Caesar Cipher', True),
    '2': ('RSA (Demo)', False),
    '3': ('Swapping Cipher', False),
    '4': ('Vigenère Cipher', True),
    '5': ('Atbash Cipher', False),
    '6': ('ROT13', False),
}


# ── Public pages ──────────────────────────────────────────────────────────────

def home(request):
    return render(request, 'home.html')

def documentation(request):
    return render(request, 'documentation.html')

def examples(request):
    return render(request, 'examples.html')

def about(request):
    return render(request, 'about.html')

def symmetric(request):
    return render(request, 'symmetric.html')

def asymmetric(request):
    return render(request, 'asymmetric.html')

def tools(request):
    return render(request, 'tools.html', {'mode': 'encrypt'})


# ── Encryption tool ───────────────────────────────────────────────────────────

def run_cipher(algorithm, mode, text, key):
    """Run one cipher. Returns (result_text, label, error)."""
    if not text:
        return None, None, 'Please enter some text.'
    if algorithm not in ALGORITHMS:
        return None, None, 'Please select an algorithm.'
    name, needs_key = ALGORITHMS[algorithm]
    if needs_key and not key:
        return None, None, 'The selected algorithm requires a key.'
    decrypt = mode == 'decrypt'

    try:
        if algorithm == '1':
            if not (key.lstrip('-').isascii() and key.lstrip('-').isdigit()):
                return None, None, 'Caesar Cipher requires an integer key (e.g. 3).'
            shift = int(key)
            out = sc.caesar_decrypt(text, shift) if decrypt else sc.caesar_cipher(text, shift)
            return out, f'{name} (shift={shift})', None
        if algorithm == '2':
            pub, priv = ra.rsa_generate_keys()
            if decrypt:
                out = ra.rsa_decrypt_message(text, priv[0], priv[1])
                return out, f'RSA Decrypted (Demo: d={priv[0]}, n={priv[1]})', None
            out = ra.rsa_algo(text)
            return out, f'RSA Encrypted (Demo: e={pub[0]}, n={pub[1]})', None
        if algorithm == '3':
            return sa.swapping_encrypt(text), name, None
        if algorithm == '4':
            if not (key.isascii() and key.isalpha()):
                return None, None, 'Vigenère Cipher requires an alphabetic key (letters A–Z only).'
            fn = vc.vigenere_decrypt if decrypt else vc.vigenere_encrypt
            return fn(text, key), f'{name} (key={key.upper()})', None
        if algorithm == '5':
            return ar.atbash_cipher(text), name, None
        if algorithm == '6':
            return ar.rot13(text), name, None
    except ValueError as e:
        if decrypt and algorithm == '2':
            return None, None, 'RSA ciphertext must be space-separated numbers produced by this tool.'
        return None, None, str(e)
    except Exception as e:  # pragma: no cover - defensive
        return None, None, f'Operation failed: {e}'
    return None, None, 'Unsupported algorithm.'


def encrypt_data(request):
    if request.method != 'POST':
        return redirect('tools')

    text      = request.POST.get('plain_text', '').strip()
    key       = request.POST.get('key', '').strip()
    algorithm = request.POST.get('algorithm', '0')
    mode      = 'decrypt' if request.POST.get('mode') == 'decrypt' else 'encrypt'

    result_text, result_label, error = run_cipher(algorithm, mode, text, key)

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        status = 400 if error else 200
        return JsonResponse({'ok': not error, 'error': error,
                             'result': result_text, 'label': result_label}, status=status)

    return render(request, 'tools.html', {
        'result_text':  result_text,
        'result_label': result_label,
        'error':        error,
        'plain_text':   text,
        'key':          key,
        'algorithm':    algorithm,
        'mode':         mode,
    })


# ── Auth helpers ──────────────────────────────────────────────────────────────

def vault_login_required(view):
    @wraps(view)
    def wrapper(request, *args, **kwargs):
        user = SessionUser(request.session.get('vault_user'))
        if not user.is_authenticated:
            return redirect('/login')
        request.vault_user = user
        return view(request, *args, **kwargs)
    return wrapper


def admin_required(view):
    """Signed in AND still holding the Firebase `admin` claim (re-checked on every request)."""
    @vault_login_required
    @wraps(view)
    def wrapper(request, *args, **kwargs):
        try:
            allowed = get_backend().is_admin(request.vault_user.uid)
        except Exception:
            allowed = False
        if not allowed:
            raise Http404()
        return view(request, *args, **kwargs)
    return wrapper


def _profile(user):
    return get_backend().get_profile(user.uid, user.email, user.username)


# ── Vault: auth pages ─────────────────────────────────────────────────────────

def login_page(request):
    """Sign-in / sign-up page. Firebase's browser SDK proves identity, then /vault/session verifies it."""
    nxt = _safe_next(request, request.GET.get('next', ''))
    if SessionUser(request.session.get('vault_user')).is_authenticated:
        return redirect(nxt)
    tab = request.GET.get('tab', 'login')
    return render(request, 'login.html', {
        'active_tab': tab if tab in ('login', 'signup') else 'login',
        'next': nxt,
    })


def vault(request):
    return redirect('vault_dashboard')


def _safe_next(request, value):
    """Only allow same-site relative redirects (prevents open redirects)."""
    if value and value.startswith('/') and not value.startswith('//')             and url_has_allowed_host_and_scheme(value, allowed_hosts={request.get_host()}):
        return value
    return '/'


@require_POST
def vault_session(request):
    """Exchange a Firebase ID token for a server session."""
    token = request.POST.get('id_token', '')
    username = request.POST.get('username', '').strip()[:30]
    try:
        info = get_backend().verify_token(token)
        name = username or info['name'] or info['email'].split('@')[0]
        get_backend().get_profile(info['uid'], info['email'], name)
    except BackendError as e:
        return JsonResponse({'ok': False, 'error': str(e)}, status=401)
    request.session.cycle_key()
    request.session['vault_user'] = {
        'uid': info['uid'], 'email': info['email'], 'username': name, 'is_admin': info['is_admin']}
    return JsonResponse({'ok': True, 'next': _safe_next(request, request.POST.get('next', ''))})


@require_POST
def vault_logout(request):
    request.session.flush()
    messages.success(request, 'You have been signed out.')
    return redirect('login')


# ── Vault: dashboard ──────────────────────────────────────────────────────────

@vault_login_required
def vault_dashboard(request):
    user = request.vault_user
    profile = _profile(user)
    entries = []
    for e in get_backend().list_entries(user.uid):
        try:
            content = vault_crypto.decrypt(user.uid, profile['salt'], e['content_encrypted'])
        except InvalidToken:
            content = '[decryption error — entry may be corrupted]'
        entries.append({
            'id':         e['id'],
            'title':      e['title'],
            'content':    content,
            'preview':    content[:140] + ('…' if len(content) > 140 else ''),
            'updated_at': e['updated_at'],
            'char_count': len(content),
        })
    return render(request, 'vault_dashboard.html', {
        'entries':      entries,
        'entry_count':  len(entries),
        'entries_json': [{'id': e['id'], 'title': e['title'], 'content': e['content']} for e in entries],
        'fingerprint':  vault_crypto.fingerprint(profile['salt']),
    })


# ── Vault: CRUD ───────────────────────────────────────────────────────────────

def _clean_entry_form(request):
    title   = request.POST.get('title', '').strip()[:200]
    content = request.POST.get('content', '').strip()
    if not title:
        messages.error(request, 'Entry title is required.')
    elif not content:
        messages.error(request, 'Entry content cannot be empty.')
    elif len(content) > 100_000:
        messages.error(request, 'Entry content is too long (100,000 characters max).')
    else:
        return title, content
    return None


@vault_login_required
@require_POST
def vault_create(request):
    user, form = request.vault_user, _clean_entry_form(request)
    if form:
        title, content = form
        salt = _profile(user)['salt']
        get_backend().create_entry(user.uid, title, vault_crypto.encrypt(user.uid, salt, content))
        messages.success(request, f'Entry "{title}" encrypted and saved.')
    return redirect('vault_dashboard')


@vault_login_required
def vault_edit(request, eid):
    user, backend = request.vault_user, get_backend()
    entry = backend.get_entry(user.uid, eid)
    if not entry:
        raise Http404()
    salt = _profile(user)['salt']

    if request.method == 'POST':
        form = _clean_entry_form(request)
        if form:
            title, content = form
            backend.update_entry(user.uid, eid, title, vault_crypto.encrypt(user.uid, salt, content))
            messages.success(request, f'Entry "{title}" updated.')
        return redirect('vault_dashboard')

    try:
        content = vault_crypto.decrypt(user.uid, salt, entry['content_encrypted'])
    except InvalidToken:
        content = ''
    return render(request, 'vault_edit.html', {'entry': entry, 'content': content})


@vault_login_required
@require_POST
def vault_delete(request, eid):
    user, backend = request.vault_user, get_backend()
    entry = backend.get_entry(user.uid, eid)
    if not entry:
        raise Http404()
    backend.delete_entry(user.uid, eid)
    messages.success(request, 'Entry "%s" permanently deleted.' % entry['title'])
    return redirect('vault_dashboard')


# ── Admin panel ───────────────────────────────────────────────────────────────

@admin_required
def admin_panel(request):
    q = request.GET.get('q', '').strip().lower()
    users = get_backend().list_users()
    stats = {
        'total':    len(users),
        'entries':  sum(u['entry_count'] for u in users),
        'disabled': sum(1 for u in users if u['disabled']),
        'admins':   sum(1 for u in users if u['is_admin']),
    }
    if q:
        users = [u for u in users if q in u['email'].lower() or q in u['username'].lower()]
    return render(request, 'admin_panel.html', {'users': users, 'stats': stats, 'q': q})


@admin_required
@require_POST
def admin_user_action(request, uid):
    action = request.POST.get('action')
    if uid == request.vault_user.uid:
        messages.error(request, "You can't change your own account from the admin panel.")
        return redirect('admin_panel')
    backend = get_backend()
    try:
        if action in ('disable', 'enable'):
            backend.set_disabled(uid, action == 'disable')
            messages.success(request, 'User %sd.' % action)
        elif action == 'delete':
            backend.delete_user(uid)
            messages.success(request, 'User and all their vault entries were permanently deleted.')
        else:
            messages.error(request, 'Unknown action.')
    except Exception as e:
        messages.error(request, 'Action failed: %s' % e)
    return redirect('admin_panel')
