from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.http import require_POST
from django.utils import timezone

import encryption_algorithms.rsa_algo          as ra
import encryption_algorithms.substitution_cipher as sc
import encryption_algorithms.swapping_algo       as sa
import encryption_algorithms.vigenere_cipher     as vc
import encryption_algorithms.atbash_rot13        as ar
from home.models    import VaultEntry
from home           import vault_crypto


# ── Algorithm config ──────────────────────────────────────────────────────────

KEYLESS_ALGORITHMS = {'3', '5', '6'}


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
    return render(request, 'tools.html')


# ── Encryption tool ───────────────────────────────────────────────────────────

def encrypt_data(request):
    if request.method != 'POST':
        return render(request, 'tools.html')

    plain_text = request.POST.get('plain_text', '').strip()
    key        = request.POST.get('key', '').strip()
    algorithm  = request.POST.get('algorithm', '0')
    error = result_text = result_label = None

    if not plain_text:
        error = 'Please enter some text to encrypt.'
    elif algorithm == '0':
        error = 'Please select an algorithm.'
    elif algorithm not in KEYLESS_ALGORITHMS and algorithm not in ('2',) and not key:
        error = 'The selected algorithm requires a key.'
    else:
        try:
            if algorithm == '1':
                if not key.lstrip('-').isdigit():
                    error = 'Caesar Cipher requires an integer key (e.g. 3).'
                else:
                    result_text  = sc.caesar_cipher(plain_text, int(key))
                    result_label = f'Caesar Cipher (shift={key})'
            elif algorithm == '2':
                result_text  = ra.rsa_algo(plain_text)
                pub_key, _   = ra.rsa_generate_keys()
                result_label = f'RSA Encrypted (Demo: e={pub_key[0]}, n={pub_key[1]})'
            elif algorithm == '3':
                result_text  = sa.swapping_encrypt(plain_text)
                result_label = 'Swapping Cipher'
            elif algorithm == '4':
                if not key.isalpha():
                    error = 'Vigenère Cipher requires an alphabetic key (letters only).'
                else:
                    result_text  = vc.vigenere_encrypt(plain_text, key)
                    result_label = f'Vigenère Cipher (key={key.upper()})'
            elif algorithm == '5':
                result_text  = ar.atbash_cipher(plain_text)
                result_label = 'Atbash Cipher'
            elif algorithm == '6':
                result_text  = ar.rot13(plain_text)
                result_label = 'ROT13'
        except Exception as e:
            error = f'Encryption failed: {str(e)}'

    return render(request, 'tools.html', {
        'result_text':  result_text,
        'result_label': result_label,
        'error':        error,
        'plain_text':   plain_text,
        'key':          key,
        'algorithm':    algorithm,
    })


# ── Vault: auth pages ─────────────────────────────────────────────────────────

def vault(request):
    """Auth landing — redirect to dashboard if already logged in."""
    if request.user.is_authenticated:
        return redirect('vault_dashboard')
    tab = request.GET.get('tab', 'login')
    return render(request, 'vault.html', {'active_tab': tab})


@require_POST
def vault_register(request):
    username  = request.POST.get('username', '').strip()
    email     = request.POST.get('email', '').strip()
    password1 = request.POST.get('password1', '')
    password2 = request.POST.get('password2', '')

    if not username or not email or not password1:
        messages.error(request, 'All fields are required.')
        return redirect('/vault?tab=signup')
    if password1 != password2:
        messages.error(request, 'Passwords do not match.')
        return redirect('/vault?tab=signup')
    if len(password1) < 8:
        messages.error(request, 'Password must be at least 8 characters.')
        return redirect('/vault?tab=signup')
    if User.objects.filter(username__iexact=username).exists():
        messages.error(request, 'Username already taken.')
        return redirect('/vault?tab=signup')
    if User.objects.filter(email__iexact=email).exists():
        messages.error(request, 'An account with this email already exists.')
        return redirect('/vault?tab=signup')

    # Create user — post_save signal auto-creates UserVaultProfile + salt
    user = User.objects.create_user(username=username, email=email, password=password1)
    login(request, user)
    messages.success(request, f'Welcome to the Vault, {username}! Your unique encryption key has been generated.')
    return redirect('vault_dashboard')


@require_POST
def vault_login(request):
    email    = request.POST.get('email', '').strip()
    password = request.POST.get('password', '')

    try:
        user_obj = User.objects.get(email__iexact=email)
    except User.DoesNotExist:
        messages.error(request, 'No account found with that email address.')
        return redirect('/vault?tab=login')

    user = authenticate(request, username=user_obj.username, password=password)
    if user is not None:
        login(request, user)
        return redirect('vault_dashboard')
    messages.error(request, 'Incorrect password. Please try again.')
    return redirect('/vault?tab=login')


def vault_logout(request):
    logout(request)
    messages.success(request, 'You have been securely logged out.')
    return redirect('vault')


# ── Vault: dashboard ──────────────────────────────────────────────────────────

@login_required(login_url='/vault')
def vault_dashboard(request):
    raw_entries = VaultEntry.objects.filter(user=request.user)
    entries = []
    for e in raw_entries:
        try:
            content = vault_crypto.decrypt(request.user.id, e.content_encrypted)
        except Exception:
            content = '[decryption error — entry may be corrupted]'
        entries.append({
            'id':         e.id,
            'title':      e.title,
            'content':    content,
            'preview':    content[:140] + ('…' if len(content) > 140 else ''),
            'created_at': e.created_at,
            'updated_at': e.updated_at,
            'char_count': len(content),
        })

    try:
        fingerprint = vault_crypto.get_key_fingerprint(request.user.id)
    except Exception:
        fingerprint = 'UNKNOWN'

    return render(request, 'vault_dashboard.html', {
        'entries':     entries,
        'entry_count': len(entries),
        'fingerprint': fingerprint,
    })


# ── Vault: CRUD ───────────────────────────────────────────────────────────────

@login_required(login_url='/vault')
@require_POST
def vault_create(request):
    title   = request.POST.get('title', '').strip()
    content = request.POST.get('content', '').strip()

    if not title:
        messages.error(request, 'Entry title is required.')
        return redirect('vault_dashboard')
    if not content:
        messages.error(request, 'Entry content cannot be empty.')
        return redirect('vault_dashboard')

    encrypted = vault_crypto.encrypt(request.user.id, content)
    VaultEntry.objects.create(user=request.user, title=title, content_encrypted=encrypted)
    messages.success(request, f'Entry "{title}" encrypted and saved.')
    return redirect('vault_dashboard')


@login_required(login_url='/vault')
def vault_edit(request, pk):
    entry = get_object_or_404(VaultEntry, pk=pk, user=request.user)

    if request.method == 'POST':
        title   = request.POST.get('title', '').strip()
        content = request.POST.get('content', '').strip()
        if not title or not content:
            messages.error(request, 'Title and content are required.')
            return redirect('vault_dashboard')
        entry.title             = title
        entry.content_encrypted = vault_crypto.encrypt(request.user.id, content)
        entry.save()
        messages.success(request, f'Entry "{title}" updated.')
        return redirect('vault_dashboard')

    try:
        content = vault_crypto.decrypt(request.user.id, entry.content_encrypted)
    except Exception:
        content = ''

    return render(request, 'vault_edit.html', {'entry': entry, 'content': content})


@login_required(login_url='/vault')
@require_POST
def vault_delete(request, pk):
    entry = get_object_or_404(VaultEntry, pk=pk, user=request.user)
    title = entry.title
    entry.delete()
    messages.success(request, f'Entry "{title}" permanently deleted.')
    return redirect('vault_dashboard')