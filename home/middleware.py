from urllib.parse import quote

from django.http import JsonResponse
from django.shortcuts import redirect

from home.context import SessionUser

# Reachable without an account: the auth page itself, the token exchange and static assets.
PUBLIC_PREFIXES = ('/login', '/vault/session', '/static/', '/favicon.ico')


class SiteLoginMiddleware:
    """Every page requires a signed-in account (Firebase-backed session)."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path
        if path.startswith(PUBLIC_PREFIXES) or SessionUser(request.session.get('vault_user')).is_authenticated:
            return self.get_response(request)

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'ok': False, 'error': 'Please sign in to continue.', 'login': '/login'}, status=401)

        target = '/login'
        if request.method == 'GET' and path != '/':
            target += '?next=' + quote(request.get_full_path(), safe='/')
        return redirect(target)
