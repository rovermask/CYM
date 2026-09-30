from django.core.management.base import BaseCommand, CommandError

from home.backends import BackendError, get_backend


class Command(BaseCommand):
    help = 'Grant (or with --revoke, remove) the admin claim for a Firebase user by email.'

    def add_arguments(self, parser):
        parser.add_argument('email')
        parser.add_argument('--revoke', action='store_true')

    def handle(self, *args, email, revoke, **opts):
        try:
            uid = get_backend().set_admin(email, not revoke)
        except (BackendError, Exception) as e:
            raise CommandError(f'Could not update {email}: {e}')
        verb = 'Removed admin from' if revoke else 'Granted admin to'
        self.stdout.write(self.style.SUCCESS(f'{verb} {email} ({uid}). They must sign in again.'))
