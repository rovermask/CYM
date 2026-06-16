import os
import hmac
import hashlib
import base64
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver


class UserVaultProfile(models.Model):
    """
    Stores a random salt generated once per user at registration.
    The Fernet encryption key for this user is:
        HMAC-SHA256( settings.SECRET_KEY, salt + str(user.id) )
    The salt is never exposed; only its fingerprint (first 8 hex chars) is shown in the UI.
    """
    user       = models.OneToOneField(User, on_delete=models.CASCADE, related_name='vault_profile')
    salt       = models.CharField(max_length=64)          # 32 hex-encoded random bytes
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"VaultProfile({self.user.username})"

    @property
    def key_fingerprint(self):
        """First 8 chars of the salt — shown to users as their 'key ID'."""
        return self.salt[:8].upper()


@receiver(post_save, sender=User)
def create_vault_profile(sender, instance, created, **kwargs):
    """Auto-generate a salt whenever a new User is created."""
    if created:
        salt = os.urandom(32).hex()          # 256 bits of randomness
        UserVaultProfile.objects.create(user=instance, salt=salt)


class VaultEntry(models.Model):
    user              = models.ForeignKey(User, on_delete=models.CASCADE, related_name='vault_entries')
    title             = models.CharField(max_length=200)
    content_encrypted = models.TextField()
    created_at        = models.DateTimeField(auto_now_add=True)
    updated_at        = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']

    def __str__(self):
        return f"{self.user.username} — {self.title}"