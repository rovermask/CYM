from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from django.utils.html import format_html

from home.models import VaultEntry, UserVaultProfile


# ── Inline: show vault profile inside User admin ──────────────────────────────

class VaultProfileInline(admin.StackedInline):
    model  = UserVaultProfile
    extra  = 0
    readonly_fields = ('key_fingerprint_display', 'created_at')
    fields = ('key_fingerprint_display', 'created_at')

    def key_fingerprint_display(self, obj):
        return format_html(
            '<code style="font-size:1rem;letter-spacing:0.1em;">{}</code>',
            obj.key_fingerprint if obj else '—'
        )
    key_fingerprint_display.short_description = 'Key Fingerprint (first 8 chars of salt)'


class VaultEntryInline(admin.TabularInline):
    model           = VaultEntry
    extra           = 0
    readonly_fields = ('title', 'entry_size', 'created_at', 'updated_at')
    fields          = ('title', 'entry_size', 'updated_at')
    can_delete      = True
    show_change_link = True

    def entry_size(self, obj):
        return f"{len(obj.content_encrypted)} chars (encrypted)"
    entry_size.short_description = 'Encrypted Size'


# ── Custom User admin ─────────────────────────────────────────────────────────

class CYMUserAdmin(BaseUserAdmin):
    """
    Extends Django's built-in UserAdmin to:
    - Show email prominently in the list view
    - Show vault profile key fingerprint
    - Show vault entry count
    - Show inline vault profile + entry list
    """
    list_display  = ('username', 'email', 'date_joined', 'is_active', 'is_staff', 'vault_entry_count', 'key_fingerprint')
    list_filter   = ('is_active', 'is_staff', 'is_superuser', 'date_joined')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    ordering      = ('-date_joined',)
    inlines       = [VaultProfileInline, VaultEntryInline]

    # Make email required in the add/change form
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'email')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields':  ('username', 'email', 'password1', 'password2'),
        }),
    )

    def vault_entry_count(self, obj):
        count = obj.vault_entries.count()
        color = '#22c55e' if count > 0 else '#6b7280'
        return format_html(
            '<span style="color:{};font-weight:600;">{} entr{}</span>',
            color, count, 'y' if count == 1 else 'ies'
        )
    vault_entry_count.short_description = 'Vault Entries'

    def key_fingerprint(self, obj):
        try:
            fp = obj.vault_profile.key_fingerprint
            return format_html('<code style="color:#00dca0;">{}</code>', fp)
        except UserVaultProfile.DoesNotExist:
            return format_html('<span style="color:#ef4444;">No profile</span>')
    key_fingerprint.short_description = 'Key Fingerprint'


# ── VaultEntry admin ──────────────────────────────────────────────────────────

@admin.register(VaultEntry)
class VaultEntryAdmin(admin.ModelAdmin):
    list_display  = ('title', 'user_email', 'username', 'entry_size', 'created_at', 'updated_at')
    list_filter   = ('created_at', 'updated_at')
    search_fields = ('title', 'user__username', 'user__email')
    readonly_fields = ('user', 'title', 'content_encrypted', 'created_at', 'updated_at', 'entry_size')
    ordering      = ('-updated_at',)

    fieldsets = (
        ('Entry Info', {'fields': ('user', 'title', 'created_at', 'updated_at')}),
        ('Encrypted Content', {
            'fields': ('content_encrypted', 'entry_size'),
            'description': (
                '⚠️  Content is stored as an AES-128 Fernet token. '
                'To read it, use vault_crypto.decrypt(user.id, content_encrypted) in the Django shell.'
            ),
        }),
    )

    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'Email'

    def username(self, obj):
        return obj.user.username
    username.short_description = 'Username'

    def entry_size(self, obj):
        return f"{len(obj.content_encrypted)} chars"
    entry_size.short_description = 'Encrypted Size'

    def has_add_permission(self, request):
        return False  # Entries must be created through the Vault UI


# ── UserVaultProfile admin ────────────────────────────────────────────────────

@admin.register(UserVaultProfile)
class UserVaultProfileAdmin(admin.ModelAdmin):
    list_display  = ('username', 'email', 'key_fingerprint', 'created_at')
    readonly_fields = ('user', 'salt', 'key_fingerprint', 'created_at')
    search_fields = ('user__username', 'user__email')
    ordering      = ('-created_at',)

    def username(self, obj):
        return obj.user.username
    username.short_description = 'Username'

    def email(self, obj):
        return obj.user.email
    email.short_description = 'Email'

    def key_fingerprint(self, obj):
        return format_html('<code style="color:#00dca0;">{}</code>', obj.key_fingerprint)
    key_fingerprint.short_description = 'Key Fingerprint'

    def has_add_permission(self, request):
        return False   # Profiles are auto-created on User registration

    def has_change_permission(self, request, obj=None):
        return False   # Salt must never be modified manually


# ── Re-register User with custom admin ───────────────────────────────────────
admin.site.unregister(User)
admin.site.register(User, CYMUserAdmin)

# ── Customize admin site header ───────────────────────────────────────────────
admin.site.site_header  = 'CryptYourMind Admin'
admin.site.site_title   = 'CYM Admin'
admin.site.index_title  = 'User & Vault Management'