from django.urls import path
from home import views

urlpatterns = [
    # ── Public pages ─────────────────────────────────────────────────────────
    path("",             views.home,          name="home"),
    path("documentation",views.documentation, name="documentaion"),   # kept original typo for compatibility
    path("examples",     views.examples,      name="examples"),
    path("about",        views.about,         name="about"),
    path("symmetric",    views.symmetric,     name="symmetric"),
    path("asymmetric",   views.asymmetric,    name="asymmetric"),
    path("tools",        views.tools,         name="tools"),
    path("encrypt_data", views.encrypt_data,  name="encrypt_data"),

    # ── Vault: auth ───────────────────────────────────────────────────────────
    path("vault",              views.vault,          name="vault"),
    path("vault/login",        views.vault_login,    name="vault_login"),
    path("vault/register",     views.vault_register, name="vault_register"),
    path("vault/logout",       views.vault_logout,   name="vault_logout"),

    # ── Vault: dashboard & CRUD ───────────────────────────────────────────────
    path("vault/dashboard",         views.vault_dashboard, name="vault_dashboard"),
    path("vault/create",            views.vault_create,    name="vault_create"),
    path("vault/edit/<int:pk>",     views.vault_edit,      name="vault_edit"),
    path("vault/delete/<int:pk>",   views.vault_delete,    name="vault_delete"),
]