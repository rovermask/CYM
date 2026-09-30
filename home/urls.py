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

    # ── Vault (Firebase Auth + Firestore) ────────────────────────────────────
    path("vault",                    views.vault,           name="vault"),
    path("vault/session",            views.vault_session,   name="vault_session"),
    path("vault/logout",             views.vault_logout,    name="vault_logout"),
    path("vault/dashboard",          views.vault_dashboard, name="vault_dashboard"),
    path("vault/create",             views.vault_create,    name="vault_create"),
    path("vault/edit/<slug:eid>",    views.vault_edit,      name="vault_edit"),
    path("vault/delete/<slug:eid>",  views.vault_delete,    name="vault_delete"),

    # ── Admin panel (requires the Firebase `admin` custom claim) ─────────────
    path("manage/",                  views.admin_panel,       name="admin_panel"),
    path("manage/users/<str:uid>",   views.admin_user_action, name="admin_user_action"),
]
