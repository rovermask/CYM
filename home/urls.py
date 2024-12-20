from django.urls import path
from home import views

urlpatterns = [
    path("",views.home,name="home"),
    path("documentation",views.documentation ,name="documentaion"),
    path("examples",views.examples,name="examples"),
    path("about",views.about,name="about"),
    path("symmetric",views.symmetric,name="symmetric"),
    path("asymmetric",views.asymmetric,name="asymmetric"),
    path("vault",views.vault,name="vault"),
    path("tools",views.tools,name="tools"),
    path("encrypt_data",views.encrypt_data,name="encrypt_data")
]