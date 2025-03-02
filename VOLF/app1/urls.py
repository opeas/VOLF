from django.urls import path
from . import views
from .views import PasswordsChangeView
from django.contrib.auth import views as auth_views

urlpatterns = [
    path("", views.home, name='home'),
    path("change_password/", PasswordsChangeView.as_view(template_name='registration/change_password.html')),
    path("get_cve_details/", views.get_cve_details, name="get_cve_details"),
    path("get_cve_details_", views.get_cve_details_),
]