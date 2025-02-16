from django.urls import path
from . import views

from django.contrib.auth import views as auth_views

# from .views import CustomPasswordResetView  # Import the custom view

urlpatterns = [
    path('signup', views.signup, name='accounts.signup'),
    path('login', views.login, name='accounts.login'),
    path('logout/', views.logout, name='accounts.logout'),
    path('orders/', views.orders, name='accounts.orders'),
    path('accounts/self-service-password-reset/', views.self_service_password_reset, name="self-service-password-reset"),
]
