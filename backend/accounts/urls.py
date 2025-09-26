# accounts/urls.py
from django.urls import path
from .views import (
    LoginView,
    RegisterView, 
    ProfileView,
    LogoutView,
    TokenRefreshView
)

urlpatterns = [
    # Authentication
    path('token/', LoginView.as_view(), name='login'),
    path('register/', RegisterView.as_view(), name='register'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('logout/', LogoutView.as_view(), name='logout'),
    
    # Profile management
    path('profile/', ProfileView.as_view(), name='profile'),
]