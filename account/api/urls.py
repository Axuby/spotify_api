from django.urls import path
from . import views

from rest_framework_simplejwt.views import (
    TokenRefreshView,
)


urlpatterns = [
    path('login/', views.LoginView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/', views.RegistrationView.as_view(), name='register'),
    path('verify-email/', views.VerifyEmail.as_view(), name='verify-email'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('change-password/<int:pk>/', views.ChangePasswordView.as_view(),
         name='change-password'),
    path('profiles/<int:pk>/',
         views.ProfileRetrieveAPIView.as_view(), name="profile"),
    path('update-profile/<int:pk>/', views.UpdateProfileView.as_view(),
         name='update-profile'),
    path('', views.GetRouteAV.as_view(), name='get-routes'),
]
