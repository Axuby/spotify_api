"""spotify_api URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include

from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

...

schema_view = get_schema_view(
    openapi.Info(
        title="Spotify API",
        default_version='v1',
        description="A small API for Listening to Spotify Music By Samuel",
        terms_of_service="https://www.spoti.com/policies/terms/",
        contact=openapi.Contact(email="contact@spoti.com",),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
)

urlpatterns = [
    # path('admin/', include('admin_honeypot.urls'), name='admin_honeypot'),
    path('admin/', admin.site.urls),
    path('api/', include('account.api.urls')),
    path('', schema_view.with_ui('swagger',
                                 cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc',
                                       cache_timeout=0), name='schema-redoc'),
]

handler404 = "utils.views.handle_404"
handler500 = "utils.views.handle_500"
