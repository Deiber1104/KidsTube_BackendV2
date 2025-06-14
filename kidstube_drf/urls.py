"""
URL configuration for kidstube_drf project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
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
from django.urls import path, include
from apps.backend.views import LoginViewSet

urlpatterns = [
    path('api/auth/login/', LoginViewSet.as_view(), name='custom-login'),
    # dj-ret-auth urls
    path('api/auth/', include('dj_rest_auth.urls')),       # Endpoints provided by dj-rest-auth
    # Our own app's urls
    # path('api/auth-api/', include('apps.auth_api.urls')), # Our own views

    path("api/", include("apps.backend.urls")), 
]
