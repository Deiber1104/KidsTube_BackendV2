from django.urls import include, path
from rest_framework import routers

from . import views

# Rutas de los ViewSets
custom_user_router = routers.DefaultRouter()
custom_user_router.register(r'', views.CustomUserViewSet)

playlist_router = routers.DefaultRouter()
playlist_router.register(r'', views.PlaylistViewSet)

restricted_user_router = routers.DefaultRouter()
restricted_user_router.register(r'', views.RestrictedUserViewSet)

video_router = routers.DefaultRouter()
video_router.register(r'', views.VideoViewSet)

# Definición de las URLs para la aplicación
urlpatterns = [
    path('login/', views.LoginViewSet.as_view(), name='login'),
    path('custom_user/', include(custom_user_router.urls)),
    path('restricted_user/', include(restricted_user_router.urls)),
    path('playlist/', include(playlist_router.urls)),
    path('video/', include(video_router.urls)),
]