from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend

class EmailBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            User = get_user_model()  # Usamos el modelo de usuario configurado
            user = User.objects.get(email=username)
            if user.check_password(password):
                return user
        except User.DoesNotExist:
            return None

    def get_user(self, user_id):
        try:
            User = get_user_model()  # Usamos el modelo de usuario configurado
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None