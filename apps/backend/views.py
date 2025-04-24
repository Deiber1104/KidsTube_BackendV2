import django_filters

from django.contrib.auth import authenticate, login
from django_filters import rest_framework as filters
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.db.models import ProtectedError
from django.views.decorators.csrf import csrf_exempt
from googleapiclient.discovery import build
from rest_framework import permissions, status, viewsets
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView

from .models import CustomUserModel, PlaylistModel, RestrictedUserModel, VideoModel
from .serializers import CustomUserSerializer, PlaylistSerializer, RestrictedUserSerializer, VideoSerializer


"""
Endpoint API to manage Login
"""
class LoginViewSet(TokenObtainPairView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        password = request.data.get("password")

        # Intentar obtener al usuario con el email
        try:
            user = CustomUserModel.objects.get(email=email)
        except CustomUserModel.DoesNotExist:
            return Response({"error": "Wrong email or password."}, status=status.HTTP_401_UNAUTHORIZED)

        # Verificación de la contraseña
        if not user.check_password(password):
            return Response({"error": "Wrong email or password."}, status=status.HTTP_401_UNAUTHORIZED)

        # Verificación de si el usuario está activo
        if not user.is_active:
            return Response({"error": "The user is not active"}, status=status.HTTP_401_UNAUTHORIZED)

        # Obtener el token JWT (el token de acceso y el de refresco)
        response = super().post(request, *args, **kwargs)

        # Agregar el user_id al token antes de enviarlo
        response.data["user_id"] = user.user_id  # Agregar el user_id personalizado al token

        # Agregar información adicional del usuario al token
        user_data = CustomUserSerializer(user).data
        response.data["user"] = user_data
        
        return response
    

"""
Endpoint API to manage Users.
"""
class CustomUserViewSet(viewsets.ModelViewSet):
    queryset = CustomUserModel.objects.all()
    permission_classes = [permissions.AllowAny]
    serializer_class = CustomUserSerializer
    
    def update(self, request, *args, **kwargs):
        response = {'message': 'Update function is not offered in this path.'}
        return Response(response, status=status.HTTP_403_FORBIDDEN)
    
    def partial_update(self, request, *args, **kwargs):
        response = {'message': 'Partial update function is not offered in this path.'}
        return Response(response, status=status.HTTP_403_FORBIDDEN)

    def destroy(self, request, pk=None):
        response = {'message': 'Delete function is not offered in this path.'}
        return Response(response, status=status.HTTP_403_FORBIDDEN)


"""
Endpoint API to manage Restricted Users.
"""
class RestrictedUserViewSet(viewsets.ModelViewSet):
    queryset = RestrictedUserModel.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    serializer_class = RestrictedUserSerializer

    def get_queryset(self):
        user = self.request.user  # Obtener el usuario autenticado
        return RestrictedUserModel.objects.filter(restricted_user=user)

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            instance.delete()
            return Response({'message': 'Restricted user deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)
        except ProtectedError:
            return Response({'message': 'Cannot delete this restricted user as it is protected.'}, status=status.HTTP_400_BAD_REQUEST)
        except RestrictedUserModel.DoesNotExist:
            return Response({'message': 'Restricted user not found.'}, status=status.HTTP_404_NOT_FOUND)


"""
Filter Applied to Playlist Endpoint.
"""
class PlaylistFilter(django_filters.FilterSet):
    profile = django_filters.ModelChoiceFilter(field_name="associated_profiles", queryset=RestrictedUserModel.objects.all(), label="Profile")
    video_name = django_filters.CharFilter(field_name='videos__name', lookup_expr='icontains', label='Video Name')
    video_desc = django_filters.CharFilter(field_name='videos__description', lookup_expr='icontains', label='Video Description')

    class Meta:
        model = PlaylistModel
        fields = ['profile', 'video_name', 'video_desc']


"""
Endpoint API to manage Playlist.
"""
class PlaylistViewSet(viewsets.ModelViewSet):
    queryset = PlaylistModel.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = PlaylistSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = PlaylistFilter

    def get_queryset(self):
        return PlaylistModel.objects.filter(associated_profiles__restricted_user=self.request.user).distinct().prefetch_related('videos').all()
    
    def get_serializer_context(self):
        # Add the video_title filter to the context
        context = super().get_serializer_context()
        context['video_name'] = self.request.query_params.get('video_name', None)
        context['video_desc'] = self.request.query_params.get('video_desc', None)
        return context
    

    def destroy(self, request, *args, **kwargs):
        try:
            instance = PlaylistModel.objects.filter(playlist_id=kwargs['pk'], associated_profiles__restricted_user=self.request.user).first()
            if instance:
                instance.delete()
                return Response({'message': 'Playlist deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)
            else:
                return Response({'message': 'Playlist not found.'}, status=status.HTTP_404_NOT_FOUND)
        except PlaylistModel.DoesNotExist:
            return Response({'message': 'Playlist not found.'}, status=status.HTTP_404_NOT_FOUND)


"""
Endpoint API to manage Videos.
"""
class VideoViewSet(viewsets.ModelViewSet):
    queryset = VideoModel.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = VideoSerializer

    def get_queryset(self):
        return VideoModel.objects.filter(playlists__associated_profiles__restricted_user=self.request.user).distinct()

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            instance.delete()
            return Response({'message': 'Video deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)
        except VideoModel.DoesNotExist:
            return Response({'message': 'Video not found.'}, status=status.HTTP_404_NOT_FOUND)


"""
Endpoint API to search for Youtube videos.
"""
class YouTubeSearchView(APIView):
    def get(self, request):
        query = request.query_params.get('query')
        if not query:
            return Response({'error': 'Query parameter is required.'}, status=status.HTTP_400_BAD_REQUEST)

        # Replace with your actual API key from Google Console (https://console.cloud.google.com/)
        api_key = 'AIzaSyASiFcSCfD1y0K-m-C-uJAwE6oP6EIDV9A'
        youtube = build('youtube', 'v3', developerKey=api_key)

        try:
            search_response = youtube.search().list(
                q=query,
                part='snippet',
                maxResults=15,
                type='video'
            ).execute()

            items = search_response.get('items')
            if not items:
                return Response({'error': 'No videos found.'}, status=status.HTTP_404_NOT_FOUND)
            print(items[0])
            videos = [
                {
                    "id": item['id']['videoId'],
                    "url": f"https://www.youtube.com/watch?v={item['id']['videoId']}",
                    "title": item['snippet']['title']
                } for item in items
            ]
            print(videos)
            return Response(videos, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)