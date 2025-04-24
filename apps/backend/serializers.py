from datetime import date
from django.contrib.auth import authenticate
from rest_framework import serializers
from .models import CustomUserModel, PlaylistModel, RestrictedUserModel, VideoModel

"""
Serializer to manage Login
"""
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    # Verificar que el role sea
    """
    def validate(self, data):
        email = data.get('email')

        try:
            user = CustomUserModel.objects.get(email=email)
        except CustomUserModel.DoesNotExist:
            raise serializers.ValidationError("User not found.")

        if user.role != 'Active':
            raise serializers.ValidationError("Your account is not verified yet.")

        return data
    """ 

"""
Serializer to manage User
"""
class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUserModel
        fields = ('user_id', 'email', 'phone', 'pin', 'first_name', 'last_name', 'country', 'birth_date', 'password', 'created_at')
        read_only_fields = ('user_id', 'created_at', )
        extra_kwargs = {'password': {'write_only': True}}

    # Verificar que el email sea único
    def validate_email(self, value):
        if CustomUserModel.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use.")
        return value

    # Verificar que el usuario tenga más de 18 años
    def validate_birth_date(self, value):
        today = date.today()
        if today.year - value.year < 18:
            raise serializers.ValidationError("You must be over 18 years old to register.")
        return value

    # Verificar que el PIN tenga exactamente 6 dígitos
    def validate_pin(self, value):
        if len(value) != 6 or not value.isdigit():
            raise serializers.ValidationError("The PIN must be a 6-digit number.")
        return value

    def create(self, validated_data):
        # Asignar el email como username si no se proporciona
        validated_data['username'] = validated_data.get('email', '')
        user = CustomUserModel.objects.create_user(**validated_data)
        return user


"""
Serializer to manage Videos
"""
class VideoSerializer(serializers.ModelSerializer):
    class Meta:
        model = VideoModel
        fields = ('video_id', 'playlists', 'name', 'youtube_url', 'description', 'created_at', 'updated_at')
        read_only_fields = ('video_id', 'created_at', 'updated_at', )


"""
Serializer to manage Videos
"""
class PlaylistVideoSerializer(serializers.ModelSerializer):
    class Meta:
        model = VideoModel
        fields = ('video_id', 'name', 'youtube_url', 'description')
        read_only_fields = ('video_id', )


"""
Serializer to manage Restricted User/Profiles
"""
class RestrictedUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = RestrictedUserModel
        fields = ('restricted_id', 'restricted_user', 'full_name', 'pin', 'avatar', 'created_at', 'updated_at')
        read_only_fields = ('restricted_id', 'created_at', 'updated_at', )
    
    # Verification that the PIN has exactly 6 digits
    def validate_pin(self, value):
        if len(value) != 6 or not value.isdigit():
            raise serializers.ValidationError("The PIN must be a 6-digit number.")
        return value

"""
Serializer to manage Playlist
"""
class PlaylistSerializer(serializers.ModelSerializer):
    videos = serializers.SerializerMethodField()
    class Meta:
        model = PlaylistModel
        fields = ('playlist_id', 'name', 'associated_profiles', 'created_at', 'updated_at', 'videos')
        read_only_fields = ('playlist_id', 'created_at', 'updated_at', )
    
    def get_videos(self, obj):
        # Get the filtered videos
        video_name = self.context.get('video_name')
        video_desc = self.context.get('video_desc')
        videos = obj.videos.all()
        if video_name:
            # Filter the videos by name if provided in the context
            videos = videos.filter(name__icontains=video_name)
        
        if video_desc:
            # Filter the videos by description if provided in the context
            videos = videos.filter(description__icontains=video_desc)

        # Return the filtered list of videos using VideoSerializer
        return PlaylistVideoSerializer(videos, many=True).data
