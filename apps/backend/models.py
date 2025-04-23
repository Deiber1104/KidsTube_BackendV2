import logging
from uuid import uuid4

from django.contrib.auth.models import AbstractUser
from django.db import models

from . import constants

logger = logging.getLogger(__name__)

class CustomUserModel(AbstractUser):
    user_id = models.CharField(max_length=50, default=uuid4, primary_key=True, editable=False)
    email = models.EmailField(max_length=150, null=False, blank=False, unique=True)
    phone = models.PositiveIntegerField(default=0)
    pin = models.CharField(max_length=6, null=False, blank=False)
    first_name = models.CharField(max_length=150, null=False, blank=False)
    last_name = models.CharField(max_length=150, null=False, blank=False)
    country = models.CharField(null=True, blank=False)
    birth_date = models.DateField(null=False, blank=False)
    role = models.CharField(choices=constants.ROLE_CHOICES, default=constants.ROLE_CHOICES[0][0])
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.email


class RestrictedUserModel(models.Model):
    restricted_id = models.CharField(max_length=50, default=uuid4, primary_key=True, editable=False)
    restricted_user = models.ForeignKey(CustomUserModel, on_delete=models.PROTECT, related_name='restricted_users')
    full_name = models.CharField(max_length=255, null=False, blank=False)
    pin = models.CharField(max_length=6, null=False, blank=False)
    avatar = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.full_name


class PlaylistModel(models.Model):
    playlist_id = models.CharField(max_length=50, default=uuid4, primary_key=True, editable=False)
    name = models.CharField(max_length=255, null=False, blank=False)
    associated_profiles = models.ManyToManyField(RestrictedUserModel, related_name='playlists')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class VideoModel(models.Model):
    video_id = models.CharField(max_length=50, default=uuid4, primary_key=True, editable=False)
    playlists = models.ManyToManyField(PlaylistModel, related_name='videos')
    name = models.CharField(max_length=255, null=False, blank=False)
    youtube_url = models.URLField(max_length=255, null=False, blank=False)
    description = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name