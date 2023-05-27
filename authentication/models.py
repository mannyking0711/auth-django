import uuid
from django.contrib.auth.models import AbstractUser
from django.db import models


# Create your models here.
class CustomUser(AbstractUser):
    USERNAME_FIELD = 'email'
    fav_color = models.CharField(blank=True, max_length=120)
    picture = models.CharField(blank=True, max_length=120)
    email = models.EmailField('email address', unique=True)
    REQUIRED_FIELDS = []

class ScanRequest(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    domain = models.CharField(blank=False, max_length=100)
    track = models.UUIDField(auto_created=True, default=uuid.uuid4)
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(blank=False, default=None, null=True)