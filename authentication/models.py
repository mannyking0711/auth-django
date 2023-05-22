from django.contrib.auth.models import AbstractUser
from django.db import models


# Create your models here.
class CustomUser(AbstractUser):
    USERNAME_FIELD = 'email'
    fav_color = models.CharField(blank=True, max_length=120)
    picture = models.CharField(blank=True, max_length=120)
    email = models.EmailField('email address', unique=True)
    REQUIRED_FIELDS = []
