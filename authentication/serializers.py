from django.contrib.auth.models import User
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, RefreshToken
from rest_framework import serializers
from .models import CustomUser, ScanRequest

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = User.EMAIL_FIELD

    @classmethod
    def get_token(cls, user):
        token = super(MyTokenObtainPairSerializer, cls).get_token(user)

        # Add custom claims
        token['picture'] = user.picture
        token['username'] = user.username
        token['email'] = user.email
        return token


class CustomUserSerializer(serializers.ModelSerializer):
    """
    Currently unused in preference of the below.
    """
    email = serializers.EmailField(
        required=True
    )
    username = serializers.CharField(required=True)
    password = serializers.CharField(min_length=8, write_only=True, required=True)
    picture = serializers.CharField(required=False)

    class Meta:
        model = CustomUser
        fields = ('email', 'username', 'password', 'picture')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)  # as long as the fields are the same, we can just use this
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance


class ScanRequestSerializer(serializers.ModelSerializer):

    class Meta:
        model = ScanRequest
        exclude = ()
