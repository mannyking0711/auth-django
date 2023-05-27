import json
from django.http import HttpResponse, JsonResponse
from django.core import serializers
from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenViewBase

from .models import CustomUser, ScanRequest
from .serializers import MyTokenObtainPairSerializer, CustomUserSerializer, ScanRequestSerializer


class ObtainTokenPairWithColorView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer

    def post(self, request):
        try:
            currentUser = CustomUser.objects.get(email=request.data['email'])
            if request.data.get('sub') is not None:
                request.data['password'] = request.data['sub']
            try:
                return super(TokenObtainPairView, self).post(request)
            except:
                return Response('Invalid account info', status=status.HTTP_400_BAD_REQUEST)
        except:
            if request.data.get('sub') is not None:
                request.data['password'] = request.data['sub']
                request.data['username'] = request.data['name']
                serializer = CustomUserSerializer(data=request.data)
                if serializer.is_valid():
                    user = serializer.save()
                    return super(TokenObtainPairView, self).post(request)
            else:
                return Response('Email does not exist, please sign up before login', status=status.HTTP_400_BAD_REQUEST)


class CustomUserCreate(APIView):
    permission_classes = (permissions.AllowAny,)
    authentication_classes = ()

    def post(self, request, format='json'):
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            try:
                currentUser = CustomUser.objects.get(email=request.data['email'])
                if (currentUser):
                    return Response('Email already exists', status=status.HTTP_400_BAD_REQUEST)
            except:
                user = serializer.save()
                if user:
                    json = serializer.data
                    return Response(json, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutAndBlacklistRefreshTokenForUserView(APIView):
    permission_classes = (permissions.AllowAny,)
    authentication_classes = ()

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class HelloWorldView(APIView):

    def get(self, request):
        return Response(data={"hello": request.user.id}, status=status.HTTP_200_OK)
    
class ScanRequestView(APIView):

    def post(self, request, format='json'):
        scan = ScanRequest.objects.create(user = request.user, domain = request.data['domain'])
        scan.save()
        return Response(data={"track": scan.track}, status=status.HTTP_200_OK)

class TrackView(APIView):

    def get(self, request, uuid):
        try:
            scan = ScanRequest.objects.get(track=uuid)
            if scan.finished_at == None:
                return Response(data="Track not started", status=status.HTTP_412_PRECONDITION_FAILED) 
            with open('result.json') as json_file:
                data = json.load(json_file)
                return Response(data=data, status=status.HTTP_200_OK)
        except ScanRequest.DoesNotExist:
            return Response(data="Track does not exist", status=status.HTTP_404_NOT_FOUND)
        
class TrackTableView(APIView):
    serializer_class = ScanRequestSerializer

    def get(self, request):
        objects = ScanRequest.objects.all()
        return JsonResponse(
            ScanRequestSerializer(objects, many=True).data,
            safe=False
        )
