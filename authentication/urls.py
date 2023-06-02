from django.urls import path
from rest_framework_simplejwt import views as jwt_views
from authentication import views

urlpatterns = [
    path('user/create/', views.CustomUserCreate.as_view(), name="create_user"),
    path('token/obtain/', views.ObtainTokenPairWithColorView.as_view(), name='token_create'),
    path('token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),
    path('blacklist/', views.LogoutAndBlacklistRefreshTokenForUserView.as_view(), name='blacklist'),


    path('hello/', views.HelloWorldView.as_view(), name='hello_world'),


    path('scan_request', views.ScanRequestView.as_view(), name='scan_request'),
    path('track/<str:uuid>', views.ScanRequestView.as_view(), name='get_track'),
    path('track', views.TrackTableView.as_view(), name='track'),


    path('dashboard/', views.DashboardView.as_view(), name='dashboard')
]