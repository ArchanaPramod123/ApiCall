from django.urls import path
from .views import *
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

urlpatterns = [
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('posts/create/', PostCreateView.as_view(), name='post_create'),  
    path('posts/<int:pk>/publish/', PostPublishView.as_view(), name='post_publish'),  # Add this line
    path('posts/', PostListView.as_view(), name='post_list'),  # New URL for listing posts
    path('posts/<int:pk>/like/', PostLikeToggleView.as_view(), name='post_like_toggle'),  # URL for liking/unliking posts
]
