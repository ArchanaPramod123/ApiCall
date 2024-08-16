from rest_framework import generics, status,permissions
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.views import APIView
from django.contrib.auth import login
from .models import *
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import *
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated

class UserRegistrationView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserRegistrationSerializer
    
    def post(self, request, *args, **kwargs):
        print(request.data)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({
            "user": UserRegistrationSerializer(user, context=self.get_serializer_context()).data,
            "message": "User created successfully",
        }, status=status.HTTP_201_CREATED)

class UserLoginView(APIView):
    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)
        
        if user is not None:
            if user.is_active:
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                refresh_token = str(refresh)
                login(request, user)
                content = {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                
                }
                return Response({
                        "user": content,
                        "message": "User login successfully",
                    }, status=status.HTTP_200_OK)
            else:
                return Response({'detail': 'Account is not active'}, status=status.HTTP_403_FORBIDDEN)
        else:
            return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

class PostCreateView(generics.CreateAPIView):
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(author=self.request.user)

class PostPublishView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request, pk, *args, **kwargs):
        try:
            post = Post.objects.get(pk=pk, author=request.user)
        except Post.DoesNotExist:
            return Response({'error': 'Post not found or not authorized'}, status=status.HTTP_404_NOT_FOUND)

        post.published = not post.published  # Toggle published status
        post.save()
        return Response({
            'id': post.id,
            'published': post.published,
            'message': f'Post {"published" if post.published else "unpublished"} successfully'
        }, status=status.HTTP_200_OK)

class PostListView(generics.ListAPIView):
    queryset = Post.objects.filter(published=True)  # Only show published posts
    serializer_class = PostSerializer
    permission_classes = [permissions.IsAuthenticated]  # Only logged-in users can see posts

class PostLikeToggleView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk, *args, **kwargs):
        try:
            post = Post.objects.get(pk=pk)
        except Post.DoesNotExist:
            return Response({'error': 'Post not found'}, status=status.HTTP_404_NOT_FOUND)

        user = request.user
        if user in post.liked_by.all():
            post.liked_by.remove(user)
            post.likes -= 1
            message = 'Unliked'
        else:
            post.liked_by.add(user)
            post.likes += 1
            message = 'Liked'
        
        post.save()
        return Response({'message': message, 'likes': post.likes}, status=status.HTTP_200_OK)