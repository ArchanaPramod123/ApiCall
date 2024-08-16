from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from .models import *

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    class Meta:
        model = User
        fields = ('full_name', 'email', 'username', 'phone', 'password')

    def create(self, validated_data):
        user = User.objects.create_user(
            full_name=validated_data['full_name'],
            email=validated_data['email'],
            username=validated_data['username'],
            phone=validated_data.get('phone'),
            password=validated_data['password']
        )
        return user


class PostSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(format="%d-%m-%Y")  # Custom date format

    class Meta:
        model = Post
        fields = ['id', 'author', 'title', 'description', 'tags', 'created_at','published','likes','liked_by']
        read_only_fields = ['author', 'created_at']

    def create(self, validated_data):
        request = self.context.get('request')
        validated_data['author'] = request.user
        return super().create(validated_data)