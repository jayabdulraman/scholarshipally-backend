import uuid
from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Chats, Threads, Feedback, Favorites, Scholarships

User = get_user_model()

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('fullname', 'email', 'password')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validate_data):
        user = User.objects.create(**validate_data)
        user.set_password(validate_data['password'])
        user.save()
        return user

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'fullname', 'email', 'password')

class ChatSerializer(serializers.ModelSerializer):
    class Meta:
        model = Chats
        fields = ('id', 'role', 'content', 'metadata', 'searchType', 'threadId')

class ThreadsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Threads
        fields = ('id', 'title', 'path', 'user', 'createdAt')

class FeedbackSerializer(serializers.ModelSerializer):
    class Meta:
        model = Feedback
        fields = ('id', 'value', 'comment', 'chatId', 'userId', 'createdAt')

class FavoritesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Favorites
        fields = ('id', 'name', 'description', 'eligibility', 'value', 'fields', 'deadline', 'website', 'track', 'remind_me', 'userId', 'createdAt')

class UpdateFavoritesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Favorites
        fields = ('id', 'track', 'remind_me')

class CombinedThreadChatSerializer(serializers.Serializer):
    threadId = serializers.UUIDField()
    role = serializers.CharField(max_length=50)
    content = serializers.CharField()
    title = serializers.CharField(max_length=255)
    path = serializers.CharField(max_length=50)
    user = serializers.PrimaryKeyRelatedField(read_only=True)

    def create(self, validated_data):
        thread = Threads.objects.create(
            id = validated_data['threadId'],
            title=validated_data['title'],
            path=validated_data['path'],
            user=self.context['request'].user
        )
        chat = Chats.objects.create(
            threadId=thread,
            role=validated_data['role'],
            content=validated_data['content']
        )
        return {'thread': thread, 'chat': chat}
    
class ScholarshipSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scholarships
        fields = ('id', 'name', 'description', 'eligibility', 'value', 'fields', 'deadline', 'website', 'hostCountry', 'createdAt')
