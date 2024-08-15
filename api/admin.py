from django.contrib import admin
from .models import User, Chats, Threads, Feedback, Favorites, Scholarships, RateLimit

# Register your models here.
@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('id', 'fullname', 'email', 'is_active', 'date_joined')

@admin.register(Chats)
class ChatAdmin(admin.ModelAdmin):
    list_display = ('id', 'role', 'content', 'threadId', 'createdAt')
    list_filter = ('role',)
    ordering = ('-createdAt',)

@admin.register(Threads)
class ThreadAdmin(admin.ModelAdmin):
    list_display = ('id', 'title', 'path', 'user', 'createdAt')
    ordering = ('-createdAt',)

@admin.register(Feedback)
class FeedbackAdmin(admin.ModelAdmin):
    list_display = ('id', 'chatId', 'comment', 'userId', 'createdAt')

@admin.register(Favorites)
class FavouritesAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'value', 'deadline', 'website', 'updatedAt')

@admin.register(Scholarships)
class FavouritesAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'value', 'deadline', 'website', 'createdAt')

@admin.register(RateLimit)
class RateLimitAdmin(admin.ModelAdmin):
    list_display = ('id', 'last_request', 'request_count', 'user', 'createdAt')


