from django.urls import path
from .import views
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from django.urls import re_path

app_name = 'api'

schema_view = get_schema_view(
    openapi.Info(
        title="Scholar Backend",
        default_version='v1',
        description="The backend of scholar",
        terms_of_service="#",
        contact=openapi.Contact(email="ajalloh6@asu.edu"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
)

urlpatterns = [
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    re_path(r'^docs/$', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    re_path(r'^redoc/$', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    path('login/', views.LoginAPI.as_view()),
    path('register/', views.RegisterAPI.as_view()),
    path('get-user/', views.GetUserAPI.as_view()),
    path('thread/<str:pk>/', views.ThreadsAPI.as_view()),
    path('user-threads/<int:pk>/', views.GetUserThreadsAPI.as_view()),
    path('delete-thread/<str:pk>/', views.DeleteThread.as_view()),
    path('shared-thread/<str:pk>/', views.GetSharedThreadsAPI.as_view()),
    path('new-thread/', views.StartNewThreadAPI.as_view()),
    path('feedback/', views.FeedbackAPI.as_view()),
    path('favorites/', views.AddFavoritesAPI.as_view()),
    path('favorites/<int:pk>/', views.FavoritesAPI.as_view()),
    path('scholarship/', views.SubmitNewScholarship.as_view()),
    path('rate-limited/', views.RateLimitedAPI.as_view()),
]