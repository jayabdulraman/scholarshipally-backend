from django.http import Http404
from django.shortcuts import get_object_or_404
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import Chats, RateLimit, Threads, Favorites
from django.forms.models import model_to_dict
from django.contrib.auth import get_user_model
from .serializers import (
    RegisterSerializer, ChatSerializer, ThreadsSerializer, FeedbackSerializer, FavoritesSerializer,
    CombinedThreadChatSerializer, UpdateFavoritesSerializer, ScholarshipSerializer
)
from drf_yasg.utils import swagger_auto_schema
from collections import defaultdict
from functools import wraps
from django.core.cache import cache
from django.http import JsonResponse
from django.utils import timezone
from datetime import timedelta
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

User = get_user_model()

# def rate_limit(view_func):
#     @wraps(view_func)
#     def wrapped_view(request, *args, **kwargs):
#         user = getattr(request, 'user', None)
#         if user and user.is_authenticated:
#             identifier = user.id
#         else:
#             identifier = request.META['REMOTE_ADDR']

#         today = datetime.date.today().isoformat()
#         cache_key = f"{identifier}_{today}_requests"
        
#         request_count = cache.get(cache_key, 0)
#         if request_count > 1:
#             print("RATE LIMIT EXCEEDED:", identifier, request_count)
#             return JsonResponse({"error": "Rate limit exceeded. Try again tomorrow."}, status=429)
        
#         cache.incr(cache_key, 1)
#         if request_count == 0:
#             cache.expire(cache_key, 60 * 60 * 24)

#         return view_func(request, *args, **kwargs)

#     return wrapped_view

# API for authentication
class LoginAPI(ObtainAuthToken):
    permission_classes = [AllowAny]

    def get_user(self, id):
        try:
            return User.objects.filter(id=id)
        except User.DoesNotExist:
            raise Http404
    
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)

        return Response({
            'token': token.key,
            'user_id': user.pk,
            'fullname': user.fullname,
            "email": user.email,
            'is_active': user.is_active,
        })

# API for registration
class RegisterAPI(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(operation_description="The API to Register", request_body=RegisterSerializer)
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)

        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            return Response({"user": serializer.data}, status=status.HTTP_201_CREATED)
        else:
            return Response({"message": "Registration fail"}, status=status.HTTP_400_BAD_REQUEST)

class GetUserAPI(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        try:
            email = request.data["email"]
            user = User.objects.get(email=email)
            return Response({'email': user.email})
        except:
            return Response(False)
    
# API for registration
class FeedbackAPI(APIView):
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(operation_description="The API to save chat response feedback", request_body=FeedbackSerializer)
    def post(self, request):
        serializer = FeedbackSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"user": serializer.data}, status=status.HTTP_201_CREATED)
        else:
            return Response({"message": "Failed saving feedback"}, status=status.HTTP_400_BAD_REQUEST)

# API for registration
class AddFavoritesAPI(APIView):
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(operation_description="The API to post new favorite scholarships", request_body=FavoritesSerializer)
    def post(self, request):
        serializer = FavoritesSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"user": serializer.data}, status=status.HTTP_201_CREATED)
        else:
            return Response({"message": "Failed saving favorite"}, status=status.HTTP_400_BAD_REQUEST)
        
class FavoritesAPI(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, pk):
        try:
            user = User.objects.get(id=pk)
        except:
            return Response({'error': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)

        user_favorites = Favorites.objects.filter(user_id=user).values('id', 'name', 'description', 'eligibility', 'value', 'fields', 
                                                                           'deadline', 'website', 'track', 'remind_me', 'user_id', 'created_at')
        user_favorites_list = list(user_favorites)
        return Response(user_favorites_list, status=status.HTTP_200_OK)
    
    @swagger_auto_schema(operation_description="The API to update existing favorite scholarships to track", request_body=UpdateFavoritesSerializer)
    def patch(self, request, pk):
        data = request.data
        try:
            favorite = Favorites.objects.get(id=data['id'])
            if (model_to_dict(favorite)['user_id'] != pk):
                return Response({'error': 'Owner rights is required'}, status=status.HTTP_404_NOT_FOUND)

            for field, value in data.items():
                setattr(favorite, field, value)
            favorite.track = favorite.track
            favorite.remind_me = favorite.remind_me
            favorite.save()
            return Response(model_to_dict(favorite), status=status.HTTP_201_CREATED)

        except:
            return Response({"status": "Bad request"}, status=status.HTTP_400_BAD_REQUEST)


class ThreadsAPI(APIView):
    permission_classes = [IsAuthenticated]
    # get specific thread with user id and thread id
    def get(self, request, pk):
        print("Thread ID:", pk)
        try:
            thread_id = Threads.objects.get(id=pk)
        except:
            return Response({'error': 'Thread does not exist'}, status=status.HTTP_404_NOT_FOUND)
        # if thread belongs to user, return thread
        if thread_id.user == request.user:
            chats = Chats.objects.filter(threadId=thread_id).values('id', 'threadId__title', 'role', 'content', 'metadata', 'searchType',
                                                                     'threadId', 'threadId__createdAt', 'threadId__user', 'threadId__path')
            # Using defaultdict to group messages
            grouped_data = defaultdict(lambda: {"messages": []})
            for chat in chats:
                main_key = (chat["threadId"], chat["threadId__title"], chat["threadId__user"], chat["threadId__createdAt"], chat["threadId__path"])
                # check if metadata object is not None, pass object as content
                if chat["searchType"] == "DatabaseSearch":
                    if chat["metadata"] is not None:
                        grouped_data[main_key]["messages"].append({
                            "id": chat["id"],
                            "role": chat["role"],
                            "content": chat["metadata"],
                            "metadata": chat["metadata"],
                            "searchType": chat["searchType"],
                        })
                    else:
                        grouped_data[main_key]["messages"].append({
                            "id": chat["id"],
                            "role": chat["role"],
                            "content": chat["content"],
                            "metadata": chat["metadata"],
                            "searchType": chat["searchType"],
                        })
                elif chat["searchType"] == "GoogleSearch":
                    # if chat["metadata"] is not None:
                    grouped_data[main_key]["messages"].append({
                        "id": chat["id"],
                        "role": chat["role"],
                        "content": chat["content"],
                        "metadata": chat["metadata"],
                        "searchType": chat["searchType"],
                    })

            # Transforming grouped data to the desired format
            thread_chats = []
            for (threadId, title, userId, createdAt, path), value in grouped_data.items():
                thread_chats.append({
                    "id": threadId,
                    "title": title,
                    "userId": userId,
                    "createdAt": createdAt,
                    "messages": value["messages"],
                    "path": path
                })
            print("LENGTH OF THREADS:", len(thread_chats))
            # return first element which is a dict
            return Response(thread_chats[0], status=status.HTTP_200_OK)

    #@swagger_auto_schema(operation_description="The API to create a new chat in a thread", request_body=CombinedThreadChatSerializer)
    def post(self, request, *args, **kwargs):
        thread_id = request.data.get("id", None)
        # add chat to thread
        if thread_id != None and Threads.objects.filter(id=thread_id).exists():
            thread = Threads.objects.get(id=thread_id)
            if thread.user == request.user:
                data =  request.data
                messages = data["messages"]
                IDs = []
                for index, message in enumerate(messages):
                    chatId = message["id"]
                    if Chats.objects.filter(id=chatId).exists():
                        continue
                        #return Response({f"Chat ID: {chatId} exists! Creation Failed!"}, status=status.HTTP_403_FORBIDDEN)
                    else:
                        if isinstance(message["content"], str) and message["metadata"] is None:
                            chat = Chats.objects.create(
                                id=chatId,
                                threadId=thread,
                                role=message["role"],
                                content=message["content"],
                                searchType=message["searchType"],
                            )
                        elif isinstance(message["content"], str) and message["metadata"] is not None:
                            chat = Chats.objects.create(
                                id=chatId,
                                threadId=thread,
                                role=message["role"],
                                content=message["content"],
                                metadata=message["metadata"],
                                searchType=message["searchType"],
                            )
                        elif isinstance(message["content"], (list, dict)):
                            chat = Chats.objects.create(
                                id=chatId,
                                threadId=thread,
                                role=message["role"],
                                content=message["content"],
                                metadata=message["content"],
                                searchType=message["searchType"],
                            )
                        IDs.append(chatId)
                return Response({"Chat Created with IDs": IDs}, status=status.HTTP_201_CREATED)
            else:
                return Response({'error': 'Thread does not belong to this user!'}, status=status.HTTP_400_BAD_REQUEST)
        # create new thread and chat
        else:
            try:
                data =  request.data
                # create new thread
                user_id = data.get("userId")
                # get user that owns the thread
                user = get_object_or_404(User, id=user_id)
                thread = Threads.objects.create(
                    id = data["id"],
                    title = data["title"],
                    path = data["path"],
                    user = user
                )
                # add chat to thread
                messages = data["messages"]
                if isinstance(messages[-1]["content"], str) and messages[-1]["metadata"] is None:
                    chat = Chats.objects.create(
                        id=chatId,
                        threadId=thread,
                        role=messages[-1]["role"],
                        content=messages[-1]["content"],
                        searchType=messages[-1]["searchType"],
                    )
                    print("CHAT DATA:", chat)
                elif isinstance(messages[-1]["content"], str) and messages[-1]["metadata"] is not None:
                    chat = Chats.objects.create(
                        id=chatId,
                        threadId=thread,
                        role=messages[-1]["role"],
                        content=messages[-1]["content"],
                        metadata=messages[-1]["metadata"],
                        searchType=messages[-1]["searchType"],
                    )
                elif isinstance(messages[-1]["content"], (list, dict)):
                    chat = Chats.objects.create(
                        id=chatId,
                        threadId=thread,
                        role=messages[-1]["role"],
                        content=messages[-1]["content"],
                        metadata=messages[-1]["content"],
                        searchType=messages[-1]["searchType"],
                    )
                return Response({
                    'Thread Created': thread.id,
                    'Chat Created': chat.id
                }, status=status.HTTP_201_CREATED)
            except Exception as e:
                return Response({"Error": str(e)})

class GetUserThreadsAPI(APIView):
    permission_classes = [IsAuthenticated]
    # get all threads with chats for specific user
    def get(self, request, pk):
        #print("User:", pk)
        try:
            user = get_object_or_404(User, pk=pk)
            #print("User:", user)
            threads = Threads.objects.filter(user=user).values('id')
            # print("Threads:", threads)
            thread_chats = []
            for thread in threads:
                chats = Chats.objects.filter(threadId=thread["id"]).values('id', 'threadId__title', 'role', 'content', 'metadata', 'searchType',
                                                                     'threadId', 'threadId__createdAt', 'threadId__user', 'threadId__path')
                #print("Thread ID:", thread["id"])
                # Using defaultdict to group messages
                grouped_data = defaultdict(lambda: {"messages": []})
                for chat in chats:
                    main_key = (chat["threadId"], chat["threadId__title"], chat["threadId__user"], chat["threadId__createdAt"], chat["threadId__path"])
                     # check if metadata object is not None, pass object as content
                    if chat["searchType"] == "DatabaseSearch":
                        if chat["metadata"] is not None:
                            grouped_data[main_key]["messages"].append({
                                "id": chat["id"],
                                "role": chat["role"],
                                "content": chat["metadata"],
                                "metadata": chat["metadata"],
                                "searchType": chat["searchType"],
                            })
                        else:
                            grouped_data[main_key]["messages"].append({
                                "id": chat["id"],
                                "role": chat["role"],
                                "content": chat["content"],
                                "metadata": chat["metadata"],
                                "searchType": chat["searchType"],
                            })
                    elif chat["searchType"] == "GoogleSearch":
                        if chat["metadata"] is not None:
                            grouped_data[main_key]["messages"].append({
                                "id": chat["id"],
                                "role": chat["role"],
                                "content": chat["content"],
                                "metadata": chat["metadata"],
                                "searchType": chat["searchType"],
                            })

                # Transforming grouped data to the desired format
                for (threadId, title, userId, createdAt, path), value in grouped_data.items():
                    thread_chats.append({
                        "id": threadId,
                        "title": title,
                        "userId": userId,
                        "createdAt": createdAt,
                        "messages": value["messages"],
                        "path": path
                    })
            
            return Response(thread_chats, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_404_NOT_FOUND)

class DeleteThread(APIView):
    permission_classes = [IsAuthenticated]    
    def delete(self, request, pk):
        try:
            thread  = Threads.objects.get(id=pk)
            if request.user == thread.user:
                thread.delete()
                return Response({"Success:": f"Thread with ID: {pk} successfully deleted!"})
            else:
                return Response({"Error:": "Unauthorized!"}, status=status.HTTP_401_UNAUTHORIZED)
        except Threads.DoesNotExist:
            return Response({"Error": "Thread does not exist!"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"Error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class GetSharedThreadsAPI(APIView):
    permission_classes = [AllowAny]
    # get specific thread with user id and thread id
    def get(self, request, pk):
        print("Get Shared Thread ID:", pk)
        try:
            thread_id = Threads.objects.get(id=pk)
            # if thread belongs to user, return thread
            chats = Chats.objects.filter(threadId=thread_id).values('id', 'threadId__title', 'role', 'content', 'metadata', 'searchType',
                                                                        'threadId', 'threadId__createdAt', 'threadId__user', 'threadId__path')
            # Using defaultdict to group messages
            grouped_data = defaultdict(lambda: {"messages": []})
            for chat in chats:
                main_key = (chat["threadId"], chat["threadId__title"], chat["threadId__user"], chat["threadId__createdAt"], chat["threadId__path"])
                # Define the condition for filtering out message with tool-call in assistant
                should_remove = (
                    chat["role"] == "assistant" and
                    isinstance(chat["content"], str) and
                    "tool-call" in chat["content"]  # Remove if "tool-call" is included
                )

                # If the condition is met, skip adding the chat to the messages
                if should_remove:
                    continue

                if chat["searchType"] == "DatabaseSearch":
                    if chat["metadata"] is not None:
                        grouped_data[main_key]["messages"].append({
                            "id": chat["id"],
                            "role": chat["role"],
                            "content": chat["metadata"],
                            "metadata": chat["metadata"],
                            "searchType": chat["searchType"],
                        })
                    else:
                        grouped_data[main_key]["messages"].append({
                            "id": chat["id"],
                            "role": chat["role"],
                            "content": chat["content"],
                            "metadata": chat["metadata"],
                            "searchType": chat["searchType"],
                        })
                elif chat["searchType"] == "GoogleSearch":
                    # if chat["metadata"] is not None:
                    grouped_data[main_key]["messages"].append({
                        "id": chat["id"],
                        "role": chat["role"],
                        "content": chat["content"],
                        "metadata": chat["metadata"],
                        "searchType": chat["searchType"],
                    })

            # Transforming grouped data to the desired format
            thread_chats = []

            for (threadId, title, userId, createdAt, path), value in grouped_data.items():
                thread_chats.append({
                    "id": threadId,
                    "title": title,
                    "userId": userId,
                    "createdAt": createdAt,
                    "messages": value["messages"],
                    "path": path
                })
            print("SHARED CHAT:", thread_chats[0])
            return Response(thread_chats[0], status=status.HTTP_200_OK)
        except:
            return Response({'error': 'Thread does not exist'}, status=status.HTTP_404_NOT_FOUND)
        
class StartNewThreadAPI(APIView):
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(operation_description="The API to create new thread", request_body=CombinedThreadChatSerializer)
    def post(self, request):
        serializer = CombinedThreadChatSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            result = serializer.save()
            thread_data = ThreadsSerializer(result['thread']).data
            chat_data = ChatSerializer(result['chat']).data
            return Response({
                'Thread': thread_data,
                'chat': chat_data
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class SubmitNewScholarship(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = ScholarshipSerializer(data=request.data)
        if serializer.is_valid():
            result = serializer.save()
            return Response({"result": serializer.data}, status=status.HTTP_201_CREATED)
        else:
            return Response({"message": "Failed saving scholarship"}, status=status.HTTP_400_BAD_REQUEST)


class RateLimitedAPI(APIView):
    RATE_LIMIT = 4  # requests per minute
    WINDOW_SIZE = 60  # seconds

    def get(self, request):
        user = request.user
        now = timezone.now()
        
        rate_limit, created = RateLimit.objects.get_or_create(
            user=user,
            defaults={'last_request': now}
        )
        print("RATE LIMIT SECTION:", rate_limit, created)
        
        # Check if the window has passed and reset if necessary
        if (now - rate_limit.last_request).total_seconds() > self.WINDOW_SIZE:
            rate_limit.request_count = 0
            rate_limit.last_request = now
        
        if rate_limit.request_count > self.RATE_LIMIT:
            reset_time = rate_limit.last_request + timedelta(seconds=self.WINDOW_SIZE)
            headers = {
                'X-RateLimit-Limit': str(self.RATE_LIMIT),
                'X-RateLimit-Remaining': '0',
                'X-RateLimit-Reset': str(int((reset_time - now).total_seconds()))
            }
            return Response({"detail": "Rate limit exceeded"}, status=status.HTTP_429_TOO_MANY_REQUESTS, headers=headers)
        
        rate_limit.request_count += 1
        rate_limit.save()
        
        remaining = self.RATE_LIMIT - rate_limit.request_count
        reset_time = rate_limit.last_request + timedelta(seconds=self.WINDOW_SIZE)
        headers = {
            'X-RateLimit-Limit': str(self.RATE_LIMIT),
            'X-RateLimit-Remaining': str(remaining),
            'X-RateLimit-Reset': str(int((reset_time - now).total_seconds()))
        }
        return Response(headers=headers)