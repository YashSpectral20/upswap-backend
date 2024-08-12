from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import (
    RegisterView, LoginView, VerifyOTPView, 
    ActivityListCreateView, ActivityRetrieveUpdateDestroyView, 
    ActivityImageUploadView, ChatRoomCreateView, ChatRoomRetrieveView,
    ChatMessageCreateView, ChatMessageListView
)

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    ########
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('activities/', ActivityListCreateView.as_view(), name='activity-list-create'),
    path('activities/<uuid:pk>/', ActivityRetrieveUpdateDestroyView.as_view(), name='activity-detail'),
    path('activities/upload-image/', ActivityImageUploadView.as_view(), name='activity-image-upload'),

    # Chat Room URLs
    path('chat-rooms/', ChatRoomCreateView.as_view(), name='chat-room-create'),
    path('chat-rooms/<uuid:pk>/', ChatRoomRetrieveView.as_view(), name='chat-room-detail'),

    # Chat Message URLs
    path('chat-rooms/<uuid:chat_room_id>/messages/', ChatMessageListView.as_view(), name='chat-message-list'),
    path('chat-messages/', ChatMessageCreateView.as_view(), name='chat-message-create'),
]
