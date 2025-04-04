from django.urls import path

from .views import ChatRequestAPIView, ChatMessageAPIView
  
urlpatterns = [
    # Chat requests
    path('get-chat-requests/<str:activity_id>/', ChatRequestAPIView.as_view(), name='get-chat-requests'),
    path('create-chat-request/', ChatRequestAPIView.as_view(), name='create-chat-request'),
    path('accept-chat-request/', ChatRequestAPIView.as_view(), name='accept-chat-request'),
    
    # Chat messages
    path('get-chat-messages/<str:chat_room_id>/', ChatMessageAPIView.as_view(), name='get-chat-messages'),
]