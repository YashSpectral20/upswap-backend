from django.urls import path

from .views import ChatRequestAPIView

urlpatterns = [
    # Chat requests
    path('get-chat-requests/<str:activity_id>/', ChatRequestAPIView.as_view(), name='get-chat-requests'),
    path('create-chat-request/', ChatRequestAPIView.as_view(), name='create-chat-request'),
    path('accept-chat-request/', ChatRequestAPIView.as_view(), name='accept-chat-request'),
    
]