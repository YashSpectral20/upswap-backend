from django.urls import path
from .consumers import ChatConsumer

websocket_urlpatterns = [
    path('ws/uchat/<str:room_uuid>/', ChatConsumer.as_asgi()),
]
