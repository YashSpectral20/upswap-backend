from django.urls import path
from .consumers import ChatConsumer

websocket_urlpatterns = [
    path('ws/uchat/<str:room_uuid>/<str:session_id>/', ChatConsumer.as_asgi()),
]
