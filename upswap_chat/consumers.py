import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async

from .models import ChatMessage, ChatRoom, CustomUser

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_uuid = self.scope['url_route']['kwargs']['room_uuid']
        self.chat_room = await database_sync_to_async(ChatRoom.objects.get)(id=self.room_uuid)
        self.room_group_name = f'chat_{self.room_uuid}'
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        text_data_json = json.loads(text_data)
        message = text_data_json.get('message', '')

        await self.create_message(
            chat_room=self.chat_room,
            sender=self.scope['user'],
            content=message
        )

        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'chat_message',
                'message': message
            }
        )

    async def chat_message(self, event):
        message = event['message']

        await self.send(text_data=json.dumps({
            'message': message
        }))

    @database_sync_to_async
    def create_message(self, chat_room, sender, content):
        return ChatMessage.objects.create(
            chat_room=chat_room, 
            sender=sender, 
            content=content
        )