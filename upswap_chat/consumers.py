import json
from channels.generic.websocket import AsyncWebsocketConsumer
from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.utils import timezone
from channels.db import database_sync_to_async

from .models import ChatRoom, ChatMessage  # Adjust this import as per your project

User = get_user_model()

class ChatConsumer(AsyncWebsocketConsumer):

    async def connect(self):
        self.room_uuid = self.scope['url_route']['kwargs']['room_uuid']
        self.session_id = self.scope['url_route']['kwargs']['session_id']

        # Get ChatRoom instance
        self.chat_room = await database_sync_to_async(ChatRoom.objects.get)(id=self.room_uuid)
        self.room_group_name = f'chat_{self.room_uuid}'

        # Get user from session_id
        self.user = await self.get_user_from_session(self.session_id)

        if self.user is None:
            await self.close()
            return

        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()

        # participants = await database_sync_to_async(list)(self.chat_room.participants.all())
        # # Prepare participant data
        # participant_data = [
        #     {
        #         "id": str(participant.id),
        #         "username": participant.username
        #     }
        #     for participant in participants
        # ]

        # # Send participant data to the group
        # await self.channel_layer.group_send(
        #     self.room_group_name,
        #     {
        #         'type': 'user_info',
        #         'participants': participant_data
        #     }
        # )

    @database_sync_to_async
    def get_user_from_session(self, session_id):
        try:
            session = Session.objects.get(session_key=session_id)
            session_data = session.get_decoded()
            user_id = session_data.get('_auth_user_id')
            return User.objects.get(id=user_id)
        except (Session.DoesNotExist, User.DoesNotExist, KeyError):
            return None

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        text_data_json = json.loads(text_data)
        message = text_data_json.get('message', '')
        user = self.scope['user']

        await self.create_message(
            chat_room=self.chat_room,
            sender=self.user,
            content=message
        )

        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'chat_message',
                'message': message,
                'sender_id': str(self.user.id),
                'sent_at': timezone.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        )

    @database_sync_to_async
    def create_message(self, chat_room, sender, content):
        return ChatMessage.objects.create(
            chat_room=chat_room,
            sender=sender,
            content=content
        )

    async def chat_message(self, event):
        await self.send(text_data=json.dumps({
            'message': event['message'],
            'sender': event['sender_id'],
            'sent_at': event['sent_at']
        }))

    # async def user_info(self, event):
    #         # Send participant data to WebSocket client
    #         await self.send(text_data=json.dumps({
    #             'type': 'user_info',
    #             'participants': event['participants']
    #         }))



# import json
# from channels.generic.websocket import AsyncWebsocketConsumer
# from channels.db import database_sync_to_async

# from django.utils import timezone

# from .models import ChatMessage, ChatRoom, CustomUser

# class ChatConsumer(AsyncWebsocketConsumer):
#     async def connect(self):
#         self.room_uuid = self.scope['url_route']['kwargs']['room_uuid']
#         self.session_id = self.scope['url_route']['kwargs']['session_id'] #session id le liya
        
#         self.chat_room = await database_sync_to_async(ChatRoom.objects.get)(id=self.room_uuid)
#         self.room_group_name = f'chat_{self.room_uuid}'
#         await self.channel_layer.group_add(
#             self.room_group_name,
#             self.channel_name
#         )
#         await self.accept()

#     async def disconnect(self, close_code):
#         await self.channel_layer.group_discard(
#             self.room_group_name,
#             self.channel_name
#         )

#     async def receive(self, text_data):
#         text_data_json = json.loads(text_data)
#         message = text_data_json.get('message', '')
#         user = self.scope['user']
#         await self.create_message(
#             chat_room=self.chat_room,
#             sender=user,
#             content=message
#         )

#         await self.channel_layer.group_send(
#             self.room_group_name,
#             {
#                 'type': 'chat_message',
#                 'message': message,
#                 'sender': user.username,
#                 'sent_at': timezone.now().strftime('%Y-%m-%d %H:%M:%S')
#             }
#         )

#     async def chat_message(self, event):

#         await self.send(text_data=json.dumps({
#             'message': event['message'],
#             'sender': event['sender'],
#             'sent_at': event['sent_at']
#         }))

#     @database_sync_to_async
#     def create_message(self, chat_room, sender, content):
#         return ChatMessage.objects.create(
#             chat_room=chat_room, 
#             sender=sender, 
#             content=content
#         )