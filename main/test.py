# from channels.testing import WebsocketCommunicator
# from django.test import TestCase
# from asgiref.sync import sync_to_async
# from upswap.asgi import application
# import uuid
# import asyncio

# class ChatConsumerTestCase(TestCase):
#     def setUp(self):
#         self.loop = asyncio.new_event_loop()
#         asyncio.set_event_loop(self.loop)
#         self.room_uuid = str(uuid.uuid4())

#     def tearDown(self):
#         self.loop.close()

#     async def test_chat_communication(self):
#         # Define the correct path that matches your routing.py
#         communicator_user1 = WebsocketCommunicator(
#             application,
#             f'/ws/chat/{self.room_uuid}/'
#         )

#         # Connect user 1
#         connected_user1, _ = await communicator_user1.connect()
#         self.assertTrue(connected_user1)

#         # Test sending and receiving messages
#         message = "Hello, world!"
#         await communicator_user1.send_json_to({'message': message})
#         response = await communicator_user1.receive_json_from()

#         self.assertEqual(response['message'], message)

#         # Close the WebSocket connection
#         await communicator_user1.disconnect()
