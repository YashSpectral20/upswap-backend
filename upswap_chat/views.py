from .models import ChatRoom, ChatRequest, ChatMessage
from .serializers import ChatRequestSerializer, ChatRoomSerializer, ChatMessageSerializer, MyInterestedActivitySerializer
from main.serializers import CustomUserSerializer

from main.paginations import CustomPagination
from rest_framework.permissions import IsAuthenticated

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from main.firebase_utils import send_single_fcm_message
from main.models import Device, Activity, CustomUser
from django.db.models import Q
from rest_framework import status

class ChatRequestAPIView(APIView):
    '''
    get() --> Get chat requests for an activity...
    post() --> Create chat requests...
    patch() --> Accept or reject chat requests...
    '''
    def get(self, request, activity_id):
        try:
            chat_requests = ChatRequest.objects.filter(activity=activity_id, is_rejected=False)
            if chat_requests.exists():
                serializer = ChatRequestSerializer(chat_requests, many=True)
                return Response({
                    'message': 'Chat requests retrieved successfully.',
                    'data': serializer.data
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'message': 'No chat requests found for this activity.',
                    'data': {}
                }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'error': str(e),
                'message': 'Chat requests could not be retrieved.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


    def post(self, request, format=None):
        data = request.data
        serializer = ChatRequestSerializer(data=data)
        
        if serializer.is_valid():
            chat_request = serializer.save()

            # ✅ Send notification to the activity admin
            activity_admin = chat_request.activity.created_by
            devices = Device.objects.filter(user=activity_admin)

            if devices.exists():
                for device in devices:
                    send_single_fcm_message(
                        registration_token=device.device_token,
                        title="New Chat Request",
                        body=f"{chat_request.from_user.name} has sent you a chat request for {chat_request.activity.activity_title}.",
                        data={
                            "type": "chat_request_received",
                            "activity_id": str(chat_request.activity.activity_id),
                            "from_user_id": str(chat_request.from_user.id),
                        }
                    )

            return Response({
                'message': 'Chat request has been sent.',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED)

        # ✅ If serializer is invalid, return immediately
        return Response({
            'message': 'Chat request could not be sent.',
            'error': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

        
    def patch(self, request, format=None):
        data = request.data
        if not isinstance(data, list):
            return Response({
                'error': 'Data must be a list of chat requests.'
            }, status=status.HTTP_400_BAD_REQUEST)

        response_data = []
        errors = []

        for item in data:
            try:
                chat_request = ChatRequest.objects.filter(id=item['id']).first()
                if chat_request:
                    is_undo = item.get('is_undo', False)
                    is_accepted = item.get('is_accepted', False)

                    if is_undo:
                        # ✅ Undo logic: reset the status
                        chat_request.is_accepted = False
                        chat_request.is_clicked = False
                        chat_request.is_undo = True
                        chat_request.save()
                        response_data.append({
                            'id': chat_request.id,
                            'message': 'Chat request undone.',
                            'chat_room': None
                        })
                    elif is_accepted:
                        # ✅ Accept logic
                        chat_room = chat_request.accept()
                        chat_request.is_undo = False
                        chat_request.is_rejected = False
                        chat_request.save()
                        
                    # After accepting, send notification to the user
                    user = chat_request.from_user
                    devices = Device.objects.filter(user=user)

                    if devices.exists():
                        for device in devices:
                            send_single_fcm_message(
                                registration_token=device.device_token,
                                title="Chat Request Accepted",
                                body=f"Your chat request for {chat_request.activity.activity_title} has been accepted.",
                                data={
                                    "type": "chat_request_accepted",
                                    "activity_id": str(chat_request.activity.activity_id),
                                    "chat_room_id": str(chat_room.id),
                                }
                            )
                        serializer = ChatRoomSerializer(chat_room)
                        response_data.append({
                            'id': chat_request.id,
                            'chat_room': serializer.data
                        })
                    else:
                        # ✅ Reject logic
                        chat_request.is_accepted = False
                        chat_request.is_clicked = True
                        chat_request.is_undo = False
                        chat_request.is_rejected = True
                        chat_request.save()
                        response_data.append({
                            'id': chat_request.id,
                            'chat_room': None
                        })
            except Exception as e:
                errors.append({
                    'id': item.get('id'),
                    'error': str(e)
                })

        response = {
            'message': 'Processed chat requests.',
            'accepted': response_data,
        }

        if errors:
            response['errors'] = errors

        return Response(response, status=status.HTTP_200_OK)


class ChatMessageAPIView(APIView, CustomPagination):
    '''
    get messages from a ChatRoom.
    '''
    pagination_class = CustomPagination
    serializer_class = ChatMessageSerializer

    def get(self, request, chat_room_id):
        try:
            messages = ChatMessage.objects.filter(chat_room=chat_room_id)
            
            # ✅ Mark all retrieved messages as seen by the current user
            for message in messages.exclude(seen_by=request.user):
                message.seen_by.add(request.user)
            
            page = self.paginate_queryset(messages, request, view=self)
            if page is not None:
                serializer = self.serializer_class(page, many=True)
                return self.get_paginated_response(serializer.data)

            return Response({
                'message': 'No chat messages were found.',
                'data': {}
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'error': str(e),
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
class MyEventsAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        activities = Activity.objects.filter(created_by=user)
        result = []

        for activity in activities:
            accepted_requests = ChatRequest.objects.filter(activity=activity, is_accepted=True)
            participants = [req.from_user for req in accepted_requests]

            for participant in participants:
                chatroom = ChatRoom.objects.filter(
                    activity=activity,
                    participants=participant
                ).distinct().first()

                last_message = None
                chatroom_id = None
                if chatroom:
                    chatroom_id = str(chatroom.id)
                    last_msg = ChatMessage.objects.filter(chat_room=chatroom).order_by('-created_at').first()
                    if last_msg:
                        last_message = {
                            "sender_name": last_msg.sender.name,
                            "content": last_msg.content,
                            "created_at": last_msg.created_at.strftime("%Y-%m-%d %H:%M:%S")
                        }

                result.append({
                    "activity_id": str(activity.activity_id),
                    "activity_title": activity.activity_title,
                    "thumbnail": activity.uploaded_images[0].get('thumbnail') if activity.uploaded_images else None,
                    "participants": [
                        {
                            "id": participant.id,
                            "name": participant.name,
                            "username": participant.username,
                            "profile_pic": participant.profile_pic if participant.profile_pic else None,
                            "chatroom_id": chatroom_id  # ✅ Add this
                        }
                    ],
                    "last_message": last_message
                })

        return Response({
            "message": "My Events retrieved successfully.",
            "data": result
        }, status=status.HTTP_200_OK)


class MyInterestedActivitiesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            chat_requests = ChatRequest.objects.filter(
                from_user=request.user,
                is_accepted=True,
                is_rejected=False
            ).select_related('activity', 'activity__created_by')

            serializer = MyInterestedActivitySerializer(chat_requests, many=True)
            return Response({
                'message': 'My interested activities fetched successfully.',
                'data': serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'error': str(e),
                'message': 'Failed to fetch interested activities.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
class UnseenMessagesAPIView(APIView):
    """
    GET: /api/chat/chatrooms/<uuid:chat_room_id>/unseen/
    Returns unseen message count for each participant in the chatroom.
    """

    def get(self, request, chat_room_id):
        try:
            chat_room = ChatRoom.objects.get(id=chat_room_id)
            participants = chat_room.participants.all()

            unseen_counts = {}
            for user in participants:
                count = ChatMessage.objects.filter(
                    chat_room=chat_room
                ).exclude(seen_by=user).exclude(sender=user).count()

                unseen_counts[str(user.id)] = {
                    "user": user.name,
                    "unseen_messages": count
                }

            return Response({
                'message': 'Unseen message counts fetched.',
                'data': unseen_counts
            }, status=status.HTTP_200_OK)

        except ChatRoom.DoesNotExist:
            return Response({
                'error': 'Chat room not found.'
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)