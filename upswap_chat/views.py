from .models import ChatRoom, ChatRequest, ChatMessage
from .serializers import ChatRequestSerializer, ChatRoomSerializer, ChatMessageSerializer

from main.paginations import CustomPagination

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

class ChatRequestAPIView(APIView):
    '''
    get() --> Get chat requests for an activity...
    post() --> Create chat requests...
    patch() --> Accept or reject chat requests...
    '''
    def get(self, request, activity_id):
        try:
            chat_requests = ChatRequest.objects.filter(activity=activity_id)
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
        try:
            serializer = ChatRequestSerializer(data=data)
            if serializer.is_valid():
                serializer.save()

                return Response({
                    'message': 'Chat request has been sent.',
                    'data': serializer.data
                }, status=status.HTTP_201_CREATED)
            
            return Response({
                'error': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'message': 'Chat request could not be sent.',
                'error': str(e)
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
                if chat_request and item.get('is_accepted', False):
                    chat_room = chat_request.accept()
                    serializer = ChatRoomSerializer(chat_room)
                    response_data.append({
                        'id': chat_request.id,
                        'chat_room': serializer.data
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

        if errors:  # Add errors only if any exist
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