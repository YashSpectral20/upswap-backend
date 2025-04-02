from .models import ChatRoom, ChatRequest
from .serializers import ChatRequestSerializer

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
        try:
            chat_request = ChatRequest.objects.filter(id=data['id']).first() 
            if chat_request:
                if data['is_accepted']:
                    chat_room = chat_request.accept()
                    return Response({
                        'message': 'Chat request accepted & chat room has been created.',
                        'data': chat_room
                    }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'error': str(e),
                'message': 'Chat request could not be accepted, please try again later.'
            }, status=status.HTTP_400_BAD_REQUEST)  