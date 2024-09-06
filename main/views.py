from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.authtoken.models import Token  # Import Token from rest_framework
from .models import CustomUser, Activity, ChatRoom, ChatMessage, ChatRequest, VendorKYC, ActivityImage
from .serializers import (
    CustomUserSerializer, VerifyOTPSerializer, LoginSerializer,
    ActivitySerializer, ActivityImageSerializer, ChatRoomSerializer, ChatMessageSerializer,
    ChatRequestSerializer, VendorKYCSerializer
)
from .utils import generate_otp 
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed

class RegisterView(generics.CreateAPIView):
    serializer_class = CustomUserSerializer
    permission_classes = [AllowAny]  # No authentication required for registration

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # Generate and send OTP
        generate_otp(user)

        # Generate JWT tokens for the user
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        return Response({
            'user': CustomUserSerializer(user, context=self.get_serializer_context()).data,
            'refresh': str(refresh),
            'access': access_token,
            'message': 'OTP sent successfully for login. Use the access token for OTP verification.'
        }, status=status.HTTP_201_CREATED)

class VerifyOTPView(generics.GenericAPIView):
    serializer_class = VerifyOTPSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validated_data, status=status.HTTP_200_OK)



class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']  # Ensure 'user' is correctly accessed
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        return Response({
            'id': user.id,
            'name': user.get_full_name(),  # Using the updated get_full_name method
            'email': user.email,
            'phone_number': user.phone_number,
            'date_of_birth': user.date_of_birth,
            'gender': user.gender,
            'country_code': user.country_code,
            'dial_code': user.dial_code,
            'country': user.country,
            'refresh': str(refresh),
            'access': access_token
        }, status=status.HTTP_200_OK)
    
class CustomUserCreateView(APIView):
    """
    API view for creating a new CustomUser (requires authentication).
    """
    authentication_classes = [JWTAuthentication] 
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'CustomUser created successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ActivityListCreateView(APIView):
    """
    API view for listing and creating activities (requires authentication).
    """
    authentication_classes = [JWTAuthentication] 
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        activities = Activity.objects.all()
        serializer = ActivitySerializer(activities, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        serializer = ActivitySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Activity created successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ActivityRetrieveUpdateDestroyView(APIView):
    """
    API view for retrieving, updating, and deleting a specific activity (requires authentication).
    """
    authentication_classes = [JWTAuthentication] 
    permission_classes = [IsAuthenticated]

    def get(self, request, pk, *args, **kwargs):
        activity = Activity.objects.get(pk=pk)
        serializer = ActivitySerializer(activity)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk, *args, **kwargs):
        activity = Activity.objects.get(pk=pk)
        serializer = ActivitySerializer(activity, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Activity updated successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, *args, **kwargs):
        activity = Activity.objects.get(pk=pk)
        activity.delete()
        return Response({'message': 'Activity deleted successfully'}, status=status.HTTP_204_NO_CONTENT)


class ActivityImageCreateView(APIView):
    """
    API view for creating activity images (requires authentication).
    """
    authentication_classes = [JWTAuthentication] 
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = ActivityImageSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Activity image created successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChatRoomCreateView(APIView):
    """
    API view for creating chat rooms (requires authentication).
    """
    authentication_classes = [JWTAuthentication] 
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = ChatRoomSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Chat room created successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChatRoomRetrieveView(APIView):
    """
    API view for retrieving a specific chat room (requires authentication).
    """
    authentication_classes = [JWTAuthentication] 
    permission_classes = [IsAuthenticated]

    def get(self, request, pk, *args, **kwargs):
        chat_room = ChatRoom.objects.get(pk=pk)
        serializer = ChatRoomSerializer(chat_room)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ChatMessageCreateView(APIView):
    """
    API view for creating chat messages (requires authentication).
    """
    authentication_classes = [JWTAuthentication] 
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = ChatMessageSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Chat message created successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChatMessageListView(APIView):
    """
    API view for listing chat messages in a specific chat room (requires authentication).
    """
    authentication_classes = [JWTAuthentication] 
    permission_classes = [IsAuthenticated]

    def get(self, request, chat_room_id, *args, **kwargs):
        chat_messages = ChatMessage.objects.filter(chat_room_id=chat_room_id)
        serializer = ChatMessageSerializer(chat_messages, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ChatRequestCreateView(APIView):
    """
    API view for creating chat requests (requires authentication).
    """
    authentication_classes = [JWTAuthentication] 
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = ChatRequestSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Chat request created successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChatRequestRetrieveView(APIView):
    """
    API view for retrieving a specific chat request (requires authentication).
    """
    authentication_classes = [JWTAuthentication] 
    permission_classes = [IsAuthenticated]

    def get(self, request, pk, *args, **kwargs):
        chat_request = ChatRequest.objects.get(pk=pk)
        serializer = ChatRequestSerializer(chat_request)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AcceptChatRequestView(APIView):
    """
    API view for accepting a chat request (requires authentication).
    """
    authentication_classes = [JWTAuthentication] 
    permission_classes = [IsAuthenticated]

    def post(self, request, pk, *args, **kwargs):
        chat_request = ChatRequest.objects.get(pk=pk)
        chat_request.status = 'accepted'
        chat_request.save()
        return Response({'message': 'Chat request accepted'}, status=status.HTTP_200_OK)


class VendorKYCCreateView(APIView):
    """
    API view for creating vendor KYC (requires authentication).
    """
    authentication_classes = [JWTAuthentication] 
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = VendorKYCSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Vendor KYC created successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VendorKYCListView(APIView):
    """
    API view for listing vendor KYC (requires authentication).
    """
    authentication_classes = [JWTAuthentication] 
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        vendor_kyc = VendorKYC.objects.all()
        serializer = VendorKYCSerializer(vendor_kyc, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class VendorKYCDetailView(APIView):
    """
    API view for retrieving a specific vendor KYC (requires authentication).
    """
    authentication_classes = [JWTAuthentication] 
    permission_classes = [IsAuthenticated]

    def get(self, request, pk, *args, **kwargs):
        vendor_kyc = VendorKYC.objects.get(pk=pk)
        serializer = VendorKYCSerializer(vendor_kyc)
        return Response(serializer.data, status=status.HTTP_200_OK)


class VendorKYCUpdateView(APIView):
    """
    API view for updating a specific vendor KYC (requires authentication).
    """
    authentication_classes = [JWTAuthentication] 
    permission_classes = [IsAuthenticated]

    def put(self, request, pk, *args, **kwargs):
        vendor_kyc = VendorKYC.objects.get(pk=pk)
        serializer = VendorKYCSerializer(vendor_kyc, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Vendor KYC updated successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VendorKYCDeleteView(APIView):
    """
    API view for deleting a specific vendor KYC (requires authentication).
    """
    authentication_classes = [JWTAuthentication] 
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk, *args, **kwargs):
        vendor_kyc = VendorKYC.objects.get(pk=pk)
        vendor_kyc.delete()
        return Response({'message': 'Vendor KYC deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
