from django.core.mail import send_mail
from django.conf import settings
from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from .models import OTP, Activity, ActivityImage, ChatRoom, ChatMessage
from .serializers import (
    CustomUserSerializer, LoginSerializer, OTPSerializer,
    ActivitySerializer, ActivityImageSerializer,
    ChatRoomSerializer, ChatMessageSerializer
)
import random
import string
from django.utils import timezone
from rest_framework.parsers import MultiPartParser, FormParser

User = get_user_model()

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = CustomUserSerializer

    def perform_create(self, serializer):
        user = serializer.save()
        otp_code = ''.join(random.choices(string.digits, k=6))
        expires_at = timezone.now() + timezone.timedelta(minutes=5)
        OTP.objects.create(user=user, otp=otp_code, expires_at=expires_at)
        
        try:
            send_mail(
                'Your OTP Code',
                f'Your OTP code is {otp_code}',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
        except Exception as e:
            # Handle email sending failure
            raise Exception(f"Failed to send OTP email: {str(e)}")

class VerifyOTPView(generics.GenericAPIView):
    serializer_class = OTPSerializer
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        otp = serializer.validated_data['otp']
        
        try:
            otp_instance = OTP.objects.get(user=user, otp=otp)
        except OTP.DoesNotExist:
            return Response({"detail": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)
        
        if otp_instance.is_expired():
            return Response({"detail": "OTP has expired."}, status=status.HTTP_400_BAD_REQUEST)

        user.otp_verified = True
        user.save()
        otp_instance.delete()  # Delete OTP if it should only be used once
        
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })

class LoginView(generics.GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        
        if not user.otp_verified:
            return Response({"detail": "OTP not verified."}, status=status.HTTP_401_UNAUTHORIZED)
        
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })

# Activity Views
class ActivityListCreateView(generics.ListCreateAPIView):
    queryset = Activity.objects.all()
    serializer_class = ActivitySerializer
    permission_classes = (IsAuthenticated,)

    def perform_create(self, serializer):
        infinite_time = self.request.data.get('infinite_time', False)
        serializer.save(
            infinite_time=infinite_time,
            created_by=self.request.user
        )

class ActivityRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Activity.objects.all()
    serializer_class = ActivitySerializer
    permission_classes = (IsAuthenticated,)

    def perform_update(self, serializer):
        infinite_time = self.request.data.get('infinite_time', False)
        if infinite_time:
            serializer.save(infinite_time=True)
        else:
            super().perform_update(serializer)

class ActivityImageUploadView(generics.CreateAPIView):
    queryset = ActivityImage.objects.all()
    serializer_class = ActivityImageSerializer
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Chat Room Views
class ChatRoomCreateView(generics.CreateAPIView):
    queryset = ChatRoom.objects.all()
    serializer_class = ChatRoomSerializer
    permission_classes = (IsAuthenticated,)

    def perform_create(self, serializer):
        serializer.save()

class ChatRoomRetrieveView(generics.RetrieveAPIView):
    queryset = ChatRoom.objects.all()
    serializer_class = ChatRoomSerializer
    permission_classes = (IsAuthenticated,)

class ChatMessageCreateView(generics.CreateAPIView):
    queryset = ChatMessage.objects.all()
    serializer_class = ChatMessageSerializer
    permission_classes = (IsAuthenticated,)

    def perform_create(self, serializer):
        serializer.save(sender=self.request.user)

class ChatMessageListView(generics.ListAPIView):
    serializer_class = ChatMessageSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        chat_room_id = self.kwargs.get('chat_room_id')
        return ChatMessage.objects.filter(chat_room_id=chat_room_id)
