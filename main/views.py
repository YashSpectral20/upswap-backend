from django.core.mail import send_mail
from django.conf import settings
from rest_framework import status, generics, serializers
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from .models import OTP, Activity, ActivityImage, ChatRoom, ChatMessage, ChatRequest, VendorKYC
from .serializers import (
    CustomUserSerializer, LoginSerializer, OTPSerializer,
    ActivitySerializer, ActivityImageSerializer,
    ChatRoomSerializer, ChatMessageSerializer, ChatRequestSerializer,
    VendorKYCSerializer
)
from rest_framework.views import APIView
import random
import string
from django.utils import timezone
from rest_framework.parsers import MultiPartParser, FormParser

User = get_user_model()

# User Registration and Authentication Views
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
            raise Exception(f"Failed to send OTP email: {str(e)}")

class OTPVerifyView(generics.GenericAPIView):
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

# Custom User Creation View
class CustomUserCreateView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = (AllowAny,)

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

# Chat Message Views
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

# Chat Request Views
class ChatRequestCreateView(generics.CreateAPIView):
    queryset = ChatRequest.objects.all()
    serializer_class = ChatRequestSerializer
    permission_classes = (IsAuthenticated,)

    def perform_create(self, serializer):
        serializer.save(from_user=self.request.user)

class ChatRequestRetrieveView(generics.RetrieveAPIView):
    queryset = ChatRequest.objects.all()
    serializer_class = ChatRequestSerializer
    permission_classes = (IsAuthenticated,)

    def get_object(self):
        return ChatRequest.objects.get(pk=self.kwargs['pk'])

class ChatRequestUpdateView(generics.UpdateAPIView):
    queryset = ChatRequest.objects.all()
    serializer_class = ChatRequestSerializer
    permission_classes = (IsAuthenticated,)

    def perform_update(self, serializer):
        chat_request = self.get_object()
        if serializer.validated_data.get('is_accepted') and chat_request.is_rejected:
            raise serializers.ValidationError("A chat request cannot be both accepted and rejected.")
        if serializer.validated_data.get('is_rejected') and chat_request.is_accepted:
            raise serializers.ValidationError("A chat request cannot be both accepted and rejected.")
        serializer.save()

class AcceptChatRequestView(APIView):
    def post(self, request, *args, **kwargs):
        chat_request_id = request.data.get('chat_request_id')
        try:
            chat_request = ChatRequest.objects.get(id=chat_request_id)
        except ChatRequest.DoesNotExist:
            return Response({"error": "Chat request not found."}, status=status.HTTP_404_NOT_FOUND)

        if chat_request.is_accepted or chat_request.is_rejected:
            return Response({"error": "Chat request already processed."}, status=status.HTTP_400_BAD_REQUEST)

        # Accept the chat request
        chat_request.is_accepted = True
        chat_request.save()

        # Create a chat room if the request is accepted
        chat_room, created = ChatRoom.objects.get_or_create(activity=chat_request.activity)
        if created:
            chat_room.participants.add(chat_request.from_user, chat_request.to_user)
            chat_room.save()

        return Response({"message": "Chat request accepted and chat room created.", "chat_room_id": chat_room.id}, status=status.HTTP_201_CREATED)

# VendorKYC Views
class VendorKYCCreateView(generics.CreateAPIView):
    queryset = VendorKYC.objects.all()
    serializer_class = VendorKYCSerializer
    permission_classes = (IsAuthenticated,)

    def perform_create(self, serializer):
        user = self.request.user
        phone_number = user.phone_number if self.request.data.get('same_as_personal_phone_number') else serializer.validated_data.get('phone_number')
        business_email_id = user.email if self.request.data.get('same_as_personal_email_id') else serializer.validated_data.get('business_email_id')

        serializer.save(
            user=user,
            phone_number=phone_number,
            business_email_id=business_email_id,
            full_name=user.name
        )

class VendorKYCListView(generics.ListAPIView):
    queryset = VendorKYC.objects.all()
    serializer_class = VendorKYCSerializer
    permission_classes = (IsAuthenticated,)

class VendorKYCDetailView(generics.RetrieveAPIView):
    queryset = VendorKYC.objects.all()
    serializer_class = VendorKYCSerializer
    permission_classes = (IsAuthenticated,)

class VendorKYCUpdateView(generics.UpdateAPIView):
    queryset = VendorKYC.objects.all()
    serializer_class = VendorKYCSerializer
    permission_classes = (IsAuthenticated,)

    def perform_update(self, serializer):
        user = self.request.user
        phone_number = user.phone_number if self.request.data.get('same_as_personal_phone_number') else serializer.validated_data.get('phone_number')
        business_email_id = user.email if self.request.data.get('same_as_personal_email_id') else serializer.validated_data.get('business_email_id')

        serializer.save(
            phone_number=phone_number,
            business_email_id=business_email_id
        )

class VendorKYCDeleteView(generics.DestroyAPIView):
    queryset = VendorKYC.objects.all()
    permission_classes = (IsAuthenticated,)

