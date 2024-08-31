from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from django.core.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
from .models import (
    CustomUser, OTP, Activity, ChatRequest, ChatRoom,
    ChatMessage, VendorKYC, ActivityImage
)
from .serializers import (
    CustomUserSerializer, LoginSerializer, OTPSerializer, ActivitySerializer,
    ChatRequestSerializer, ChatRoomSerializer, ChatMessageSerializer,
    VendorKYCSerializer, ActivityImageSerializer
)

# Custom User Views
class CustomUserCreateView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer

    def perform_create(self, serializer):
        # Remove password confirmation from serializer data before creating user
        validated_data = serializer.validated_data
        validated_data.pop('confirm_password', None)
        serializer.save()

class RegisterView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer

    def perform_create(self, serializer):
        # Remove password confirmation from serializer data before creating user
        validated_data = serializer.validated_data
        validated_data.pop('confirm_password', None)
        serializer.save()

class OTPVerifyView(generics.GenericAPIView):
    serializer_class = OTPSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        otp = serializer.validated_data['otp']
        user = serializer.validated_data['user']

        otp_instance = OTP.objects.filter(user=user, otp=otp).first()
        if not otp_instance or otp_instance.is_expired():
            return Response({'detail': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)

        user.otp_verified = True
        user.save()
        return Response({'detail': 'OTP verified successfully'}, status=status.HTTP_200_OK)

class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })

# Activity Views
class ActivityListCreateView(generics.ListCreateAPIView):
    queryset = Activity.objects.all()
    serializer_class = ActivitySerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

class ActivityRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Activity.objects.all()
    serializer_class = ActivitySerializer
    permission_classes = [IsAuthenticated]

# Chat Request Views
class ChatRequestCreateView(generics.CreateAPIView):
    queryset = ChatRequest.objects.all()
    serializer_class = ChatRequestSerializer
    permission_classes = [IsAuthenticated]

class ChatRequestRetrieveView(generics.RetrieveAPIView):
    queryset = ChatRequest.objects.all()
    serializer_class = ChatRequestSerializer
    permission_classes = [IsAuthenticated]

class AcceptChatRequestView(generics.GenericAPIView):
    serializer_class = ChatRequestSerializer

    def post(self, request, *args, **kwargs):
        chat_request = get_object_or_404(ChatRequest, pk=kwargs['pk'])
        if chat_request.is_accepted or chat_request.is_rejected:
            raise ValidationError("This chat request has already been accepted or rejected.")
        chat_request.is_accepted = True
        chat_request.save()
        return Response({'detail': 'Chat request accepted'}, status=status.HTTP_200_OK)

# Chat Room Views
class ChatRoomCreateView(generics.CreateAPIView):
    queryset = ChatRoom.objects.all()
    serializer_class = ChatRoomSerializer
    permission_classes = [IsAuthenticated]

class ChatRoomRetrieveView(generics.RetrieveAPIView):
    queryset = ChatRoom.objects.all()
    serializer_class = ChatRoomSerializer
    permission_classes = [IsAuthenticated]

# Chat Message Views
class ChatMessageCreateView(generics.CreateAPIView):
    queryset = ChatMessage.objects.all()
    serializer_class = ChatMessageSerializer
    permission_classes = [IsAuthenticated]

class ChatMessageListView(generics.ListAPIView):
    serializer_class = ChatMessageSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        chat_room_id = self.kwargs['chat_room_id']
        return ChatMessage.objects.filter(chat_room__id=chat_room_id)

# Vendor KYC Views
class VendorKYCCreateView(generics.CreateAPIView):
    queryset = VendorKYC.objects.all()
    serializer_class = VendorKYCSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        user = self.request.user
        if serializer.validated_data.get('same_as_personal_phone_number', False):
            serializer.validated_data['phone_number'] = user.phone_number

        if serializer.validated_data.get('same_as_personal_email_id', False):
            serializer.validated_data['business_email_id'] = user.email

        serializer.save(user=user)

class VendorKYCListView(generics.ListAPIView):
    queryset = VendorKYC.objects.all()
    serializer_class = VendorKYCSerializer
    permission_classes = [IsAuthenticated]

class VendorKYCDetailView(generics.RetrieveAPIView):
    queryset = VendorKYC.objects.all()
    serializer_class = VendorKYCSerializer
    permission_classes = [IsAuthenticated]

class VendorKYCUpdateView(generics.UpdateAPIView):
    queryset = VendorKYC.objects.all()
    serializer_class = VendorKYCSerializer
    permission_classes = [IsAuthenticated]

class VendorKYCDeleteView(generics.DestroyAPIView):
    queryset = VendorKYC.objects.all()
    serializer_class = VendorKYCSerializer
    permission_classes = [IsAuthenticated]

class ActivityImageCreateView(generics.CreateAPIView):
    queryset = ActivityImage.objects.all()
    serializer_class = ActivityImageSerializer
