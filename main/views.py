from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import CustomUser, OTP, Activity, ActivityImage, ChatRequest, ChatRoom, ChatMessage, VendorKYC, BankDetails, ServicesProvide
from .serializers import (
    CustomUserSerializer, LoginSerializer, OTPSerializer, ActivitySerializer, ActivityImageSerializer,
    ChatRequestSerializer, ChatRoomSerializer, ChatMessageSerializer, VendorKYCSerializer, BankDetailsSerializer, ServicesProvideSerializer

)
from django.core.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken

# Custom User Views
class CustomUserCreateView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer

class RegisterView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer

class OTPVerifyView(generics.GenericAPIView):
    serializer_class = OTPSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        otp = serializer.validated_data['otp']
        user = serializer.validated_data['user']
        
        if not OTP.objects.filter(user=user, otp=otp).exists():
            return Response({'detail': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        otp_instance = OTP.objects.get(user=user, otp=otp)
        if otp_instance.is_expired():
            return Response({'detail': 'OTP has expired'}, status=status.HTTP_400_BAD_REQUEST)

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

class ActivityRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Activity.objects.all()
    serializer_class = ActivitySerializer
    permission_classes = [IsAuthenticated]

class ActivityImageUploadView(generics.CreateAPIView):
    queryset = ActivityImage.objects.all()
    serializer_class = ActivityImageSerializer
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

class ChatRequestUpdateView(generics.UpdateAPIView):
    queryset = ChatRequest.objects.all()
    serializer_class = ChatRequestSerializer
    permission_classes = [IsAuthenticated]

class AcceptChatRequestView(generics.GenericAPIView):
    serializer_class = ChatRequestSerializer

    def post(self, request, *args, **kwargs):
        chat_request = generics.get_object_or_404(ChatRequest, pk=kwargs['pk'])
        chat_request.accept()
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

# Bank Details Views
class BankDetailsCreateView(generics.CreateAPIView):
    queryset = BankDetails.objects.all()
    serializer_class = BankDetailsSerializer
    permission_classes = [IsAuthenticated]

class BankDetailsRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = BankDetails.objects.all()
    serializer_class = BankDetailsSerializer
    permission_classes = [IsAuthenticated]

class ServicesProvideCreateView(generics.CreateAPIView):
    queryset = ServicesProvide.objects.all()
    serializer_class = ServicesProvideSerializer

class ServicesProvideRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = ServicesProvide.objects.all()
    serializer_class = ServicesProvideSerializer