import random
import re
from django.db.models import Q
from django.db.models import F, Func, FloatField
from django.db.models.functions import ACos, Cos, Radians, Sin, Cast
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status, generics,  permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import CreateAPIView, ListAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.authtoken.models import Token  # Import Token from rest_framework
from .models import CustomUser, OTP, Activity, ChatRoom, ChatMessage, ChatRequest, PasswordResetOTP, VendorKYC, ActivityImage, BusinessDocument, BusinessPhoto, CreateDeal, DealImage
from .serializers import (
    CustomUserSerializer, OTPRequestSerializer, OTPResetPasswordSerializer, OTPValidationSerializer, VerifyOTPSerializer, LoginSerializer,
    ActivitySerializer, ActivityImageSerializer, ChatRoomSerializer, ChatMessageSerializer,
    ChatRequestSerializer, VendorKYCSerializer, BusinessDocumentSerializer, BusinessPhotoSerializer,
    CreateDealSerializer, DealImageSerializer, CreateDealImageUploadSerializer, VendorDetailSerializer,
    VendorListSerializer, ActivityListSerializer
)
from .utils import generate_otp 
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import get_user_model
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from django.core.mail import send_mail


User = get_user_model()

USERNAME_REGEX = r'^[a-z0-9]{6,}$'  # Adjust the pattern as needed
PASSWORD_REGEX = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$'  # At least 8 characters, 1 letter and 1 number


class RegisterView(generics.CreateAPIView):
    serializer_class = CustomUserSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        data = request.data

        # Regex validation for username and password
        username = data.get('username', '')
        password = data.get('password', '')

        if not re.match(USERNAME_REGEX, username):
            return Response({'message': 'Username does not meet the required format. It should be at least 6 characters long and can include only small letters, numbers'},
                            status=status.HTTP_400_BAD_REQUEST)

        if not re.match(PASSWORD_REGEX, password):
            return Response({'message': 'Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, a digit, and a special character.'},
                            status=status.HTTP_400_BAD_REQUEST)
            
        def validate(self, data):
            if data['password'] != data['confirm_password']:
                raise serializers.ValidationError({"confirm_password": "Passwords must match."})
            return data
        

        # Check if the username, email, or phone number already exists
        if CustomUser.objects.filter(username=username).exists():
            return Response({'message': 'User already exists with the same username'}, status=status.HTTP_400_BAD_REQUEST)
        
        if CustomUser.objects.filter(email=data.get('email')).exists():
            return Response({'message': 'User already exists with the same email'}, status=status.HTTP_400_BAD_REQUEST)
        
        if CustomUser.objects.filter(phone_number=data.get('phone_number')).exists():
            return Response({'message': 'User already exists with the same phone number'}, status=status.HTTP_400_BAD_REQUEST)

        # If no duplicate user, proceed with registration
        serializer = self.get_serializer(data=data)
        
        try:
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

        except ValidationError as e:
            error_message = e.detail

            # Handle specific 'date_of_birth' validation error
            if isinstance(error_message, dict) and 'date_of_birth' in error_message:
                return Response({
                    "message": "Date has wrong format. Use one of these formats instead: YYYY-MM-DD."
                }, status=status.HTTP_400_BAD_REQUEST)

            # General validation error handling
            return Response({
                'message': list(error_message.values())[0][0] if error_message else "Validation error occurred."
            }, status=status.HTTP_400_BAD_REQUEST)
            

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
    authentication_classes = []  # No authentication required for login
    permission_classes = [AllowAny]  # Allow any user to access the login API

    def post(self, request, *args, **kwargs):
        # Validate login credentials
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response({"message": "Invalid Credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        user = serializer.validated_data['user']

        # Check if OTP has been verified
        try:
            otp_instance = OTP.objects.get(user=user)
            if not otp_instance.is_verified:  # Check if OTP is verified
                return Response({"message": "OTP not verified. Please verify your OTP first."},
                                status=status.HTTP_403_FORBIDDEN)
        except OTP.DoesNotExist:
            return Response({"message": "OTP not found for this user. Please register and verify OTP."},
                            status=status.HTTP_400_BAD_REQUEST)

        # OTP is verified, proceed with login
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        return Response({
            'user': CustomUserSerializer(user, context=self.get_serializer_context()).data,
            'refresh': str(refresh),
            'access': access_token,  # Return access token after successful login
            'message': 'User logged in successfully.'
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

class ActivityCreateView(generics.CreateAPIView):
    queryset = Activity.objects.all()
    serializer_class = ActivitySerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        # Set `user_participation` to True by default if not provided in the request data
        if 'user_participation' not in serializer.validated_data:
            serializer.validated_data['user_participation'] = True
        serializer.save(created_by=self.request.user)

    

class Distance(Func):
    function = "6371 * 2 * ATAN2(SQRT(%s), SQRT(1 - %s))"
    template = "%(function)s"

    def __init__(self, user_lat, user_lon, *args, **kwargs):
        super().__init__(
            Cos(Radians(user_lat)) * Cos(Radians(F("latitude"))) * Cos(
                Radians(F("longitude")) - Radians(user_lon)
            )
            + Sin(Radians(user_lat)) * Sin(Radians(F("latitude"))),
            output_field=FloatField(),
            **kwargs,
        )

class ActivityListView(ListAPIView):
    serializer_class = ActivitySerializer
    permission_classes = [AllowAny]  # Allow any user, including guests, to access this view
    
    def get_queryset(self):
        queryset = Activity.objects.all()
        user_lat = self.request.query_params.get('user_lat', None)
        user_lon = self.request.query_params.get('user_lon', None)
        max_distance_km = 15  # Maximum distance in kilometers

        if user_lat is not None and user_lon is not None:
            user_lat = float(user_lat)
            user_lon = float(user_lon)

            # Cast latitude and longitude fields to FloatField for proper calculation
            queryset = queryset.annotate(
                latitude_float=Cast('latitude', FloatField()),
                longitude_float=Cast('longitude', FloatField())
            ).annotate(
                distance=6371 * 2 * ACos(
                    Cos(Radians(user_lat)) * Cos(Radians(F('latitude_float'))) * Cos(
                        Radians(F('longitude_float')) - Radians(user_lon)
                    ) +
                    Sin(Radians(user_lat)) * Sin(Radians(F('latitude_float')))
                )
            ).filter(distance__lte=max_distance_km)

        return queryset

    
class ActivityImageListCreateView(generics.ListCreateAPIView):
    queryset = ActivityImage.objects.all()
    serializer_class = ActivityImageSerializer
    permission_classes = [IsAuthenticated]  # Use [AllowAny] if you don't want any restrictions for the DRF UI

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)


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


class VendorKYCListCreateView(generics.ListCreateAPIView):
    queryset = VendorKYC.objects.all()
    serializer_class = VendorKYCSerializer
    permission_classes = [IsAuthenticated]

class VendorKYCDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = VendorKYC.objects.all()
    serializer_class = VendorKYCSerializer
    permission_classes = [AllowAny]  # Allow any user to access this view


# Business Document views
class BusinessDocumentListCreateView(generics.ListCreateAPIView):
    queryset = BusinessDocument.objects.all()  # Make sure BusinessDocument is imported
    serializer_class = BusinessDocumentSerializer
    permission_classes = [IsAuthenticated]

# Business Photo views
class BusinessPhotoListCreateView(generics.ListCreateAPIView):
    queryset = BusinessPhoto.objects.all()  # Make sure BusinessPhoto is imported
    serializer_class = BusinessPhotoSerializer
    permission_classes = [IsAuthenticated]
    

class CreateDealView(generics.CreateAPIView):
    serializer_class = CreateDealSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Ensure vendor's KYC is approved
        vendor_kyc = serializer.validated_data.get('vendor_kyc')
        if not vendor_kyc.is_approved:
            return Response(
                {"detail": "Cannot create a deal because Vendor KYC is not approved."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Create the deal
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data,
            status=status.HTTP_201_CREATED,
            headers=headers
        )

    def perform_create(self, serializer):
        serializer.save()  # Require authentication


class DealImageUploadView(APIView):
    """API view to handle image uploads for a deal."""
    permission_classes = [IsAuthenticated]  # Require authentication

    def post(self, request, deal_id):
        # Get the deal instance
        try:
            deal = CreateDeal.objects.get(id=deal_id)
        except CreateDeal.DoesNotExist:
            return Response({'error': 'Deal not found.'}, status=status.HTTP_404_NOT_FOUND)
        
        # Handle multiple image uploads
        images = request.FILES.getlist('images')
        image_paths = []
        for img in images:
            deal_image = DealImage(image=img)
            deal_image.save()
            deal.add_image(deal_image)  # Add image path to deal
            image_paths.append(deal_image.get_image_path())

        return Response({'uploaded_images': image_paths}, status=status.HTTP_201_CREATED)


class CreateDealListView(generics.ListAPIView):
    queryset = CreateDeal.objects.all()
    serializer_class = CreateDealSerializer
    permission_classes = [AllowAny]  # Allow any user to access this view

class VendorDetailListView(generics.ListAPIView):
    queryset = VendorKYC.objects.all()
    serializer_class = VendorDetailSerializer
    permission_classes = [AllowAny]
    
class VendorListView(generics.ListAPIView):
    queryset = VendorKYC.objects.all()
    serializer_class = VendorListSerializer
    permission_classes = [AllowAny]
    
class ActivityListView(generics.ListAPIView):
    queryset = Activity.objects.all()  # Retrieves all Activity instances
    serializer_class = ActivityListSerializer
    permission_classes = [AllowAny]
    


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def post(self, request):
        # Get the refresh token from the request
        refresh_token = request.data.get('refresh')

        if not refresh_token:
            return Response({"message": "Refresh token required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Blacklist the refresh token
            token = OutstandingToken.objects.get(token=refresh_token)
            BlacklistedToken.objects.create(token=token)
            
            return Response({"message": "User logged out successfully."}, status=status.HTTP_200_OK)
        except OutstandingToken.DoesNotExist:
            return Response({"message": "Token is invalid or expired."}, status=status.HTTP_400_BAD_REQUEST)
        
     
class SendOTPView(APIView):
    serializer_class = OTPRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)

        try:
            # Delete any existing OTP for the user
            existing_otp = PasswordResetOTP.objects.filter(user=user)
            if existing_otp.exists():
                existing_otp.delete()
        except PasswordResetOTP.DoesNotExist:
            # This exception will not occur when using `filter()`
            # because `filter()` does not raise `DoesNotExist`.
            pass
        

        # Generate a new OTP
        otp = str(random.randint(100000, 999999))
        try:
            PasswordResetOTP.objects.create(user=user, otp=otp)
        except Exception as e:
            # Handle unexpected errors during OTP creation
            return Response(
                {"error": "An error occurred while generating a new OTP. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # Send the OTP via email
        try:
            send_mail(
                'Password Reset OTP',
                f'Your OTP for password reset is: {otp}',
                'admin@example.com',  # From email
                [email],
                fail_silently=False,
            )
        except Exception as e:
            return Response(
                {"error": "Failed to send OTP email. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response({"message": "OTP sent to your email."}, status=status.HTTP_200_OK)
    

class ValidateOTPView(APIView):
    serializer_class = OTPValidationSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        # OTP is valid
        return Response({"message": "OTP is valid. Proceed to reset your password."}, status=status.HTTP_200_OK)
    

class OTPResetPasswordView(APIView):
    serializer_class = OTPResetPasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)