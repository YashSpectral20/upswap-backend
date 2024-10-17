import re
from django.db.models import Q
from django.db.models import F, Func, FloatField
from django.db.models.functions import ACos, Cos, Radians, Sin, Cast
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken, TokenError
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from rest_framework import status, generics,  permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import CreateAPIView, ListAPIView, RetrieveAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.authtoken.models import Token  # Import Token from rest_framework
from .models import CustomUser, OTP, Activity, ChatRoom, ChatMessage, ChatRequest, VendorKYC, ActivityImage, BusinessDocument, BusinessPhoto, CreateDeal, DealImage
from .serializers import (
    CustomUserSerializer, VerifyOTPSerializer, LoginSerializer,
    ActivitySerializer, ActivityImageSerializer, ChatRoomSerializer, ChatMessageSerializer,
    ChatRequestSerializer, VendorKYCSerializer, BusinessDocumentSerializer, BusinessPhotoSerializer,
    CreateDealSerializer, CreateDealImageSerializer, VendorKYCDetailSerializer,
    VendorKYCListSerializer, ActivityListSerializer, ForgotPasswordSerializer, ResetPasswordSerializer, CreateDeallistSerializer, CreateDealDetailSerializer

)
from .utils import generate_otp 
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import get_user_model
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken

from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth import get_user_model
from rest_framework import generics


from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.urls import reverse

from rest_framework.parsers import MultiPartParser, FormParser

User = get_user_model()
token_generator = PasswordResetTokenGenerator()

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

        # Check if user has VendorKYC
        vendor_kyc = VendorKYC.objects.filter(user=user).first()
        is_approved = False  # Default value

        if vendor_kyc:
            is_approved = vendor_kyc.is_approved  # Fetch is_approved status if VendorKYC exists

        # Prepare response
        return Response({
            'user': CustomUserSerializer(user, context=self.get_serializer_context()).data,
            'refresh': str(refresh),
            'access': access_token,  # Return access token after successful login
            'is_approved': is_approved,  # Include is_approved status
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



class VendorKYCCreateView(generics.CreateAPIView):
    queryset = VendorKYC.objects.all()
    serializer_class = VendorKYCSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        user = self.request.user

        # Check if VendorKYC instance already exists for this user
        try:
            vendor_kyc = VendorKYC.objects.get(user=user)
            # If the instance exists, update it instead of creating a new one
            serializer.instance = vendor_kyc
            # Reset is_approved to False since the vendor is making changes
            serializer.validated_data['is_approved'] = False
        except VendorKYC.DoesNotExist:
            # If no instance exists, create a new one
            vendor_kyc = None
        
        # Save the instance (either create or update)
        serializer.save(user=user)

    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            return Response({
                'message': 'Vendor KYC created successfully.',
                'vendor_kyc': serializer.data  
            }, status=status.HTTP_201_CREATED)
        except ValidationError as e:
            error_message = e.detail
            return Response({
                'message': list(error_message.values())[0][0] if error_message else "Validation error occurred."
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            # Catch any unexpected exceptions
            return Response({
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def get_serializer_context(self):
        """
        Provide any extra context to the serializer, if necessary.
        """
        context = super().get_serializer_context()
        context['request'] = self.request
        return context



class VendorKYCListView(generics.RetrieveUpdateDestroyAPIView):
    queryset = VendorKYC.objects.all()
    serializer_class = VendorKYCListSerializer
    permission_classes = [AllowAny]

class VendorKYCDetailView(generics.RetrieveAPIView):
    """
    View to fetch the VendorKYC details based on the user's uuid.
    Only authenticated users can access this endpoint.
    """
    queryset = VendorKYC.objects.all()
    permission_classes = [AllowAny]
    serializer_class = VendorKYCDetailSerializer

    def get(self, request, *args, **kwargs):
        # Get the user's uuid from the URL
        user_uuid = self.kwargs.get('uuid')  # Assuming UUID is passed

        try:
            # Find the user by uuid
            user = CustomUser.objects.get(uuid=user_uuid)
        except CustomUser.DoesNotExist:
            return Response({"message": "User not found"}, status=404)

        try:
            # Find the VendorKYC entry associated with the user
            vendor_kyc = VendorKYC.objects.get(user=user)
        except VendorKYC.DoesNotExist:
            return Response({"message": "VendorKYC for this user is not exists."}, status=404)

        # If VendorKYC exists, return the details
        serializer = self.get_serializer(vendor_kyc)
        return Response(serializer.data)  # Allow any user to access this view


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
        # Fetch the vendor's KYC details
        try:
            vendor_kyc = VendorKYC.objects.get(user=request.user)
        except VendorKYC.DoesNotExist:
            return Response({"error": "Vendor KYC not found for this user."}, status=status.HTTP_404_NOT_FOUND)

        if not vendor_kyc.is_approved:
            return Response({"error": "Vendor KYC is not approved."}, status=status.HTTP_400_BAD_REQUEST)

        # Copy request data and add vendor KYC to the data
        data = request.data.copy()
        data['vendor_kyc'] = vendor_kyc.vendor_id

        # Create the deal using the serializer
        serializer = self.get_serializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DealImageUploadView(generics.CreateAPIView):
    serializer_class = CreateDealImageSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, deal_uuid, *args, **kwargs):
        user = request.user

        try:
            deal = CreateDeal.objects.get(deal_uuid=deal_uuid, vendor_kyc__user=user)
        except CreateDeal.DoesNotExist:
            return Response({"detail": "Deal not found or you don't have permission to upload images for this deal."}, status=status.HTTP_404_NOT_FOUND)

        if 'images' not in request.FILES:
            return Response({"detail": "No image provided."}, status=status.HTTP_400_BAD_REQUEST)

        images = request.FILES.getlist('images')  # Get the list of images

        for image in images:
            DealImage.objects.create(create_deal=deal, images=image)

        return Response({"detail": "Images uploaded successfully!"}, status=status.HTTP_201_CREATED)






class CreateDealDetailView(RetrieveAPIView):
    queryset = CreateDeal.objects.all()
    serializer_class = CreateDealDetailSerializer
    permission_classes = [AllowAny]
    lookup_field = 'deal_uuid'  # This should match the URL pattern
    
    def get_queryset(self):
        # Now use deal_uuid instead of pk
        return CreateDeal.objects.filter(deal_uuid=self.kwargs['deal_uuid'])

    
class CreateDeallistView(generics.ListAPIView):
    queryset = CreateDeal.objects.all()
    serializer_class = CreateDeallistSerializer
    permission_classes = [AllowAny] # Allow any user to access this view
    
    
class ActivityListView(generics.ListAPIView):
    queryset = Activity.objects.all()  # Retrieves all Activity instances
    serializer_class = ActivityListSerializer
    permission_classes = [AllowAny]
    


class LogoutAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Extract tokens from request data
        refresh_token = request.data.get('refresh')
        access_token = request.data.get('access')

        # Check for presence of both tokens
        if not refresh_token or not access_token:
            return Response({"message": "Refresh and Access tokens are required."}, status=status.HTTP_400_BAD_REQUEST)

        # Handle refresh token
        try:
            refresh = RefreshToken(refresh_token)
            refresh.blacklist()  # Blacklists the refresh token
        except TokenError:
            return Response({"message": "User already logged out."}, status=status.HTTP_400_BAD_REQUEST)

        # Handle access token
        try:
            access = AccessToken(access_token)
            # Blacklist access token logic can be implemented here if supported by the application.
            # In many cases, logging out only invalidates the refresh token.
            # Custom handling can be done to add access tokens to blacklist manually if required.
        except TokenError:
            # Access token is either already expired or invalid.
            return Response({"message": "Access token invalid or already expired."}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"message": "User logged out successfully."}, status=status.HTTP_200_OK)
    
class ForgotPasswordView(generics.GenericAPIView):
    serializer_class = ForgotPasswordSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Send reset password email
        user = User.objects.get(email=serializer.validated_data['email'])
        token = token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        reset_url = request.build_absolute_uri(
            reverse('password-reset-confirm', kwargs={'uidb64': uid, 'token': token})
        )

        send_mail(
            'Password Reset Request',
            f'Click the link to reset your password: {reset_url}',
            'admin@example.com',  # From email
            [user.email],
            fail_silently=False,
        )

        return Response({"message": "Password reset link has been sent to your email."}, status=status.HTTP_200_OK)
    
class ResetPasswordView(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer

    def post(self, request, uidb64, token):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            serializer.save(uidb64=uidb64, token=token)
        except serializers.ValidationError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)