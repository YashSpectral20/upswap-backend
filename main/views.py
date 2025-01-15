import random
from PIL import Image
from io import BytesIO
import logging
import re
import os
import uuid
import boto3
from uuid import uuid4
import traceback
import base64
from django.conf import settings
from botocore.exceptions import ClientError
from django.http import HttpResponse, JsonResponse
from django.core.files.base import ContentFile
from django.utils import timezone
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
from .models import (CustomUser, OTP, Activity, ChatRoom, ChatMessage, ChatRequest, PasswordResetOTP, VendorKYC, CreateDeal, PlaceOrder,
                    ActivityCategory, ServiceCategory)

from .serializers import (
    CustomUserSerializer, OTPRequestSerializer, OTPResetPasswordSerializer, OTPValidationSerializer, VerifyOTPSerializer, LoginSerializer,
    ActivitySerializer, ChatRoomSerializer, ChatMessageSerializer,
    ChatRequestSerializer, VendorKYCSerializer,
    CreateDealSerializer, VendorKYCDetailSerializer,
    VendorKYCListSerializer, ActivityListsSerializer, ActivityDetailsSerializer, ForgotPasswordSerializer, ResetPasswordSerializer, CreateDeallistSerializer, CreateDealDetailSerializer, PlaceOrderSerializer, PlaceOrderDetailsSerializer,
    ActivityCategorySerializer, ServiceCategorySerializer, CustomUserDetailsSerializer, PlaceOrderListsSerializer, VendorKYCStatusSerializer, CustomUserEditSerializer

)
from rest_framework.generics import RetrieveAPIView
from .utils import generate_otp, process_image, upload_to_s3, upload_to_s3_documents, upload_to_s3_profile_image, generate_asset_uuid 
from geopy.distance import geodesic
from .services import get_image_from_s3
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import get_user_model
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from rest_framework.exceptions import NotFound
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth import get_user_model
from rest_framework import generics, serializers
#from django.contrib.gis.measure import D
#from django.contrib.gis.geos import Point

from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.urls import reverse

from rest_framework.parsers import MultiPartParser, FormParser

from django.shortcuts import get_object_or_404

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
            if not otp_instance.is_verified:
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
        vendor_id = ""  # Default empty string for non-vendors

        if vendor_kyc:
            is_approved = vendor_kyc.is_approved
            vendor_id = str(vendor_kyc.vendor_id)  # Use vendor_id instead of vendor_uuid

        # Prepare response
        return Response({
            'user': CustomUserSerializer(user, context=self.get_serializer_context()).data,
            'refresh': str(refresh),
            'access': access_token,  # Return access token after successful login
            'is_approved': is_approved,  # Include is_approved status
            'vendor_id': vendor_id,  # Include vendor_id if the user is a vendor
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
        uploaded_images = self.request.data.get('uploaded_images', [])
        
        if not isinstance(uploaded_images, list):
            raise ValidationError({"uploaded_images": "uploaded_images must be a list of dictionaries."})
        
        # Check if VendorKYC instance already exists for this user
        try:
            vendor_kyc = VendorKYC.objects.get(user=user)
            # If the instance exists, update it instead of creating a new one
            serializer.instance = vendor_kyc
            serializer.validated_data['is_approved'] = False  # Reset is_approved
        except VendorKYC.DoesNotExist:
            vendor_kyc = None

        # Add uploaded_images to validated data
        serializer.save(user=user, uploaded_images=uploaded_images)

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
            return Response({
                'message': list(e.detail.values())[0][0] if e.detail else "Validation error occurred."
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            # Catch unexpected exceptions
            return Response({
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def get_serializer_context(self):
        """
        Provide extra context to the serializer.
        """
        context = super().get_serializer_context()
        context['request'] = self.request
        return context



"""
class VendorKYCListView(generics.RetrieveUpdateDestroyAPIView):
    queryset = VendorKYC.objects.all()
    serializer_class = VendorKYCListSerializer
    permission_classes = [AllowAny]
"""

class VendorKYCStatusView(generics.RetrieveAPIView):
    def get(self, request, vendor_id):
        try:
            # Fetch VendorKYC instance by vendor_id
            vendor_kyc = VendorKYC.objects.get(vendor_id=vendor_id)
            serializer = VendorKYCStatusSerializer(vendor_kyc)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except VendorKYC.DoesNotExist:
            return Response({"message": "VendorKYC not found."}, status=status.HTTP_404_NOT_FOUND)


class VendorKYCListView(ListAPIView):
    queryset = VendorKYC.objects.all()
    serializer_class = VendorKYCListSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        country = self.request.query_params.get('country', None)
        queryset = VendorKYC.objects.all()

        if country:
            queryset = queryset.filter(addresses__country=country).distinct()  # Ensure unique vendors

        return queryset


    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()

        # Prepare the response structure
        response_data = {
            "message": "No Vendor KYC entries available for the specified country." if not queryset.exists() else "Lists of Vendors",
            "vendors": []
        }

        if queryset.exists():
            serializer = self.get_serializer(queryset, many=True)
            response_data["vendors"] = serializer.data

        return Response(response_data, status=status.HTTP_200_OK)
    

class VendorKYCDetailView(generics.RetrieveAPIView):
    """
    View to fetch the VendorKYC details based on the vendor's ID.
    """
    queryset = VendorKYC.objects.all()
    permission_classes = [AllowAny]
    serializer_class = VendorKYCDetailSerializer

    def get(self, request, *args, **kwargs):
        # Get the vendor's id from the URL
        vendor_id = self.kwargs.get('vendor_id')  # Assuming vendor_id is passed as a URL parameter

        try:
            # Find the VendorKYC entry by vendor_id
            vendor_kyc = VendorKYC.objects.get(vendor_id=vendor_id)
        except VendorKYC.DoesNotExist:
            return Response({"message": "VendorKYC for this vendor does not exist."}, status=404)

        # If VendorKYC exists, return the details
        serializer = self.get_serializer(vendor_kyc)
        return Response(serializer.data)
    


##########################################################################################################

# class CreateDealView(generics.CreateAPIView):
#     serializer_class = CreateDealSerializer
#     permission_classes = [IsAuthenticated]

#     def post(self, request, *args, **kwargs):
#         # Fetch the vendor's KYC details
#         try:
#             vendor_kyc = VendorKYC.objects.get(user=request.user)
#         except VendorKYC.DoesNotExist:
#             return Response({"message": "Vendor KYC not found for this user."}, status=status.HTTP_404_NOT_FOUND)

#         if not vendor_kyc.is_approved:
#             return Response({"message": "Vendor KYC is not approved."}, status=status.HTTP_400_BAD_REQUEST)

#         # Copy request data and add vendor KYC to the data
#         data = request.data.copy()
#         data['vendor_kyc'] = vendor_kyc.vendor_id

#         # Create the deal using the serializer
#         serializer = self.get_serializer(data=data)
#         if serializer.is_valid():
#             deal = serializer.save()
#             response_data = serializer.data
#             response_data['message'] = "Deal created successfully."
#             return Response(response_data, status=status.HTTP_201_CREATED)

#         # Handle errors and convert to the desired format
#         error_message = self.format_errors(serializer.errors)
#         return Response({"message": error_message}, status=status.HTTP_400_BAD_REQUEST)

#     def format_errors(self, errors):
#         """
#         Convert all validation errors to a single message format.
#         """
#         # If there are non-field-specific errors
#         if 'non_field_errors' in errors:
#             return errors['non_field_errors'][0]

#         # If there are field-specific errors, pick the first error message
#         for field, messages in errors.items():
#             return messages[0]  # Take the first message for each field error


###################################################################################################################

# class CreateDealView(generics.CreateAPIView):
#     serializer_class = CreateDealSerializer
#     permission_classes = [IsAuthenticated]

#     def post(self, request, *args, **kwargs):
#         # Fetch the vendor's KYC details
#         try:
#             vendor_kyc = VendorKYC.objects.get(user=request.user)
#         except VendorKYC.DoesNotExist:
#             return Response({"message": "Vendor KYC not found for this user."}, status=status.HTTP_404_NOT_FOUND)

#         if not vendor_kyc.is_approved:
#             return Response({"message": "Vendor KYC is not approved."}, status=status.HTTP_400_BAD_REQUEST)

#         # Copy request data and add vendor KYC to the data
#         data = request.data.copy()
#         data['vendor_kyc'] = vendor_kyc.vendor_id

#         # Create the deal using the serializer
#         serializer = self.get_serializer(data=data)
#         if serializer.is_valid():
#             deal = serializer.save()

#             # Vendor location
#             vendor_location = (vendor_kyc.latitude, vendor_kyc.longitude)

#             # Notify nearby users
#             users = CustomUser.objects.exclude(device_token=None)  # Users with device tokens
#             notifications_sent = 0  # Track the number of notifications sent

#             for user in users:
#                 if user.latitude and user.longitude:
#                     user_location = (user.latitude, user.longitude)
#                     distance = geodesic(vendor_location, user_location).km

#                     if distance <= 15:
#                         send_fcm_notification(
#                             device_token=user.device_token,
#                             title=f"New Deal: {deal.deal_title}",
#                             message=f"{vendor_kyc.user.username} has a new deal: {deal.deal_title}!"
#                         )
#                         notifications_sent += 1

#             response_data = serializer.data
#             response_data['message'] = f"Deal created successfully. {notifications_sent} notifications sent."
#             return Response(response_data, status=status.HTTP_201_CREATED)

#         # Handle errors and convert to the desired format
#         error_message = self.format_errors(serializer.errors)
#         return Response({"message": error_message}, status=status.HTTP_400_BAD_REQUEST)

#     def format_errors(self, errors):
#         """
#         Convert all validation errors to a single message format.
#         """
#         # If there are non-field-specific errors
#         if 'non_field_errors' in errors:
#             return errors['non_field_errors'][0]

#         # If there are field-specific errors, pick the first error message
#         for field, messages in errors.items():
#             return messages[0]  # Take the first message for each field error

########################################################################################################

class CreateDealView(generics.CreateAPIView):
    """
    API endpoint to create a new deal.
    """
    queryset = CreateDeal.objects.all()
    serializer_class = CreateDealSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        vendor_kyc = self.request.user.vendorkyc_set.first()
        if not vendor_kyc:
            raise ValidationError("Vendor KYC not found for the user.")
        if not vendor_kyc.is_approved:
            raise ValidationError("Cannot create a deal because Vendor KYC is not approved.")

        serializer.save(vendor_kyc=vendor_kyc)

    def create(self, request, *args, **kwargs):
        # Extract uploaded images metadata from the request if provided
        uploaded_images = request.data.get('uploaded_images', [])

        # Ensure the metadata is a list of dictionaries
        if not isinstance(uploaded_images, list) or not all(isinstance(img, dict) for img in uploaded_images):
            return Response(
                {"error": "uploaded_images must be a list of dictionaries."},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        # Add uploaded images metadata to the deal
        deal = serializer.instance
        deal.set_uploaded_images(uploaded_images)
        deal.save()

        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


class CreateDealDetailView(generics.RetrieveAPIView):
    queryset = CreateDeal.objects.all()  # Retrieves all Activity instances
    serializer_class = CreateDealDetailSerializer
    permission_classes = [AllowAny]
    lookup_field = 'deal_uuid'


class UploadImagesAPI(APIView):
    def post(self, request):
        model_name = request.data.get("model_name")  # e.g., 'Activity', 'VendorKYC', 'CreateDeal'
        images = request.FILES.getlist("images")

        if not model_name or not images:
            return Response({"error": "Model name and images are required."}, status=status.HTTP_400_BAD_REQUEST)

        folder_mapping = {
            "Activity": "activity",
            "VendorKYC": "vendor_kyc",
            "CreateDeal": "create_deal",
        }

        if model_name not in folder_mapping:
            return Response({"error": "Invalid model name."}, status=status.HTTP_400_BAD_REQUEST)

        folder_name = folder_mapping[model_name]
        uploaded_images = []

        for image in images:
            asset_uuid = generate_asset_uuid()
            base_file_name = f"asset_{asset_uuid}.webp"

            # Process and upload thumbnail
            thumbnail = process_image(image, (160, 130))
            thumbnail_url = upload_to_s3(thumbnail, f"{folder_name}", f"thumbnail_{base_file_name}")

            # Process and upload compressed image
            compressed = process_image(image, (600, 250))
            compressed_url = upload_to_s3(compressed, f"{folder_name}", base_file_name)

            uploaded_images.append({
                "thumbnail": thumbnail_url,
                "compressed": compressed_url,
            })

        return Response({
            "message": "Images uploaded successfully.",
            "data": uploaded_images
        }, status=status.HTTP_201_CREATED)
        
        

class UploadDocumentsAPI(APIView):
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request, *args, **kwargs):
        files = request.FILES.getlist('file')  # Get the list of uploaded files
        
        if not files:
            return Response({"error": "No files provided."}, status=status.HTTP_400_BAD_REQUEST)
        
        file_urls = []
        for file in files:
            # Determine file type based on file extension
            file_extension = file.name.split('.')[-1].lower()
            if file_extension in ['jpg', 'jpeg', 'png']:
                file_type = "image"
            elif file_extension in ['pdf', 'doc', 'docx']:
                file_type = "document"
            else:
                return Response({"error": f"Unsupported file type for {file.name}."}, status=status.HTTP_400_BAD_REQUEST)

            try:
                # Upload file to S3 and get its URL
                folder = "vendor_kyc/vendor_kyc_documents"
                file_url = upload_to_s3_documents(file, folder, file_type=file_type)
                file_urls.append(file_url)
            except Exception as e:
                return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Directly return the list of file URLs
        return Response(file_urls, status=status.HTTP_200_OK)
    
class UploadProfileImageAPI(APIView):
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request, *args, **kwargs):
        # Get the uploaded file
        file = request.FILES.get('file')
        
        if not file:
            return Response({"error": "No file provided."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate the file extension
        file_extension = file.name.split('.')[-1].lower()
        if file_extension not in ['jpg', 'jpeg', 'png', 'webp']:
            return Response({"error": "Unsupported file type. Only jpg, jpeg, png, or webp are allowed."}, 
                            status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Define folder path for upload
            folder = "vendor_kyc/vendor_kyc_profile_images"
            
            # Upload the file to S3 and get its URL
            file_url = upload_to_s3_profile_image(file, folder, file_type="image")
            
            # Return only the file URL in the response
            return Response({file_url}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class CreateDeallistView(generics.ListAPIView):
    serializer_class = CreateDeallistSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        # Current date and time
        now = timezone.now()

        # Extract search keyword from query params
        search_keyword = self.request.query_params.get('address', None)

        # Base query: fetch only active deals (end_date >= now)
        queryset = CreateDeal.objects.filter(end_date__gte=now)

        # If search keyword is provided, filter deals based on address fields
        if search_keyword:
            queryset = queryset.filter(
                Q(location_house_no__icontains=search_keyword) |
                Q(location_road_name__icontains=search_keyword) |
                Q(location_country__icontains=search_keyword) |
                Q(location_state__icontains=search_keyword) |
                Q(location_city__icontains=search_keyword) |
                Q(location_pincode__icontains=search_keyword)
            )

        return queryset



    
    
class ActivityListsView(generics.ListAPIView):
    queryset = Activity.objects.all()  # Retrieves all Activity instances
    serializer_class = ActivityListsSerializer
    permission_classes = [AllowAny]
    
class ActivityDetailsView(generics.RetrieveAPIView):
    queryset = Activity.objects.all()  # Retrieves all Activity instances
    serializer_class = ActivityDetailsSerializer
    permission_classes = [AllowAny]
    lookup_field = 'activity_id'


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
    
#PlaceOrder
class PlaceOrderView(generics.CreateAPIView):
    queryset = PlaceOrder.objects.all()
    serializer_class = PlaceOrderSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        # Expecting deal_uuid in the request data
        deal_uuid = request.data.get('deal_uuid')
        if not deal_uuid:
            return Response({"message": "Deal UUID is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Fetch the deal using the deal_uuid
        try:
            deal = CreateDeal.objects.get(deal_uuid=deal_uuid)
        except CreateDeal.DoesNotExist:
            return Response({"message": "Deal not found."}, status=status.HTTP_404_NOT_FOUND)

        # Check if the user is attempting to purchase their own deal
        if VendorKYC.objects.filter(user=request.user, vendor_id=deal.vendor_kyc.vendor_id).exists():
            return Response({"message": "You cannot purchase your own deal."}, status=status.HTTP_403_FORBIDDEN)

        # Create the order using the deal and request data
        serializer = self.get_serializer(data=request.data, context={'request': request})

        # Validate the serializer and check for errors
        if not serializer.is_valid():
            # Flatten the error response
            error_message = list(serializer.errors.values())[0][0]  # Get the first error message
            return Response({"message": error_message}, status=status.HTTP_400_BAD_REQUEST)

        # Save the order if everything is valid
        place_order = serializer.save(user=request.user, deal=deal)  # Pass the deal to the save method

        # Custom response for successful order creation
        response_data = {
            "order_id": str(place_order.order_id),  # Ensure UUID is string
            "deal_uuid": str(place_order.deal.deal_uuid),  # Ensure UUID is string
            "user_id": str(place_order.user.id),  # Ensure UUID is string
            "vendor_id": str(deal.vendor_kyc.vendor_id),  # Ensure UUID is string
            "quantity": place_order.quantity,
            "country": place_order.country,
            "latitude": place_order.latitude,
            "longitude": place_order.longitude,
            "total_amount": str(place_order.total_amount),  # Convert Decimal to string
            "transaction_id": place_order.transaction_id,
            "payment_status": place_order.payment_status,
            "payment_mode": place_order.payment_mode,
            "created_at": place_order.created_at.strftime("%Y-%m-%d %H:%M:%S")  # Format datetime
        }

        # Return the response with the message and data
        return Response({"message": "Order placed successfully", **response_data}, status=status.HTTP_201_CREATED)

class PlaceOrderDetailsView(generics.RetrieveAPIView):
    queryset = PlaceOrder.objects.all()
    serializer_class = PlaceOrderDetailsSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, order_id, *args, **kwargs):
        try:
            # Fetch the order by ID
            place_order = PlaceOrder.objects.get(order_id=order_id)
            
            # Check if the order belongs to the requesting user
            if place_order.user != request.user:
                return Response(
                    {"message": "You are not authorized to access this order."},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Serialize and return the order details
            serializer = PlaceOrderDetailsSerializer(place_order)
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except PlaceOrder.DoesNotExist:
            return Response(
                {"message": "Order not found."},
                status=status.HTTP_404_NOT_FOUND
            )
            
class CategoriesView(APIView):
    def get(self, request):
        # Fetch activity categories and serialize them
        activity_categories = ActivityCategory.objects.all()
        activity_data = ActivityCategorySerializer(activity_categories, many=True).data

        # Fetch service categories and serialize them
        service_categories = ServiceCategory.objects.all()
        service_data = ServiceCategorySerializer(service_categories, many=True).data

        # Format the response
        response_data = {
            "activity_category": activity_data,
            "service_category": service_data,
        }

        return Response(response_data)
    
class CustomUserDetailView(generics.RetrieveAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserDetailsSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'  # This should match the URL pattern
    
    def get_queryset(self):
        # Now use deal_uuid instead of pk
        return CustomUser.objects.filter(id=self.kwargs['id'])
    
    
class CustomUserEditView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user
        serializer = CustomUserEditSerializer(user, context={'request': request})  # Pass the request
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        user = request.user
        serializer = CustomUserEditSerializer(user, data=request.data, partial=True, context={'request': request})  # Pass the request
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
class PlaceOrderListsView(generics.ListAPIView):
    serializer_class = PlaceOrderListsSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Get the logged-in user
        user = self.request.user

        # Filter orders where the user is either the buyer or the vendor
        return PlaceOrder.objects.filter(Q(user=user))


class SocialLogin(generics.GenericAPIView):
    serializer_class = CustomUserSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        social_id = request.data.get("social_id")
        email = request.data.get("email")
        name = request.data.get("name")
        login_type = request.data.get("type")  # Google or Apple

        if not social_id or not email or not login_type:
            return Response(
                {"message": "social_id, email, and type (google/apple) are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Check if user exists with the same email
        user = CustomUser.objects.filter(email=email).first()

        if user:
            # Update social_id and type if blank
            if not user.social_id:
                user.social_id = social_id
            if not user.type:
                user.type = login_type
            user.save()
        else:
            # Generate a unique placeholder phone number
            placeholder_phone = f"phone_{uuid.uuid4().hex[:8]}"
            
            # Create a new user with minimal required data
            user = CustomUser.objects.create(
                social_id=social_id,
                email=email,
                name=name,
                username=email.split('@')[0],  # Default username from email
                phone_number=placeholder_phone,  # Temporary placeholder phone number
                date_of_birth=None,             # Default for date of birth
                gender=None,                    # Default for gender
                type=login_type,                # Login type (Google/Apple)
            )

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        return Response(
            {
                "user": CustomUserSerializer(user).data,
                "refresh": str(refresh),
                "access": access_token,
                "message": "Login successful.",
            },
            status=status.HTTP_200_OK,
        )







    
# class SocialLogin(generics.GenericAPIView):
#     serializer_class = CustomUserSerializer
#     permission_classes = [AllowAny]

#     def post(self, request, *args, **kwargs):
#         social_id = request.data.get("social_id")
#         email = request.data.get("email")
#         name = request.data.get("name")
#         login_type = request.data.get("type")  # Google ya Apple

#         if not social_id or not email or not login_type:
#             return Response({"message": "social_id, email, and type (google/apple) are required."}, status=status.HTTP_400_BAD_REQUEST)

#         # Check if user exists with the same email
#         user = CustomUser.objects.filter(email=email).first()

#         if user:
#             # Update social_id and type if blank
#             if not user.social_id:
#                 user.social_id = social_id
#             if not user.type:
#                 user.type = login_type
#             user.save()
#         else:
#             # Create new user for social login
#             user = CustomUser.objects.create(
#                 social_id=social_id,
#                 email=email,
#                 name=name,
#                 type=login_type,  # Set login type
#             )

#         # Generate JWT tokens
#         refresh = RefreshToken.for_user(user)
#         access_token = str(refresh.access_token)

#         return Response({
#             "user": CustomUserSerializer(user).data,
#             "refresh": str(refresh),
#             "access": access_token,
#             "message": "Login successful.",
#         }, status=status.HTTP_200_OK)

    
    
    
    
# class NotificationView(APIView):
#     permission_classes = [AllowAny]

#     def post(self, request):
#         user_location = request.data.get('location')  # {'latitude': 21.643640, 'longitude': 69.615650}
#         if not user_location:
#             return Response({"error": "Location is required"}, status=400)

#         user_point = Point(user_location['longitude'], user_location['latitude'])

#         # Fetch active deals within 15 KM radius
#         deals = CreateDeal.objects.filter(
#             location__distance_lte=(user_point, D(km=15))
#         )

#         # Send notifications to users
#         notifications_sent = []
#         for deal in deals:
#             vendor_name = deal.vendor_kyc.full_name
#             deal_title = deal.deal_title
#             user_device_token = request.user.device_token

#             if user_device_token:
#                 send_notification(user_device_token, vendor_name, deal_title)
#                 notifications_sent.append({"vendor_name": vendor_name, "deal_title": deal_title})

#         return Response({"notifications": notifications_sent})    
    

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