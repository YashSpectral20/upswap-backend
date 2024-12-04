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
from .models import (CustomUser, OTP, Activity, ChatRoom, ChatMessage, ChatRequest, VendorKYC, ActivityImage, BusinessDocument, BusinessPhoto, CreateDeal, DealsImage, PlaceOrder,
                    ActivityCategory, ServiceCategory)

from .serializers import (
    CustomUserSerializer, VerifyOTPSerializer, LoginSerializer,
    ActivitySerializer, ActivityImageSerializer, ChatRoomSerializer, ChatMessageSerializer,
    ChatRequestSerializer, VendorKYCSerializer, BusinessDocumentSerializer, BusinessPhotoSerializer,
    CreateDealSerializer, CreateDealImageSerializer, VendorKYCDetailSerializer,
    VendorKYCListSerializer, ActivityListsSerializer, ForgotPasswordSerializer, ResetPasswordSerializer, CreateDeallistSerializer, CreateDealDetailSerializer, PlaceOrderSerializer, PlaceOrderDetailsSerializer,
    ActivityCategorySerializer, ServiceCategorySerializer, CustomUserDetailsSerializer, PlaceOrderListsSerializer, ActivityImageListsSerializer

)
from rest_framework.generics import RetrieveAPIView
from .utils import generate_otp, process_images_from_s3, send_fcm_notification 
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

# views.py
class ActivityImageListCreateView(generics.ListCreateAPIView):
    serializer_class = ActivityImageSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        activity_id = self.kwargs.get('activity_id')
        return ActivityImage.objects.filter(activity__activity_id=activity_id)

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['activity_id'] = self.kwargs.get('activity_id')
        return context

    def perform_create(self, serializer):
        activity_id = self.kwargs.get('activity_id')
        try:
            activity = Activity.objects.get(activity_id=activity_id)
        except Activity.DoesNotExist:
            raise serializers.ValidationError("Activity not found.")
        
        # Pass the activity object to the serializer to associate the image with the activity
        serializer.save(activity=activity)


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


"""
class VendorKYCListView(generics.RetrieveUpdateDestroyAPIView):
    queryset = VendorKYC.objects.all()
    serializer_class = VendorKYCListSerializer
    permission_classes = [AllowAny]
"""


class VendorKYCListView(ListAPIView):
    queryset = VendorKYC.objects.all()
    serializer_class = VendorKYCListSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        country = self.request.query_params.get('country', None)
        queryset = VendorKYC.objects.all()

        if country:
            queryset = queryset.filter(addresses__country=country)  # Filter based on related 'Address' country field

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


class CreateDealView(generics.CreateAPIView):
    serializer_class = CreateDealSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        # Fetch the vendor's KYC details
        try:
            vendor_kyc = VendorKYC.objects.get(user=request.user)
        except VendorKYC.DoesNotExist:
            return Response({"message": "Vendor KYC not found for this user."}, status=status.HTTP_404_NOT_FOUND)

        if not vendor_kyc.is_approved:
            return Response({"message": "Vendor KYC is not approved."}, status=status.HTTP_400_BAD_REQUEST)

        # Copy request data and add vendor KYC to the data
        data = request.data.copy()
        data['vendor_kyc'] = vendor_kyc.vendor_id

        # Create the deal using the serializer
        serializer = self.get_serializer(data=data)
        if serializer.is_valid():
            deal = serializer.save()

            # Vendor location
            vendor_location = (vendor_kyc.latitude, vendor_kyc.longitude)

            # Notify nearby users
            users = CustomUser.objects.exclude(device_token=None)  # Users with device tokens
            notifications_sent = 0  # Track the number of notifications sent

            for user in users:
                if user.latitude and user.longitude:
                    user_location = (user.latitude, user.longitude)
                    distance = geodesic(vendor_location, user_location).km

                    if distance <= 15:
                        send_fcm_notification(
                            device_token=user.device_token,
                            title=f"New Deal: {deal.deal_title}",
                            message=f"{vendor_kyc.user.username} has a new deal: {deal.deal_title}!"
                        )
                        notifications_sent += 1

            response_data = serializer.data
            response_data['message'] = f"Deal created successfully. {notifications_sent} notifications sent."
            return Response(response_data, status=status.HTTP_201_CREATED)

        # Handle errors and convert to the desired format
        error_message = self.format_errors(serializer.errors)
        return Response({"message": error_message}, status=status.HTTP_400_BAD_REQUEST)

    def format_errors(self, errors):
        """
        Convert all validation errors to a single message format.
        """
        # If there are non-field-specific errors
        if 'non_field_errors' in errors:
            return errors['non_field_errors'][0]

        # If there are field-specific errors, pick the first error message
        for field, messages in errors.items():
            return messages[0]  # Take the first message for each field error

class DealImageUploadView(generics.ListCreateAPIView):
    queryset = DealsImage.objects.all()
    serializer_class = CreateDealImageSerializer
    parser_classes = [MultiPartParser]

    def post(self, request, *args, **kwargs):
        """
        Handle multiple image uploads, save them to the database, 
        and return their details along with base64-encoded versions of resized images.
        """
        # Validate if images are provided in the request
        if not request.FILES.getlist('images'):
            return Response(
                {"error": "At least one image is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        images = request.FILES.getlist('images')
        uploaded_images = []

        # Process each uploaded image
        for image in images:
            try:
                # Save the image instance to the database
                deal_image = DealsImage(images=image)
                deal_image.save()

                # Convert the image to a base64 string
                image_base64 = self._convert_image_to_base64(deal_image)

                # Append details of the saved image
                uploaded_images.append({
                    "image_id": deal_image.image_id,
                    "uploaded_at": deal_image.uploaded_at,
                    "file_name": deal_image.images.name,
                    "image_base64": image_base64,
                })

            except ValueError as e:
                # Return ValueError with traceback for debugging
                tb = traceback.format_exc()
                return Response(
                    {
                        "error": f"An error occurred while processing image {image.name}: {str(e)}",
                        "traceback": tb,
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            except Exception as e:
                # Return generic exceptions with traceback for debugging
                tb = traceback.format_exc()
                return Response(
                    {
                        "error": f"An unexpected error occurred while processing image {image.name}: {str(e)}",
                        "traceback": tb,
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        # Return response for all successfully uploaded images
        return Response(
            {"message": "Images uploaded successfully", "uploaded_images": uploaded_images},
            status=status.HTTP_201_CREATED
        )

    def _convert_image_to_base64(self, deal_image):
        """
        Convert the uploaded image to a base64-encoded string after resizing to a maximum width of 600 pixels while maintaining the aspect ratio.
        Uses Image.ANTIALIAS for resizing and handles both local and remote storage backends.
        """
        try:
            if hasattr(deal_image.images, 'file'):
                img = Image.open(deal_image.images.file)
            else:
                # Fetch the image via URL if it's stored remotely
                response = requests.get(deal_image.images.url, stream=True)
                response.raise_for_status()
                img = Image.open(BytesIO(response.content))

            # Calculate new dimensions preserving the aspect ratio
            base_width = 600
            w_percent = (base_width / float(img.size[0]))
            h_size = int((float(img.size[1]) * float(w_percent)))

            # Resize the image using Image.ANTIALIAS for high-quality downsampling
            img = img.resize((base_width, h_size), Image.ANTIALIAS)
            output = BytesIO()
            img.save(output, format='WEBP', quality=85)
            output.seek(0)

            # Encode the image to base64 and prepend the MIME type for HTML display
            base64_data = base64.b64encode(output.read()).decode('utf-8')
            return f'data:image/webp;base64,{base64_data}'

        except Exception as e:
            print(f"Error processing image: {e}")
            raise ValueError(f"Error processing image: {str(e)}")


def download_s3_file(request, file_key):
    """
    Download a file from S3 and return it as a response.

    Args:
        request: The HTTP request object.
        file_key (str): The S3 key of the file (path in the bucket).

    Returns:
        HttpResponse: The file content as an HTTP response.
        JsonResponse: Error message in case of failure.
    """
    # Initialize the S3 client with credentials from settings.py
    s3_client = boto3.client(
        's3',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_S3_REGION_NAME
    )

    try:
        # Fetch the object from S3 bucket
        file_object = s3_client.get_object(
            Bucket=settings.AWS_STORAGE_BUCKET_NAME,
            Key=file_key
        )
        file_content = file_object['Body'].read()  # Read the content of the file

        # Create a response with the file content
        response = HttpResponse(file_content, content_type=file_object['ContentType'])
        response['Content-Disposition'] = f'attachment; filename="{file_key.split("/")[-1]}"'
        return response

    except ClientError as e:
        # Handle errors (e.g., file not found or access denied)
        error_message = str(e)
        return JsonResponse({'error': error_message}, status=404)
    
 
class CreateDealDetailView(APIView):

    def get(self, request, deal_uuid):
        try:
            # Fetch the deal
            deal = CreateDeal.objects.get(deal_uuid=deal_uuid)

            # Serialize data
            serializer = CreateDealDetailSerializer(deal, context={"request": request})

            uploaded_images = []

            # Process each image from S3
            for image_data in deal.uploaded_images:
                try:
                    file_name = image_data.get("file_name")  # S3 file path
                    if not file_name:
                        raise ValueError("File name missing")

                    # Download the image from S3
                    s3_client = boto3.client(
                        's3',
                        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                        region_name=settings.AWS_S3_REGION_NAME
                    )
                    file_object = s3_client.get_object(
                        Bucket=settings.AWS_STORAGE_BUCKET_NAME,
                        Key=file_name
                    )
                    file_content = file_object['Body'].read()

                    # Open the image with PIL
                    img = Image.open(BytesIO(file_content))

                    # Calculate the new size while maintaining the aspect ratio
                    base_width = 600
                    w_percent = base_width / float(img.size[0])  # Width scaling factor
                    h_size = int(float(img.size[1]) * float(w_percent))  # Adjust height to keep aspect ratio

                    img = img.resize((base_width, h_size), Image.ANTIALIAS)  # Resize with maintained ratio
                    buffer = BytesIO()
                    img.save(buffer, format='WEBP', quality=85)
                    buffer.seek(0)

                    # Convert the image to base64
                    image_base64 = base64.b64encode(buffer.read()).decode('utf-8')
                    base64_data = f"data:image/webp;base64,{image_base64}"

                    # Append image data to the list
                    uploaded_images.append({
                        "image_id": image_data.get("image_id"),
                        "image_base64": base64_data,
                        "uploaded_at": image_data.get("uploaded_at"),
                    })

                except ClientError as e:
                    # Handle S3 errors
                    uploaded_images.append({
                        "image_id": image_data.get("image_id"),
                        "error": f"S3 error: {str(e)}",
                        "uploaded_at": image_data.get("uploaded_at"),
                    })
                except Exception as e:
                    # Handle generic errors
                    uploaded_images.append({
                        "image_id": image_data.get("image_id"),
                        "error": str(e),
                        "uploaded_at": image_data.get("uploaded_at"),
                    })

            # Add images to the serialized data
            serialized_data = serializer.data
            serialized_data["uploaded_images"] = uploaded_images

            return Response(serialized_data, status=200)

        except CreateDeal.DoesNotExist:
            # Return error if deal not found
            return Response({"error": "Deal not found"}, status=404)



# class CreateDealDetailView(APIView):
#     def get(self, request, deal_uuid):
#         # Initialize S3 client
#         s3_client = boto3.client(
#             's3',
#             aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
#             aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
#             region_name=settings.AWS_S3_REGION_NAME,
#         )

#         try:
#             # Fetch the deal instance
#             deal = CreateDeal.objects.get(deal_uuid=deal_uuid)

#             # Fetch linked images for the deal
#             images = DealsImage.objects.filter(create_deal=deal)

#             # Initialize list for storing base64-encoded image data
#             base64_images = []

#             # Process each image
#             for image in images:
#                 file_key = image.images.name  # Path to the image in S3
#                 if file_key:  # Ensure the file key exists
#                     try:
#                         # Process the image to get base64 string
#                         base64_data = self._download_and_process_s3_image(
#                             s3_client, file_key
#                         )
#                         if base64_data:
#                             # Add image details to the response
#                             base64_images.append({
#                                 "image_id": str(image.image_id),
#                                 "uploaded_at": image.uploaded_at,
#                                 "base64": base64_data
#                             })
#                     except Exception as e:
#                         print(f"Error processing image {file_key}: {e}")
#                 else:
#                     print(f"Empty file key for image: {image.image_uuid}")

#             # Serialize the deal data
#             serializer = CreateDealDetailSerializer(deal)
#             serialized_data = serializer.data

#             # Add the processed images to the response
#             serialized_data["upload_images"] = base64_images

#             return Response(serialized_data, status=status.HTTP_200_OK)

#         except CreateDeal.DoesNotExist:
#             return Response(
#                 {"error": "No deal found for the specified deal_uuid."},
#                 status=status.HTTP_404_NOT_FOUND,
#             )
#         except Exception as e:
#             return Response(
#                 {"error": f"An unexpected error occurred: {str(e)}"},
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             )

#     def _download_and_process_s3_image(self, s3_client, file_key):
#         """
#         Download an image from S3, resize it, and convert it to base64.
#         """
#         try:
#             # Fetch the file from S3
#             response = s3_client.get_object(
#                 Bucket=settings.AWS_STORAGE_BUCKET_NAME,
#                 Key=file_key
#             )
#             image_data = response['Body'].read()

#             # Load and resize the image
#             img = Image.open(BytesIO(image_data))
#             base_width = 600
#             w_percent = (base_width / float(img.size[0]))
#             h_size = int((float(img.size[1]) * float(w_percent)))
#             img = img.resize((base_width, h_size), Image.ANTIALIAS)

#             # Save the resized image to a buffer
#             output = BytesIO()
#             img.save(output, format="WEBP", quality=85)
#             output.seek(0)

#             # Convert to base64
#             base64_data = base64.b64encode(output.read()).decode('utf-8')
#             return f"data:image/webp;base64,{base64_data}"
#         except Exception as e:
#             raise ValueError(f"Failed to process S3 image: {str(e)}")




class CreateDeallistView(generics.ListAPIView):
    serializer_class = CreateDeallistSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        # Get the current date and time
        now = timezone.now()

        # Get the country from the query parameters
        country = self.request.query_params.get('country', None)

        # Filter deals based on end date and location_country
        queryset = CreateDeal.objects.filter(end_date__gte=now)

        # Apply country filter if country is provided
        if country:
            queryset = queryset.filter(location_country__iexact=country)  # Use location_country field for filtering

        return queryset
    
    
class ActivityListsView(generics.ListAPIView):
    queryset = Activity.objects.all()  # Retrieves all Activity instances
    serializer_class = ActivityListsSerializer
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
            "created_at": place_order.created_at.isoformat()  # Convert datetime to ISO 8601 string
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
    
class PlaceOrderListsView(generics.ListAPIView):
    serializer_class = PlaceOrderListsSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Get the logged-in user
        user = self.request.user

        # Filter orders where the user is either the buyer or the vendor
        return PlaceOrder.objects.filter(Q(user=user))
    
class ActivityImagesListView(generics.ListAPIView):
    serializer_class = ActivityImageListsSerializer

    def get_queryset(self):
        activity_id = self.kwargs['activity_id']
        return ActivityImage.objects.filter(activity__activity_id=activity_id)
    
    
class NotificationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        user_location = request.data.get('location')  # {'latitude': 21.643640, 'longitude': 69.615650}
        if not user_location:
            return Response({"error": "Location is required"}, status=400)

        user_point = Point(user_location['longitude'], user_location['latitude'])

        # Fetch active deals within 15 KM radius
        deals = CreateDeal.objects.filter(
            location__distance_lte=(user_point, D(km=15))
        )

        # Send notifications to users
        notifications_sent = []
        for deal in deals:
            vendor_name = deal.vendor_kyc.full_name
            deal_title = deal.deal_title
            user_device_token = request.user.device_token

            if user_device_token:
                send_notification(user_device_token, vendor_name, deal_title)
                notifications_sent.append({"vendor_name": vendor_name, "deal_title": deal_title})

        return Response({"notifications": notifications_sent})    