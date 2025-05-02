import random
import datetime as dt
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
from datetime import timedelta
from django.db.models import Q
from django.db.models import F, Func, FloatField
from math import radians, sin, cos, sqrt, atan2, asin
from django.db.models import Sum
from django.db import models
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
from .models import (CustomUser, OTP, Activity, PasswordResetOTP, VendorKYC, Address, CreateDeal, PlaceOrder,
                    ActivityCategory, ServiceCategory, FavoriteVendor, RaiseAnIssueVendors, RaiseAnIssueCustomUser, Notification, Device)

from .serializers import (
    CustomUserSerializer, OTPRequestSerializer, OTPResetPasswordSerializer, OTPValidationSerializer, VerifyOTPSerializer, LoginSerializer,
    ActivitySerializer, VendorKYCSerializer,
    CreateDealSerializer, VendorKYCDetailSerializer,
    VendorKYCListSerializer, ActivityListsSerializer, ActivityDetailsSerializer, ForgotPasswordSerializer, ResetPasswordSerializer, CreateDeallistSerializer, CreateDealDetailSerializer, PlaceOrderSerializer, PlaceOrderDetailsSerializer,
    ActivityCategorySerializer, ServiceCategorySerializer, CustomUserDetailsSerializer, PlaceOrderListsSerializer, VendorKYCStatusSerializer, CustomUserEditSerializer, MyDealSerializer, SuperadminLoginSerializer, FavoriteVendorSerializer,
    MyActivitysSerializer, FavoriteVendorsListSerializer, VendorRatingSerializer, RaiseAnIssueSerializerMyOrders, RaiseAnIssueVendorsSerializer, RaiseAnIssueCustomUserSerializer, AddressSerializer,
    ActivityRepostSerializer, MySalesSerializer, NotificationSerializer, DeviceSerializer

)    # ChatRoomSerializer, ChatMessageSerializer, ChatRequestSerializer,
from datetime import datetime
from datetime import datetime as dt
from rest_framework.generics import RetrieveAPIView
from .utils import generate_otp, process_image, upload_to_s3, upload_to_s3_documents, upload_to_s3_profile_image, generate_asset_uuid, send_otp_via_sms, create_notification 
from .firebase_utils import send_notification_to_user 
from rest_framework.decorators import api_view
from geopy.distance import geodesic
from .services import get_image_from_s3
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated, PermissionDenied
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
from datetime import datetime, date, time  
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.urls import reverse
from geopy.distance import distance
from rest_framework.parsers import MultiPartParser, FormParser
from django.utils.timezone import make_aware
from rest_framework.permissions import IsAuthenticated
from firebase_admin import messaging

from django.shortcuts import get_object_or_404

from activity_log.models import ActivityLog
from activity_log.serializers import ActivityLogSerializer

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
            
            # Create session manually
            request.session["registered_user_id"] = str(user.id)  # 👈 Fix UUID serialization
            if not request.session.session_key:
                request.session.save()
            session_id = request.session.session_key

            # activity log
            ActivityLog.objects.create(
            user=user,
            event=ActivityLog.SIGN_UP,
            metadata={
                "user_id": str(user.id),
                "longitude": str(user.longitude),
                "latitude": str(user.latitude)
            },
        )

            return Response({
                'user': CustomUserSerializer(user, context=self.get_serializer_context()).data,
                'refresh': str(refresh),
                'access': access_token,
                'session_id': session_id,
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
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        from django.contrib.auth import login
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response({"message": "Invalid Credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        user = serializer.validated_data['user']
        login(request, user)
        
        # ✅ Save session and fetch session ID
        if not request.session.session_key:
            request.session.save()
        session_id = request.session.session_key

        try:
            otp_instance = OTP.objects.get(user=user)
            if not otp_instance.is_verified:
                return Response({"message": "OTP not verified. Please verify your OTP first."}, status=status.HTTP_403_FORBIDDEN)
        except OTP.DoesNotExist:
            return Response({"message": "You have not set a  password yet. Log in with Google or Signup with a new account."}, status=status.HTTP_400_BAD_REQUEST)

        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        # activity log
        ActivityLog.objects.create(
            user=user,
            event=ActivityLog.LOGIN,
            metadata={}
        )

        vendor_kyc = VendorKYC.objects.filter(user=user).first()
        is_approved = vendor_kyc.is_approved if vendor_kyc else False
        vendor_id = str(vendor_kyc.vendor_id) if vendor_kyc else ""

        return Response({
            'user': CustomUserSerializer(user, context=self.get_serializer_context()).data,
            'refresh': str(refresh),
            'access': access_token,
            'sessionid': session_id,
            'is_approved': is_approved,
            'vendor_id': vendor_id,
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
    
# Haversine distance calculation
def calculate_distance(lat1, lon1, lat2, lon2):
    lon1, lat1, lon2, lat2 = map(radians, [lon1, lat1, lon2, lat2])
    dlon = lon2 - lon1 
    dlat = lat2 - lat1 
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a)) 
    r = 6371  # Radius of earth in kilometers
    return c * r

class ActivityCreateView(generics.CreateAPIView):
    queryset = Activity.objects.all()
    serializer_class = ActivitySerializer
    permission_classes = [permissions.IsAuthenticated]

    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid():
                if 'user_participation' not in serializer.validated_data:
                    serializer.validated_data['user_participation'] = True
                if 'infinite_time' not in serializer.validated_data:
                    serializer.validated_data['infinite_time'] = False  # Ensure default is False
                
                activity = serializer.save(created_by=self.request.user)
                
                # ✅ Notify Nearby Users Within 5KM Only
                notified_users = []

                if activity.latitude and activity.longitude:
                    # Exclude creator and users without location data
                    nearby_users = CustomUser.objects.exclude(id=request.user.id).exclude(latitude__isnull=True, longitude__isnull=True)
                    
                    for user in nearby_users:
                        distance = calculate_distance(
                            float(activity.latitude),
                            float(activity.longitude),
                            float(user.latitude),
                            float(user.longitude)
                        )
                        if distance <= 5:
                            create_notification(
                                user=user,
                                notification_type="activity",
                                title="New Activity Near You!",
                                body=f"{request.user.name} just posted: {activity.activity_title}",
                                reference_instance=activity,
                                data={"activity_id": str(activity.activity_id)}
                            )
                            notified_users.append(str(user.id))
                else:
                    print("Activity location not provided; skipping user-distance filtering.")

                # 🔔 Notify the creator as well
                create_notification(
                    user=request.user,
                    notification_type="activity",
                    title="Your Activity is Live!",
                    body=f"You have successfully posted: {activity.activity_title}",
                    reference_instance=activity,
                    data={"activity_id": str(activity.activity_id)}
                )
                    
                # activity log
                ActivityLog.objects.create(
                    user=activity.created_by,
                    event=ActivityLog.CREATE_ACTIVITY,
                    metadata={}
                )
                return Response(
                    {
                        "message": "Activity created successfully",
                        "activity_id": str(activity.activity_id),
                        "activity_title": activity.activity_title,
                        "activity_description": activity.activity_description,
                        "activity_category": activity.activity_category.actv_category if activity.activity_category else None,
                        "uploaded_images": activity.uploaded_images,
                        "user_participation": activity.user_participation,
                        "maximum_participants": activity.maximum_participants,
                        "start_date": activity.start_date,
                        "end_date": activity.end_date,
                        "start_time": activity.start_time,
                        "end_time": activity.end_time,
                        "created_at": activity.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                        "created_by": str(activity.created_by.id),
                        "infinite_time": activity.infinite_time,
                        "set_current_datetime": activity.set_current_datetime,
                        "location": activity.location,
                        "latitude": activity.latitude,
                        "longitude": activity.longitude,
                    },
                    status=status.HTTP_201_CREATED,
                )
            else:
                # Validation error
                error_message = next(iter(serializer.errors.values()))[0]
                return Response(
                    {"message": error_message},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except Exception as e:
            # Koi unexpected error
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def handle_exception(self, exc):
        if isinstance(exc, NotAuthenticated):
            return Response({"message": "Authentication credentials were not provided or invalid."},
                            status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)



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



# class ChatRoomCreateView(APIView):
#     """
#     API view for creating chat rooms (requires authentication).
#     """
#     authentication_classes = [JWTAuthentication] 
#     permission_classes = [IsAuthenticated]

#     def post(self, request, *args, **kwargs):
#         serializer = ChatRoomSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response({'message': 'Chat room created successfully'}, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# class ChatRoomRetrieveView(APIView):
#     """
#     API view for retrieving a specific chat room (requires authentication).
#     """
#     authentication_classes = [JWTAuthentication] 
#     permission_classes = [IsAuthenticated]

#     def get(self, request, pk, *args, **kwargs):
#         chat_room = ChatRoom.objects.get(pk=pk)
#         serializer = ChatRoomSerializer(chat_room)
#         return Response(serializer.data, status=status.HTTP_200_OK)


# class ChatMessageCreateView(APIView):
#     """
#     API view for creating chat messages (requires authentication).
#     """
#     authentication_classes = [JWTAuthentication] 
#     permission_classes = [IsAuthenticated]

#     def post(self, request, *args, **kwargs):
#         serializer = ChatMessageSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response({'message': 'Chat message created successfully'}, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# class ChatMessageListView(APIView):
#     """
#     API view for listing chat messages in a specific chat room (requires authentication).
#     """
#     authentication_classes = [JWTAuthentication] 
#     permission_classes = [IsAuthenticated]

#     def get(self, request, chat_room_id, *args, **kwargs):
#         chat_messages = ChatMessage.objects.filter(chat_room_id=chat_room_id)
#         serializer = ChatMessageSerializer(chat_messages, many=True)
#         return Response(serializer.data, status=status.HTTP_200_OK)


# class ChatRequestCreateView(APIView):
#     """
#     API view for creating chat requests (requires authentication).
#     """
#     authentication_classes = [JWTAuthentication] 
#     permission_classes = [IsAuthenticated]

#     def post(self, request, *args, **kwargs):
#         serializer = ChatRequestSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response({'message': 'Chat request created successfully'}, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# class ChatRequestRetrieveView(APIView):
#     """
#     API view for retrieving a specific chat request (requires authentication).
#     """
#     authentication_classes = [JWTAuthentication] 
#     permission_classes = [IsAuthenticated]

#     def get(self, request, pk, *args, **kwargs):
#         chat_request = ChatRequest.objects.get(pk=pk)
#         serializer = ChatRequestSerializer(chat_request)
#         return Response(serializer.data, status=status.HTTP_200_OK)


# class AcceptChatRequestView(APIView):
#     """
#     API view for accepting a chat request (requires authentication).
#     """
#     authentication_classes = [JWTAuthentication] 
#     permission_classes = [IsAuthenticated]

#     def post(self, request, pk, *args, **kwargs):
#         chat_request = ChatRequest.objects.get(pk=pk)
#         chat_request.status = 'accepted'
#         chat_request.save()
#         return Response({'message': 'Chat request accepted'}, status=status.HTTP_200_OK)


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
        
    def perform_create(self, serializer):
        user = self.request.user
        profile_pic = self.request.data.get('profile_pic', '')

        # Ensure profile_pic is stored as a string
        if isinstance(profile_pic, list) or isinstance(profile_pic, dict):
            raise ValidationError({"profile_pic": "profile_pic must be a string (image URL or path)."})

        serializer.save(user=user, profile_pic=profile_pic)

    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)

            # activity log
            ActivityLog.objects.create(
                user=request.user,
                event=ActivityLog.APPLY_KYC,
                metadata={}
            )

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


# class VendorKYCListView(ListAPIView):
#     serializer_class = VendorKYCListSerializer
#     permission_classes = [AllowAny]

#     def get_queryset(self):
#         # Get the search keyword from query params
#         search_keyword = self.request.query_params.get('address', None)

#         # Base query for fetching all vendors
#         queryset = VendorKYC.objects.all()

#         if search_keyword:
#             # Split the search keyword into individual terms
#             search_terms = search_keyword.split(',')

#             # Start with a Q object for the filtering conditions
#             query = Q()

#             if len(search_terms) == 1:
#                 # If only one term, assume it's a country, state, or city
#                 clean_term = search_terms[0].strip()

#                 # If the term matches a country, filter by country
#                 query |= Q(addresses__country__icontains=clean_term)
                
#                 # If the term matches a state, filter by state
#                 query |= Q(addresses__state__icontains=clean_term)
                
#                 # If the term matches a city, filter by city
#                 query |= Q(addresses__city__icontains=clean_term)

#             elif len(search_terms) == 2:
#                 # Two terms: Could be (city, state) or (city, country) or (state, country)
#                 clean_first = search_terms[0].strip()
#                 clean_second = search_terms[1].strip()

#                 # Check for city, state (e.g., Mathura, Uttar Pradesh)
#                 query |= (
#                     Q(addresses__city__icontains=clean_first) & 
#                     Q(addresses__state__icontains=clean_second)
#                 )

#                 # Check for city, country (e.g., Mathura, India)
#                 query |= (
#                     Q(addresses__city__icontains=clean_first) & 
#                     Q(addresses__country__icontains=clean_second)
#                 )

#                 # Check for state, country (e.g., Uttar Pradesh, India)
#                 query |= (
#                     Q(addresses__state__icontains=clean_first) & 
#                     Q(addresses__country__icontains=clean_second)
#                 )

#             elif len(search_terms) == 3:
#                 # Three terms: Could be full address with house, road, city, state, country
#                 clean_house = search_terms[0].strip()
#                 clean_road = search_terms[1].strip()
#                 clean_city = search_terms[2].strip()

#                 query |= (
#                     Q(addresses__house_no_building_name__icontains=clean_house) &
#                     Q(addresses__road_name_area_colony__icontains=clean_road) &
#                     Q(addresses__city__icontains=clean_city)
#                 )

#             # Apply the query filter
#             queryset = queryset.filter(query).distinct()

#         return queryset

#     def list(self, request, *args, **kwargs):
#         queryset = self.get_queryset()

#         # Prepare response structure
#         response_data = {
#             "message": "No Vendor KYC entries available for the specified search keyword." if not queryset.exists() else "Lists of Vendors",
#             "vendors": []
#         }

#         if queryset.exists():
#             serializer = self.get_serializer(queryset, many=True)
#             response_data["vendors"] = serializer.data

#         return Response(response_data, status=status.HTTP_200_OK)



class VendorKYCListView(ListAPIView):
    serializer_class = VendorKYCListSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        queryset = VendorKYC.objects.all()
        search_keyword = self.request.query_params.get('address', None)

        if search_keyword:
            search_terms = [term.strip() for term in search_keyword.split(',')]
            query = Q()

            if len(search_terms) == 1:
                clean_term = search_terms[0]
                query |= Q(addresses__city__icontains=clean_term)
                query |= Q(addresses__state__icontains=clean_term)
                query |= Q(addresses__country__icontains=clean_term)
                query |= Q(addresses__pincode__icontains=clean_term)
                query |= Q(addresses__road_name_area_colony__icontains=clean_term)

            elif len(search_terms) == 2:
                if queryset.filter(addresses__city__icontains=search_terms[0]).exists():
                    query |= Q(addresses__city__icontains=search_terms[0])
                elif queryset.filter(addresses__state__icontains=search_terms[0]).exists():
                    query |= Q(addresses__state__icontains=search_terms[0])
                elif queryset.filter(addresses__country__icontains=search_terms[0]).exists():
                    query |= Q(addresses__country__icontains=search_terms[0])

            elif len(search_terms) == 3:
                if queryset.filter(addresses__city__icontains=search_terms[0]).exists():
                    query |= Q(addresses__city__icontains=search_terms[0])
                if queryset.filter(addresses__state__icontains=search_terms[1]).exists():
                    query |= Q(addresses__state__icontains=search_terms[1])
                if queryset.filter(addresses__country__icontains=search_terms[2]).exists():
                    query |= Q(addresses__country__icontains=search_terms[2])

            elif len(search_terms) >= 4:
                if queryset.filter(addresses__road_name_area_colony__icontains=search_terms[0]).exists():
                    query |= Q(addresses__road_name_area_colony__icontains=search_terms[0])
                else:
                    return VendorKYC.objects.none()

            queryset = queryset.filter(query).distinct()

        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        response_data = {
            "message": "No vendors found for the specified search keyword." if not queryset.exists() else "List of Vendors",
        }

        if queryset.exists():
            serializer = self.get_serializer(queryset, many=True, context={'request': request})
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

# Helper function to calculate distance between two lat/lng points
def calculate_distance(lat1, lon1, lat2, lon2):
    # convert decimal degrees to radians 
    lat1, lon1, lat2, lon2 = map(float, [lat1, lon1, lat2, lon2])
    lon1, lat1, lon2, lat2 = map(radians, [lon1, lat1, lon2, lat2])
    
    # haversine formula
    dlon = lon2 - lon1 
    dlat = lat2 - lat1 
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a)) 
    r = 6371  # Radius of earth in kilometers
    return c * r

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
            raise ValidationError("VendorKYC for this user does not exist.")
        if not vendor_kyc.is_approved:
            raise ValidationError("Cannot create a deal because Vendor KYC is not approved.")

        serializer.save()

    def create(self, request, *args, **kwargs):
        try:
            # Extract uploaded images metadata from the request if provided
            uploaded_images = request.data.get('uploaded_images', [])

            # Ensure the metadata is a list of dictionaries
            if not isinstance(uploaded_images, list) or not all(isinstance(img, dict) for img in uploaded_images):
                return Response(
                    {"message": "uploaded_images must be a list of dictionaries."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)

            # Add uploaded images metadata to the deal
            deal = serializer.instance
            deal.set_uploaded_images(uploaded_images)
            deal.save()
            
            create_notification(
                user=request.user,
                notification_type="deal",
                title="Your Deal is Live!",
                body=f"Congrats {request.user.name}, your deal '{deal.deal_title}' is now live!",
                reference_instance=deal,
                data={"deal_id": str(deal.deal_uuid)}
            )
            
            # Notify users within 5KM
            if deal.latitude and deal.longitude:
                nearby_users = User.objects.exclude(id=request.user.id).filter(latitude__isnull=False, longitude__isnull=False)
                for user in nearby_users:
                    try:
                        distance = calculate_distance(deal.latitude, deal.longitude, user.latitude, user.longitude)
                        if distance <= 5:
                            create_notification(
                                user=user,
                                notification_type="deal",
                                title="New Deal Posted Nearby!",
                                body=f"{request.user.name} just posted a new deal: '{deal.deal_title}' near you!",
                                reference_instance=deal,
                                data={"deal_id": str(deal.deal_uuid)}
                            )
                    except Exception as e:
                        print(f"❌ Distance calc error for user {user.id}: {e}")
            
            # activity log
            ActivityLog.objects.create(
                user=deal.vendor_kyc.user,
                event=ActivityLog.CREATE_DEAL,
                metadata={}
            )

            headers = self.get_success_headers(serializer.data)
            return Response({"message": "Deal created successfully!", "data": serializer.data}, status=status.HTTP_201_CREATED, headers=headers)

        except ValidationError as e:
            # Convert all validation errors to a single string message
            if isinstance(e.detail, dict):
                message = " ".join([f"{key}: {', '.join(map(str, value))}" for key, value in e.detail.items()])
            else:
                message = str(e.detail)

            return Response({"message": message}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#################################################################################################

# class CreateDealView(generics.CreateAPIView):
#     queryset = CreateDeal.objects.all()
#     serializer_class = CreateDealSerializer
#     permission_classes = [IsAuthenticated]

#     def perform_create(self, serializer):
#         vendor_kyc = self.request.user.vendorkyc_set.first()
#         if not vendor_kyc:
#             raise ValidationError("Vendor KYC not found for the user.")
#         if not vendor_kyc.is_approved:
#             raise ValidationError("Cannot create a deal because Vendor KYC is not approved.")

#         serializer.save(vendor_kyc=vendor_kyc)

#     def create(self, request, *args, **kwargs):
#         uploaded_images = request.data.get('uploaded_images', [])

#         if not isinstance(uploaded_images, list) or not all(isinstance(img, dict) for img in uploaded_images):
#             return Response(
#                 {"error": "uploaded_images must be a list of dictionaries."},
#                 status=status.HTTP_400_BAD_REQUEST
#             )

#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         self.perform_create(serializer)

#         # Get the saved deal instance
#         deal = serializer.instance
#         vendor_kyc = deal.vendor_kyc  

#         # Add uploaded images metadata to the deal
#         deal.set_uploaded_images(uploaded_images)
#         deal.save()

#         # **Vendor Notification**
#         vendor_notification_sent = False
#         vendor_fcm_token = vendor_kyc.user.fcm_token
#         if vendor_fcm_token:
#             send_push_notification(
#                 device_tokens=vendor_fcm_token,  # Pass the single token directly
#                 title="Deal Created",
#                 message=f"Your deal '{deal.deal_title}' has been created successfully."
#             )
#             vendor_notification_sent = True  # Confirm notification sent

#         # **Nearby Users Notification**
#         users_to_notify = []
#         if vendor_kyc.latitude and vendor_kyc.longitude:
#             users_within_radius = CustomUser.objects.filter(
#                 Q(latitude__isnull=False) & Q(longitude__isnull=False)
#             )
#             for user in users_within_radius:
#                 distance = calculate_distance(vendor_kyc.latitude, vendor_kyc.longitude, user.latitude, user.longitude)
#                 if distance <= 15 and user.fcm_token:
#                     users_to_notify.append(user.fcm_token)

#             if users_to_notify:
#                 send_push_notification(
#                     device_tokens=users_to_notify,  # Pass the list of tokens
#                     title="New Deal Nearby",
#                     message=f"A new deal '{deal.deal_title}' has been created near you."
#                 )

#         users_notification_sent = len(users_to_notify) > 0  # Confirm users received notification

#         headers = self.get_success_headers(serializer.data)
#         return Response({
#             "deal": serializer.data,
#             "notifications": {
#                 "vendor_notification_sent": vendor_notification_sent,
#                 "users_notification_sent": users_notification_sent,
#                 "users_notified_count": len(users_to_notify)
#             }
#         }, status=status.HTTP_201_CREATED, headers=headers)









class CreateDealDetailView(generics.RetrieveAPIView):
    queryset = CreateDeal.objects.all()  # Retrieves all Activity instances
    serializer_class = CreateDealDetailSerializer
    permission_classes = [AllowAny]
    lookup_field = 'deal_uuid'
    
    def get(self, request, *args, **kwargs):
        deal = self.get_object()  # Get the specific deal
        user = request.user

        # Agar user authenticated hai aur usi vendor ka deal hai to view count increase nahi hoga
        if user.is_authenticated and deal.vendor_kyc.user == user:
            pass  # Vendor apni deal dekh raha hai, toh kuch nahi hoga
        else:
            deal.view_count += 1  # View count increase karenge
            deal.save(update_fields=['view_count'])  # Sirf view_count field ko update karenge

        return super().get(request, *args, **kwargs)  # Normal response return kar do


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
            "RaiseAnIssueMyOrders": "raise_an_issue_my_orders",
            "RaiseAnIssueVendors": "raise_an_issue_vendors",
            "RaiseAnIssueCustomUser": "raise_an_issue_customuser",
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
        now = timezone.now()
        today = now.date()
        current_time = now.time()

        queryset = CreateDeal.objects.filter(
            start_date__lte=today,  # Jo deals aaj ya pehle start ho chuki hain
            end_date__gte=today,  # Jo deals aaj ya uske baad tak valid hain
            available_deals__gt=0   # Sirf wo deals jinki available_deals 0 se zyada hai
        ).exclude(
            end_date=today, end_time__lte=current_time  # Aaj ki but end_time nikal chuka hai
        ).exclude(
            start_date__gt=today  # Jo future me start hone wali hain
        ).exclude(
            start_date=today, start_time__gt=current_time  # Aaj ki but future me start hone wali hain
        )
        
        
        search_keyword = self.request.query_params.get('address', None)
        if search_keyword:
            search_terms = [term.strip() for term in search_keyword.split(',')]
            query = Q()

            # Single search term ke liye multiple fields me search karenge
            if len(search_terms) == 1:
                clean_term = search_terms[0]
                query |= Q(location_city__icontains=clean_term)
                query |= Q(location_state__icontains=clean_term)
                query |= Q(location_country__icontains=clean_term)
                query |= Q(location_pincode__icontains=clean_term)
                query |= Q(location_road_name__icontains=clean_term)

            # Do search terms ke liye priority dete hue filter karenge
            elif len(search_terms) == 2:
                if queryset.filter(location_city__icontains=search_terms[0]).exists():
                    query |= Q(location_city__icontains=search_terms[0])
                elif queryset.filter(location_state__icontains=search_terms[0]).exists():
                    query |= Q(location_state__icontains=search_terms[0])
                elif queryset.filter(location_country__icontains=search_terms[0]).exists():
                    query |= Q(location_country__icontains=search_terms[0])

            # Teen search terms ke liye bhi similarly handle karenge
            elif len(search_terms) == 3:
                if queryset.filter(location_city__icontains=search_terms[0]).exists():
                    query |= Q(location_city__icontains=search_terms[0])
                elif queryset.filter(location_state__icontains=search_terms[1]).exists():
                    query |= Q(location_state__icontains=search_terms[1])
                elif queryset.filter(location_country__icontains=search_terms[2]).exists():
                    query |= Q(location_country__icontains=search_terms[2])

            # Agar 4 ya usse zyada terms hain to road name ya pincode ko priority denge
            elif len(search_terms) >= 4:
                if queryset.filter(location_road_name__icontains=search_terms[0]).exists():
                    query |= Q(location_road_name__icontains=search_terms[0])
                else:
                    return CreateDeal.objects.none()

            queryset = queryset.filter(query).distinct()

        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        response_data = {
            "message": "No deals found for the specified search keyword." if not queryset.exists() else "List of Deals",
            "deals": []
        }

        if queryset.exists():
            serializer = self.get_serializer(queryset, many=True)
            response_data["deals"] = serializer.data

        return Response(response_data, status=status.HTTP_200_OK)


    
    
class ActivityListsView(generics.ListAPIView):
    serializer_class = ActivityListsSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        current_time = make_aware(datetime.now())  # Timezone aware datetime
        search_keyword = self.request.query_params.get('address', None)

        # Base queryset jo sirf live activities ko filter karega
        queryset = Activity.objects.all()

        live_activities = []
        for activity in queryset:
            start_date = activity.start_date or current_time.date()
            start_time = activity.start_time or time(0, 0)
            end_date = activity.end_date or current_time.date()
            end_time = activity.end_time or time(23, 59)

            activity_start_datetime = make_aware(datetime.combine(start_date, start_time))
            activity_end_datetime = make_aware(datetime.combine(end_date, end_time))

            if activity_start_datetime <= current_time <= activity_end_datetime:
                live_activities.append(activity)

        # Agar search filter diya hai toh location ko bhi filter karein
        if search_keyword:
            search_terms = [term.strip().lower() for term in search_keyword.split(',')]
            filtered_activities = []
            for activity in live_activities:
                activity_location = activity.location.lower() if activity.location else ''
                if any(term in activity_location for term in search_terms):
                    filtered_activities.append(activity)
            return filtered_activities

        return live_activities

    
class ActivityDetailsView(generics.RetrieveAPIView):
    queryset = Activity.objects.all()  # Retrieves all Activity instances
    serializer_class = ActivityDetailsSerializer
    permission_classes = [AllowAny]
    lookup_field = 'activity_id'


class LogoutAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        from django.contrib.auth import logout
        # Extract refresh token from request data
        refresh_token = request.data.get('refresh_token')
        
        if not refresh_token:
            return Response({"message": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Handle refresh token
        try:
            refresh = RefreshToken(refresh_token)
            refresh.blacklist()  # Blacklists the refresh token
        except TokenError:
            return Response({"message": "Invalid or expired refresh token."}, status=status.HTTP_400_BAD_REQUEST)
    

        # activity log
        ActivityLog.objects.create(
            user=request.user,
            event=ActivityLog.LOGOUT,
            metadata={}
        )
        logout(request)
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
        deal_uuid = request.data.get('deal_uuid')
        if not deal_uuid:
            return Response({"message": "Deal UUID is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            deal = CreateDeal.objects.get(deal_uuid=deal_uuid)
        except CreateDeal.DoesNotExist:
            return Response({"message": "Deal not found."}, status=status.HTTP_404_NOT_FOUND)

        if VendorKYC.objects.filter(user=request.user, vendor_id=deal.vendor_kyc.vendor_id).exists():
            return Response({"message": "You cannot purchase your own deal."}, status=status.HTTP_403_FORBIDDEN)

        serializer = self.get_serializer(data=request.data, context={'request': request})
        if not serializer.is_valid():
            error_message = list(serializer.errors.values())[0][0]
            return Response({"message": error_message}, status=status.HTTP_400_BAD_REQUEST)

        place_order = serializer.save(user=request.user, deal=deal)    

        response_data = {
            "order_id": str(place_order.order_id),
            "placeorder_id": place_order.placeorder_id,
            "deal_uuid": str(place_order.deal.deal_uuid),
            "user_id": str(place_order.user.id),
            "vendor_id": str(deal.vendor_kyc.vendor_id),
            "quantity": place_order.quantity,
            "country": place_order.country,
            "latitude": place_order.latitude,
            "longitude": place_order.longitude,
            "total_amount": str(place_order.total_amount),
            "transaction_id": place_order.transaction_id,
            "payment_status": place_order.payment_status,
            "payment_mode": place_order.payment_mode,
            "created_at": place_order.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }
        # activity log
        ActivityLog.objects.create(
            user=request.user,
            event=ActivityLog.PLACE_ORDER,
            metadata={}
        )

        return Response({"message": "Order placed successfully", **response_data}, status=status.HTTP_201_CREATED)

class PlaceOrderDetailsView(generics.RetrieveAPIView):
    queryset = PlaceOrder.objects.all()
    serializer_class = PlaceOrderDetailsSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, placeorder_id, *args, **kwargs):
        try:
            # Fetch the order by ID
            place_order = PlaceOrder.objects.get(placeorder_id=placeorder_id)
            
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
            # activity log
            ActivityLog.objects.create(
                user=user,
                event=ActivityLog.EDIT_PROFILE,
                metadata={}
            )
            return Response(
                {
                    "message": "Profile updated successfully.",
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )
        else:
            # Extract the first error message from serializer.errors
            error_message = next(iter(serializer.errors.values()))[0]
            return Response(
                {
                    "message": error_message
                },
                status=status.HTTP_400_BAD_REQUEST
            )
    
    
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
        from django.contrib.auth import login
        social_id = request.data.get("social_id")
        email = request.data.get("email")
        name = request.data.get("name")
        login_type = request.data.get("type")
        fcm_token = request.data.get("fcm_token")
        latitude = request.data.get("latitude")
        longitude = request.data.get("longitude")

        if not social_id or not email or not login_type:
            return Response({"message": "social_id, email, and type (google/apple) are required."}, status=status.HTTP_400_BAD_REQUEST)

        user = CustomUser.objects.filter(email=email).first()

        if user:
            if not user.social_id:
                user.social_id = social_id
            if not user.type:
                user.type = login_type
            user.fcm_token = fcm_token or user.fcm_token
            user.latitude = latitude or user.latitude
            user.longitude = longitude or user.longitude
            user.save()
        else:
            user = CustomUser.objects.create(
                social_id=social_id,
                email=email,
                name=name,
                username=email.split('@')[0],
                phone_number="",
                date_of_birth=None,
                gender=None,
                type=login_type,
                fcm_token=fcm_token,
                latitude=latitude,
                longitude=longitude
            )

        vendor_kyc = VendorKYC.objects.filter(user=user).first()
        vendor_id = str(vendor_kyc.vendor_id) if vendor_kyc else ""
        is_approved = vendor_kyc.is_approved if vendor_kyc else False

        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        login(request, user)
        
        # 🔐 Login and generate session
        login(request, user)
        if not request.session.session_key:
            request.session.save()
        session_id = request.session.session_key

        # activity log
        ActivityLog.objects.create(
            user=user,
            event=ActivityLog.LOGIN,
            metadata={
                'type': login_type
            }
        )

        return Response({
            "user": CustomUserSerializer(user).data,
            "refresh": str(refresh),
            "access": access_token,
            "sessionid": session_id,
            "vendor_id": vendor_id,
            "is_approved": is_approved,
            "message": "Login successful."
        }, status=status.HTTP_200_OK)









    
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
    

# class SendOTPView(APIView):
#     serializer_class = OTPRequestSerializer

#     def post(self, request):
#         serializer = self.serializer_class(data=request.data)
#         serializer.is_valid(raise_exception=True)

#         email = serializer.validated_data['email']
#         try:
#             user = User.objects.get(email=email)
#         except User.DoesNotExist:
#             return Response({"error": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)

#         try:
#             # Delete any existing OTP for the user
#             existing_otp = PasswordResetOTP.objects.filter(user=user)
#             if existing_otp.exists():
#                 existing_otp.delete()
#         except PasswordResetOTP.DoesNotExist:
#             # This exception will not occur when using `filter()`
#             # because `filter()` does not raise `DoesNotExist`.
#             pass
        

#         # Generate a new OTP
#         otp = str(random.randint(100000, 999999))
#         try:
#             PasswordResetOTP.objects.create(user=user, otp=otp)
#         except Exception as e:
#             # Handle unexpected errors during OTP creation
#             return Response(
#                 {"error": "An error occurred while generating a new OTP. Please try again later."},
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             )

#         # Send the OTP via email
#         try:
#             send_mail(
#                 'Password Reset OTP',
#                 f'Your OTP for password reset is: {otp}',
#                 'admin@example.com',  # From email
#                 [email],
#                 fail_silently=False,
#             )
#         except Exception as e:
#             return Response(
#                 {"error": "Failed to send OTP email. Please try again later."},
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             )

#         return Response({"message": "OTP sent to your email."}, status=status.HTTP_200_OK)


class SendOTPView(APIView):
    serializer_class = OTPRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            first_error_message = next(iter(serializer.errors.values()))[0]
            return Response({"message": first_error_message}, status=status.HTTP_400_BAD_REQUEST)

        phone_number = serializer.validated_data['phone_number']
        try:
            user = User.objects.get(phone_number=phone_number)
        except User.DoesNotExist:
            return Response({"message": "User with this phone number does not exist."}, status=status.HTTP_404_NOT_FOUND)

        # Delete any existing OTP for the user
        PasswordResetOTP.objects.filter(user=user).delete()

        # Generate a new OTP
        otp = str(random.randint(100000, 999999))
        try:
            PasswordResetOTP.objects.create(user=user, otp=otp)
        except Exception:
            return Response(
                {"message": "An error occurred while generating a new OTP. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # Send the OTP via SMS using Twilio
        try:
            send_otp_via_sms(user.phone_number, otp)
        except Exception as e:
            return Response(
                {"message": f"Failed to send OTP SMS. Error: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response({"message": "OTP sent successfully to your phone number."}, status=status.HTTP_200_OK)


   
# class ValidateOTPView(APIView):
#     serializer_class = OTPValidationSerializer

#     def post(self, request):
#         serializer = self.serializer_class(data=request.data)
#         if serializer.is_valid():
#             message = serializer.validated_data.get('message')
#             if message == "OTP is valid. Proceed to reset your password.":
#                 return Response({"message": message}, status=status.HTTP_200_OK)
#             else:
#                 return Response({"message": message}, status=status.HTTP_400_BAD_REQUEST)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ValidateOTPView(APIView):
    serializer_class = OTPValidationSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        
        if not serializer.is_valid():
            # Extract the first error message
            first_error_message = next(iter(serializer.errors.values()))[0]
            return Response({"message": first_error_message}, status=status.HTTP_400_BAD_REQUEST)

        # Validation was successful
        message = serializer.validated_data.get('message')
        status_code = status.HTTP_200_OK if message == "OTP is valid. Proceed to reset your password." else status.HTTP_400_BAD_REQUEST
        return Response({"message": message}, status=status_code)

            
# class OTPResetPasswordView(APIView):
#     serializer_class = OTPResetPasswordSerializer

#     def post(self, request):
#         serializer = self.serializer_class(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         serializer.save()

#         return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)

# class OTPResetPasswordView(APIView):
#     serializer_class = OTPResetPasswordSerializer

#     def post(self, request):
#         serializer = self.serializer_class(data=request.data)
#         if serializer.is_valid():
#             # Handle successful validation and save logic
#             serializer.save()
#             return Response(
#                 {"message": "Password has been reset successfully."},
#                 status=status.HTTP_200_OK
#             )
#         else:
#             # Return custom error messages from the serializer
#             errors = serializer.errors
#             custom_message = errors.get('message', "Invalid data provided.")
#             return Response(
#                 {"message": custom_message},
#                 status=status.HTTP_400_BAD_REQUEST
#             )

class OTPResetPasswordView(APIView):
    serializer_class = OTPResetPasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        
        if not serializer.is_valid():
            # Extract the first error message from the serializer
            first_error_message = next(iter(serializer.errors.values()))[0]
            return Response({"message": first_error_message}, status=status.HTTP_400_BAD_REQUEST)

        # Handle successful validation and save logic
        serializer.save()
        # activity log
        user = serializer.validated_data.get("user")
        ActivityLog.objects.create(
            user=user,
            event=ActivityLog.RESET_PASSWORD,
            metadata={}
        )
        return Response(
            {"message": "Password has been reset successfully."},
            status=status.HTTP_200_OK
        )


class MyActivityView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        current_time = make_aware(datetime.now())  # Timezone aware datetime
        user = request.user

        # Authenticated user ki activities filter karna
        activities = Activity.objects.filter(created_by=request.user)

        live_activities = []
        scheduled_activities = []
        history_activities = []

        for activity in activities:
            # Agar start_date ya start_time missing hai, toh default values set karte hain
            start_date = activity.start_date or current_time.date()
            start_time = activity.start_time or time(0, 0)
            end_date = activity.end_date or current_time.date()
            end_time = activity.end_time or time(23, 59)

            activity_start_datetime = make_aware(datetime.combine(start_date, start_time))
            activity_end_datetime = make_aware(datetime.combine(end_date, end_time))

            if activity_start_datetime <= current_time <= activity_end_datetime:
                live_activities.append(activity)
            elif current_time < activity_start_datetime:
                scheduled_activities.append(activity)
            elif current_time > activity_end_datetime:
                history_activities.append(activity)
                
        # Participation tab: user ne doosron ke activity mein participate kiya
        participated_activities = Activity.objects.filter(
            chatrequest__from_user=user
        ).exclude(created_by=user).distinct()

        # Context zaroori hai serializer ke get_is_accepted & get_chat_room_id ke liye
        # Context zaroori hai serializer ke get_is_accepted & get_chat_room_id ke liye
        context = {'request': request}

        # Teeno categories ko serialize karna (context sab jagah pass karo)
        live_activities_serializer = MyActivitysSerializer(live_activities, many=True, context=context)
        scheduled_activities_serializer = MyActivitysSerializer(scheduled_activities, many=True, context=context)
        history_activities_serializer = MyActivitysSerializer(history_activities, many=True, context=context)
        all_activities_serializer = MyActivitysSerializer(activities, many=True, context=context)
        participation_activities_serializer = MyActivitysSerializer(participated_activities, many=True, context=context)

        return Response({
            'live': live_activities_serializer.data,
            'scheduled': scheduled_activities_serializer.data,
            'history': history_activities_serializer.data,
            'participation': participation_activities_serializer.data,
            'all': all_activities_serializer.data  # Sabhi activities
        }, status=status.HTTP_200_OK)
        
class MyDealView(APIView):
    permission_classes = [IsAuthenticated]

    def permission_denied(self, request, message=None, code=None):
        response = Response(
            {"message": message or "Authentication credentials were not provided."},
            status=status.HTTP_401_UNAUTHORIZED
        )
        self.raise_exception = False
        return response

    def get(self, request):
        try:
            vendor_kyc = VendorKYC.objects.get(user=request.user)
            current_time = timezone.now()

            deals = CreateDeal.objects.filter(vendor_kyc=vendor_kyc)

            live_deals, scheduled_deals, history_deals = [], [], []

            for deal in deals:
                # ⚠️ Skip if date or time is missing
                if not all([deal.start_date, deal.start_time, deal.end_date, deal.end_time]):
                    # Optional: You can move such deals to history or skip
                    history_deals.append(deal)
                    continue

                deal_start_datetime = timezone.make_aware(
                    datetime.combine(deal.start_date, deal.start_time)
                )
                deal_end_datetime = timezone.make_aware(
                    datetime.combine(deal.end_date, deal.end_time)
                )

                # ✅ Check for available_deals
                if deal.available_deals is not None and deal.available_deals <= 0:
                    # ✅ Expire the deal
                    deal.start_date = current_time.date()
                    deal.start_time = current_time.time()
                    deal.end_date = current_time.date()
                    deal.end_time = current_time.time()
                    deal.save()
                    history_deals.append(deal)
                else:
                    # ✅ Classify deals based on time
                    if deal_start_datetime <= current_time <= deal_end_datetime:
                        live_deals.append(deal)
                    elif current_time < deal_start_datetime:
                        scheduled_deals.append(deal)
                    elif current_time > deal_end_datetime:
                        history_deals.append(deal)

            live_deals_serializer = MyDealSerializer(live_deals, many=True)
            scheduled_deals_serializer = MyDealSerializer(scheduled_deals, many=True)
            history_deals_serializer = MyDealSerializer(history_deals, many=True)

            return Response({
                "message": "Deals fetched successfully.",
                "live": live_deals_serializer.data,
                "scheduled": scheduled_deals_serializer.data,
                "history": history_deals_serializer.data
            }, status=status.HTTP_200_OK)

        except VendorKYC.DoesNotExist:
            return Response({"message": "Vendor KYC not found for this user."}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({"message": f"An error occurred: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
        
class FavoriteVendorView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, vendor_id):
        try:
            # Get the vendor
            vendor = VendorKYC.objects.get(vendor_id=vendor_id)
        except VendorKYC.DoesNotExist:
            return Response({"error": "Vendor not found."}, status=status.HTTP_404_NOT_FOUND)

        # Prevent user from favoriting themselves
        if vendor.user == request.user:
            return Response({"error": "You cannot favorite yourself."}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the vendor is already favorited by the user
        try:
            favorite = FavoriteVendor.objects.get(user=request.user, vendor=vendor)
            # If the vendor is already in favorites, delete it (unfavorite)
            favorite.delete()
            # activity log
            ActivityLog.objects.create(
                user=request.user,
                event=ActivityLog.UNFAVORITE_VENDOR,
                metadata={
                    'vendor': str(vendor.vendor_id)
                }
            )
            return Response({"message": f"{vendor.full_name} removed from favorites."}, status=status.HTTP_200_OK)
        except FavoriteVendor.DoesNotExist:
            # If the vendor is not in favorites, create a new entry (favorite)
            FavoriteVendor.objects.create(user=request.user, vendor=vendor)
            # activity log
            ActivityLog.objects.create(
                user=request.user,
                event=ActivityLog.FAVORITE_VENDOR,
                metadata={
                    'vendor': str(vendor.vendor_id)
                }
            )
            return Response({"message": f"{vendor.full_name} added to favorites."}, status=status.HTTP_201_CREATED)
        
class FavoriteVendorsListView(generics.ListAPIView):
    serializer_class = FavoriteVendorsListSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Fetching only the vendors favorited by the authenticated user
        user = self.request.user
        return FavoriteVendor.objects.filter(user=user)

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True, context={'request': request})
        
        # Customizing the response format
        response_data = {
            "message": "List of Favorite Vendors",
            "vendors": serializer.data
        }
        
        return Response(response_data)
        
# For Upswap Web App Version:
class SuperadminLoginView(APIView):
    def post(self, request):
        serializer = SuperadminLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data.get("email")
        password = serializer.validated_data.get("password")

        # ✅ Check if user exists
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise AuthenticationFailed("User do not exists.")

        # ✅ Authenticate user
        user = authenticate(email=email, password=password)
        if user is None:
            raise AuthenticationFailed("Invalid Credentials.")

        # ✅ Check if user is superadmin
        if not user.is_superuser:
            raise AuthenticationFailed("Access denied. Only superadmins can log in.")

        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        return Response({
            "user": {
                "id": str(user.id),
                "name": user.name,
                "username": user.username,
                "email": user.email,
                "phone_number": user.phone_number,
                "date_of_birth": user.date_of_birth,
                "gender": user.gender,
                "country_code": user.country_code,
                "dial_code": user.dial_code,
                "country": user.country,
                "social_id": user.social_id,
                "type": user.type,
                "is_superuser": user.is_superuser
            },
            "message": "Superadmin logged in successfully.",
            "access_token": access_token,
            "refresh_token": str(refresh),
        }, status=status.HTTP_200_OK)
        
#####################
#####################

class SubmitRatingView(generics.CreateAPIView):
    serializer_class = VendorRatingSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, placeorder_id, *args, **kwargs):
        try:
            order = PlaceOrder.objects.get(placeorder_id=placeorder_id, user=request.user)
            vendor = order.vendor

            serializer = self.get_serializer(data=request.data, context={'request': request, 'placeorder_id': placeorder_id})

            if serializer.is_valid():
                serializer.save(user=request.user, vendor=vendor, order=order)
                # activity log
                ActivityLog.objects.create(
                    user=request.user,
                    event=ActivityLog.RATE_VENDOR,
                    metadata={
                        'vendor': str(vendor.vendor_id),
                        'rating': str(serializer.validated_data['rating'])
                    }
                )
                return Response({"message": "Rating submitted successfully!", "data": serializer.data}, status=status.HTTP_201_CREATED)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except PlaceOrder.DoesNotExist:
            return Response({"message": "Order not found or you are not authorized to rate this order."}, status=status.HTTP_404_NOT_FOUND)

        
class RaiseAnIssueMyOrdersView(generics.CreateAPIView):
    serializer_class = RaiseAnIssueSerializerMyOrders
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        place_order_id = kwargs.get("place_order_id")  
        try:
            place_order = PlaceOrder.objects.get(placeorder_id=place_order_id)  
        except PlaceOrder.DoesNotExist:
            return Response({"error": "Invalid PlaceOrder ID"}, status=status.HTTP_404_NOT_FOUND)

        data = request.data.copy()
        data["place_order"] = place_order.placeorder_id  # Directly use placeorder_id

        serializer = self.get_serializer(data=data, context={"request": request})  
        if serializer.is_valid():
            serializer.save()
            # activity log
            ActivityLog.objects.create(
                user=request.user,
                event=ActivityLog.RAISE_ISSUE,
                metadata={
                    'issue_type': 'user_orders',
                    'vendor': str(place_order.vendor.vendor_id),
                    'order': str(place_order.order_id),
                    'subject': serializer.validated_data['subject']
                }
            )
            return Response({"message": "Issue raised successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class RaiseAnIssueVendorsCreateView(generics.CreateAPIView):
    queryset = RaiseAnIssueVendors.objects.all()
    serializer_class = RaiseAnIssueVendorsSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        vendor_id = self.kwargs.get('vendor_id')
        try:
            vendor = VendorKYC.objects.get(vendor_id=vendor_id)
        except VendorKYC.DoesNotExist:
            raise ValidationError({"error": "Vendor not found."})

        serializer.save(user=self.request.user, vendor=vendor)
        

class RaiseAnIssueCustomUserView(generics.CreateAPIView):
    queryset = RaiseAnIssueCustomUser.objects.all()
    serializer_class = RaiseAnIssueCustomUserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        user = self.request.user
        against_user_id = self.kwargs.get("against_user_id")
        activity_id = self.kwargs.get("activity_id")

        try:
            against_user = CustomUser.objects.get(id=against_user_id)
        except CustomUser.DoesNotExist:
            raise ValidationError("User not found.")

        try:
            activity = Activity.objects.get(activity_id=activity_id)
        except Activity.DoesNotExist:
            raise ValidationError("Activity not found.")

        if activity.created_by != against_user:
            raise ValidationError("This activity does not belong to the mentioned user.")

        serializer.save(raised_by=user, against_user=against_user, activity=activity)
        
class DeactivateDealView(APIView):
    permission_classes = [IsAuthenticated]  

    def post(self, request, deal_uuid):
        try:
            data = CreateDeal.objects.get(deal_uuid=deal_uuid)
            current_time = timezone.now()

            data_start_datetime = datetime.combine(data.start_date, data.start_time)
            data_end_datetime = datetime.combine(data.end_date, data.end_time)

            data_start_datetime = timezone.make_aware(data_start_datetime, timezone.get_current_timezone())
            data_end_datetime = timezone.make_aware(data_end_datetime, timezone.get_current_timezone())

            if data_start_datetime <= current_time <= data_end_datetime:
                data.end_date = current_time.date()
                data.end_time = current_time.time().replace(microsecond=0)
                data.save()  # Saving the end date/time update

            elif current_time < data_start_datetime:
                data.start_date = current_time.date()
                data.start_time = current_time.time().replace(microsecond=0)
                data.end_date = current_time.date()
                data.end_time = current_time.time().replace(microsecond=0)
                data.save()  # Saving the scheduled deal update

            # Update status after saving time changes
            data.status = 'history'
            data.save()

            # activity log
            ActivityLog.objects.create(
                user=request.user,
                event=ActivityLog.DEACTIVATE_DEAL,
                metadata={
                    'deal': str(deal_uuid)
                }
            )

            serializer = CreateDealSerializer(data)
            return Response({
                "message": "Deal deactivated successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except CreateDeal.DoesNotExist:
            return Response({
                'message': 'Deal not found.'
            }, status=status.HTTP_404_NOT_FOUND)
            

class RepostDealView(generics.CreateAPIView): 
    serializer_class = CreateDealSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, deal_uuid, *args, **kwargs):
        try:
            # Existing deal fetch karo
            old_deal = CreateDeal.objects.get(deal_uuid=deal_uuid)
        except CreateDeal.DoesNotExist:
            return Response({"message": "Invalid deal UUID"}, status=status.HTTP_404_NOT_FOUND)

        # Check karo ki ye deal expire ya history me hai
        now = timezone.now()  # Current date aur time dono
        old_deal_end_datetime = timezone.make_aware(
            dt.combine(old_deal.end_date, old_deal.end_time)
        )

        if old_deal_end_datetime >= now:
            return Response({"message": "Only expired or historical deals can be reposted"}, status=status.HTTP_400_BAD_REQUEST)

        # Naye start and end dates fetch karo
        start_date = request.data.get('start_date')
        start_time = request.data.get('start_time')
        end_date = request.data.get('end_date')
        end_time = request.data.get('end_time')
        available_deals = request.data.get('available_deals')  # ✅ New Field

        if not all([start_date, start_time, end_date, end_time, available_deals]):
            return Response({"message": "Start/End date-time fields and available_deals are required"}, status=status.HTTP_400_BAD_REQUEST)

        # Validate available_deals
        try:
            available_deals = int(available_deals)
            if available_deals < 1:
                return Response({"message": "Available deals must be at least 1"}, status=status.HTTP_400_BAD_REQUEST)
        except (ValueError, TypeError):
            return Response({"message": "Available deals must be a valid integer"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Convert to datetime objects
            start_date = dt.strptime(start_date, "%Y-%m-%d").date()
            start_time = dt.strptime(start_time, "%H:%M:%S").time()
            end_date = dt.strptime(end_date, "%Y-%m-%d").date()
            end_time = dt.strptime(end_time, "%H:%M:%S").time()
        except ValueError:
            return Response({"message": "Invalid date or time format"}, status=status.HTTP_400_BAD_REQUEST)

        # Validate date & time
        if start_date < now.date():
            return Response({"message": "Start date cannot be in the past"}, status=status.HTTP_400_BAD_REQUEST)

        if start_date > end_date:
            return Response({"message": "End date cannot be before start date"}, status=status.HTTP_400_BAD_REQUEST)
        
        if start_date == end_date and start_time >= end_time:
            return Response({"message": "End time cannot be before or same as start time"}, status=status.HTTP_400_BAD_REQUEST)

        # Naya deal create karo (repost)
        new_deal = CreateDeal.objects.create(
            vendor_kyc=old_deal.vendor_kyc,
            deal_uuid=uuid.uuid4(),  # New UUID
            deal_title=old_deal.deal_title,
            deal_description=old_deal.deal_description,
            select_service=old_deal.select_service,
            uploaded_images=old_deal.uploaded_images,
            start_date=start_date,
            start_time=start_time,
            end_date=end_date,
            end_time=end_time,
            actual_price=old_deal.actual_price,
            deal_price=old_deal.deal_price,
            location_house_no=old_deal.location_house_no,
            location_road_name=old_deal.location_road_name,
            location_country=old_deal.location_country,
            location_state=old_deal.location_state,
            location_city=old_deal.location_city,
            location_pincode=old_deal.location_pincode,
            latitude=old_deal.latitude,
            longitude=old_deal.longitude,
            available_deals=available_deals  # ✅ Store available_deals
        )

        # Naya deal status check karo
        start_datetime = timezone.make_aware(dt.combine(start_date, start_time))
        new_deal.start_now = True if start_datetime <= now else False
        new_deal.save()
        # activity log
        ActivityLog.objects.create(
            user=request.user,
            event=ActivityLog.REPOST_DEAL,
            metadata={
                'old_deal': str(deal_uuid),    # old deal id from the request parameter
                'new_deal': str(new_deal.deal_uuid)
            }
        )
        return Response({"message": "Deal successfully reposted", "data": CreateDealSerializer(new_deal).data}, status=status.HTTP_201_CREATED)
    
    
    
class DeactivateActivitiesView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def post(self, request, activity_id):
        try:
            # Fetch the activity using the activity_id
            activity = Activity.objects.get(activity_id=activity_id, created_by=request.user)
            current_time = timezone.now()

            # Convert start_date & start_time and end_date & end_time to datetime
            activity_start_datetime = datetime.combine(activity.start_date, activity.start_time)
            activity_end_datetime = datetime.combine(activity.end_date, activity.end_time)

            # Make them timezone-aware
            activity_start_datetime = timezone.make_aware(activity_start_datetime, timezone.get_current_timezone())
            activity_end_datetime = timezone.make_aware(activity_end_datetime, timezone.get_current_timezone())

            # Check if it's a live or scheduled activity and update accordingly
            if activity_start_datetime <= current_time <= activity_end_datetime:
                # Live activity: Set end_date and end_time to current time
                update_fields = {
                    "end_date": current_time.date(),
                    "end_time": current_time.time().replace(microsecond=0),
                }
            elif current_time < activity_start_datetime:
                # Scheduled activity: Set start_date, start_time, end_date, and end_time to current time
                update_fields = {
                    "start_date": current_time.date(),
                    "start_time": current_time.time().replace(microsecond=0),
                    "end_date": current_time.date(),
                    "end_time": current_time.time().replace(microsecond=0),
                }
            else:
                return Response({"message": "Activity has already ended."}, status=status.HTTP_400_BAD_REQUEST)

            # ✅ Bypass validation by using `update()` instead of `save()`
            Activity.objects.filter(activity_id=activity_id).update(**update_fields)

            # Serialize the updated activity and return response
            activity.refresh_from_db()  # Refresh instance after update
            serializer = ActivitySerializer(activity)
            # activity log
            ActivityLog.objects.create(
                user=request.user,
                event=ActivityLog.DEACTIVATE_ACTIVITY,
                metadata={
                    'activity': str(activity.activity_id),
                    'activity_title': activity.activity_title
                }
            )
            return Response({
                "message": "Activity deactivated successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Activity.DoesNotExist:
            return Response({
                "message": "Activity not found."
            }, status=status.HTTP_404_NOT_FOUND)
            
class ActivityRepostView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, activity_id):
        try:
            # Existing activity ko fetch karo
            existing_activity = Activity.objects.get(activity_id=activity_id, created_by=request.user)
        except Activity.DoesNotExist:
            return Response({"message": "Activity not found or you do not have permission to repost it."}, status=status.HTTP_404_NOT_FOUND)

        # Start and end dates fetch karo
        start_date = request.data.get('start_date')
        start_time = request.data.get('start_time')
        end_date = request.data.get('end_date')
        end_time = request.data.get('end_time')
        infinite_time = request.data.get('infinite_time', False)  # Default False

        # New activity ka data banayein
        new_activity_data = {
            'activity_title': existing_activity.activity_title,
            'activity_description': existing_activity.activity_description,
            'activity_category': {'actv_category': existing_activity.activity_category.actv_category},
            'uploaded_images': existing_activity.uploaded_images,
            'user_participation': existing_activity.user_participation,
            'maximum_participants': existing_activity.maximum_participants,
            'location': existing_activity.location,
            'latitude': existing_activity.latitude,
            'longitude': existing_activity.longitude,
            'start_date': start_date,
            'start_time': start_time,
            'end_date': end_date,
            'end_time': end_time,
            'infinite_time': infinite_time,  # Frontend se jo value aaye wahi store hogi
        }

        # Serializer ko validate aur save karo
        serializer = ActivityRepostSerializer(data=new_activity_data, context={'request': request})
        if serializer.is_valid():
            serializer.save(created_by=request.user)
            # activity log
            ActivityLog.objects.create(
                user=request.user,
                event=ActivityLog.REPOST_ACTIVITY,
                metadata={
                    'old_activity': str(activity_id),  # Old activity ID from the request parameter
                    'new_activity': serializer.data['activity_id']  # New activity ID from the serializer data
                }
            )
            return Response({"message": "Activity successfully reposted.", "data": serializer.data}, status=status.HTTP_201_CREATED)

        # Errors ko extract karke sirf "message" format me bhejna
        error_message = next(iter(serializer.errors.values()))[0] if serializer.errors else "Validation error."
        return Response({"message": error_message}, status=status.HTTP_400_BAD_REQUEST)
    
class MySalesAPIView(generics.ListAPIView):
    serializer_class = MySalesSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        vendor = VendorKYC.objects.filter(user=self.request.user).first()
        if vendor:
            return PlaceOrder.objects.filter(vendor=vendor).select_related('user', 'vendor')
        return PlaceOrder.objects.none()

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()

            if not queryset.exists():
                return Response({"message": "No sales found."}, status=status.HTTP_404_NOT_FOUND)

            serializer = self.get_serializer(queryset, many=True)
            return Response({"message": "Sales fetched successfully", "sales_data": serializer.data}, status=status.HTTP_200_OK)

        except (AuthenticationFailed, NotAuthenticated, PermissionDenied) as auth_error:
            return Response({"message": str(auth_error)}, status=status.HTTP_401_UNAUTHORIZED)

        except ValidationError as validation_error:
            return Response({"message": str(validation_error)}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"message": "Something went wrong. " + str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
class ViewTotalSales(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        sales_type = request.query_params.get('sales_type')

        if sales_type not in ['daily', 'weekly', 'monthly']:
            return Response({"message": "Invalid sales_type. Choose from 'daily', 'weekly', 'monthly'."},
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            vendor = VendorKYC.objects.get(user=request.user)
        except VendorKYC.DoesNotExist:
            return Response({"message": "Vendor profile not found."}, status=status.HTTP_404_NOT_FOUND)

        now = timezone.now()

        if sales_type == 'daily':
            time_threshold = now - timedelta(days=1)
        elif sales_type == 'weekly':
            time_threshold = now - timedelta(days=7)
        else:
            time_threshold = now - timedelta(days=30)

        orders = PlaceOrder.objects.filter(
            vendor=vendor,
            created_at__gte=time_threshold
        )

        total_sales = orders.aggregate(total=Sum('total_amount'))['total'] or 0

        return Response({
            "sales_type": sales_type,
            "total_sales": float(total_sales)
        }, status=status.HTTP_200_OK)
        
class ResendOTPView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user

        # Generate and send a new OTP
        generate_otp(user)

        return Response({
            "message": "A new OTP has been sent to your registered phone number."
        }, status=status.HTTP_200_OK)
        
class NotificationListView(generics.ListAPIView):
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Notification.objects.filter(user=self.request.user).order_by('-created_at')

class MarkNotificationAsReadView(generics.UpdateAPIView):
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Notification.objects.filter(user=self.request.user)

    def perform_update(self, serializer):
        serializer.save(is_read=True)

class RegisterDeviceView(generics.CreateAPIView):
    serializer_class = DeviceSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        user = request.user
        device_token = request.data.get('device_token')
        device_type = request.data.get('device_type')

        # Required fields check
        if not device_token or not device_type:
            return Response(
                {'message': 'Device token and device type dono chahiye.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get existing or create new
        device, created = Device.objects.get_or_create(
            user=user,
            device_token=device_token,
            defaults={'device_type': device_type}
        )

        if not created:
            # Agar pehle se exist karta hai
            return Response(
                {'message': 'Device already registered.', 'device_id': str(device.id)},
                status=status.HTTP_200_OK
            )

        # Naya device bana, serializer se response bhejo
        serializer = self.get_serializer(device)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
        
@api_view(["POST"])
def test_push_notification(request):
    device_token = request.data.get("device_token")
    title = request.data.get("title", "Test Notification")
    body = request.data.get("body", "This is a test message.")
    
    # You can also pass data payload if you want
    data = {
        "custom_key": "custom_value"
    }

    # Temporarily send without using user object
    try:
        message = messaging.Message(
            notification=messaging.Notification(title=title, body=body),
            token=device_token,
            data=data,
        )
        response = messaging.send(message)
        return Response({"message": "Notification sent!", "response_id": response})
    except Exception as e:
        return Response({"message": "Failed to send notification", "error": str(e)}, status=500)
    
    
#For WebVersion
class VendorAddressListView(generics.ListAPIView):
    serializer_class = AddressSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Logged-in user ka VendorKYC fetch karo
        vendor_kyc = VendorKYC.objects.filter(user=self.request.user).first()
        if vendor_kyc:
            return Address.objects.filter(vendor=vendor_kyc)
        return Address.objects.none()