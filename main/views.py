import json
import random, string
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
from twilio.rest import Client
from django.core.cache import cache
from django.conf import settings
from botocore.exceptions import ClientError
from django.http import HttpResponse, JsonResponse
from django.core.files.base import ContentFile
from django.utils import timezone
from datetime import timedelta
from django.db.models import Q
from django.db.models import F, Func, FloatField, Value, ExpressionWrapper
from math import radians, sin, cos, sqrt, atan2, asin
from django.db.models import Sum
from django.db import models
from django.contrib.auth import login, logout
from django.db import transaction
from django.db import IntegrityError
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
from .models import (
    CustomUser, OTP, Activity, PasswordResetOTP, VendorKYC, Address, CreateDeal, PlaceOrder,
    ActivityCategory, ServiceCategory, FavoriteVendor, RaiseAnIssueVendors, RaiseAnIssueCustomUser, Notification, Device, FavoriteUser, FavoriteService, FavoriteVendor, DealViewCount, Purchase
    )
from appointments.models import Service
from .serializers import (
    CustomUserSerializer, OTPRequestSerializer, OTPResetPasswordSerializer, OTPValidationSerializer, VerifyOTPSerializer, LoginSerializer,
    ActivitySerializer, VendorKYCSerializer,
    CreateDealSerializer, VendorKYCDetailSerializer,
    VendorKYCListSerializer, ActivityListsSerializer, ActivityDetailsSerializer, ForgotPasswordSerializer, ResetPasswordSerializer, CreateDeallistSerializer, CreateDealDetailSerializer, PlaceOrderSerializer, PlaceOrderDetailsSerializer,
    ActivityCategorySerializer, ServiceCategorySerializer, CustomUserDetailsSerializer, PlaceOrderListsSerializer, VendorKYCStatusSerializer, CustomUserEditSerializer, MyDealSerializer, SuperadminLoginSerializer, FavoriteVendorSerializer,
    MyActivitysSerializer, FavoriteVendorsListSerializer, VendorRatingSerializer, RaiseAnIssueSerializerMyOrders, RaiseAnIssueVendorsSerializer, RaiseAnIssueCustomUserSerializer, AddressSerializer,
    ActivityRepostSerializer, MySalesSerializer, NotificationSerializer, DeviceSerializer, ServiceCreateSerializer, GetVendorSerializer, RegisterSerializerV2, FavoriteVendorSerializer, FavoriteUserSerializer, FavoriteServiceSerializer,
    PurchaseDealSerializer, EditPurchaseDealSerializer,

)

from datetime import timezone as pytimezone
from datetime import datetime as dt
from rest_framework.generics import RetrieveAPIView
from .utils import generate_otp, process_image, upload_to_s3, upload_to_s3_documents, upload_to_s3_profile_image, generate_asset_uuid, send_otp_via_sms, create_notification, send_whatsapp_message, send_email_via_mailgun, convert_to_utc_date_time
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
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.contrib.auth.models import AnonymousUser

from django.shortcuts import get_object_or_404

from activity_log.models import ActivityLog
from activity_log.serializers import ActivityLogSerializer


User = get_user_model()
token_generator = PasswordResetTokenGenerator()

USERNAME_REGEX = r'^[a-z0-9._]{5,20}$'  # r'^[a-z0-9]{6,}$'  # Adjust the pattern as needed
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

        # Check if user already exists
        existing_user = CustomUser.objects.filter(
            Q(username=username) | Q(email=data.get('email')) | Q(phone_number=data.get('phone_number'))
        ).first()

        if existing_user:
            if existing_user:
                if existing_user.email == data.get('email'):
                    return Response({
                        'message': 'User with this email already exists.'
                    }, status=status.HTTP_400_BAD_REQUEST) 
                elif existing_user.username == data.get('username'):
                    return Response({
                        'message': 'User with this username already exists.'
                    }, status=status.HTTP_400_BAD_REQUEST) 
                elif existing_user.phone_number == data.get('phone_number'):
                    return Response({
                        'message': 'User with this phone number already exists.'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                return Response({'message': f"User already registered." }, status=status.HTTP_400_BAD_REQUEST)


        # If user does not exist, proceed with fresh registration
        serializer = self.get_serializer(data=data)

        try:
            serializer.is_valid(raise_exception=True)
            user = serializer.save()

            # Generate and send OTP
            generate_otp(user)

            # Generate tokens
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            # Create session manually
            request.session["registered_user_id"] = str(user.id)
            if not request.session.session_key:
                request.session.save()
            session_id = request.session.session_key

            # Log activity
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
        try:
            user = CustomUser.objects.get(email=request.data.get('email').lower())
        except CustomUser.DoesNotExist as e:
            return Response({
                'error': 'No user exist with this email.'
            }, status=status.HTTP_400_BAD_REQUEST)
        serializer = self.get_serializer(data=request.data, context={'username': user.username})
        if not serializer.is_valid():
            return Response({"error": "Invalid Credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        user = serializer.validated_data['user']
        if not user.otp_verified and not user.email_verified:
            return Response({
                'error': 'Your OTP is not verified.'
            }, status=status.HTTP_400_BAD_REQUEST)

        login(request, user)
        
        # ✅ Save session and fetch session ID
        if not request.session.session_key:
            request.session.save()
        session_id = request.session.session_key

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
            data = request.data.copy()
            end_date_str = data.get('end_date')
            end_time_str = data.get('end_time')
            timezone_info = data.get('timezone') 
            if not timezone_info:
                return Response({
                    'error': 'Timezone information is missing.',
                }, status=status.HTTP_400_BAD_REQUEST)

            utc_end_date_str, utc_end_time_str, err = convert_to_utc_date_time(end_date_str, end_time_str, timezone_info)
            if err:
                return Response({
                    'error': err
                }, status=status.HTTP_200_OK)

            if not data['user_participation']:
                data['maximum_participants'] = 0

            # implement a past endtime check for activity. 
            data['end_date'] = utc_end_date_str
            data['end_time'] = utc_end_time_str
            serializer = self.get_serializer(data=data)
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
                        if distance <= 20:
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
                        "uploaded_images": activity.uploaded_images,
                        "user_participation": activity.user_participation,
                        "maximum_participants": activity.maximum_participants,
                        "end_date": activity.end_date,
                        "end_time": activity.end_time,
                        "created_at": activity.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                        "created_by": str(activity.created_by.id),
                        "infinite_time": activity.infinite_time,
                        "location": activity.location,
                        "latitude": activity.latitude,
                        "longitude": activity.longitude,
                    },
                    status=status.HTTP_201_CREATED,
                )
            else:
                errors = serializer.errors
                error_list = [f"{field} {str(msg)}" for field, messages in errors.items() for msg in messages]
                return Response(
                    {"error": error_list[0]},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except Exception as e:
            # Koi unexpected error
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

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


class VendorKYCCreateView(generics.CreateAPIView):
    queryset = VendorKYC.objects.all()
    serializer_class = VendorKYCSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        user = self.request.user
        uploaded_images = self.request.data.get('uploaded_images', [])
        profile_pic = self.request.data.get('profile_pic', '')

        # Validate uploaded_images
        if not isinstance(uploaded_images, list):
            raise ValidationError({"uploaded_images": "uploaded_images must be a list of dictionaries."})

        # Validate profile_pic
        if isinstance(profile_pic, list) or isinstance(profile_pic, dict):
            raise ValidationError({"profile_pic": "profile_pic must be a string (image URL or path)."})

        # Check if VendorKYC already exists
        try:
            vendor_kyc = VendorKYC.objects.get(user=user)
            serializer.instance = vendor_kyc
        except VendorKYC.DoesNotExist:
            pass

        serializer.save(user=user, uploaded_images=uploaded_images, profile_pic=profile_pic, is_approved=False)

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
        serializer.save()

    def create(self, request, *args, **kwargs):
        try:
            # Extract uploaded images metadata from the request if provided
            uploaded_images = request.data.get('uploaded_images', [])
            vendor_kyc = self.request.user.vendorkyc_set.first()
            if not vendor_kyc:
                return Response({
                    'error': 'You do not have any vendor KYC.'
                }, status=status.HTTP_400_BAD_REQUEST)
            if not vendor_kyc.is_approved:
                return Response({
                    'error': 'You vendor KYC is not approved yet.'
                }, status=status.HTTP_400_BAD_REQUEST)
            # Ensure the metadata is a list of dictionaries
            if not isinstance(uploaded_images, list) or not all(isinstance(img, dict) for img in uploaded_images):
                return Response(
                    {"message": "uploaded_images must be a list of dictionaries."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            data = request.data.copy()
            end_date_str = data.get('end_date')
            end_time_str = data.get('end_time')
            timezone_info = data.get('timezone') 
            if not timezone_info:
                return Response({
                    'error': 'Timezone information is missing.',
                }, status=status.HTTP_400_BAD_REQUEST)

            utc_end_date_str, utc_end_time_str, err = convert_to_utc_date_time(end_date_str, end_time_str, timezone_info)
            if err:
                return Response({
                    'error': err
                }, status=status.HTTP_200_OK)

            # implement a past endtime check for activity. 
            data['end_date'] = utc_end_date_str
            data['end_time'] = utc_end_time_str
            
            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)

            # Add uploaded images metadata to the deal
            deal = serializer.instance
            deal.deals_left = int(data.get('available_deals'))
            deal.set_uploaded_images(uploaded_images)
            deal.save()
            
            # Get vendor_id from VendorKYC
            vendor_kyc = get_object_or_404(VendorKYC, user=request.user)
            vendor_id = str(vendor_kyc.vendor_id) if hasattr(vendor_kyc, 'vendor_id') else None
            
            create_notification(
                user=request.user,
                notification_type="deal",
                title="Your Deal is Live!",
                body=f"Congrats {request.user.name}, your deal '{deal.deal_title}' is now live!",
                reference_instance=deal,
                data={"deal_id": str(deal.deal_uuid), "vendor_id": vendor_id,}
            )
            
            # Notify users within 20KM
            if deal.latitude and deal.longitude:
                nearby_users = User.objects.exclude(id=request.user.id).filter(latitude__isnull=False, longitude__isnull=False)
                for user in nearby_users:
                    try:
                        distance = calculate_distance(deal.latitude, deal.longitude, user.latitude, user.longitude)
                        if distance <= 20:
                            create_notification(
                                user=user,
                                notification_type="deal",
                                title="New Deal Posted Nearby!",
                                body=f"{request.user.name} just posted a new deal: '{deal.deal_title}' near you!",
                                reference_instance=deal,
                                data={"deal_id": str(deal.deal_uuid), "vendor_id": vendor_id,}
                            )
                    except Exception as e:
                        print(f"❌ Distance calc error for user {user.id}: {e}")

            # ✅ Notify users who favorited this vendor — regardless of location
            # vendor_kyc = get_object_or_404(VendorKYC, user=request.user)
            # favoriting_users = CustomUser.objects.filter(
            #     favorite_vendors__vendor=vendor_kyc
            # ).exclude(id=request.user.id).distinct()

            # for user in favoriting_users:
            #     create_notification(
            #         user=user,
            #         notification_type="deal",
            #         title="Your Favorite Vendor Posted a New Deal!",
            #         body=f"{request.user.name} posted a new deal: '{deal.deal_title}'. Check it out!",
            #         reference_instance=deal,
            #         data={"deal_id": str(deal.deal_uuid), "vendor_id": vendor_id,}
            #     )
            
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


class CreateDealDetailView(generics.RetrieveAPIView):
    queryset = CreateDeal.objects.all()  # Retrieves all Activity instances
    serializer_class = CreateDealDetailSerializer
    permission_classes = [AllowAny]
    lookup_field = 'deal_uuid'
    
    def get(self, request, *args, **kwargs):
        deal = self.get_object()
        user = request.user
        location_param = request.GET.get('location')
        if user.is_authenticated and deal.vendor_kyc.user.id == user.id:
            pass
        else:
            try:
                print("location params --> ", location_param, " on ", deal.deal_title)
                location_data = json.loads(location_param) if location_param else {}
                area = location_data.get("area", "").strip().lower()

                # Treat empty/blank/None area as "other"
                if not area or area == 'null':
                    area = "other"
                # Fill default location data if missing
                location_data.setdefault('longitude', '')
                location_data.setdefault('latitude', '')
                location_data.setdefault('city', '')
                location_data.setdefault('state', '')
                location_data.setdefault('country', '')
                location_data.setdefault('username', '')
                location_data['area'] = area  # Ensure area is set properly

                existing_entry = DealViewCount.objects.filter(
                    deal=deal,
                    location__area=area,
                    location__city=location_data.get('city'),
                    location__state=location_data.get('state')
                ).first()
                
                if existing_entry:
                    DealViewCount.objects.filter(id=existing_entry.id).update(
                        view_count=F('view_count') + 1
                    )
                else:
                    DealViewCount.objects.create(
                        deal=deal,
                        view_count=1,
                        location=location_data
                    )

            except json.JSONDecodeError as err:
                print("Deal Details error creating view data json error ---> ", err)
            except Exception as e:
                print("Deal Details error creating view data exceprion  ---> ", e)
        return super().get(request, *args, **kwargs)



class UploadImagesAPI(APIView):
    def post(self, request):
        model_name = request.data.get("model_name")  # e.g., 'Activity', 'VendorKYC', 'CreateDeal'
        images = request.FILES.getlist("images")

        if not model_name or not images:
            return Response({"error": "Model name and images are required."}, status=status.HTTP_400_BAD_REQUEST)

        folder_mapping = {
            "Activity": "activity",
            "VendorKYC": "vendor_kyc",
            "Service": "service-images",
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
            allowed_extensions = {'.jpg', '.jpeg', '.png', '.webp'}
            ext = os.path.splitext(image.name)[1].lower()
            allowed = ext in allowed_extensions
            if not allowed:
                return Response({
                    'error': f"Please upload only .jpg, .jpeg, .png, or .webp"
                }, status=status.HTTP_400_BAD_REQUEST)

        for image in images:
            asset_uuid = generate_asset_uuid()
            base_file_name = f"asset_{asset_uuid}.webp"

            # Process and upload thumbnail
            thumbnail = process_image(image, (160, 130))
            thumbnail_url = upload_to_s3(thumbnail, f"{folder_name}", f"thumbnail_{base_file_name}")

            # Process and upload compressed image
            compressed = process_image(image, (600, 250))
            compressed_url = upload_to_s3(compressed, f"{folder_name}", base_file_name)

            original_image = process_image(image, None)   # Only changing format to WEBP
            original_url = upload_to_s3(original_image, f"{folder_name}", f"original_{base_file_name}")

            uploaded_images.append({
                "thumbnail": thumbnail_url,
                "compressed": compressed_url,
                "original": original_url
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
            return Response({
                "error": "Unsupported file type. Only jpg, jpeg, png, or webp are allowed."
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Define folder path for upload
            folder = "vendor_kyc/vendor_kyc_profile_images"
            
            # Upload the file to S3 and get its URL
            file_url = upload_to_s3_profile_image(file, folder, file_type="image")
            
            # Return only the file URL in the response
            return Response({file_url}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




# class CreateDeallistView(generics.ListAPIView):
#     serializer_class = CreateDeallistSerializer
#     permission_classes = [AllowAny]

#     def get_queryset(self):
#         now = timezone.now()
#         today = now.date()
#         current_time = now.time()

#         queryset = CreateDeal.objects.filter(
#             end_date__gte=today, 
#             available_deals__gt=0
#         ).exclude(
#             end_date=today, end_time__lte=current_time
#         )
        
        
#         search_keyword = self.request.query_params.get('address', None)
#         if search_keyword:
#             search_terms = [term.strip() for term in search_keyword.split(',')]
#             query = Q()

#             # Single search term ke liye multiple fields me search karenge
#             if len(search_terms) == 1:
#                 clean_term = search_terms[0]
#                 query |= Q(location_city__icontains=clean_term)
#                 query |= Q(location_state__icontains=clean_term)
#                 query |= Q(location_country__icontains=clean_term)
#                 query |= Q(location_pincode__icontains=clean_term)
#                 query |= Q(location_road_name__icontains=clean_term)

#             # Do search terms ke liye priority dete hue filter karenge
#             elif len(search_terms) == 2:
#                 if queryset.filter(location_city__icontains=search_terms[0]).exists():
#                     query |= Q(location_city__icontains=search_terms[0])
#                 elif queryset.filter(location_state__icontains=search_terms[0]).exists():
#                     query |= Q(location_state__icontains=search_terms[0])
#                 elif queryset.filter(location_country__icontains=search_terms[0]).exists():
#                     query |= Q(location_country__icontains=search_terms[0])

#             # Teen search terms ke liye bhi similarly handle karenge
#             elif len(search_terms) == 3:
#                 if queryset.filter(location_city__icontains=search_terms[0]).exists():
#                     query |= Q(location_city__icontains=search_terms[0])
#                 elif queryset.filter(location_state__icontains=search_terms[1]).exists():
#                     query |= Q(location_state__icontains=search_terms[1])
#                 elif queryset.filter(location_country__icontains=search_terms[2]).exists():
#                     query |= Q(location_country__icontains=search_terms[2])

#             elif len(search_terms) >= 4:
#                 if queryset.filter(location_road_name__icontains=search_terms[0]).exists():
#                     query |= Q(location_road_name__icontains=search_terms[0])
#                 else:
#                     return CreateDeal.objects.none()

#             queryset = queryset.filter(query).distinct()

#         return queryset

#     def list(self, request, *args, **kwargs):
#         queryset = self.get_queryset()
#         response_data = {
#             "message": "No deals found for the specified search keyword." if not queryset.exists() else "List of Deals",
#             "deals": []
#         }

#         if queryset.exists():
#             serializer = self.get_serializer(queryset, many=True)
#             response_data["deals"] = serializer.data

#         return Response(response_data, status=status.HTTP_200_OK)

# from django.db.models import Q, F, Value, FloatField, ExpressionWrapper
# from django.db.models.functions import ACos, Cos, Sin, Radians
# from django.utils import timezone
# from rest_framework.response import Response
# from rest_framework import status
# from functools import reduce
# from rest_framework import generics
# from rest_framework.permissions import AllowAny

class CreateDeallistView(generics.ListAPIView):
    serializer_class = CreateDeallistSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        now = timezone.now()
        today = now.date()
        current_time = now.time()

        queryset = CreateDeal.objects.filter(
            end_date__gte=today,
            available_deals__gt=0
        ).exclude(
            end_date=today, end_time__lte=current_time
        )

        # Address filtering
        search_keyword = self.request.query_params.get('address', None)
        if search_keyword:
            search_terms = [term.strip() for term in search_keyword.split(',')]
            query = Q()

            if len(search_terms) == 1:
                clean_term = search_terms[0]
                query |= Q(location_city__icontains=clean_term)
                query |= Q(location_state__icontains=clean_term)
                query |= Q(location_country__icontains=clean_term)
                query |= Q(location_pincode__icontains=clean_term)
                query |= Q(location_road_name__icontains=clean_term)

            elif len(search_terms) == 2:
                if queryset.filter(location_city__icontains=search_terms[0]).exists():
                    query |= Q(location_city__icontains=search_terms[0])
                elif queryset.filter(location_state__icontains=search_terms[0]).exists():
                    query |= Q(location_state__icontains=search_terms[0])
                elif queryset.filter(location_country__icontains=search_terms[0]).exists():
                    query |= Q(location_country__icontains=search_terms[0])

            elif len(search_terms) == 3:
                if queryset.filter(location_city__icontains=search_terms[0]).exists():
                    query |= Q(location_city__icontains=search_terms[0])
                elif queryset.filter(location_state__icontains=search_terms[1]).exists():
                    query |= Q(location_state__icontains=search_terms[1])
                elif queryset.filter(location_country__icontains=search_terms[2]).exists():
                    query |= Q(location_country__icontains=search_terms[2])

            elif len(search_terms) >= 4:
                if queryset.filter(location_road_name__icontains=search_terms[0]).exists():
                    query |= Q(location_road_name__icontains=search_terms[0])
                else:
                    return CreateDeal.objects.none()

            queryset = queryset.filter(query).distinct()

        # Distance sorting (if lat/lng provided)
        lat = self.request.query_params.get('lat', None)
        lng = self.request.query_params.get('lng', None)

        if lat and lng:
            try:
                user_lat = float(lat)
                user_lng = float(lng)
                earth_radius_km = 6371.0

                acos_expr = ACos(
                    Cos(Radians(Value(user_lat))) *
                    Cos(Radians(F('latitude'))) *
                    Cos(Radians(F('longitude')) - Radians(Value(user_lng))) +
                    Sin(Radians(Value(user_lat))) * Sin(Radians(F('latitude')))
                )

                distance_expr = ExpressionWrapper(
                    Value(earth_radius_km) * acos_expr,
                    output_field=FloatField()
                )

                queryset = queryset.annotate(distance=distance_expr).order_by('distance')

            except ValueError:
                pass

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
    
    
# class ActivityListsView(generics.ListAPIView):
#     serializer_class = ActivityListsSerializer
#     permission_classes = [AllowAny]

#     def get_queryset(self):
#         current_time = make_aware(datetime.now())
#         search_keyword = self.request.query_params.get('address', None)

#         queryset = Activity.objects.filter(
#             is_deleted=False
#         ).filter(
#             Q(end_date__gt=current_time.date()) |
#             Q(end_date=current_time.date(), end_time__gte=current_time.time()) |
#             Q(end_date__isnull=True, end_time__gte=current_time.time()) |
#             Q(end_date__gte=current_time.date(), end_time__isnull=True) |
#             Q(end_date__isnull=True, end_time__isnull=True)
#         )

#         if search_keyword:
#             search_terms = [term.strip().lower() for term in search_keyword.split(',')]
#             queryset = queryset.filter(
#                 reduce(
#                     lambda q, term: q | Q(location__icontains=term),
#                     search_terms,
#                     Q()
#                 )
#             )

#         return queryset

class Radians(Func):
    function = 'RADIANS'
    arity = 1

# class ActivityListsView(generics.ListAPIView):
#     serializer_class = ActivityListsSerializer
#     permission_classes = [AllowAny]

#     def get_queryset(self):
#         current_time = make_aware(datetime.now())
#         search_keyword = self.request.query_params.get('address', None)

#         queryset = Activity.objects.filter(
#             is_deleted=False
#         ).filter(
#             Q(end_date__gt=current_time.date()) |
#             Q(end_date=current_time.date(), end_time__gte=current_time.time()) |
#             Q(end_date__isnull=True, end_time__gte=current_time.time()) |
#             Q(end_date__gte=current_time.date(), end_time__isnull=True) |
#             Q(end_date__isnull=True, end_time__isnull=True)
#         )

#         if search_keyword:
#             search_terms = [term.strip().lower() for term in search_keyword.split(',')]
#             queryset = queryset.filter(
#                 reduce(
#                     lambda q, term: q | Q(location__icontains=term),
#                     search_terms,
#                     Q()
#                 )
#             )

#         lat = self.request.query_params.get('lat', None)
#         lng = self.request.query_params.get('lng', None)
#         distance_expr = None
#         try:
#             if lat and lng:
#                 user_lat = float(lat)
#                 user_lng = float(lng)
#                 earth_radius_km = 6371.0

#                 acos_expr = ACos(
#                     Cos(Radians(Value(user_lat))) *
#                     Cos(Radians(F('latitude'))) *
#                     Cos(Radians(F('longitude')) - Radians(Value(user_lng))) +
#                     Sin(Radians(Value(user_lat))) * Sin(Radians(F('latitude')))
#                 )

#                 # Wrap the full formula in ExpressionWrapper to declare the output type
#                 distance_expr = ExpressionWrapper(
#                     Value(earth_radius_km) * acos_expr,
#                     output_field=FloatField()
#                 )          
#         except Exception:
#             pass
#             queryset = queryset.annotate(distance=distance_expr).order_by('distance')
#         return queryset
    
class ActivityListsView(generics.ListAPIView):
    serializer_class = ActivityListsSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        current_time = make_aware(datetime.now())
        search_keyword = self.request.query_params.get('address', None)

        queryset = Activity.objects.filter(
            is_deleted=False
        ).filter(
            Q(end_date__gt=current_time.date()) |
            Q(end_date=current_time.date(), end_time__gte=current_time.time()) |
            Q(end_date__isnull=True, end_time__gte=current_time.time()) |
            Q(end_date__gte=current_time.date(), end_time__isnull=True) |
            Q(end_date__isnull=True, end_time__isnull=True)
        )

        # Optional keyword filtering
        if search_keyword:
            search_terms = [term.strip().lower() for term in search_keyword.split(',')]
            queryset = queryset.filter(
                reduce(
                    lambda q, term: q | Q(location__icontains=term),
                    search_terms,
                    Q()
                )
            )

        # Optional location-based distance sorting
        lat = self.request.query_params.get('lat')
        lng = self.request.query_params.get('lng')

        if lat and lng:
            try:
                user_lat = float(lat)
                user_lng = float(lng)
                earth_radius_km = 6371.0

                acos_expr = ACos(
                    Cos(Radians(Value(user_lat))) *
                    Cos(Radians(F('latitude'))) *
                    Cos(Radians(F('longitude')) - Radians(Value(user_lng))) +
                    Sin(Radians(Value(user_lat))) * Sin(Radians(F('latitude')))
                )

                distance_expr = ExpressionWrapper(
                    Value(earth_radius_km) * acos_expr,
                    output_field=FloatField()
                )

                queryset = queryset.annotate(distance=distance_expr).order_by('distance')

            except (ValueError, TypeError):
                # If lat/lng are invalid, skip distance sorting
                pass

        return queryset

class ActivityDetailsView(generics.RetrieveAPIView):
    queryset = Activity.objects.all()  # Retrieves all Activity instances
    serializer_class = ActivityDetailsSerializer
    permission_classes = [AllowAny]
    lookup_field = 'activity_id'


class LogoutAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        from django.contrib.auth import logout
        refresh_token = request.data.get('refresh_token')
        
        if not refresh_token:
            return Response({"message": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            refresh = RefreshToken(refresh_token)
            refresh.blacklist()
        except TokenError:
            return Response({"message": "Invalid or expired refresh token."}, status=status.HTTP_400_BAD_REQUEST)
    

        # activity log
        ActivityLog.objects.create(
            user=request.user,
            event=ActivityLog.LOGOUT,
            metadata={}
        )
        try:
            logout(request)
        except Exception as e:
            pass
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
        SERVICE_CATEGORIES = [
            "Automotive Services & Products",
            "Art, Crafts & Collectibles",
            "Baby Care",
            "Bakery",
            "Books, Stationery & Toys",
            "Clothing",
            "Consultants",
            "Dentist",
            "Electronics",
            "Estate Agents",
            "Fashion, Apparel & Accessories",
            "Food",
            "Furniture",
            "Groceries",
            "Health, Wellness & Fitness",
            "Home, Living & Kitchen",
            "Others",
            "Personal Care",
            "Pet Care Services & Supplies",
            "Professional & Business Services",
            "Rent & Hire",
            "Restaurants",
            "Sports & Outdoors",
            "Other Services & Consultations",
        ]

        ACTIVITY_CATEGORIES = [
            "Tech and Gaming",
            "Volunteer Opportunities",
            "Cultural Exchanges",
            "Intellectual Pursuits",
            "Sports and Recreation",
            "Arts and Crafts",
            "Social Gatherings",
            "Educational Workshops",
            "Music and Entertainment",
            "Others",
        ]
        response_data = {
            "activity_category": ACTIVITY_CATEGORIES,
            "service_category": SERVICE_CATEGORIES,
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
        if (not user.otp_verified or user.phone_number != request.data.get('phone_number')) and request.data.get('phone_number'):
            return Response({
                'error': 'This phone number is not verified via OTP.'
            }, status=status.HTTP_200_OK)

        if (not user.email_verified or user.email != request.data.get('email')) and request.data.get('email'):
            return Response({
                'error': 'This email is not verified via OTP.'
            }, status=status.HTTP_200_OK)
        
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
            # error_message = next(iter(serializer.errors.values()))[0]
            errors = serializer.errors
            error_list = [f"{field} {str(msg)}" for field, messages in errors.items() for msg in messages]

            return Response(
                {
                    "errors": error_list
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
            user.email_verified = True
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
                otp_verified=True,
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
            send_otp_via_sms(user.dial_code, user.phone_number, otp)
        except Exception as e:
            return Response(
                {"message": f"Failed to send OTP SMS. Error: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response({"message": "OTP sent successfully to your phone number."}, status=status.HTTP_200_OK)


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
        activities = Activity.objects.filter(created_by=request.user, is_deleted=False)

        live_activities = []
        scheduled_activities = []
        history_activities = []

        for activity in activities:
            # Agar start_date ya start_time missing hai, toh default values set karte hain
            # start_date = activity.start_date or current_time.date()
            # start_time = activity.start_time or time(0, 0)
            end_date = activity.end_date or current_time.date()
            end_time = activity.end_time or time(23, 59)

            # activity_start_datetime = make_aware(datetime.combine(start_date, start_time))
            activity_end_datetime = make_aware(datetime.combine(end_date, end_time))

            if current_time <= activity_end_datetime:
                live_activities.append(activity)
            # elif current_time < activity_start_datetime:
            #     scheduled_activities.append(activity)
            elif current_time > activity_end_datetime:
                history_activities.append(activity)
                
        # Participation tab: user ne doosron ke activity mein participate kiya
        participated_activities = Activity.objects.filter(
            chat_requests__from_user=user
        ).exclude(created_by=user).distinct()

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

    def get(self, request, vendor_id):
        try:
            vendor_kyc = VendorKYC.objects.get(vendor_id=vendor_id)
            current_time = timezone.now()

            deals = CreateDeal.objects.filter(vendor_kyc=vendor_kyc)

            live_deals, scheduled_deals, history_deals = [], [], []

            for deal in deals:
                # ⚠️ Skip if date or time is missing
                if not all([deal.end_date, deal.end_time]):
                    # Optional: You can move such deals to history or skip
                    history_deals.append(deal)
                    continue

                deal_end_datetime = timezone.make_aware(
                    datetime.combine(deal.end_date, deal.end_time)
                )

                # ✅ Check for available_deals
                if deal.available_deals is not None and deal.available_deals <= 0:
                    # ✅ Expire the deal
                    deal.end_date = current_time.date()
                    deal.end_time = current_time.time()
                    deal.save()
                    history_deals.append(deal)
                else:
                    # ✅ Classify deals based on time
                    if current_time <= deal_end_datetime:
                        live_deals.append(deal)
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

class CreateDealHackathonView(CreateAPIView):
    queryset = CreateDeal.objects.all()
    serializer_class = CreateDealSerializer
    authentication_classes = []  # No authentication
    permission_classes = []      # No permissions

    def perform_create(self, serializer):
        serializer.save()  # Save without user or KYC validation

    def post(self, request, *args, **kwargs):
        try:
            uploaded_images = request.data.get('uploaded_images', [])

            if not isinstance(uploaded_images, list) or not all(isinstance(img, dict) for img in uploaded_images):
                return Response(
                    {"message": "uploaded_images must be a list of dictionaries."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)

            deal = serializer.instance
            deal.set_uploaded_images(uploaded_images)
            deal.save()

            headers = self.get_success_headers(serializer.data)
            return Response(
                {"message": "Deal created successfully!", "data": serializer.data},
                status=status.HTTP_201_CREATED,
                headers=headers
            )

        except ValidationError as e:
            message = " ".join([f"{key}: {', '.join(map(str, value))}" for key, value in e.detail.items()]) if isinstance(e.detail, dict) else str(e.detail)
            return Response({"message": message}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
class SendVendorWhatsAppMessage(APIView):
    """
    POST /api/vendor/send-whatsapp/
    Body: {
        "vendor_id": "<uuid>"
    }
    """

    def post(self, request):
        vendor_id = request.data.get("vendor_id")

        if not vendor_id:
            return Response({"detail": "vendor_id is required."}, status=status.HTTP_400_BAD_REQUEST)

        vendor = get_object_or_404(VendorKYC, vendor_id=vendor_id)

        phone = vendor.phone_number
        dial_code = vendor.dial_code or "+91"  # fallback
        full_phone = f"{dial_code}{phone}".replace(" ", "").replace("-", "")

        result = send_whatsapp_message(full_phone)  # only phone pass kar rahe

        if result["status"] == "success":
            return Response({"detail": "Message sent successfully", "sid": result["sid"]}, status=200)
        else:
            return Response({"detail": result["message"]}, status=500)

        
class CheckVendorStatusView(APIView):
    def get(self, request, user_id):
        try:
            user = CustomUser.objects.get(id=user_id)
        except CustomUser.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        vendor = VendorKYC.objects.filter(user=user).first()

        if vendor:
            return Response({
                "is_vendor": True,
                "vendor_id": str(vendor.vendor_id)
            })
        else:
            return Response({
                "is_vendor": False,
                "vendor_id": ""
            })
            
class SendPhoneVerificationOTP(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        new_phone_number = request.data.get("phone_number")

        if not new_phone_number:
            return Response({"message": "Phone number is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Generate OTP
        otp = ''.join(random.choices(string.digits, k=6))
        expires_at = timezone.now() + timedelta(minutes=10)

        # Save OTP entry
        OTP.objects.update_or_create(
            user=user,
            phone_number=new_phone_number,
            defaults={
                'otp': otp,
                'expires_at': expires_at,
                'is_verified': False
            }
        )

        # Send OTP
        send_otp_via_sms(new_phone_number, otp)

        return Response({"message": f"OTP has been sent to {new_phone_number}."}, status=status.HTTP_200_OK)
    
class VerifyOTPNewPhoneNumberView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        phone_number = request.data.get('phone_number')
        otp = request.data.get('otp')

        if not phone_number or not otp:
            return Response({"message": "Phone number and OTP are required."}, status=status.HTTP_400_BAD_REQUEST)

        otp_entry = OTP.objects.filter(user=request.user, phone_number=phone_number, otp=otp).order_by('-created_at').first()

        if not otp_entry:
            return Response({"message": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)

        if otp_entry.is_expired():
            return Response({"message": "OTP has expired."}, status=status.HTTP_400_BAD_REQUEST)

        # Mark as verified
        otp_entry.is_verified = True
        otp_entry.save()

        # Optionally: Mark user as verified too
        request.user.otp_verified = True
        request.user.save()

        return Response({"message": "OTP verified successfully."}, status=status.HTTP_200_OK)
    
class ServicesCreateView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, vendor_id):
        try:
            vendor_kyc = VendorKYC.objects.get(vendor_id=vendor_id, user=request.user)
        except VendorKYC.DoesNotExist:
            return Response({"detail": "Vendor KYC not found or not yours."}, status=status.HTTP_404_NOT_FOUND)

        services_data = request.data  # Expecting list of dicts
        created_services = []
        errors = []

        for data in services_data:
            serializer = ServiceCreateSerializer(data=data, context={'vendor_kyc': vendor_kyc})
            if serializer.is_valid():
                service = serializer.save()
                created_services.append({
                    "uuid": service.uuid,
                    "item_name": service.item_name,
                    "item_description": service.item_description,
                    "item_price": service.item_price
                })
            else:
                errors.append(serializer.errors)

        if errors:
            return Response({
                "services": created_services,
                "errors": errors
            }, status=status.HTTP_207_MULTI_STATUS)  # 207 = Partial Success

        return Response({"services": created_services}, status=status.HTTP_201_CREATED)

##  New APIs by Rahul

from appointments.serializers import (
    ProviderSerializer,
    ServiceSerializer,
)

from appointments.models import (
    Service as AppointmentService,
    Provider,
) 


class GetAllVendors(generics.ListAPIView):
    """
    Get all vendors
    """
    queryset = VendorKYC.objects.all()
    serializer_class = GetVendorSerializer
    permission_classes = [AllowAny]

class GetVendorServiceAndProviders(APIView):
    """
    Get vendor's info, services and providers in single API call
    """

    def get(self, request, vendor_id, format=None):
        try:
            vendor = VendorKYC.objects.get(vendor_id=vendor_id)
        except VendorKYC.DoesNotExist:
            return Response({"detail": "Vendor not found."}, status=status.HTTP_404_NOT_FOUND)
        try:
            # Serialize vendor info
            vendor_serializer = GetVendorSerializer(vendor)

            # Get services and providers
            services = AppointmentService.objects.filter(vendor=vendor).select_related('category')
            service_serializer = ServiceSerializer(services, many=True)

            providers = Provider.objects.filter(vendor=vendor)
            provider_serializer = ProviderSerializer(providers, many=True)

            return Response({
                "vendor": vendor_serializer.data,
                "services": service_serializer.data,
                "providers": provider_serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'message': 'An error occurred while fetching vendor data.',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class SendVerificationOTP(APIView):
    """
    Post() ---> Send OTP to the phone number or email of the user
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        verification_type = request.data.get('verification_type')
        if not verification_type:
            return Response({
                'error': 'Verification type is required.',
                'data': {}
            }, status=status.HTTP_400_BAD_REQUEST)

        if verification_type == 'email':
            email = request.data.get('email')
            if not email:
                return Response({
                    'error': 'Email is required.',
                    'data': []
                }, status=status.HTTP_400_BAD_REQUEST)

            if email == request.user.email:
                return Response({
                    'error': 'New email is same as old email.',
                    'data': []
                }, status=status.HTTP_400_BAD_REQUEST)

            email_exists = CustomUser.objects.filter(email=email).exists()
            if email_exists:
                return Response({
                    'error': 'User with this email already exists.',
                    'data': []
                }, status=status.HTTP_400_BAD_REQUEST)

            otp = ''.join(str(random.randint(0, 9)) for _ in range(6))
            cache.set(email, otp, timeout=600)
            sent = send_email_via_mailgun(email, otp)
            if not sent:
                return Response({
                    'error': 'OTP couldn\'t be sent, please try again later.',
                    'data': {}
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({
                    'message': 'OTP send successfully.',
                    'data': {}
                }, status=status.HTTP_200_OK)
                            
        elif verification_type == 'phone':
            phone = request.data.get('phone')
            dial_code = request.data.get('dial_code')
            if not phone or not dial_code:
                return Response({
                    'error': 'Phone number and dial code is required.',
                    'data': {}
                }, status=status.HTTP_400_BAD_REQUEST)

            if phone == request.user.phone_number and request.user.otp_verified:
                return Response({
                    'error': 'New Phone number is same as old number.',
                    'data': []
                }, status=status.HTTP_400_BAD_REQUEST)

            phone_exists = CustomUser.objects.filter(phone_number=phone).exclude(id=request.user.id).exists()
            if phone_exists:
                return Response({
                    'error': 'User with this phone number already exists.',
                    'data': []
                }, status=status.HTTP_400_BAD_REQUEST)

            dial_code = request.data.get('dial_code')
            otp = ''.join(str(random.randint(0, 9)) for _ in range(6))
            cache.set(phone, otp, timeout=600)
            err, err_code = send_otp_via_sms(dial_code, phone, otp)
            if err or err_code:
                return Response({
                'error': 'OTP couldn\'t be sent.',
                'info': f"{err}, {err_code}"
            }, status=status.HTTP_400_BAD_REQUEST)
            return Response({
                'message': 'OTP sent successfully.',
                'data': {}
            }, status=status.HTTP_200_OK)

class VerifyOTPViewV2(APIView):
    """
    Post() ---> verify the OTP &
        verification_type: email - set updated email & socail id to None.
        verification_tyoe: phone - set updated phone number & otp_verified to True.
    """
    permission_classes = [IsAuthenticated]
    def post(self, request):
        user = request.user
        verification_type = request.data.get('verification_type')
        otp = request.data.get('otp')

        try:
            if verification_type == 'email':
                email = request.data.get('email')
                original_otp = cache.get(email)
                if not original_otp:
                    return Response({
                        'error': 'OTP has expired, please try again.',
                    }, status=status.HTTP_400_BAD_REQUEST)
                if original_otp == otp:     
                    # user = CustomUser.objects.get(email=user.email)
                    user.email = email
                    user.social_id = None
                    user.email_verified = True
                    user.save()
                    return Response({
                        'message': 'OTP has been verified.',
                        'data': {}
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({
                        'error': 'OTP didn\'t match. Please try again.',
                    }, status=status.HTTP_400_BAD_REQUEST)
            
            elif verification_type == 'phone':
                phone = request.data.get('phone')
                original_otp = cache.get(phone)
                if not original_otp:
                    return Response({
                        'error': 'OTP has expired, please try again.',
                    }, status=status.HTTP_400_BAD_REQUEST)
                if original_otp == otp:     
                    # user = CustomUser.objects.get(phone_number=user.phone_number)
                    user.otp_verified = True
                    user.phone_number = phone
                    user.save()
                    return Response({
                        'message': 'OTP has been verified.',
                        'data': {}
                    }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'error': 'OTP cannot be verified.',
                'info': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UpdatePasswordAPI(APIView):
    """
    Post() ---> Update the password of an User.
    """
    permission_classes = [IsAuthenticated]
    def post(self, request):
        user = request.user
        password = request.data.get('password')
        confirm_password = request.data.get('confirm_password')

        if not password or not confirm_password:
            return Response({
                'error': 'Password or Confirm Password is missing.',
            }, status=status.HTTP_400_BAD_REQUEST)

        if password != confirm_password:
            return Response({
                'error': 'Passwords do not match.',
            }, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(password)
        user.save()
        return Response({
            'message': 'Password has been updated successfully.',
            'data': {}
        }, status=status.HTTP_200_OK)

class ActivityDeleteView(APIView):
    """
    Delete() ---> Delete the activity
    """
    def delete(self, request, activity_id, format=None):
        try:
            activity = Activity.objects.get(activity_id=activity_id)
        except Activity.DoesNotExist:
            return Response({
                'error': 'Activity not found.'
            }, status=status.HTTP_404_NOT_FOUND)
        
        activity.is_deleted = True
        activity.save()
        return Response({
            'message': 'Activity deleted successfully.'
        }, status=status.HTTP_204_NO_CONTENT)

class DealDeleteView(APIView):
    """
    Delete() ---> Delete the Deal.
    """
    def delete(self, request, deal_uuid, format=None):
        try:
            deal = CreateDeal.objects.get(deal_uuid=deal_uuid)
        except CreateDeal.DoesNotExist:
            return Response({
                'error': 'Deal not found.'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Optionally delete and return success
        deal.delete()
        return Response({
            'message': 'Activity deleted successfully.'
        }, status=status.HTTP_204_NO_CONTENT)


class SendOTPToEmail(APIView):
    """
    Post() ---> Send OTP to email 
        Used for - Forgot Password, (more usecases can be added...)
    """

    def post(self, request, format=None):
        email = request.data.get('email')
        if not email:
            return Response({
                'error': 'Email is required.',
                'data': []
            }, status=status.HTTP_400_BAD_REQUEST)

        user = CustomUser.objects.filter(email=email).exists()

        if not user:
            return Response({
                'error': 'No user exist with this email.',
                'data': []
            }, status=status.HTTP_400_BAD_REQUEST)
        otp = ''.join(random.choices(string.digits, k=6))
        try:
            sent = send_email_via_mailgun(email, otp)
            if not sent:
                return Response({
                'error': 'OTP couldn\'t be sent, please try again later.',
                'data': []
            }, status=status.HTTP_400_BAD_REQUEST)
            cache.set(email, otp, timeout=300)
            return Response({
                'message': 'OTP sent at your email.',
                'data': []
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'error': 'Something went wrong while sending OTP.',
                'data': []
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyOTPForPassword(APIView):
    """
    Post() ---> Verify OTP and set the password for the user
    """

    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')

        if not email or not otp:
            return Response({
                'error': 'Email, OTP, or password is missing.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        original_otp = cache.get(email)
        if not original_otp:
            return Response({
                'error': 'OTP expired.'
            }, status=status.HTTP_400_BAD_REQUEST)

        if original_otp == otp:
            return Response({
                'message': 'OTP verified successfully.',
                'data': {'email': email}
            }, status=status.HTTP_200_OK)
        return Response({
            'error': 'OTP cannot be verified.'
        }, status=status.HTTP_400_BAD_REQUEST)


class SetPasswordAPI(APIView):
    """
    Post() ---> Reset password
    """

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        password2 = request.data.get('password2')

        if not re.match(PASSWORD_REGEX, password):
            return Response({
                'error': 'Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, a digit, and a special character.'
            },status=status.HTTP_400_BAD_REQUEST)

        if password != password2:
            return Response({
                'error': 'Passwords do not match.'
            }, status=status.HTTP_400_BAD_REQUEST)

        user = CustomUser.objects.get(email=email)
        user.set_password(password)
        user.save()
        return Response({
            'message': 'Password has been set successfully.'
        }, status=status.HTTP_200_OK)


class ConfirmRejectActivityPartcipation(APIView):
    """
    Post() ---> Accept or Reject a participation.
    """

    def post(self, request, activity_id):
        participation_status = request.data.get('status').lower() # accept, reject
        user_id = request.data.get('user_id')
        try:
            activity = Activity.objects.filter(activity_id=activity_id).first()
            if not activity:
                return Response({
                    'error': 'Activity does not exists.'
                }, status=status.HTTP_400_BAD_REQUEST)

            curr_participant_count = activity.participants.count()
            if participation_status == 'accept':
                if curr_participant_count < activity.maximum_participants:
                    activity.participants.add(user_id)
                    chat_request = activity.chat_requests.filter(from_user=user_id).first()
                    chat_request.participation_status = 'ACCEPTED'
                    chat_request.save()
                    activity.save()

                    return Response({
                        'message': 'Participant confirmed.',
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({
                        'error': 'Maximum participation reached.'
                    }, status=status.HTTP_400_BAD_REQUEST)
            elif participation_status == 'reject':
                chat_request = activity.chat_requests.filter(from_user=user_id).first()
                chat_request.participation_status = 'REJECTED'
                chat_request.save()

                return Response({
                    'message': 'Participant Rejected.'
                }, status=status.HTTP_200_OK)
            return Response({
                'error': 'Participation status is required.',
            }, status=status.HTTP_400_BAD_REQUEST)
        except Activity.DoesNotExist as e:
            return Response({
                'error': 'No activity found.'
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'message': 'Error occured while accepting/rejecting participation.',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class RemoveActivityParticipantView(APIView):

    def post(self, request, activity_id):
        try:
            activity = Activity.objects.filter(activity_id=activity_id).first()
            if not activity:
                return Response({
                    'error': 'Activity does not exist.'
                }, status=status.HTTP_400_BAD_REQUEST)

            user_id = request.data.get('user_id')
            if not activity.participants.filter(id=user_id).exists():
                return Response({'error': 'User is not a participant.'}, status=status.HTTP_400_BAD_REQUEST)

            activity.participants.remove(user_id)

            chat_request = activity.chat_requests.filter(from_user=user_id).first()
            if chat_request:
                chat_request.participation_status = 'REJECTED'
                chat_request.save()
            else:
                return Response({
                    'error': 'No chat request found.'
                }, status=status.HTTP_400_BAD_REQUEST)

            return Response({
                'message': 'User removed from participants.'
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'message': 'Error occurred while removing participant.',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RegisterAPIViewV2(APIView):
    def post(self, request):
        data1 = request.data.copy()
        username = data1.get('username', '')
        password = data1.get('password', '')

        if not re.match(USERNAME_REGEX, username):
            return Response({
                'message': 'Username does not meet the required format. It should be at least 6 characters long and can include only small letters, numbers'},status=status.HTTP_400_BAD_REQUEST
            )

        if not re.match(PASSWORD_REGEX, password):
            return Response({
                'message': 'Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, a digit, and a special character.'},
            status=status.HTTP_400_BAD_REQUEST
        )
        existing_user = CustomUser.objects.filter(
            Q(username=username) | Q(email=data1.get('email')) | Q(phone_number=data1.get('phone_number'))
        ).first()

        if existing_user:
            if existing_user.email == data1.get('email'):
                return Response({
                    'message': 'User with this email already exists.'
                }, status=status.HTTP_400_BAD_REQUEST) 
            elif existing_user.username == data1.get('username'):
                return Response({
                    'message': 'User with this username already exists.'
                }, status=status.HTTP_400_BAD_REQUEST) 
            elif existing_user.phone_number == data1.get('phone_number'):
                return Response({
                    'message': 'User with this phone number already exists.'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            return Response({'message': f"User already registered." }, status=status.HTTP_400_BAD_REQUEST)

        if not data1['longitude']:
            data1['longitude'] = None
        if not data1['latitude']:
            data1['latitude'] = None
        serializer = RegisterSerializerV2(data=data1)
        if serializer.is_valid():
            data = serializer.validated_data
            email = data["email"]
            dial_code = data["dial_code"]
            phone = data["phone_number"]

            otp = ''.join(random.choices(string.digits, k=6)) 
            err, err_code = send_otp_via_sms(dial_code, phone, otp)

            if err or err_code:
                return Response({
                    'error': f'Couldn\'t send OTP to your number {phone}.'
                }, status=status.HTTP_400_BAD_REQUEST)

            cache.set(f"otp:{email}", otp, timeout=300)  # 5 mins
            cache.set(f"user_data:{email}", data, timeout=300)

            return Response({
                "message": "OTP sent successfully.",
                "email": email
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyOTPAPIViewV2(APIView):
    def post(self, request):
        email = request.data.get('email')
        otp_input = request.data.get('otp')

        if not email or not otp_input:
            return Response({"error": "Email and OTP required."}, status=status.HTTP_400_BAD_REQUEST)

        real_otp = cache.get(f"otp:{email}")
        if real_otp != otp_input:
            return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)

        user_data = cache.get(f"user_data:{email}")
        user_data.pop('confirm_password')
        if not user_data:
            return Response({"error": "User data expired or missing."}, status=status.HTTP_400_BAD_REQUEST)
        
        user_data['email'] = user_data['email'].lower()
        
        user = CustomUser.objects.create_user(**user_data)
        user.otp_verified = True
        user.save()

        cache.delete(f"otp:{email}")
        cache.delete(f"user_data:{email}")

        return Response({"message": "User registered successfully."}, status=status.HTTP_201_CREATED)

class RegisterResendOTP(APIView):

    def post(self, request):
        resend_type = request.data.get('resend_type').lower()
        otp = ''.join(random.choices(string.digits, k=6))

        if resend_type == 'email':
            email = request.data.get('email')

            if not email:
                return Response({
                    'error': 'Email is missing.'
                }, status=status.HTTP_400_BAD_REQUEST)
            sent = send_email_via_mailgun(email, otp)
            if not sent:
                return Response({
                    'error': 'OTP couldn\'t be sent to your email. Please try again later.'
                }, status=status.HTTP_400_BAD_REQUEST)

            cache.set(f"otp:{email}", otp, timeout=300)

            return Response({
                'message': 'OTP resent on your Email.',
                'data': {'email': email, 'phone': '', 'dial_code': ''}
            }, status.HTTP_200_OK)

        if resend_type == 'phone':
            phone = request.data.get('phone')
            dial_code = request.data.get('dial_code')

            if not phone or not dial_code:
                return Response({
                    'error': 'Phone number or dial code is missing.'
                }, status=status.HTTP_400_BAD_REQUEST)

            err, err_code = send_otp_via_sms(dial_code, phone, otp)
            if err or err_code:
                return Response({
                    'error': 'OTP couldn\'t be sent to your Phone number. Please try again later.'
                }, status=status.HTTP_400_BAD_REQUEST)

            cache.set(f"otp:{phone}", otp, timeout=300)

            return Response({
                'message': 'OTP resent on your Number.',
                'data': {'email': '', 'phone': phone, 'dial_code': dial_code}
            }, status.HTTP_200_OK)


class LoginResendOTP(APIView):
    def post(self, request):
        phone = request.data.get('phone')
        dial_code = request.data.get('dial_code')

        if not phone or not dial_code:
            return Response({
                'error': 'Phone number or dial code is missing.'
            }, status=status.HTTP_400_BAD_REQUEST)
        otp = ''.join(random.choices(string.digits, k=6))
        err, err_code = send_otp_via_sms(dial_code, phone, otp)
        if err or err_code:
            return Response({
                'error': 'Couldn\'t send OTP to phone number.'
            }, status=status.HTTP_400_BAD_REQUEST)
        cache.set(f"otp:{phone}", otp, timeout=300)
        return Response({
            'message': 'OTP resent to your phone number.',
            'data': {'phone': phone, 'dial_code': dial_code}
        }, status=status.HTTP_200_OK)


# ==================== Register v3 =================== #

class RegisterAPIViewV3(APIView):

    def post(self, request):
        data = request.data.copy()
        registration_type = data.get('registration_type').lower()
        otp = ''.join(random.choices(string.digits, k=6))

        if registration_type == 'email':
            email = data.get('email')
            if not email:
                return Response({
                    'error': 'Email is missing.'
                }, status=status.HTTP_400_BAD_REQUEST
                )

            email_exists = CustomUser.objects.filter(email=email).exists()
            if email_exists:
                return Response({
                    'error': 'User with Email already exists.'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            sent = send_email_via_mailgun(email, otp)
            if not sent:
                return Response({
                    'error': 'Couldn\'t send OTP to your email. Please try again later.'
                }, status=status.HTTP_400_BAD_REQUEST)

            cache.set(f"otp:{email}", otp, timeout=300)
            return Response({
                'message': 'Verification OTP has been sent to your email.',
                'data': {"email": email}
            }, status=status.HTTP_200_OK)

        elif registration_type == 'phone':
            phone = data.get('phone')
            dial_code = data.get('dial_code')
            if not phone or not dial_code:
                return Response({
                    'error': 'Phone number or dial code is missing.'
                }, status=status.HTTP_400_BAD_REQUEST
                )

            phone_exists = CustomUser.objects.filter(phone_number=phone).exists()
            if phone_exists:
                return Response({
                    'error': 'User with Phone number already exists.'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            err, err_code = send_otp_via_sms(dial_code, phone, otp)
            if err or err_code:
                return Response({
                    'error': 'Couldn\'t send OTP to your Phone number. Please try again later.'
                }, status=status.HTTP_400_BAD_REQUEST)

            cache.set(f"otp:{phone}", otp, timeout=300)
            return Response({
                'message': 'Verification OTP has been sent to your Phone number.',
                'data': {"phone": phone, "dial_code": dial_code}
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'error': 'Registration type is required.'
            }, status=status.HTTP_400_BAD_REQUEST)

class VerifyOTPAPIViewV3(APIView):

    def post(self, request):
        data = request.data.copy()
        registration_type = data.get('registration_type').lower()

        if registration_type == 'email':
            email = data.get('email')

            otp_input = data.get('otp')
            original_otp = cache.get(f"otp:{email}")
            err_msg = None
            if not otp_input:
                err_msg = 'OTP is missing.'
            elif not email:
                err_msg = 'Email is missing.'
            elif not original_otp:
                err_msg = 'OTP expired. Try again.'
            elif otp_input != original_otp:
                err_msg = 'OTP does not match.'
        
            if err_msg:
                return Response({
                    'error': err_msg
                }, status=status.HTTP_400_BAD_REQUEST)

            return Response({
                'message': 'OTP verified successfully.',
                'data': {'email': email}
            }, status=status.HTTP_200_OK)
            
        elif registration_type == 'phone':
            phone = data.get('phone')
            dial_code = data.get('dial_code')
            input_otp = data.get('otp')

            if not phone or not dial_code:
                return Response({
                    'error': 'Phone number or dial code is missing.'
                }, status=status.HTTP_400_BAD_REQUEST)

            original_otp = cache.get(f"otp:{phone}")
            err_msg = None
            if not original_otp:
                err_msg = 'OTP expired. Please try again.'
            
            if original_otp != input_otp:
                err_msg = 'OTP does not match.'
            
            if err_msg:
                return Response({
                    'error': err_msg
                }, status=status.HTTP_400_BAD_REQUEST)

            return Response({
                'message': 'OTP verified successfully.',
                'data': {'phone': phone, 'dial_code': dial_code}
            }, status=status.HTTP_200_OK)

class CreateUserInDB(APIView):
    def post(self, request):
        data = request.data.copy()
        registration_type = data.get('registration_type').lower()

        if registration_type == 'email':
            user = CustomUser.objects.filter(email=data.get('email')).first()
            if user and user.email == data.get('email'):
                return Response({
                    'error': 'User already exists with this email.'
                }, status=status.HTTP_400_BAD_REQUEST)
            if not data.get('password'):
                return Response({
                    'error': 'Password is required.'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if not re.match(PASSWORD_REGEX, data.get('password')):
                return Response({
                    'error': 'Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, a digit, and a special character.'
                },status=status.HTTP_400_BAD_REQUEST)


            user = CustomUser.objects.create(
                email=data.get('email'),
                email_verified=True,
                username=CustomUser.generate_unique_username(),
                name=data.get('full_name')
            )
            user.set_password(data.get('password'))
            user.save()
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            login(request, user)
            if not request.session.session_key:
                request.session.save()
            session_id = request.session.session_key
            return Response({
                'message': 'User registered successfully.',
                'user': CustomUserSerializer(user).data,
                'refresh': str(refresh),
                'access': access_token,
                'is_approved': False,
                'vendor_id': '',
                'sessionid': session_id,
            })

        elif registration_type == 'phone':
            if not data.get('date_of_birth'):
                return Response({
                    'error': 'DOB is required.'
                }, status=status.HTTP_400_BAD_REQUEST)

            user = CustomUser.objects.create(
                phone_number=data.get('phone'),
                dial_code=data.get('dial_code'),
                username=CustomUser.generate_unique_username(),
                name=data.get('full_name'),
                date_of_birth=data.get('date_of_birth'),
                otp_verified=True
            )
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            if not request.session.session_key:
                request.session.save()
            session_id = request.session.session_key
            login(request, user)
            return Response({
                'message': 'User registered successfully.',
                'user': CustomUserSerializer(user).data,
                'refresh': str(refresh),
                'access': access_token,
                'is_approved': False,
                'vendor_id': '',
                'sessionid': session_id
            })


class LoginAPIViewV2(APIView):
    
    def post(self, request):
        data = request.data.copy()
        login_type = data.get('login_type').lower()

        if login_type == 'email':
            try:
                email = data.get('email').lower()
                password = data.get('password')
                user = CustomUser.objects.filter(email=email).first()
                if not user:
                    return Response({
                        'error': 'User does not exist with this email.'
                    }, status=status.HTTP_400_BAD_REQUEST)
                username = user.username
                user = authenticate(username=username, password=password)
                if not user:
                    return Response({
                        'error': 'Invalid credentials.'
                    }, status=status.HTTP_400_BAD_REQUEST)
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                login(request, user)
                vendor = VendorKYC.objects.filter(user=user).first()
                if not request.session.session_key:
                    request.session.save()
                session_id = request.session.session_key
                return Response({
                    'message': 'Logged in successfully.',
                    'user': CustomUserSerializer(user).data,
                    'refresh': str(refresh),
                    'access': access_token,
                    'is_approved': vendor.is_approved if vendor else False,
                    'vendor_id': vendor.vendor_id if vendor else '',
                    'sessionid': session_id
                }, status=status.HTTP_200_OK)
            except Exception as e:
                return Reponse({
                    'error': str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        elif login_type == 'phone': 
            try:
                dial_code = data.get('dial_code')
                phone = data.get('phone')
                if not dial_code or not phone:
                    return Response({
                        'error': 'Dial code or phone number is missing.',
                    }, status=status.HTTP_400_BAD_REQUEST)

                user = CustomUser.objects.filter(phone_number=phone).exists()
                if not user:
                    return Response({
                        'error': 'No user exists with this Phone number.'
                    }, status=status.HTTP_400_BAD_REQUEST)

                otp = ''.join(random.choices(string.digits, k=6))
                err, err_code = send_otp_via_sms(dial_code, phone, otp)
                if err or err_code:
                    return Response({
                        'error': 'Couldn\'t send OTP to your number.',
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                cache.set(f"otp:{phone}", otp, timeout=300)
                return Response({
                    'message': 'OTP is sent to your number.'
                }, status=status.HTTP_200_OK)
            except Exception as e:
                return Reponse({
                    'error': str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LoginWithOTP(APIView):
    def post(self, request):
        data = request.data.copy()
        phone = data.get('phone')
        input_otp = data.get('otp')
        original_otp = cache.get(f"otp:{phone}")

        if original_otp != input_otp:
            return Response({
                'error': 'OTP does not match.'
            }, status=status.HTTP_400_BAD_REQUEST)

        user = CustomUser.objects.filter(phone_number=phone).first()
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        login(request, user)
        vendor = VendorKYC.objects.filter(user=user).first()
        if not request.session.session_key:
            request.session.save()
        session_id = request.session.session_key

        return Response({
            'message': 'Logged in successfully.',
            'user': CustomUserSerializer(user).data,
            'refresh': str(refresh),
            'access': access_token,
            'is_approved': vendor.is_approved if vendor else False,
            'vendor_id': vendor.vendor_id if vendor else '',
            'sessionid': session_id
        },status=status.HTTP_200_OK)

class LogoutAPIV2(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get("refresh_token")
        device_token = request.data.get("device_token")

        if not refresh_token:
            return Response({"error": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                token = RefreshToken(refresh_token)

                # Blacklist the token
                token.blacklist()

                # Delete device token
                if device_token:
                    Device.objects.filter(user=request.user, device_token=device_token).delete()

                
                # Create activity log only after successful logout
                ActivityLog.objects.create(
                    user=request.user,
                    event=ActivityLog.LOGOUT,
                    metadata={}
                )

                # Logout the user
                logout(request)

        except TokenError:
            return Response({"error": "Invalid token or token already blacklisted."}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"message": "Logged out successfully."}, status=status.HTTP_200_OK)



# ==================== Favorite Views ===================== # 

class FavoriteUnfavoriteUserAPI(APIView):
    """
    Post() ---> Favorite or Unfavorite an user
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_id = request.user.id
        fav_users = FavoriteUser.objects.filter(user=user_id)
        if fav_users:
            serializer = FavoriteUserSerializer(fav_users, many=True)
            return Response({
                'message': 'Favorite users found.',
                'data': serializer.data
            }, status=status.HTTP_200_OK)
        return Response({
            'message': 'No Favorite users found.',
            'data': []
        }, status=status.HTTP_200_OK)

    def post(self, request, user_id):
        user = request.user
        user_to_be_favorited = CustomUser.objects.filter(id=user_id).first()

        if not user_to_be_favorited:
            return Response({
                'error': 'User to be favorited does not exist.'
            }, status=status.HTTP_400_BAD_REQUEST)

        if user == user_to_be_favorited:
            return Response({
                'error': 'You cannot favorite yourself.'
            }, status=status.HTTP_400_BAD_REQUEST)

        favorite_relation = FavoriteUser.objects.filter(user=user, favorite_user=user_to_be_favorited).first()

        if favorite_relation:
            favorite_relation.delete()
            return Response({
                'message': f'You unfavorited {user_to_be_favorited.name}.'
            }, status=status.HTTP_200_OK)
        else:
            try:
                FavoriteUser.objects.create(
                    user=user,
                    favorite_user=user_to_be_favorited
                )
                return Response({
                    'message': f'You favorited {user_to_be_favorited.name}.'
                }, status=status.HTTP_200_OK)
            except IntegrityError:
                return Response({
                    'error': 'You have already favorited this user.'
                }, status=status.HTTP_400_BAD_REQUEST)


class FavoriteUnfavoriteVendorAPI(APIView):
    """
    Get() ---> Get all favorite vendors for an user.
    Post() ---> Favorite or Unfavorite a vendor.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_id = request.user.id
        fav_vendors = FavoriteVendor.objects.filter(user=user_id)
        if fav_vendors:
            serializer = FavoriteVendorSerializer(fav_vendors, many=True)
            return Response({
                'message': 'Favorite vendors found.',
                'data': serializer.data
            }, status=status.HTTP_200_OK)
        return Response({
            'message': 'No Favorite vendors found.',
            'data': []
        }, status=status.HTTP_200_OK)
        

    def post(self, request, vendor_id):
        user = request.user
        vendor_to_be_favorited = VendorKYC.objects.filter(vendor_id=vendor_id).first()

        if not vendor_to_be_favorited:
            return Response({
                'error': 'Vendor to be favorited does not exist.'
            }, status=status.HTTP_400_BAD_REQUEST)

        # if user == _to_be_favorited:
        #     return Response({
        #         'error': 'You cannot favorite yourself.'
        #     }, status=status.HTTP_400_BAD_REQUEST)

        favorite_relation = FavoriteVendor.objects.filter(user=user, vendor=vendor_to_be_favorited).first()
        if favorite_relation:
            favorite_relation.delete()
            return Response({
                'message': f'You unfavorited {vendor_to_be_favorited.full_name}.'
            }, status=status.HTTP_200_OK)
        else:
            try:
                FavoriteVendor.objects.create(
                    user=user,
                    vendor=vendor_to_be_favorited
                )
                return Response({
                    'message': f'You favorited {vendor_to_be_favorited.full_name}.'
                }, status=status.HTTP_200_OK)
            except IntegrityError:
                return Response({
                    'error': 'You have already favorited this user.'
                }, status=status.HTTP_400_BAD_REQUEST)

class FavoriteUnfavoriteServiceAPI(APIView):
    """
    Post() ---> Favorite or Unfavorite a service
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_id = request.user.id
        fav_services = FavoriteService.objects.filter(user=user_id)
        if fav_services:
            serializer = FavoriteServiceSerializer(fav_services, many=True)
            return Response({
                'message': 'Favorite services found.',
                'data': serializer.data
            }, status=status.HTTP_200_OK)
        return Response({
            'message': 'No Favorite services found.',
            'data': []
        }, status=status.HTTP_200_OK)

    def post(self, request, service_id):
        user = request.user
        service_to_be_favorited = Service.objects.filter(id=service_id).first()

        if not service_to_be_favorited:
            return Response({
                'error': 'Service to be favorited does not exist.'
            }, status=status.HTTP_400_BAD_REQUEST)

        favorite_relation = FavoriteService.objects.filter(user=user, service=service_to_be_favorited).first()

        if favorite_relation:
            favorite_relation.delete()
            return Response({
                'message': f'You unfavorited {service_to_be_favorited.name}.'
            }, status=status.HTTP_200_OK)
        else:
            try:
                FavoriteService.objects.create(
                    user=user,
                    service=service_to_be_favorited
                )
                return Response({
                    'message': f'You favorited {service_to_be_favorited.name}.'
                }, status=status.HTTP_200_OK)
            except IntegrityError:
                return Response({
                    'error': 'You have already favorited this user.'
                }, status=status.HTTP_400_BAD_REQUEST)


# ==================== End Favorite Views ===================== # 


# ==================== Buy deal dummy Views ===================== #
from main.utils import generate_and_upload_qr_to_s3
class PurchaseDealAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        try:
            purchase = Purchase.objects.get(id=pk)
            serializer = PurchaseDealSerializer(purchase)
            return Response({
                'message': 'Purchase found.',
                'data': serializer.data
            }, status=status.HTTP_200_OK)
        except BuyDeal.DoesNotExist:
            return Response({
                'error': 'No purchase with this ID.'
            }, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request):
        user = request.user
        data = request.data.copy()

        serializer = PurchaseDealSerializer(data=data, context={'user': user})
        if serializer.is_valid():
            try:
                with transaction.atomic():
                    purchase = serializer.save()
                    qr_data = {
                        "purchase_id": purchase.id,
                        "deal_id": purchase.deal_id,
                        "vendor_id": str(purchase.seller.vendor_id),
                        "buyer_id": str(user.id),
                        "quantity": purchase.quantity,
                        "created_at": timezone.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
                    qr_url = generate_and_upload_qr_to_s3(qr_data)
                    purchase.collection_code = [qr_url]
                    purchase.buyer = user
                    deal = purchase.deal
                    purchase.amount = purchase.amount or (purchase.quantity * deal.deal_price)
                    purchase.save()
                    deal.deals_left = deal.deals_left - int(purchase.quantity)
                    deal.save()

            except Exception as e:
                return Response({
                    'error': f'Error while generating collection code -> {str(e)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({
                'message': 'Purchase successful.',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED)

        errors = serializer.errors
        error_list = [f"{field} {str(msg)}" for field, messages in errors.items() for msg in messages]
        return Response({
            'message': 'Purchase failed.',
            'error': error_list[0]
        }, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, id):    
        data = request.data.copy()
        action = data.get('action')
        if not action or action != 'FULFILL':
            return Response({
                'error': 'Action is missing or invalid.'
            }, status=status.HTTP_400_BAD_REQUEST)
        try:
            purchase = Purchase.objects.get(pk=id)
        except Purchase.DoesNotExist:
            return Response({
                'error': 'This purchase does not exists.'
            }, status=status.HTTP_400_BAD_REQUEST)

        if request.user.vendorkyc_set.exists():
            vendor_kyc = request.user.vendorkyc_set.first()
            if purchase.seller.vendor_id != vendor_kyc.vendor_id:
                return Response({
                    'error': 'Deal belongs to other vendor. Scan failed.'
                }, status=status.HTTP_400_BAD_REQUEST)

        serializer = EditPurchaseDealSerializer(purchase, data=data, partial=True)
        if serializer.is_valid():
            instance = serializer.fullfill_purchase(purchase, action)
            resp_data = PurchaseDealSerializer(instance)
            return Response({
                'message': 'Purchase processed successfully.',
                'data': resp_data.data
            }, status=status.HTTP_200_OK)
        errors = serializer.errors
        error_list = [f"{field} {str(msg)}" for field, messages in errors.items() for msg in messages]
        return Response({
            'info': 'Purchase process failed.',
            'error': error_list[0]
        }, status=status.HTTP_400_BAD_REQUEST)


class GetUserPurchaseAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            purchase = Purchase.objects.filter(buyer=request.user)
            serializer = PurchaseDealSerializer(purchase, many=True)
            return Response({
                'message': 'Purchases found.',
                'data': serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'message': 'Something went wrong while fetching purchases.',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class GetVendorSalesAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, vendor_id):
        try:
            purchase = Purchase.objects.filter(seller=vendor_id)
            serializer = PurchaseDealSerializer(purchase, many=True)
            return Response({
                'message': 'Purchases found.',
                'data': serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'message': 'Something went wrong while fetching purchases.',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DeleteCustomUser(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        try:
            user = CustomUser.objects.get(pk=pk)
        except CustomUser.DoesNotExist:
            return Response({
                'error': 'User does not exists.'
            }, status=status.HTTP_400_BAD_REQUEST)
        user.is_active = False
        user.save()
        return Response({
            'message': 'User deleted successfully.'
        }, status=status.HTTP_200_OK)