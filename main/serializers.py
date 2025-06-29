import json
import pytz
import uuid
import io
import os
import re
import base64
import boto3
import datetime as dt
from PIL import Image
from rest_framework import serializers
from urllib.parse import urlparse
from datetime import datetime, timedelta
from decimal import Decimal
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model, authenticate
from django.utils import timezone
from django.utils.timezone import localtime
from .models import (
    CustomUser, OTP, Activity, PasswordResetOTP, VendorKYC, Address, Service, CreateDeal, PlaceOrder,
    ActivityCategory, ServiceCategory, FavoriteVendor, VendorRating, RaiseAnIssueMyOrders, RaiseAnIssueVendors, RaiseAnIssueCustomUser,
    Notification, Device
)
from upswap_chat.models import ChatRequest, ChatRoom, ChatMessage

from upswap_chat.models import ChatRequest
from upswap_chat.serializers import ChatRequestSerializer

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth import get_user_model
from django.utils.encoding import force_str
from .validators import validate_password_strength
from rest_framework.exceptions import ValidationError, AuthenticationFailed
from io import BytesIO
from django.core.validators import validate_email
from django.core.exceptions import ValidationError as DjangoValidationError
from django.contrib.auth import authenticate
from django.db.models import Avg
from .exceptions import PhoneNumberNotVerified

from activity_log.models import ActivityLog
from appointments.serializers import ServiceSerializer

User = get_user_model()

class CustomUserSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)
    country_code = serializers.CharField(required=False, allow_blank=True)
    dial_code = serializers.CharField(required=False, allow_blank=True)
    country = serializers.CharField(required=False, allow_blank=True)
    social_id = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    type = serializers.ChoiceField(choices=CustomUser.LOGIN_TYPE_CHOICES, required=False)
    fcm_token = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    latitude = serializers.DecimalField(max_digits=9, decimal_places=6, required=False, allow_null=True)
    longitude = serializers.DecimalField(max_digits=9, decimal_places=6, required=False, allow_null=True)

    class Meta:
        model = CustomUser
        fields = ['id', 'name', 'username', 'email', 'phone_number', 'date_of_birth', 'gender', 'password', 'confirm_password', 'country_code', 'dial_code', 'country', 'social_id', 'type', 'fcm_token', 'latitude', 'longitude', 'user_type']
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        user = CustomUser.objects.create_user(**validated_data)
        return user


class VerifyOTPSerializer(serializers.Serializer):
    otp = serializers.CharField()

    def validate(self, data):
        otp = data.get('otp')
        user = self.context['request'].user

        if user.is_anonymous:
            raise serializers.ValidationError("Authentication credentials were not provided.")

        try:
            otp_instance = OTP.objects.get(user=user, otp=otp, is_verified=False)
            if otp_instance.is_expired():
                raise serializers.ValidationError("OTP has expired.")
        except OTP.DoesNotExist:
            raise serializers.ValidationError("Invalid OTP.")

        # Mark the OTP as verified
        otp_instance.is_verified = True
        otp_instance.save()

        # Mark user as otp_verified
        user.otp_verified = True
        user.save()

        # Generate new JWT tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        # Log activity
        ActivityLog.objects.create(
            user=user,
            event=ActivityLog.VERIFY_OTP,
            metadata={}
        )

        return {
            'refresh': str(refresh),
            'access': access_token,
            'message': 'OTP verified successfully. You can now log in.'
        }

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()
    fcm_token = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    latitude = serializers.DecimalField(max_digits=9, decimal_places=6, required=False, allow_null=True)
    longitude = serializers.DecimalField(max_digits=9, decimal_places=6, required=False, allow_null=True)

    def validate(self, data):
        email = data.get('email').lower()
        password = data.get('password')
        user = authenticate(username=self.context.get('username'), password=password)
        if user is None:
            raise serializers.ValidationError({'error': 'Invalid credentials'})
        
        # Update fcm_token, latitude, longitude if provided
        user.fcm_token = data.get('fcm_token', user.fcm_token)
        user.latitude = data.get('latitude', user.latitude)
        user.longitude = data.get('longitude', user.longitude)
        user.save()
        
        data['user'] = user
        return data
    
class ActivityCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ActivityCategory
        fields = ['actv_category']
    
class ActivitySerializer(serializers.ModelSerializer):
    infinite_time = serializers.BooleanField(write_only=True, required=False, default=False)  # Updated default to False
    location = serializers.CharField(required=False, allow_blank=True)
    latitude = serializers.FloatField(required=False, allow_null=True)
    longitude = serializers.FloatField(required=False, allow_null=True)
    uploaded_images = serializers.ListField(
        child=serializers.DictField(
            child=serializers.URLField(),
            required=True
        ),
        required=False
    )
    end_date = serializers.DateField(required=False, allow_null=True)
    end_time = serializers.TimeField(required=False, allow_null=True)

    created_at = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)

    class Meta:
        model = Activity
        fields = [
            'activity_id', 'activity_title', 'activity_description',
            'uploaded_images', 'user_participation', 'maximum_participants',
            'end_date', 'end_time', 'created_at', 'category',
            'created_by', 'infinite_time',
            'location', 'latitude', 'longitude'
        ]
        read_only_fields = ['created_by', 'created_at']

    def validate(self, data):
        now = timezone.now().date()
        data['user_participation'] = data.get('user_participation', True)

        infinite_time = data.get('infinite_time', False)

        if not infinite_time:
            if data.get('end_date') and data['end_date'] < now:
                raise serializers.ValidationError({"end_date": "End date cannot be in the past."})

        if data.get('maximum_participants') and data['maximum_participants'] > 1000:
            raise serializers.ValidationError({"maximum_participants": "Maximum participants cannot exceed 1000."})

        if not data.get('user_participation', True):
            data['maximum_participants'] = 0

        return data

    def create(self, validated_data):
        uploaded_images = validated_data.pop('uploaded_images', [])
        validated_data['created_by'] = self.context['request'].user

        set_current_datetime = validated_data.get('set_current_datetime', False)
        infinite_time = validated_data.get('infinite_time', False)

        if infinite_time:
            future_date = timezone.now() + timezone.timedelta(days=365 * 999)
            validated_data['end_date'] = future_date.date()
            validated_data['end_time'] = future_date.time()

        if not validated_data.get('user_participation', True):
            validated_data['maximum_participants'] = 0

        activity = super().create(validated_data)

        if uploaded_images:
            activity.uploaded_images = uploaded_images
            activity.save()

        return activity


    def update(self, instance, validated_data):
        if validated_data.pop('infinite_time', False):
            future_date = timezone.now() + timezone.timedelta(days=365 * 999)  # 999 years from now
            validated_data['end_date'] = future_date.date()
            validated_data['end_time'] = future_date.time()

        # Update images if provided
        uploaded_images = validated_data.pop('uploaded_images', None)
        if uploaded_images is not None:
            instance.uploaded_images = uploaded_images
            instance.save()

        return super().update(instance, validated_data)
    
    def validate_uploaded_images(self, value):
        """
        Validate that uploaded_images contains valid metadata.
        """
        for image in value:
            if not all(key in image for key in ('thumbnail', 'compressed')):
                raise serializers.ValidationError(
                    "Each image must include 'thumbnail' and 'compressed' URLs."
                )
        return value

class ParticipantSerializer(serializers.ModelSerializer):
    profile_pic = serializers.SerializerMethodField()
    class Meta:
        model = CustomUser
        fields = [
            'id', 'username', 'profile_pic', 'name',
        ]

    def get_profile_pic(self, obj):
        # If profile_pic is a list and has at least one URL, return the first one
        if obj.profile_pic:
            return obj.profile_pic
        return ""
    
class ActivityListsSerializer(serializers.ModelSerializer):
    user_id = serializers.UUIDField(source='created_by.id', read_only=True)
    created_by = serializers.CharField(source='created_by.name')  # Assuming `created_by` refers to CustomUser
    # activity_category = serializers.CharField(source='activity_category.actv_category', read_only=True)
    uploaded_images = serializers.SerializerMethodField()
    original_images = serializers.SerializerMethodField()
    participants_count = serializers.SerializerMethodField()

    class Meta:
        model = Activity
        fields = [
            'activity_id', 'user_id', 'activity_title','uploaded_images', 
            'original_images','created_by', 'user_participation', 'infinite_time', 
            'category',
            'end_date', 'end_time', 'latitude', 'longitude',
            'location', 'participants_count',
        ]

    def get_original_images(self, obj):
        if not obj.uploaded_images or not isinstance(obj.uploaded_images, list):
            return []

        # Return only the thumbnail of the first image in the uploaded_images list
        first_image = obj.uploaded_images[0]  # Get the first image
        original = first_image.get("original") if first_image else None 
        return [original]
        
    def get_uploaded_images(self, obj):
        """
        Fetch only the first image thumbnail from uploaded_images.
        This ensures only the first uploaded image's thumbnail is fetched.
        """
        # Ensure uploaded_images field is valid and has data
        if not obj.uploaded_images or not isinstance(obj.uploaded_images, list):
            return []

        # Return only the thumbnail of the first image in the uploaded_images list
        first_image = obj.uploaded_images[0]  # Get the first image
        thumbnail = first_image.get("thumbnail") if first_image else None  # Extract its thumbnail
        # original = first_image.get("original") if first_image else None
        return [thumbnail]

    def get_participants_count(self, obj):
        participants_count = obj.participants.count()
        return participants_count # ParticipantSerializer(participants, many=True).data # if participants else []



class ActivityDetailsSerializer(serializers.ModelSerializer):
    user_id = serializers.UUIDField(source='created_by.id', read_only=True)
    created_by = serializers.CharField(source='created_by.name')
    uploaded_images = serializers.SerializerMethodField()
    original_images = serializers.SerializerMethodField()
    organizer_profile_picture = serializers.CharField(source='created_by.profile_pic', read_only=True)
    participants = serializers.SerializerMethodField()
    
    class Meta:
        model = Activity
        fields = [
            'activity_id', 'user_id', 'organizer_profile_picture', 'activity_title', 'activity_description', 'category',
            'uploaded_images', 'original_images', 'user_participation', 'maximum_participants',
            'end_date', 'end_time', 'created_at',
            'created_by', 'infinite_time', 'participants',
            'location', 'latitude', 'longitude', 'is_deleted',
        ]
        read_only_fields = ['created_by', 'created_at', 'is_deleted']

    def get_original_images(self, obj):
        if not obj.uploaded_images or not isinstance(obj.uploaded_images, list):
            return []

        original = [
            image.get("original") for image in obj.uploaded_images if image.get("original")
        ]

        # Return only compressed
        return original
        
    def get_uploaded_images(self, obj):
        """
        Fetch only the uploaded image compressed served via S3/CDN URLs.
        The compressed URLs are directly mapped based on uploaded images.
        """
        if not obj.uploaded_images or not isinstance(obj.uploaded_images, list):
            return []

        compressed = [
            image.get("compressed") for image in obj.uploaded_images if image.get("compressed")
        ]

        return compressed
    
    def get_participants(self, obj):
        participants = obj.participants.all()
        return ParticipantSerializer(participants, many=True).data 


class AddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = Address
        fields = ['uuid', 'house_no_building_name', 'road_name_area_colony', 'country', 
                  'state', 'city', 'pincode', 'latitude', 'longitude']
        read_only_fields = ['uuid']
        
        
class VendorKYCSerializer(serializers.ModelSerializer):
    profile_pic = serializers.CharField(required=False, allow_blank=True)
    uploaded_business_documents = serializers.ListField(
        child=serializers.URLField(),
        required=False,
        allow_empty=True,
        allow_null=True
    )
    # uploaded_images = serializers.ListField(
    #     child=serializers.DictField(
    #         child=serializers.URLField(
    #             allow_empty=True,
    #             allow_null=True,
    #             required=False
    #         ),
    #     ),
    #     required=False,
    #     allow_empty=True
    # )
    uploaded_images = serializers.ListField(
        child=serializers.DictField(
            child=serializers.URLField(
                allow_null=True,
                allow_blank=True,
                required=False
            )
        ),
        required=False,
        allow_empty=True
    )   

    business_hours = serializers.JSONField(required=False, allow_null=True)
    addresses = AddressSerializer(many=True, required=False)

    class Meta:
        model = VendorKYC
        fields = [
            'vendor_id', 'profile_pic', 'user', 'full_name', 'phone_number', 
            'business_email_id', 'business_establishment_year', 'business_description', 
            'uploaded_business_documents', 
            'uploaded_images', 'same_as_personal_phone_number', 
            'same_as_personal_email_id', 'addresses',
            'country_code', 'dial_code', 
            'bank_account_number', 
            'retype_bank_account_number', 'bank_name', 'ifsc_code', 
            'business_hours', 'is_approved', 'latitude', 'longitude'
        ]
    def validate_business_hours(self, value):
        if not isinstance(value, list):
            raise serializers.ValidationError("Business hours must be a list.")
        for item in value:
            if not isinstance(item, dict) or 'day' not in item or 'time' not in item:
                raise serializers.ValidationError("Each business hour entry must be a dictionary with 'day' and 'time'.")
        return value

    def create(self, validated_data):
        user = validated_data.get('user')

        # Check if VendorKYC exists for this user
        existing_kyc = VendorKYC.objects.filter(user=user).first()
        if existing_kyc:
            # If KYC exists, update it instead of creating a new one
            return self.update(existing_kyc, validated_data)

        # If no existing VendorKYC, create a new one
        addresses_data = validated_data.pop('addresses', [])
        uploaded_documents = validated_data.pop('uploaded_business_documents', [])

        vendor_kyc = VendorKYC.objects.create(**validated_data)

        self.handle_addresses(vendor_kyc, addresses_data) 
        if uploaded_documents:
            vendor_kyc.uploaded_business_documents = uploaded_documents
            vendor_kyc.save()

        return vendor_kyc

    def update(self, instance, validated_data):
        addresses_data = validated_data.pop('addresses', None)
        uploaded_documents = validated_data.pop('uploaded_business_documents', [])
        profile_pic = validated_data.pop('profile_pic', None)

        # Update fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        # Reset approval status on update
        instance.is_approved = False

        # Handle profile picture update
        if profile_pic:
            instance.profile_pic = profile_pic

        # Handle addresses and services
        self.handle_addresses(instance, addresses_data)

        instance.save()
        return instance

    def handle_addresses(self, vendor_kyc, addresses_data):
        """Helper method to update addresses"""
        if addresses_data is not None:
            vendor_kyc.addresses.all().delete()
            for address in addresses_data:
                Address.objects.create(vendor=vendor_kyc, **address)
    

class VendorKYCListSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(source='user.name', read_only=True)
    user = serializers.UUIDField(source='user.id', read_only=True)
    addresses = serializers.SerializerMethodField()
    uploaded_images = serializers.SerializerMethodField()
    # is_favorite = serializers.SerializerMethodField()
    average_rating = serializers.SerializerMethodField()
    services = serializers.SerializerMethodField()
    
    class Meta:
        model = VendorKYC
        fields = ['profile_pic', 'full_name', 'vendor_id', 'user', 'uploaded_images', 'addresses', 'average_rating', 'services']  # 'is_favorite', 

    def get_addresses(self, obj):
        # Assuming 'addresses' is a related field in the VendorKYC model
        addresses = obj.addresses.all()  # Fetch related addresses
        return AddressSerializer(addresses, many=True).data
    
    def get_uploaded_images(self, obj):
        """
        Fetch 'compressed' and 'thumbnail' URLs for uploaded images.
        Each image entry in the list contains these two keys.
        """
        # Ensure uploaded_images field is valid
        if not obj.uploaded_images or not isinstance(obj.uploaded_images, list):
            return []

        # Extract both 'compressed' and 'thumbnail' keys for each image
        images = [
            {
                "compressed": image.get("compressed"),
                "thumbnail": image.get("thumbnail")
            }
            for image in obj.uploaded_images
            if image.get("compressed") and image.get("thumbnail")
        ]

        return images

    def get_services(self, obj):
        services = obj.ven_services.all()
        return ServiceSerializer(services, many=True).data
    
    # def get_is_favorite(self, obj):
    #     user = self.context.get('request').user
    #     if user.is_authenticated:
    #         # Check if this vendor is favorited by the logged-in user
    #         favorite_vendor = FavoriteVendor.objects.filter(user=user, vendor=obj).exists()
    #         return favorite_vendor
    #     return False  # If user is not authenticated, return False
    
    def get_average_rating(self, obj):
        average = VendorRating.objects.filter(vendor=obj).aggregate(avg_rating=Avg('rating'))['avg_rating']
        return round(average, 1) if average else 0.0


        

class VendorKYCDetailSerializer(serializers.ModelSerializer):
    addresses = AddressSerializer(many=True, read_only=True)
    uploaded_business_documents = serializers.SerializerMethodField()
    uploaded_images = serializers.SerializerMethodField()
    
    business_hours = serializers.JSONField(required=False, allow_null=True)
    average_rating = serializers.SerializerMethodField()
    services = serializers.SerializerMethodField()

    class Meta:
        model = VendorKYC
        fields = [
            'vendor_id', 'profile_pic', 'user', 'full_name', 'phone_number', 'business_email_id',
            'business_establishment_year', 'business_description', 'uploaded_business_documents',
            'uploaded_images', 'same_as_personal_phone_number', 'services',
            'same_as_personal_email_id', 'addresses', 'country_code', 'dial_code', 
            'bank_account_number', 'retype_bank_account_number', 'bank_name', 'ifsc_code',
            'business_hours', 'is_approved', 'average_rating'
        ]
        read_only_fields = ['user', 'is_approved']

    def to_representation(self, instance):
        """
        Customize the representation of the VendorKYC instance
        to include nested relationships like addresses and services,
        and business-related documents and photos.
        """
        representation = super().to_representation(instance)
        representation['addresses'] = AddressSerializer(instance.addresses.all(), many=True).data

        return representation
    
    def get_uploaded_business_documents(self, obj):
        """
        Fetch the list of uploaded business document URLs.
        """
        return obj.uploaded_business_documents if obj.uploaded_business_documents else []
    
    def get_uploaded_images(self, obj):
        """
        Fetch 'compressed' and 'thumbnail' URLs for uploaded images.
        Each image entry in the list contains these two keys.
        """

        if not obj.uploaded_images or not isinstance(obj.uploaded_images, list):
            return []

        images = [
            {
                "compressed": image.get("compressed"),
                "thumbnail": image.get("thumbnail")
            }
            for image in obj.uploaded_images
            if image.get("compressed") and image.get("thumbnail")
        ]

        return images
    
    def get_average_rating(self, obj):
        average = VendorRating.objects.filter(vendor=obj).aggregate(avg_rating=Avg('rating'))['avg_rating']
        return round(average, 1) if average else 0.0   

    def get_services(self, obj):
        services = obj.ven_services.all()
        return ServiceSerializer(services, many=True).data

        
class VendorKYCStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = VendorKYC
        fields = ['vendor_id', 'is_approved']
    
    
from appointments.models import Service as AppService
class CreateDealSerializer(serializers.ModelSerializer):
    vendor_name = serializers.CharField(source='vendor_kyc.full_name', read_only=True)
    vendor_uuid = serializers.UUIDField(source='vendor_kyc.vendor_id', read_only=True)
    vendor_email = serializers.EmailField(source='vendor_kyc.business_email_id', read_only=True)
    vendor_number = serializers.CharField(source='vendor_kyc.phone_number', read_only=True)
    discount_percentage = serializers.SerializerMethodField()
    uploaded_images = serializers.ListField(
        child=serializers.DictField(
            child=serializers.CharField(),
            required=True,
        ),
        required=False,
    )
    deal_post_time = serializers.DateTimeField(format='%Y-%m-%d %H:%M:%S', read_only=True)
    

    class Meta:
        model = CreateDeal
        fields = [
            'deal_uuid', 'deal_title', 'deal_description', 'category', 'service',
            'uploaded_images', 'end_date', 'end_time',
            'buy_now', 'actual_price', 'deal_price', 'available_deals',
            'location_house_no', 'location_road_name', 'location_country',
            'location_state', 'location_city', 'location_pincode', 'vendor_kyc',
            'vendor_name', 'vendor_uuid', 'vendor_email', 'vendor_number',
            'discount_percentage', 'latitude', 'longitude', 'deal_post_time'
        ]
        read_only_fields = ['deal_uuid', 'discount_percentage']

    def get_discount_percentage(self, obj):
        if obj.actual_price and obj.deal_price:
            discount = ((obj.actual_price - obj.deal_price) / obj.actual_price) * 100
            return round(discount, 2)
        return 0
    
    def validate(self, data):
        available_deals = data.get('available_deals', 0)
        if available_deals < 1:
            raise serializers.ValidationError({'available_deals': "You must provide at least 1 deal."})
        print(data.get('service'))
        # serv = AppService.objects.filter(id=service_id).first()
        # if not serv:
        #     raise serializers.ValidationError({'service': f"Invalid service ID: {service_id}"})
        # print(serv)
        # print(data.get('service'))
        # data['service'] = serv
        return data

    def validate(self, data):
        """ Validate select_service and address fields, ensure they are provided manually. """
        vendor_kyc = data.get('vendor_kyc')
        category = data.get('category')

        # Ensure that all address-related fields are provided manually by the vendor
        address_fields = [
            'location_house_no', 'location_road_name', 'location_country',
            'location_state', 'location_city', 'location_pincode', 'latitude', 'longitude'
        ]
        for field in address_fields:
            if not data.get(field):
                raise serializers.ValidationError(f"{field.replace('_', ' ').capitalize()} is required.")

        return data
    
    def validate(self, data):
        """Validate date and time fields."""
        start_date = data.get('start_date')
        start_time = data.get('start_time')
        end_date = data.get('end_date')
        end_time = data.get('end_time')
        start_now = data.get('start_now', False)
        today = timezone.localdate()
        current_time = timezone.localtime().time()

        # Ensure start_date and end_date are not in the past
        if start_date and start_date < today:
            raise serializers.ValidationError({'start_date': "Start date cannot be in the past."})

        if end_date and end_date < today:
            raise serializers.ValidationError({'end_date': "End date cannot be in the past."})
        
        if start_date and end_date < today:
            raise serializers.ValidationError({'start_date & end_date': "Start & End date cannot be in the past."})

        if start_date and end_date and start_date > end_date:
            raise serializers.ValidationError({'end_date': "End date cannot be before start date."})
        
        # Ensure start_time is not before the current time if the deal is for today
        if start_date == today and start_time == current_time:
            raise serializers.ValidationError({'start_time': "Start time cannot be in the past."})
        

        if start_date and start_time and end_date and end_time:
            start_datetime = timezone.make_aware(dt.datetime.combine(start_date, start_time))
            end_datetime = timezone.make_aware(dt.datetime.combine(end_date, end_time))

            if start_datetime > end_datetime:
                raise serializers.ValidationError({'end_time': "End time must be after start time."})
            

            # If start_date and end_date are same, enforce 10 minutes gap
            if start_date == end_date:
                min_end_time = (dt.datetime.combine(start_date, start_time) + dt.timedelta(minutes=10)).time()
                if end_time < min_end_time:
                    raise serializers.ValidationError({'end_time': "End time must be at least 10 minutes."})

        return data

    
class CreateDeallistSerializer(serializers.ModelSerializer):
    vendor_name = serializers.CharField(source='vendor_kyc.full_name', read_only=True)
    vendor_uuid = serializers.UUIDField(source='vendor_kyc.vendor_id', read_only=True)
    country = serializers.CharField(source='vendor_kyc.country', read_only=True)
    discount_percentage = serializers.SerializerMethodField()
    uploaded_images = serializers.SerializerMethodField()
    original_images = serializers.SerializerMethodField()
    average_rating = serializers.SerializerMethodField()
    
    class Meta:
        model = CreateDeal
        fields = [
            'deal_uuid', 'deal_post_time', 'deal_title',
            'uploaded_images', 'original_images', 'end_date', 'end_time',
            'actual_price', 'deal_price', 'available_deals',
            'location_house_no', 'location_road_name', 'location_country',
            'location_state', 'location_city', 'location_pincode',
            'vendor_name', 'vendor_uuid', 'country', 'category',
            'discount_percentage', 'latitude', 'longitude', 'average_rating', 'buy_now'
        ]
        read_only_fields = ['deal_uuid', 'discount_percentage']

    def get_discount_percentage(self, obj):
        if obj.actual_price and obj.deal_price:
            discount = ((obj.actual_price - obj.deal_price) / obj.actual_price) * 100
            return round(discount, 2)
        return 0     

    def get_original_images(self, obj):
        if not obj.uploaded_images or not isinstance(obj.uploaded_images, list):
            return []

        first_image = obj.uploaded_images[0] 
        original = first_image.get("original")
        return [original]

    def get_uploaded_images(self, obj):
        """
        Fetch only the first image thumbnail from uploaded_images.
        This ensures only the first uploaded image's thumbnail is fetched.
        """
        # Ensure uploaded_images field is valid and has data
        if not obj.uploaded_images or not isinstance(obj.uploaded_images, list):
            return []

        first_image = obj.uploaded_images[0] 
        thumbnail = first_image.get("thumbnail")
        return [thumbnail]
    
    def get_average_rating(self, obj):
        """
        Sirf is particular deal ki rating ka average nikalega.
        """
        average = VendorRating.objects.filter(
            order__deal=obj,
            vendor=obj.vendor_kyc
        ).aggregate(avg_rating=Avg('rating'))['avg_rating']
        
        return round(average, 1) if average else 0.0
    
    
class CreateDealDetailSerializer(serializers.ModelSerializer):
    vendor_name = serializers.CharField(source='vendor_kyc.full_name', read_only=True)
    vendor_profile_picture = serializers.CharField(source='vendor_kyc.profile_pic', read_only=True)
    vendor_description = serializers.CharField(source='vendor_kyc.business_description', read_only=True)
    vendor_uuid = serializers.UUIDField(source='vendor_kyc.vendor_id', read_only=True)
    vendor_email = serializers.CharField(source='vendor_kyc.business_email_id', read_only=True)
    vendor_phone_number = serializers.CharField(source='vendor_kyc.phone_number', read_only=True)
    country = serializers.CharField(source='vendor_kyc.country', read_only=True)
    discount_percentage = serializers.SerializerMethodField()
    uploaded_images = serializers.SerializerMethodField()
    average_rating = serializers.SerializerMethodField()
    original_images = serializers.SerializerMethodField()

    class Meta:
        model = CreateDeal
        fields = [
            'vendor_uuid', 'vendor_name', 'vendor_email', 'vendor_phone_number',
            'deal_uuid','uploaded_images', 'original_images', 'deal_post_time', 
            'deal_title', 'deal_description', 'end_date', 'vendor_profile_picture', 'vendor_description', 'category',
            'end_time', 'buy_now', 'actual_price', 'deal_price', 'available_deals',
            'location_house_no', 'location_road_name', 'location_country',
            'location_state', 'location_city', 'location_pincode',
            'vendor_name', 'vendor_uuid', 'country', 'discount_percentage',
            'latitude', 'longitude', 'average_rating'
        ]
        read_only_fields = ['vendor_uuid', 'deal_uuid', 'discount_percentage']

    def get_discount_percentage(self, obj):
        if obj.actual_price and obj.deal_price:
            discount = ((obj.actual_price - obj.deal_price) / obj.actual_price) * 100
            return round(discount, 2)
        return 0

    def get_original_images(self, obj):
        if not obj.uploaded_images or not isinstance(obj.uploaded_images, list):
            return []

        original = [
            image.get("original") for image in obj.uploaded_images if image.get("original")
        ]

        return original
    
    def get_uploaded_images(self, obj):
        """
        Fetch only the uploaded image compressed served via S3/CDN URLs.
        The compressed URLs are directly mapped based on uploaded images.
        """
        # Ensure uploaded_images field is valid
        if not obj.uploaded_images or not isinstance(obj.uploaded_images, list):
            return []

        # Extract only the 'compressed' key from each image entry
        compressed = [
            image.get("compressed") for image in obj.uploaded_images if image.get("compressed")
        ]

        # Return only compressed
        return compressed

    def get_average_rating(self, obj):
        """
        Vendor ki average rating calculate karega jo MyOrders me di gayi hai.
        """
        if obj.vendor_kyc:
            average = VendorRating.objects.filter(vendor=obj.vendor_kyc).aggregate(avg_rating=Avg('rating'))['avg_rating']
            return round(average, 1) if average else 0.0  # Default 0.0 if no ratings
        return 0.0
        
class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            user = User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("This email is not registered.")
        return value
    

    
class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True, validators=[validate_password_strength])
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def save(self, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError("Invalid token.")

        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError("Invalid or expired token.")

        user.set_password(self.validated_data['new_password'])
        user.save()
        
#PlacingOrder
class PlaceOrderSerializer(serializers.ModelSerializer):
    deal_uuid = serializers.UUIDField(write_only=True)  # Allow user to send deal_uuid
    user_id = serializers.UUIDField(source='user.id', read_only=True)
    vendor_id = serializers.UUIDField(source='vendor.vendor_id', read_only=True)
    #transaction_id = serializers.UUIDField(read_only=True)
    created_at = serializers.SerializerMethodField()

    class Meta:
        model = PlaceOrder
        fields = [
            'order_id', 'placeorder_id', 'deal_uuid', 'user_id', 'vendor_id', 'quantity',
            'country', 'latitude', 'longitude', 'total_amount', 'transaction_id',
            'payment_status', 'payment_mode', 'created_at'
        ]
        read_only_fields = ['order_id', 'user_id', 'vendor_id', 'total_amount', 'placeorder_id']

    def get_created_at(self, obj):
        india_tz = pytz.timezone("Asia/Kolkata")
        local_time = localtime(obj.created_at).astimezone(india_tz)
        return local_time.strftime("%Y-%m-%d %H:%M:%S")

    def validate_deal_uuid(self, value):
        try:
            uuid.UUID(str(value))
        except ValueError:
            raise serializers.ValidationError("Must be a valid UUID.")
        return value

    def create(self, validated_data):
        user = self.context['request'].user
        deal_uuid = validated_data.pop('deal_uuid')

        try:
            deal = CreateDeal.objects.get(deal_uuid=deal_uuid)
        except CreateDeal.DoesNotExist:
            raise serializers.ValidationError({"message": "Deal not found"})

        vendor = deal.vendor_kyc
        quantity = validated_data.get('quantity', 1)

        if quantity > deal.available_deals:
            raise serializers.ValidationError({"message": "The ordered quantity exceeds the available deals."})

        total_amount = deal.deal_price * quantity
        payment_status = validated_data.get('payment_status', 'pending')
        transaction_id = validated_data.get('transaction_id') or "default-transaction-id"

        place_order = PlaceOrder.objects.create(
            user=user,
            deal=deal,
            vendor=vendor,
            quantity=quantity,
            country=validated_data.get('country', ''),
            latitude=validated_data.get('latitude', None),
            longitude=validated_data.get('longitude', None),
            total_amount=total_amount,
            transaction_id=transaction_id,
            payment_mode=validated_data.get('payment_mode', ''),
            payment_status=payment_status,
        )

        deal.available_deals -= quantity
        deal.save()

        return place_order


class PlaceOrderDetailsSerializer(serializers.ModelSerializer):
    placeorder_id = serializers.CharField(read_only=True)
    deal_uuid = serializers.UUIDField(source='deal.deal_uuid', format='hex_verbose', read_only=True)
    user_id = serializers.UUIDField(source='user.id', read_only=True)
    vendor_id = serializers.UUIDField(source='vendor.vendor_id', read_only=True)
    vendor_name = serializers.CharField(source='vendor.full_name', read_only=True)
    uploaded_images = serializers.SerializerMethodField()
    created_at = serializers.DateTimeField(format='%Y-%m-%d %H:%M:%S', read_only=True)
    

    class Meta:
        model = PlaceOrder
        fields = [
            'placeorder_id', 'deal_uuid', 'uploaded_images', 'user_id', 'vendor_id', 'vendor_name', 'quantity', 'country',
            'latitude', 'longitude', 'total_amount', 'transaction_id', 'payment_status',
            'payment_mode', 'created_at'
        ]
        read_only_fields = fields
    
    def get_uploaded_images(self, obj):
        """
        Fetch only the uploaded image compressed served via S3/CDN URLs.
        """
        if not obj.deal.uploaded_images or not isinstance(obj.deal.uploaded_images, list):
            return []

        compressed = [
            image.get("compressed") for image in obj.deal.uploaded_images if image.get("compressed")
        ]
        return compressed    


class ServiceCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ServiceCategory
        fields = ['serv_category']
        
class CustomUserDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = [
            'id', 'name', 'bio', 'profile_pic', 'username', 'email', 'phone_number', 'date_of_birth',
            'gender', 'country_code', 'dial_code', 'country', 'social_id'
        ]
        read_only_fields = fields
    
    def to_representation(self, instance):
        # Call the default `to_representation` to get the serialized data
        data = super().to_representation(instance)

        # Modify the `profile_pic` field to return "" if it's empty or null
        if not instance.profile_pic:
            data['profile_pic'] = ""

        return data
    
class CustomUserEditSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = [
            'name', 
            'username', 
            'email', 
            'phone_number', 
            'gender', 
            'date_of_birth', 
            'bio', 
            'profile_pic',
            'dial_code',
        ]
        extra_kwargs = {
            'email': {'required': True},  # Ensure email is mandatory during updates
            'username': {'required': True},  # Ensure username is mandatory
        }

    def validate_name(self, value):
        if not re.match(r'^[A-Za-z ]+$', value):
            raise serializers.ValidationError("Name can only contain letters and spaces.")
        return value

    def validate_username(self, value):
        if not re.match(r'^[a-z0-9._]{8,}$', value):
            raise serializers.ValidationError("Username can only contain letters and numbers.")
        if len(value) < 6:
            raise serializers.ValidationError("Username must be at least 6 characters long.")
        return value

    def validate_email(self, value):
        user = self.context['request'].user
        if CustomUser.objects.exclude(id=user.id).filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use.")
        return value

        
        
class PlaceOrderListsSerializer(serializers.ModelSerializer):
    placeorder_id = serializers.CharField(read_only=True)
    deal_uuid = serializers.UUIDField(source='deal.deal_uuid', format='hex_verbose', read_only=True)
    user_id = serializers.UUIDField(source='user.id', read_only=True)
    vendor_id = serializers.UUIDField(source='vendor.vendor_id', read_only=True)
    vendor_name = serializers.CharField(source='vendor.full_name', read_only=True)
    deal_title = serializers.CharField(source='deal.deal_title', read_only=True)
    deal_price = serializers.CharField(source='deal.deal_price', read_only=True)
    deal_description = serializers.CharField(source='deal.deal_description', read_only=True)
    uploaded_images = serializers.SerializerMethodField()
    created_at = serializers.DateTimeField(format='%Y-%m-%d %H:%M:%S', read_only=True) 

    class Meta:
        model = PlaceOrder
        fields = [
            'placeorder_id', 'deal_uuid', 'uploaded_images', 'deal_title', 'deal_price', 'deal_description', 'user_id', 'vendor_id', 'vendor_name', 'quantity', 'country',
            'latitude', 'longitude', 'total_amount', 'transaction_id', 'payment_status',
            'payment_mode', 'created_at'
        ]
        read_only_fields = fields

    def get_uploaded_images(self, obj):
        """
        Fetch only the first image thumbnail from the uploaded_images of the deal.
        """
        if not obj.deal.uploaded_images or not isinstance(obj.deal.uploaded_images, list):
            return []
        
        first_image = obj.deal.uploaded_images[0]  # Get the first image
        thumbnail = first_image.get("thumbnail") if first_image else None  # Extract its thumbnail
        return [thumbnail] if thumbnail else []
    
    def get_created_at(self, obj):
        india_tz = pytz.timezone("Asia/Kolkata")
        local_time = localtime(obj.created_at).astimezone(india_tz)
        return local_time.strftime("%Y-%m-%d %H:%M:%S")
    
class OTPRequestSerializer(serializers.Serializer):
    phone_number = serializers.CharField(max_length=15)

    def validate_phone_number(self, value):
        if not CustomUser.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError("No user found with this phone number.")
        return value

class OTPResetPasswordSerializer(serializers.Serializer):
    phone_number = serializers.CharField(max_length=15)
    otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True, validators=[validate_password_strength])
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")

        phone_number = data.get('phone_number')
        otp = data.get('otp')

        try:
            user = User.objects.get(phone_number=phone_number)
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this phone number does not exist.")

        try:
            otp_entry = PasswordResetOTP.objects.get(user=user, otp=otp)
        except PasswordResetOTP.DoesNotExist:
            raise serializers.ValidationError("Invalid OTP.")

        if otp_entry.is_expired():
            raise serializers.ValidationError("OTP has expired.")

        data['user'] = user
        data['otp_entry'] = otp_entry
        return data

    def save(self):
        user = self.validated_data['user']
        otp_entry = self.validated_data['otp_entry']
        new_password = self.validated_data['new_password']

        user.set_password(new_password)
        user.save()

        otp_entry.delete()


class OTPValidationSerializer(serializers.Serializer):
    phone_number = serializers.CharField(max_length=15)
    otp = serializers.CharField(max_length=6)

    def validate(self, data):
        phone_number = data.get('phone_number')
        otp = data.get('otp')

        try:
            user = User.objects.get(phone_number=phone_number)
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this phone number does not exist.")

        try:
            otp_entry = PasswordResetOTP.objects.get(user=user, otp=otp)
        except PasswordResetOTP.DoesNotExist:
            raise serializers.ValidationError("Invalid OTP.")

        if otp_entry.is_expired() or otp_entry.used:
            raise serializers.ValidationError("OTP has expired or already used.")

        otp_entry.used = True
        otp_entry.save()

        data['message'] = "OTP is valid. Proceed to reset your password."
        return data
    
class MyActivitysSerializer(serializers.ModelSerializer):
    user_id = serializers.UUIDField(source='created_by.id', read_only=True)
    created_by = serializers.CharField(source='created_by.username') 
    uploaded_images = serializers.SerializerMethodField()
    created_at = serializers.SerializerMethodField()
    is_accepted = serializers.SerializerMethodField()
    is_rejected = serializers.SerializerMethodField()
    chat_room_id = serializers.SerializerMethodField()
    original_images = serializers.SerializerMethodField()

    class Meta:
        model = Activity
        fields = ['activity_id', 'user_id', 'activity_title','uploaded_images', 'activity_description', 'created_by', 'user_participation', 'maximum_participants', 'infinite_time', 'category',
                  'end_date', 'end_time', 'latitude', 'longitude', 'created_by',
                  'location', 'created_at', 'is_accepted', 'is_rejected', 'chat_room_id',
                  'original_images'
                  ]
        
    def get_created_at(self, obj):
        if obj.created_at:
            return obj.created_at.strftime('%Y-%m-%d %H:%M:%S')
        return None
        
    def get_uploaded_images(self, obj):
        """
        Fetch only the first image thumbnail from uploaded_images.
        This ensures only the first uploaded image's thumbnail is fetched.
        """
        # Ensure uploaded_images field is valid and has data
        if not obj.uploaded_images or not isinstance(obj.uploaded_images, list):
            return []

        # Return only the thumbnail of the first image in the uploaded_images list
        first_image = obj.uploaded_images[0]  # Get the first image
        thumbnail = first_image.get("thumbnail") if first_image else None  # Extract its thumbnail
        return [thumbnail] if thumbnail else []

    def get_original_images(self, obj):
        """
        Fetch only the first image thumbnail from uploaded_images.
        This ensures only the first uploaded image's thumbnail is fetched.
        """
        # Ensure uploaded_images field is valid and has data
        if not obj.uploaded_images or not isinstance(obj.uploaded_images, list):
            return []

        # Return only the thumbnail of the first image in the uploaded_images list
        first_image = obj.uploaded_images[0]  # Get the first image
        original = first_image.get("original") if first_image else None  # Extract its thumbnail
        return [original] if original else []
    
    def get_is_accepted(self, obj):
        request = self.context.get('request', None)
        user = getattr(request, 'user', None) if request else None
        if not user or not user.is_authenticated:
            return None
        # Latest chat request lena, old nahi
        chat_request = ChatRequest.objects.filter(activity=obj, from_user=user).order_by('-created_at').first()
        return chat_request.is_accepted if chat_request else None

    def get_is_rejected(self, obj):
        request = self.context.get('request', None)
        user = getattr(request, 'user', None) if request else None
        if not user or not user.is_authenticated:
            return None
        # Latest chat request lena, old nahi
        chat_request = ChatRequest.objects.filter(activity=obj, from_user=user).order_by('-created_at').first()
        return chat_request.is_rejected if chat_request else None


    def get_chat_room_id(self, obj):
        request = self.context.get('request', None)
        user = getattr(request, 'user', None) if request else None
        if not user or not user.is_authenticated:
            return None
        chat_request = ChatRequest.objects.filter(activity=obj, from_user=user, is_accepted=True).first()
        if chat_request:
            chat_room = ChatRoom.objects.filter(activity=obj, participants=user).first()
            return str(chat_room.id) if chat_room else None
        return None

class MyDealSerializer(serializers.ModelSerializer):
    vendor_name = serializers.CharField(source='vendor_kyc.full_name', read_only=True)
    vendor_uuid = serializers.UUIDField(source='vendor_kyc.vendor_id', read_only=True)
    country = serializers.CharField(source='vendor_kyc.country', read_only=True)
    discount_percentage = serializers.SerializerMethodField()
    deal_post_time = serializers.SerializerMethodField()
    uploaded_images = serializers.SerializerMethodField()
    view_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = CreateDeal
        fields = [
            'deal_uuid', 'deal_post_time', 'deal_title',
            'uploaded_images', 'end_date', 'end_time',
            'actual_price', 'deal_price', 'available_deals',
            'location_house_no', 'location_road_name', 'location_country',
            'location_state', 'location_city', 'location_pincode',
            'vendor_name', 'vendor_uuid', 'country',
            'discount_percentage', 'latitude', 'longitude', 'view_count'
        ]

    def to_representation(self, instance):
        """
        Custom representation method to ensure `view_count` is retained in history.
        """
        data = super().to_representation(instance)

        # Ensure view_count is always included, whether the deal is live or expired
        return data

    def get_discount_percentage(self, obj):
        if obj.actual_price > 0:
            discount = ((obj.actual_price - obj.deal_price) / obj.actual_price) * 100
            return round(discount, 2)
        return 0.0

    def get_deal_post_time(self, obj):
        if obj.deal_post_time:
            return obj.deal_post_time.strftime('%Y-%m-%d %H:%M:%S')
        return None
    
    def get_uploaded_images(self, obj):
        """
        Fetch only the first image thumbnail from uploaded_images.
        This ensures only the first uploaded image's thumbnail is fetched.
        """
        if not obj.uploaded_images or not isinstance(obj.uploaded_images, list):
            return []

        first_image = obj.uploaded_images[0]  # Get the first image
        thumbnail = first_image.get("thumbnail") if first_image else None  # Extract its thumbnail
        return [thumbnail] if thumbnail else []
    
class FavoriteVendorSerializer(serializers.ModelSerializer):
    vendor_name = serializers.CharField(source='vendor.full_name', read_only=True)

    class Meta:
        model = FavoriteVendor
        fields = ['id', 'vendor', 'vendor_name', 'added_at']
        
class FavoriteVendorsListSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(source='vendor.full_name', read_only=True)
    user = serializers.UUIDField(source='user.id', read_only=True)
    services = serializers.SerializerMethodField()
    addresses = serializers.SerializerMethodField()
    uploaded_images = serializers.SerializerMethodField()
    is_favorite = serializers.SerializerMethodField()

    # Add phone_number and business_email_id fields
    phone_number = serializers.CharField(source='vendor.phone_number', read_only=True)
    business_email_id = serializers.EmailField(source='vendor.business_email_id', read_only=True)
    profile_pic = serializers.SerializerMethodField()
    
    class Meta:
        model = FavoriteVendor  # Assuming FavoriteVendor links to VendorKYC
        fields = [
            'profile_pic', 'full_name', 'phone_number', 'business_email_id', 'vendor_id', 'user',
            'uploaded_images', 'services', 'addresses',
            'is_favorite'
        ]

    def get_profile_pic(self, obj):
        return obj.vendor.profile_pic

    
    def get_services(self, obj):
        services = obj.vendor.services.all()  # Assuming 'vendor' is the related field to VendorKYC
        return ServiceSerializer(services, many=True).data

    def get_addresses(self, obj):
        addresses = obj.vendor.addresses.all()  # Assuming 'vendor' is the related field
        return AddressSerializer(addresses, many=True).data

    def get_uploaded_images(self, obj):
        uploaded_images = obj.vendor.uploaded_images  # Fetching from related vendor
        if not uploaded_images or not isinstance(uploaded_images, list):
            return []
        images = [
            {
                "compressed": image.get("compressed"),
                "thumbnail": image.get("thumbnail")
            }
            for image in uploaded_images
            if image.get("compressed") and image.get("thumbnail")
        ]
        return images

    def get_is_favorite(self, obj):
        user = self.context.get('request').user
        if user.is_authenticated:
            return FavoriteVendor.objects.filter(user=user, vendor=obj.vendor).exists()
        return False





# For Upswap Web App Version:
class SuperadminLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get("email")
        password = data.get("password")

        # Authenticate User
        user = authenticate(email=email, password=password)

        if not user:
            raise AuthenticationFailed("Invalid email or password.")

        if not user.is_superuser:
            raise AuthenticationFailed("Access denied. Superadmin only.")

        data["user"] = user
        return data
    
class VendorRatingSerializer(serializers.ModelSerializer):
    placeorder_id = serializers.CharField(source='order.placeorder_id', read_only=True)
    rating_id = serializers.UUIDField(read_only=True)
    user_id = serializers.UUIDField(source='user.id', read_only=True)
    vendor_id = serializers.UUIDField(source='vendor.vendor_id', read_only=True)
    #order_id = serializers.UUIDField(source='order.order_id', read_only=True)

    class Meta:
        model = VendorRating
        fields = ['placeorder_id', 'rating_id', 'user_id', 'vendor_id', 'rating', 'created_at']
        read_only_fields = ['rating_id', 'user_id', 'vendor_id', 'order_id', 'created_at']

    def validate_rating(self, value):
        """ Ensure rating is a valid Decimal. """
        if isinstance(value, float):  
            value = Decimal(str(value))
        return value

    def validate(self, data):
        request = self.context['request']
        user = request.user

        # Ensure order_id is passed in request
        placeorder_id = request.parser_context['kwargs'].get('placeorder_id')
        if not placeorder_id:
            raise serializers.ValidationError("PlaceOrder ID is required.")

        # Fetch order from DB
        try:
            order = PlaceOrder.objects.get(placeorder_id=placeorder_id, user=user)
        except PlaceOrder.DoesNotExist:
            raise serializers.ValidationError("You are not authorized to rate this order.")

        # Check if rating already exists
        if VendorRating.objects.filter(user=user, order=order).exists():
            raise serializers.ValidationError("You have already rated this order.")

        return data

    
class RaiseAnIssueSerializerMyOrders(serializers.ModelSerializer):
    place_order = serializers.SlugRelatedField(
        queryset=PlaceOrder.objects.all(), 
        slug_field="placeorder_id"  # placeorder_id ko map karega
    )
    
    class Meta:
        model = RaiseAnIssueMyOrders
        fields = ["issue_id", "user", "place_order", "subject", "describe_your_issue", "choose_files", "created_at"]
        read_only_fields = ["issue_id", "user", "created_at"]  # Ye fields user edit nahi kar sakta

    def create(self, validated_data):
        request = self.context.get('request')  # Request object access karein
        if request and hasattr(request, "user"):
            validated_data["user"] = request.user  # User ko manually set karein
        return RaiseAnIssueMyOrders.objects.create(**validated_data)

class RaiseAnIssueVendorsSerializer(serializers.ModelSerializer):
    class Meta:
        model = RaiseAnIssueVendors
        fields = ['issue_uuid', 'user', 'vendor', 'subject', 'describe_your_issue', 'choose_files', 'created_at']
        read_only_fields = ['issue_uuid', 'user', 'created_at', 'vendor']
        
class RaiseAnIssueCustomUserSerializer(serializers.ModelSerializer):
    against_user_details = serializers.SerializerMethodField()

    class Meta:
        model = RaiseAnIssueCustomUser
        fields = [
            "issue_id",
            "raised_by",
            "against_user",
            "activity",
            "subject",
            "describe_your_issue",
            "choose_files",
            "created_at",
            "against_user_details",
        ]
        
        read_only_fields = ['against_user', 'activity']
        
        extra_kwargs = {
            "raised_by": {"read_only": True},
        }

    def get_against_user_details(self, obj):
        user = obj.against_user
        return {
            "name": user.name,
            "username": user.username,
            "gender": user.gender,
            "bio": user.bio,
        }
        
        
class ActivityRepostSerializer(serializers.ModelSerializer):
    activity_category = ActivityCategorySerializer(read_only=True)
    start_date = serializers.DateField(required=True)
    start_time = serializers.TimeField(required=True)
    end_date = serializers.DateField(required=True)
    end_time = serializers.TimeField(required=True)

    class Meta:
        model = Activity
        fields = [
            'activity_id', 'activity_title', 'activity_description', 'activity_category',
            'uploaded_images', 'user_participation', 'maximum_participants', 'start_date',
            'end_date', 'start_time', 'end_time', 'location', 'latitude', 'longitude', 'infinite_time'
        ]
        read_only_fields = ['activity_id', 'created_by', 'created_at']

    def validate(self, data):
        start_date = data.get('start_date')
        start_time = data.get('start_time')
        end_date = data.get('end_date')
        end_time = data.get('end_time')

        # End date aur time start date aur time se pehle nahi hona chahiye
        if end_date < start_date:
            raise serializers.ValidationError({"message": "End date cannot be before start date."})
        if end_date == start_date and end_time <= start_time:
            raise serializers.ValidationError({"message": "End time cannot be before start time."})

        return data
    
class MySalesSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source='user.username', read_only=True)
    user_id = serializers.UUIDField(source='user.id', read_only=True)
    created_at = serializers.SerializerMethodField()
    uploaded_images = serializers.SerializerMethodField()

    class Meta:
        model = PlaceOrder
        fields = [
            'user_name', 'uploaded_images', 'user_id', 'quantity', 'total_amount', 'created_at',
            'payment_mode', 'transaction_id', 'country', 'latitude', 'longitude'
        ]
        
    def get_uploaded_images(self, obj):
        """
        Fetch only the first image thumbnail from the uploaded_images of the deal.
        """
        if not obj.deal.uploaded_images or not isinstance(obj.deal.uploaded_images, list):
            return []
        
        first_image = obj.deal.uploaded_images[0]  # Get the first image
        thumbnail = first_image.get("thumbnail") if first_image else None  # Extract its thumbnail
        return [thumbnail] if thumbnail else []

    def get_created_at(self, obj):
        india_tz = pytz.timezone("Asia/Kolkata")
        local_time = localtime(obj.created_at).astimezone(india_tz)
        return local_time.strftime("%Y-%m-%d %H:%M:%S")

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = '__all__'
        extra_fields = ['chat_request']

    def get_chat_request(self, obj):
        if obj.reference_type == 'chatrequest':
            try:
                chat_request = ChatRequest.objects.get(id=obj.reference_id)
                return ChatRequestSerializer(chat_request).data  # Or use model fields manually
            except ChatRequest.DoesNotExist:
                return None
        return None

class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = '__all__'
        
class ServiceCreateSerializer(serializers.Serializer):
    service_category = serializers.CharField()
    item_name = serializers.CharField()
    item_description = serializers.CharField()
    item_price = serializers.DecimalField(max_digits=10, decimal_places=2)

    def create(self, validated_data):
        vendor_kyc = self.context['vendor_kyc']
        category_name = validated_data.pop('service_category')
        category_obj, created = ServiceCategory.objects.get_or_create(serv_category=category_name)

        return Service.objects.create(
            vendor_kyc=vendor_kyc,
            service_category=category_obj,
            **validated_data
        )

from appointments.serializers import ServiceNameSerializer
class GetVendorSerializer(serializers.ModelSerializer):
    profile_pic = serializers.SerializerMethodField()
    ven_services = ServiceNameSerializer(many=True, read_only=True)
    addresses = AddressSerializer(many=True, read_only=True)
    
    class Meta:
        model = VendorKYC
        fields = ['full_name', 'vendor_id', 'business_description', 'profile_pic', 'ven_services', 'addresses']
    
    def get_profile_pic(self, obj):
        return obj.profile_pic if obj.profile_pic else ""

class RegisterSerializerV2(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    email = serializers.EmailField()
    name = serializers.CharField(max_length=255)
    phone_number = serializers.CharField(max_length=15)
    password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, min_length=8)

    country_code = serializers.CharField(max_length=10, required=False, allow_blank=True)
    dial_code = serializers.CharField(max_length=10, required=False, allow_blank=True)
    country = serializers.CharField(max_length=100, required=False, allow_blank=True)
    date_of_birth = serializers.DateField()
    gender = serializers.ChoiceField(choices=CustomUser.GENDER_CHOICES)

    latitude = serializers.DecimalField(max_digits=9, decimal_places=6, required=False, allow_null=True)
    longitude = serializers.DecimalField(max_digits=9, decimal_places=6, required=False, allow_null=True)

    def validate(self, data):
        if data.get('password') != data.get('confirm_password'):
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
        return data

    def create(self, validated_data):
        validated_data.pop('confirm_password')  # remove before saving
        return validated_data  # just return cleaned data for caching