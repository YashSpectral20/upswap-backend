import json
import uuid
import io
import os
import base64
import boto3
import datetime as dt
from PIL import Image
from rest_framework import serializers
from urllib.parse import urlparse
from decimal import Decimal
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model, authenticate
from django.utils import timezone
from .models import (
    CustomUser, OTP, Activity, ChatRoom, ChatMessage,
    ChatRequest, PasswordResetOTP, VendorKYC, Address, Service, CreateDeal, PlaceOrder,
    ActivityCategory, ServiceCategory, FavoriteVendor, VendorRating, RaiseAnIssueMyOrders
)
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
        fields = ['id', 'name', 'username', 'email', 'phone_number', 'date_of_birth', 'gender', 'password', 'confirm_password', 'country_code', 'dial_code', 'country', 'social_id', 'type', 'fcm_token', 'latitude', 'longitude']
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

        # Check if the OTP is correct and not expired
        try:
            otp_instance = OTP.objects.get(user=user, otp=otp, is_verified=False)
            if otp_instance.is_expired():
                raise serializers.ValidationError("OTP has expired.")
        except OTP.DoesNotExist:
            raise serializers.ValidationError("Invalid OTP.")

        # Mark the OTP as verified
        otp_instance.is_verified = True
        otp_instance.save()

        # Generate new JWT tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        # Return the tokens and a success message
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
        email = data.get('email')
        password = data.get('password')
        user = authenticate(email=email, password=password)
        if user is None:
            raise serializers.ValidationError('Invalid credentials')
        
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
    set_current_datetime = serializers.BooleanField(write_only=True, required=False, default=False)
    infinite_time = serializers.BooleanField(write_only=True, required=False, default=True)
    location = serializers.CharField(required=False, allow_blank=True)  # Add location field
    latitude = serializers.FloatField(required=False, allow_null=True)  # Add latitude field
    longitude = serializers.FloatField(required=False, allow_null=True)  # Add longitude field
    uploaded_images = serializers.ListField(
        child=serializers.DictField(
            child=serializers.URLField(),
            required=True
        ),
        required=False
    )
    activity_category = serializers.CharField(required=False)

    class Meta:
        model = Activity
        fields = [
            'activity_id', 'activity_title', 'activity_description',
            'activity_category', 'uploaded_images', 'user_participation', 'maximum_participants',
            'start_date', 'end_date', 'start_time', 'end_time', 'created_at',
            'created_by', 'set_current_datetime', 'infinite_time',
            'location', 'latitude', 'longitude'
        ]
        read_only_fields = ['created_by', 'created_at']
        
        
    def validate_activity_category(self, value):
        try:
            return ActivityCategory.objects.get(actv_category__iexact=value)
        except ActivityCategory.DoesNotExist:
            raise serializers.ValidationError(f"Activity category '{value}' does not exist.")

    def create(self, validated_data):
        validated_data['activity_category'] = validated_data.pop('activity_category', None)
        return super().create(validated_data)

    def update(self, instance, validated_data):
        if 'activity_category' in validated_data:
            validated_data['activity_category'] = validated_data.pop('activity_category', None)
        return super().update(instance, validated_data)

    def validate(self, data):
        now = timezone.now().date()

        # Ensure user_participation is set to True by default
        data['user_participation'] = data.get('user_participation', True)

        # Skip validation for date and time when flags are set
        set_current_datetime = data.get('set_current_datetime', False)
        infinite_time = data.get('infinite_time', False)

        if not set_current_datetime and not infinite_time:
            # Date and time validations
            if data.get('start_date') and data['start_date'] < now:
                raise serializers.ValidationError({"start_date": "Start date cannot be in the past."})
            if data.get('end_date') and data['end_date'] < now:
                raise serializers.ValidationError({"end_date": "End date cannot be in the past."})
            if data.get('start_date') and data.get('end_date') and data['end_date'] < data['start_date']:
                raise serializers.ValidationError({"end_date": "End date must be after start date."})
            if data.get('start_time') and data.get('end_time') and data['end_time'] <= data['start_time']:
                raise serializers.ValidationError({"end_time": "End time must be after start time."})

        # Validate maximum participants
        if data.get('maximum_participants') and data['maximum_participants'] > 1000:
            raise serializers.ValidationError({"maximum_participants": "Maximum participants cannot exceed 1000."})

        # Automatically set maximum participants to 0 if user participation is disabled
        if not data.get('user_participation', True):
            data['maximum_participants'] = 0

        return data

    def create(self, validated_data):
        # Extract uploaded_images
        uploaded_images = validated_data.pop('uploaded_images', [])

        # Assign the created_by field
        validated_data['created_by'] = self.context['request'].user

        # Preserve user-provided values
        start_date = validated_data.get('start_date')
        start_time = validated_data.get('start_time')
        end_date = validated_data.get('end_date')
        end_time = validated_data.get('end_time')

        if validated_data.pop('set_current_datetime', False) and not (start_date or start_time):
            current_datetime = timezone.now()
            validated_data['start_date'] = current_datetime.date()
            validated_data['start_time'] = current_datetime.time()

        if validated_data.pop('infinite_time', False) and not (end_date or end_time):
            future_date = timezone.now() + timezone.timedelta(days=365 * 999)  # 999 years from now
            validated_data['end_date'] = future_date.date()
            validated_data['end_time'] = future_date.time()

        # Create activity
        activity = super().create(validated_data)

        # Save uploaded_images metadata
        if uploaded_images:
            activity.uploaded_images = uploaded_images
            activity.save()

        return activity


    def update(self, instance, validated_data):
        # Handle updates for datetime and infinite time
        if validated_data.pop('set_current_datetime', False):
            current_datetime = timezone.now()
            validated_data['start_date'] = current_datetime.date()
            validated_data['start_time'] = current_datetime.time()

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
    



        
class ActivityListsSerializer(serializers.ModelSerializer):
    user_id = serializers.UUIDField(source='created_by.id', read_only=True)
    created_by = serializers.CharField(source='created_by.username')  # Assuming `created_by` refers to CustomUser
    activity_category = ActivityCategorySerializer(required=True)
    uploaded_images = serializers.SerializerMethodField()

    class Meta:
        model = Activity
        fields = ['activity_id', 'user_id', 'activity_title','uploaded_images','activity_category', 'created_by', 'user_participation', 'infinite_time', 'activity_category',
                  'start_date', 'start_time', 'end_date', 'end_time', 'latitude', 'longitude', 'created_by',
                  'location']
        
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



class ActivityDetailsSerializer(serializers.ModelSerializer):
    user_id = serializers.UUIDField(source='created_by.id', read_only=True)
    created_by = serializers.CharField(source='created_by.username')  # Assuming `created_by` refers to CustomUser
    activity_category = ActivityCategorySerializer(required=True)
    uploaded_images = serializers.SerializerMethodField()
    
    class Meta:
        model = Activity
        fields = [
            'activity_id', 'user_id', 'activity_title', 'activity_description',
            'activity_category', 'uploaded_images', 'user_participation', 'maximum_participants',
            'start_date', 'end_date', 'start_time', 'end_time', 'created_at',
            'created_by', 'set_current_datetime', 'infinite_time',
            'location', 'latitude', 'longitude'
        ]
        read_only_fields = ['created_by', 'created_at']
        
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

class ChatRoomSerializer(serializers.ModelSerializer):
    participants = serializers.SlugRelatedField(
        many=True,
        slug_field='email',
        queryset=CustomUser.objects.all()
    )

    class Meta:
        model = ChatRoom
        fields = ['id', 'activity', 'participants', 'created_at']
        read_only_fields = ['id', 'created_at']

    def create(self, validated_data):
        participants_data = validated_data.pop('participants', [])
        
        chat_room = ChatRoom.objects.create(**validated_data)
        chat_room.participants.set(participants_data)
        
        return chat_room

class ChatMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatMessage
        fields = ['id', 'chat_room', 'sender', 'content', 'created_at']

class ChatRequestSerializer(serializers.ModelSerializer):
    activity = serializers.PrimaryKeyRelatedField(queryset=Activity.objects.all())
    from_user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    to_user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())

    class Meta:
        model = ChatRequest
        fields = ['id', 'activity', 'from_user', 'to_user', 'is_accepted', 'is_rejected', 'interested']

    def validate(self, attrs):
        if attrs.get('is_accepted') and attrs.get('is_rejected'):
            raise serializers.ValidationError("A chat request cannot be both accepted and rejected.")
        return attrs






class AddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = Address
        fields = ['uuid', 'house_no_building_name', 'road_name_area_colony', 'country', 
                  'state', 'city', 'pincode', 'latitude', 'longitude']
        read_only_fields = ['uuid']


class ServiceSerializer(serializers.ModelSerializer):
    service_category = serializers.CharField()  # Accept category name as a string

    class Meta:
        model = Service
        fields = ['uuid', 'item_name', 'service_category', 'item_description', 'item_price']
        read_only_fields = ['uuid']

    def validate_service_category(self, value):
        """
        Validate and convert the string input to a ServiceCategory instance.
        """
        if isinstance(value, str):
            # Get or create the ServiceCategory instance by name
            service_category, created = ServiceCategory.objects.get_or_create(serv_category=value)
            return service_category
        raise serializers.ValidationError("Invalid value for service_category. Expected a string.")

    def create(self, validated_data):
        # `service_category` is now a `ServiceCategory` instance
        return super().create(validated_data)
        
        
class VendorKYCSerializer(serializers.ModelSerializer):
    profile_pic = serializers.JSONField(required=False)
    uploaded_business_documents = serializers.ListField(
        child=serializers.URLField(),
        required=False,
        allow_empty=True
    )
    uploaded_images = serializers.ListField(
        child=serializers.DictField(
            child=serializers.URLField()
        ),
        required=False,
        allow_empty=True
    )
    business_hours = serializers.JSONField(required=False, allow_null=True)
    addresses = AddressSerializer(many=True, required=False)
    services = ServiceSerializer(many=True, required=True)  # Updated to include services correctly

    class Meta:
        model = VendorKYC
        fields = [
            'vendor_id', 'profile_pic', 'user', 'full_name', 'phone_number', 
            'business_email_id', 'business_establishment_year', 'business_description', 
            'uploaded_business_documents', 
            'uploaded_images', 'same_as_personal_phone_number', 
            'same_as_personal_email_id', 'addresses',  # Include addresses field
            'country_code', 'dial_code', 
            'bank_account_number', 
            'retype_bank_account_number', 'bank_name', 'ifsc_code', 
            'services', 'business_hours', 'is_approved', 'latitude', 'longitude'  # Ensure 'is_approved' is included here
        ]

    def validate_business_hours(self, value):
        if not isinstance(value, list):
            raise serializers.ValidationError("Business hours must be a list.")
        for item in value:
            if not isinstance(item, dict) or 'day' not in item or 'time' not in item:
                raise serializers.ValidationError("Each business hour entry must be a dictionary with 'day' and 'time'.")
        return value

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

    def create(self, validated_data):
        addresses_data = validated_data.pop('addresses', [])
        services_data = validated_data.pop('services', [])
        uploaded_documents = validated_data.pop('uploaded_business_documents', [])

        # Create the VendorKYC instance
        vendor_kyc = VendorKYC.objects.create(**validated_data)

        # Handle addresses and services
        self.handle_addresses_and_services(vendor_kyc, addresses_data, services_data)

        # Add uploaded business documents
        if uploaded_documents:
            vendor_kyc.uploaded_business_documents = uploaded_documents
            vendor_kyc.save()

        return vendor_kyc

    def update(self, instance, validated_data):
        addresses_data = validated_data.pop('addresses', None)
        services_data = validated_data.pop('services', None)
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
        self.handle_addresses_and_services(instance, addresses_data, services_data)

        # Update uploaded business documents
        if uploaded_documents:
            instance.uploaded_business_documents = uploaded_documents

        instance.save()
        return instance

    def handle_addresses_and_services(self, instance, addresses_data, services_data):
        if addresses_data is not None:
            # Clear existing addresses
            instance.addresses.all().delete()
            # Add new addresses
            for address_data in addresses_data:
                Address.objects.create(vendor=instance, **address_data)

        if services_data is not None:
            # Delete existing services
            instance.services.all().delete()
            # Add new services
            for service_data in services_data:
                Service.objects.create(vendor_kyc=instance, **service_data)

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['services'] = ServiceSerializer(instance.services.all(), many=True).data
        representation['addresses'] = AddressSerializer(instance.addresses.all(), many=True).data
        representation['is_approved'] = instance.is_approved
        return representation

    
    

class VendorKYCListSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(source='user.name', read_only=True)
    user = serializers.UUIDField(source='user.id', read_only=True)
    services = serializers.SerializerMethodField()
    addresses = serializers.SerializerMethodField()
    uploaded_images = serializers.SerializerMethodField()
    is_favorite = serializers.SerializerMethodField()
    average_rating = serializers.SerializerMethodField()
    
    class Meta:
        model = VendorKYC
        fields = ['profile_pic', 'full_name', 'vendor_id', 'user', 'uploaded_images', 'services', 'addresses', 'is_favorite', 'average_rating']

    def get_services(self, obj):
        # Assuming 'services' is a related field in the VendorKYC model
        services = obj.services.all()  # Fetch related services
        return ServiceSerializer(services, many=True).data

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
    
    def get_is_favorite(self, obj):
        user = self.context.get('request').user
        if user.is_authenticated:
            # Check if this vendor is favorited by the logged-in user
            favorite_vendor = FavoriteVendor.objects.filter(user=user, vendor=obj).exists()
            return favorite_vendor
        return False  # If user is not authenticated, return False
    
    def get_average_rating(self, obj):
        average = VendorRating.objects.filter(vendor=obj).aggregate(avg_rating=Avg('rating'))['avg_rating']
        return round(average, 1) if average else 0.0


        

class VendorKYCDetailSerializer(serializers.ModelSerializer):
    # Include related fields for addresses, services, business documents, and photos
    addresses = AddressSerializer(many=True, read_only=True)
    services = ServiceSerializer(many=True, read_only=True)

    # Handling the business related documents and photos as lists of strings
    uploaded_business_documents = serializers.SerializerMethodField()
    uploaded_images = serializers.SerializerMethodField()
    
    business_hours = serializers.JSONField(required=False, allow_null=True)

    class Meta:
        model = VendorKYC
        fields = [
            'vendor_id', 'profile_pic', 'user', 'full_name', 'phone_number', 'business_email_id',
            'business_establishment_year', 'business_description', 'uploaded_business_documents',
            'uploaded_images', 'same_as_personal_phone_number', 
            'same_as_personal_email_id', 'addresses', 'country_code', 'dial_code', 
            'bank_account_number', 'retype_bank_account_number', 'bank_name', 'ifsc_code',
            'services', 'business_hours', 'is_approved'
        ]
        read_only_fields = ['user', 'is_approved']  # Keep read-only fields to avoid updates during detail fetching

    def to_representation(self, instance):
        """
        Customize the representation of the VendorKYC instance
        to include nested relationships like addresses and services,
        and business-related documents and photos.
        """
        representation = super().to_representation(instance)
        # Format services and addresses for response
        representation['services'] = ServiceSerializer(instance.services.all(), many=True).data
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
        
class VendorKYCStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = VendorKYC
        fields = ['vendor_id', 'is_approved']
    
    

class CreateDealSerializer(serializers.ModelSerializer):
    vendor_name = serializers.CharField(source='vendor_kyc.full_name', read_only=True)
    vendor_uuid = serializers.UUIDField(source='vendor_kyc.vendor_id', read_only=True)
    actual_price = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
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
    

    class Meta:
        model = CreateDeal
        fields = [
            'deal_uuid', 'deal_title', 'deal_description', 'select_service',
            'uploaded_images', 'start_date', 'end_date', 'start_time', 'end_time',
            'start_now', 'actual_price', 'deal_price', 'available_deals',
            'location_house_no', 'location_road_name', 'location_country',
            'location_state', 'location_city', 'location_pincode', 'vendor_kyc',
            'vendor_name', 'vendor_uuid', 'vendor_email', 'vendor_number',
            'discount_percentage', 'latitude', 'longitude'
        ]
        read_only_fields = ['deal_uuid', 'discount_percentage', 'actual_price']

    def get_discount_percentage(self, obj):
        if obj.actual_price and obj.deal_price:
            discount = ((obj.actual_price - obj.deal_price) / obj.actual_price) * 100
            return round(discount, 2)
        return 0

    def validate(self, data):
        """ Validate select_service and address fields, ensure they are provided manually. """
        vendor_kyc = data.get('vendor_kyc')
        select_service = data.get('select_service')

        # Check if the 'select_service' field is provided
        if not select_service:
            raise serializers.ValidationError("First provide Select Service.")

        # Fetch the service corresponding to 'select_service' and retrieve the item_price
        try:
            service = vendor_kyc.services.get(item_name=select_service)
            data['actual_price'] = service.item_price  # Fetch the price from the Service model
        except Service.DoesNotExist:
            raise serializers.ValidationError("Selected service does not exist for the vendor.")

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
        """Validate that end_date and end_time are after start_date and start_time."""
        start_date = data.get('start_date')
        start_time = data.get('start_time')
        end_date = data.get('end_date')
        end_time = data.get('end_time')
        start_now = data.get('start_now', False)

        # Ensure that end_date and end_time are after start_date and start_time
        if start_date and end_date and start_date > end_date:
            raise serializers.ValidationError({
                'end_date': "End date cannot be before start date."
            })
        if start_date and start_time and end_date and end_time:
            # Combine dates and times into full datetime objects
            start_datetime = timezone.make_aware(dt.datetime.combine(start_date, start_time))
            end_datetime = timezone.make_aware(dt.datetime.combine(end_date, end_time))
            if start_datetime > end_datetime:
                raise serializers.ValidationError({
                    'end_time': "End time cannot be before start time."
                })

        # If start_now is True, automatically set start_date and start_time
        if start_now:
            now = timezone.now()
            data['start_date'] = now.date()
            data['start_time'] = now.time().replace(microsecond=0)

            # Ensure end_date and end_time are after now
            if end_date and end_time:
                end_datetime = timezone.make_aware(dt.datetime.combine(end_date, end_time))
                if now > end_datetime:
                    raise serializers.ValidationError({
                        'end_time': "End date and time cannot be before the current date and time."
                    })

        return data

    def create(self, validated_data):
        images_data = validated_data.pop('images', [])
        vendor_kyc = validated_data.get('vendor_kyc')

        # If 'start_now' is set, automatically set start time and date to the current time
        if validated_data.get('start_now'):
            now = timezone.now()
            validated_data['start_time'] = now.time().replace(microsecond=0)
            validated_data['start_date'] = now.date()

        deal = super().create(validated_data)

    def create(self, validated_data):
        images_metadata = validated_data.pop('uploaded_images', [])
        deal = super().create(validated_data)

        # Save image metadata into JSONField
        if images_metadata:
            deal.set_uploaded_images(images_metadata)
            deal.save()

        return deal
    

    
    
class CreateDeallistSerializer(serializers.ModelSerializer):
    vendor_name = serializers.CharField(source='vendor_kyc.full_name', read_only=True)
    vendor_uuid = serializers.UUIDField(source='vendor_kyc.vendor_id', read_only=True)
    country = serializers.CharField(source='vendor_kyc.country', read_only=True)
    discount_percentage = serializers.SerializerMethodField()
    uploaded_images = serializers.SerializerMethodField()
    average_rating = serializers.SerializerMethodField()

    class Meta:
        model = CreateDeal
        fields = [
            'deal_uuid', 'deal_post_time', 'deal_title', 'select_service',
            'uploaded_images', 'start_date', 'end_date', 'start_time', 'end_time',
            'actual_price', 'deal_price', 'available_deals',
            'location_house_no', 'location_road_name', 'location_country',
            'location_state', 'location_city', 'location_pincode',
            'vendor_name', 'vendor_uuid', 'country',
            'discount_percentage', 'latitude', 'longitude', 'average_rating'
        ]
        read_only_fields = ['deal_uuid', 'discount_percentage']

    def get_discount_percentage(self, obj):
        if obj.actual_price and obj.deal_price:
            discount = ((obj.actual_price - obj.deal_price) / obj.actual_price) * 100
            return round(discount, 2)
        return 0     

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
    
    def get_average_rating(self, obj):
        """
        Vendor ki average rating calculate karega jo MyOrders me di gayi hai.
        """
        if obj.vendor_kyc:
            average = VendorRating.objects.filter(vendor=obj.vendor_kyc).aggregate(avg_rating=Avg('rating'))['avg_rating']
            return round(average, 1) if average else 0.0  # Default 0.0 if no ratings
        return 0.0
        
    
class CreateDealDetailSerializer(serializers.ModelSerializer):
    vendor_name = serializers.CharField(source='vendor_kyc.full_name', read_only=True)
    vendor_uuid = serializers.UUIDField(source='vendor_kyc.vendor_id', read_only=True)
    vendor_email = serializers.CharField(source='vendor_kyc.business_email_id', read_only=True)
    vendor_phone_number = serializers.CharField(source='vendor_kyc.phone_number', read_only=True)
    country = serializers.CharField(source='vendor_kyc.country', read_only=True)
    discount_percentage = serializers.SerializerMethodField()
    uploaded_images = serializers.SerializerMethodField()
    # uploaded_images = CreateDealImageSerializer(many=True, source='deals_assets')   # , source='deals_assets'

    class Meta:
        model = CreateDeal
        fields = [
            'vendor_uuid', 'vendor_name', 'vendor_email', 'vendor_phone_number',
            'deal_uuid','uploaded_images', 'deal_post_time', 'deal_title', 'deal_description',
            'select_service', 'start_date', 'end_date', 'start_time',
            'end_time', 'actual_price', 'deal_price', 'available_deals',
            'location_house_no', 'location_road_name', 'location_country',
            'location_state', 'location_city', 'location_pincode',
            'vendor_name', 'vendor_uuid', 'country', 'discount_percentage',
            'latitude', 'longitude'
        ]
        read_only_fields = ['vendor_uuid', 'deal_uuid', 'discount_percentage']

    def get_discount_percentage(self, obj):
        if obj.actual_price and obj.deal_price:
            discount = ((obj.actual_price - obj.deal_price) / obj.actual_price) * 100
            return round(discount, 2)
        return 0
    
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

    class Meta:
        model = PlaceOrder
        fields = [
            'order_id', 'deal_uuid', 'user_id', 'vendor_id', 'quantity', 'country',
            'latitude', 'longitude', 'total_amount', 'transaction_id', 'payment_status',
            'payment_mode', 'created_at'
        ]
        read_only_fields = ['order_id', 'user_id', 'vendor_id', 'total_amount']
        
    def get_created_at(self, obj):
        return obj.created_at.strftime("%Y-%m-%d %H:%M:%S")  # Format datetime as required

    def validate_deal_uuid(self, value):
        try:
            uuid.UUID(str(value))  # Attempt to parse the UUID
        except ValueError:
            raise serializers.ValidationError("Must be a valid UUID.")  # Simple string message
        
        return value

    def create(self, validated_data):
        user = self.context['request'].user  # Get the logged-in user

        # Retrieve the deal based on the provided deal_uuid
        deal_uuid = validated_data.pop('deal_uuid')
        try:
            deal = CreateDeal.objects.get(deal_uuid=deal_uuid)
        except CreateDeal.DoesNotExist:
            raise serializers.ValidationError({"message":"Deal not found"})

        vendor = deal.vendor_kyc  # Assuming the relationship field for vendor in the deal

        quantity = validated_data.get('quantity', 1)

        # Check if the quantity exceeds available quantity in the deal
        if quantity > deal.available_deals:
            raise serializers.ValidationError({"message":"The ordered quantity exceeds the available deals."})

        total_amount = deal.deal_price * quantity

        payment_status = validated_data.get('payment_status', 'pending')
        
        transaction_id = validated_data.get('transaction_id') or "default-transaction-id"

        # Create the PlaceOrder entry
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

        # Optionally update available quantity after the order is placed
        deal.available_deals -= quantity
        deal.save()

        return place_order


class PlaceOrderDetailsSerializer(serializers.ModelSerializer):
    order_id = serializers.UUIDField(format='hex_verbose', read_only=True)
    deal_uuid = serializers.UUIDField(source='deal.deal_uuid', format='hex_verbose', read_only=True)
    user_id = serializers.UUIDField(source='user.id', read_only=True)
    vendor_id = serializers.UUIDField(source='vendor.vendor_id', read_only=True)
    vendor_name = serializers.CharField(source='vendor.full_name', read_only=True)
    uploaded_images = serializers.SerializerMethodField()
    created_at = serializers.DateTimeField(format='%Y-%m-%d %H:%M:%S', read_only=True)
    

    class Meta:
        model = PlaceOrder
        fields = [
            'order_id', 'deal_uuid', 'uploaded_images', 'user_id', 'vendor_id', 'vendor_name', 'quantity', 'country',
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
            'gender', 'country_code', 'dial_code', 'country'
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
            'profile_pic'
        ]
        extra_kwargs = {
            'email': {'required': True},  # Ensure email is mandatory during updates
            'username': {'required': True},  # Ensure username is mandatory
        }

    def validate_email(self, value):
        user = self.context['request'].user
        if CustomUser.objects.exclude(id=user.id).filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use.")
        return value

    def validate_phone_number(self, value):
        user = self.context['request'].user
        if CustomUser.objects.exclude(id=user.id).filter(phone_number=value).exists():
            raise serializers.ValidationError("This phone number is already in use.")
        return value
        
        
class PlaceOrderListsSerializer(serializers.ModelSerializer):
    order_id = serializers.UUIDField(format='hex_verbose', read_only=True)
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
            'order_id', 'deal_uuid', 'uploaded_images', 'deal_title', 'deal_price', 'deal_description', 'user_id', 'vendor_id', 'vendor_name', 'quantity', 'country',
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
    
class OTPRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()
    
# class OTPResetPasswordSerializer(serializers.Serializer):
#     email = serializers.EmailField()
#     otp = serializers.CharField(max_length=6)
#     new_password = serializers.CharField(write_only=True, validators=[validate_password_strength])
#     confirm_password = serializers.CharField(write_only=True)

#     def validate(self, data):
#         if data['new_password'] != data['confirm_password']:
#             # raise serializers.ValidationError("Passwords do not match.")
#             data['message'] = "Passwords do not match."
#         return data

#     def save(self):
#         email = self.validated_data['email']
#         otp = self.validated_data['otp']
#         new_password = self.validated_data['new_password']

#         try:
#             user = User.objects.get(email=email)
#         except User.DoesNotExist:
#             # raise serializers.ValidationError("User with this email does not exist.")
#             data['message'] = "User with this email does not exist."
#             return data

#         try:
#             otp_entry = PasswordResetOTP.objects.get(user=user, otp=otp)
#         except PasswordResetOTP.DoesNotExist:
#             # raise serializers.ValidationError("Invalid OTP.")
#             data['message'] = "Invalid OTP."
#             return data

#         if otp_entry.is_expired():
#             # raise serializers.ValidationError("OTP has expired.")
#             data['message'] = "OTP has expired."
#             return data
        
#         user.set_password(new_password)
#         user.save()
#         otp_entry.delete()
 
# class OTPResetPasswordSerializer(serializers.Serializer):
#     email = serializers.EmailField()
#     otp = serializers.CharField(max_length=6)
#     new_password = serializers.CharField(write_only=True, validators=[validate_password_strength])
#     confirm_password = serializers.CharField(write_only=True)

#     def validate(self, data):
#         # Check if passwords match
#         if data['new_password'] != data['confirm_password']:
#             raise serializers.ValidationError({"message": "Passwords do not match."})
#         return data

#     def save(self):
#         email = self.validated_data['email']
#         otp = self.validated_data['otp']
#         new_password = self.validated_data['new_password']

#         # Check if the user exists
#         try:
#             user = User.objects.get(email=email)
#         except User.DoesNotExist:
#             raise serializers.ValidationError({"message": "User with this email does not exist."})

#         # Check if OTP is valid
#         try:
#             otp_entry = PasswordResetOTP.objects.get(user=user, otp=otp)
#         except PasswordResetOTP.DoesNotExist:
#             raise serializers.ValidationError({"message": "Invalid OTP."})

#         # Check if OTP has expired
#         if otp_entry.is_expired():
#             raise serializers.ValidationError({"message": "OTP has expired."})

#         # Save the new password
#         user.set_password(new_password)
#         user.save()

#         # Mark OTP as used
#         otp_entry.delete()

#         return {"message": "Password has been reset successfully."}

class OTPResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True, validators=[validate_password_strength])
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        # Check if passwords match
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")

        # Validate email and OTP
        email = data.get('email')
        otp = data.get('otp')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")

        try:
            otp_entry = PasswordResetOTP.objects.get(user=user, otp=otp)
        except PasswordResetOTP.DoesNotExist:
            raise serializers.ValidationError("Invalid OTP.")

        # Check if OTP has expired
        if otp_entry.is_expired():
            raise serializers.ValidationError("OTP has expired.")

        data['user'] = user  # Pass user object for saving
        data['otp_entry'] = otp_entry  # Pass OTP entry for saving
        return data

    def save(self):
        user = self.validated_data['user']
        otp_entry = self.validated_data['otp_entry']
        new_password = self.validated_data['new_password']

        # Save the new password
        user.set_password(new_password)
        user.save()

        # Mark OTP as used
        otp_entry.delete()

           
# class OTPValidationSerializer(serializers.Serializer):
#     email = serializers.EmailField()
#     otp = serializers.CharField(max_length=6)

#     def validate(self, data):
#         email = data.get('email')
#         otp = data.get('otp')
        
#         # Validate email format explicitly
#         try:
#             validate_email(email)
#         except DjangoValidationError:
#             data['message'] = "Invalid email address format."
#             return data
        

#         try:
#             user = User.objects.get(email=email)
#         except User.DoesNotExist:
#             # raise serializers.ValidationError({"message": "User with this email does not exist."})
#             data['message'] = "User with this email does not exist."
#             return data
#         try:
#             otp_entry = PasswordResetOTP.objects.get(user=user, otp=otp)
#         except PasswordResetOTP.DoesNotExist:
#             # raise serializers.ValidationError({"message": "Invalid OTP."})
#             data['message'] = "Invalid OTP."
#             return data

#         if otp_entry.is_expired() or otp_entry.used == True:
#             # raise serializers.ValidationError({"message": "OTP has expired."})
#             data['message'] = "OTP has expired."
#             return data

#         otp_entry.used = True
#         otp_entry.save()
        
#         data['message'] = "OTP is valid. Proceed to reset your password."
#         return data

class OTPValidationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

    def validate(self, data):
        email = data.get('email')
        otp = data.get('otp')

        # Validate email format explicitly
        try:
            validate_email(email)
        except DjangoValidationError:
            raise serializers.ValidationError("Invalid email address format.")

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")

        try:
            otp_entry = PasswordResetOTP.objects.get(user=user, otp=otp)
        except PasswordResetOTP.DoesNotExist:
            raise serializers.ValidationError("Invalid OTP.")

        if otp_entry.is_expired() or otp_entry.used:
            raise serializers.ValidationError("OTP has expired.")

        otp_entry.used = True
        otp_entry.save()

        # OTP is valid
        data['message'] = "OTP is valid. Proceed to reset your password."
        return data
    
class MyActivitysSerializer(serializers.ModelSerializer):
    user_id = serializers.UUIDField(source='created_by.id', read_only=True)
    created_by = serializers.CharField(source='created_by.username')  # Assuming `created_by` refers to CustomUser
    activity_category = ActivityCategorySerializer(required=True)
    uploaded_images = serializers.SerializerMethodField()
    created_at = serializers.SerializerMethodField()

    class Meta:
        model = Activity
        fields = ['activity_id', 'user_id', 'activity_title','uploaded_images','activity_category', 'activity_description', 'created_by', 'user_participation', 'maximum_participants', 'infinite_time', 'activity_category',
                  'start_date', 'start_time', 'end_date', 'end_time', 'latitude', 'longitude', 'created_by',
                  'location', 'created_at']
        
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

class MyDealSerializer(serializers.ModelSerializer):
    vendor_name = serializers.CharField(source='vendor_kyc.full_name', read_only=True)
    vendor_uuid = serializers.UUIDField(source='vendor_kyc.vendor_id', read_only=True)
    country = serializers.CharField(source='vendor_kyc.country', read_only=True)
    discount_percentage = serializers.SerializerMethodField()
    deal_post_time = serializers.SerializerMethodField()
    uploaded_images = serializers.SerializerMethodField()

    class Meta:
        model = CreateDeal
        fields = [
            'deal_uuid', 'deal_post_time', 'deal_title', 'select_service',
            'uploaded_images', 'start_date', 'end_date', 'start_time', 'end_time',
            'actual_price', 'deal_price', 'available_deals',
            'location_house_no', 'location_road_name', 'location_country',
            'location_state', 'location_city', 'location_pincode',
            'vendor_name', 'vendor_uuid', 'country',
            'discount_percentage', 'latitude', 'longitude'
        ]

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
        # Ensure uploaded_images field is valid and has data
        if not obj.uploaded_images or not isinstance(obj.uploaded_images, list):
            return []

        # Return only the thumbnail of the first image in the uploaded_images list
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
    rating_id = serializers.UUIDField(read_only=True)
    user_id = serializers.UUIDField(source='user.id', read_only=True)
    vendor_id = serializers.UUIDField(source='vendor.vendor_id', read_only=True)
    order_id = serializers.UUIDField(source='order.order_id', read_only=True)

    class Meta:
        model = VendorRating
        fields = ['rating_id', 'user_id', 'vendor_id', 'order_id', 'rating', 'created_at']
        read_only_fields = ['rating_id', 'user_id', 'vendor_id', 'order_id', 'created_at']

    def validate_rating(self, value):
        """ Ensure rating is a valid Decimal. """
        if isinstance(value, float):  
            value = Decimal(str(value))
        return value

    def validate(self, data):
        request = self.context['request']
        user = request.user
        order = self.context['order']

        # Check if user is the owner of the order
        if order.user != user:
            raise serializers.ValidationError("You are not authorized to rate this order.")

        # Check if rating already exists
        if VendorRating.objects.filter(user=user, order=order).exists():
            raise serializers.ValidationError("You have already rated this order.")

        return data
    
class RaiseAnIssueSerializerMyOrders(serializers.ModelSerializer):
    class Meta:
        model = RaiseAnIssueMyOrders
        fields = ["issue_id", "user", "place_order", "subject", "describe_your_issue", "choose_files", "created_at"]
        read_only_fields = ["issue_id", "user", "created_at"]  # Ye fields user edit nahi kar sakta

    def create(self, validated_data):
        request = self.context.get('request')  # Request object access karein
        if request and hasattr(request, "user"):
            validated_data["user"] = request.user  # User ko manually set karein
        return RaiseAnIssueMyOrders.objects.create(**validated_data)

