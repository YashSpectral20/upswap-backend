from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model, authenticate
from django.utils import timezone
from .models import (
    CustomUser, OTP, Activity, ChatRoom, ChatMessage,
    ChatRequest, VendorKYC, BusinessDocument, BusinessPhoto, ActivityImage, CreateDeal, DealImage
)
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth import get_user_model
from django.utils.encoding import force_str
from .validators import validate_password_strength


User = get_user_model()

class CustomUserSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)
    country_code = serializers.CharField(required=False, allow_blank=True)
    dial_code = serializers.CharField(required=False, allow_blank=True)
    country = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = CustomUser
        fields = ['id', 'name', 'username', 'email', 'phone_number', 'date_of_birth', 'gender', 'password', 'confirm_password', 'country_code', 'dial_code', 'country']
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

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')
        user = authenticate(email=email, password=password)
        if user is None:
            raise serializers.ValidationError('Invalid credentials')
        data['user'] = user
        return data
    
class ActivitySerializer(serializers.ModelSerializer):
    images = serializers.SerializerMethodField()  # Use a method field to get the image URLs
    uploaded_images = serializers.ListField(
        child=serializers.CharField(),  # For storing static image paths
        write_only=True,
        required=False,
        allow_empty=True
    )
    set_current_datetime = serializers.BooleanField(write_only=True, required=False, default=False)
    infinite_time = serializers.BooleanField(write_only=True, required=False, default=True)
    location = serializers.CharField(required=False, allow_blank=True)  # Add location field
    latitude = serializers.FloatField(required=False, allow_null=True)  # Add latitude field
    longitude = serializers.FloatField(required=False, allow_null=True)  # Add longitude field

    class Meta:
        model = Activity
        fields = [
            'activity_id', 'activity_title', 'activity_description',
            'activity_type', 'user_participation', 'maximum_participants',
            'start_date', 'end_date', 'start_time', 'end_time', 'created_at',
            'created_by', 'set_current_datetime', 'infinite_time', 'images',
            'uploaded_images', 'location', 'latitude', 'longitude'
        ]
        read_only_fields = ['created_by', 'created_at']

    def get_images(self, obj):
        # Get all image URLs stored in the Activity model's images JSONField
        return obj.images if obj.images else []

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
        # Handle fields from validated data
        uploaded_images = validated_data.pop('uploaded_images', [])
        validated_data['created_by'] = self.context['request'].user

        # Set current datetime if requested
        if validated_data.pop('set_current_datetime', False):
            current_datetime = timezone.now()
            validated_data['start_date'] = current_datetime.date()
            validated_data['start_time'] = current_datetime.time()

        # Set infinite time if requested
        if validated_data.pop('infinite_time', False):
            future_date = timezone.now() + timezone.timedelta(days=365 * 999)  # 999 years from now
            validated_data['end_date'] = future_date.date()
            validated_data['end_time'] = future_date.time()

        # Create activity instance
        activity = super().create(validated_data)

        # Save uploaded image paths
        if uploaded_images:
            activity.images = uploaded_images
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
            instance.images = uploaded_images
            instance.save()

        return super().update(instance, validated_data)
    
class ActivityImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ActivityImage
        fields = ['image_id', 'activity', 'image', 'uploaded_at']
        read_only_fields = ['uploaded_at']
        
class ActivityListSerializer(serializers.ModelSerializer):
    images = serializers.ListField(child=serializers.CharField(), required=False, allow_empty=True)
    created_by = serializers.CharField(source='created_by.username')  # Assuming `created_by` refers to CustomUser

    class Meta:
        model = Activity
        fields = ['images', 'activity_id', 'activity_title', 'created_by', 'user_participation', 'infinite_time', 'activity_type',
                  'start_date', 'start_time', 'end_date', 'end_time', 'latitude', 'longitude', 'created_by',
                  'location']



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

class VendorKYCSerializer(serializers.ModelSerializer):
    business_related_documents = serializers.ListField(
        child=serializers.CharField(), required=False, allow_empty=True
    )
    business_related_photos = serializers.ListField(
        child=serializers.CharField(), required=False, allow_empty=True
    )
    

    class Meta:
        model = VendorKYC
        fields = [
            'vendor_id', 'profile_pic', 'user', 'full_name', 'phone_number', 'business_email_id', 
            'business_establishment_year', 'business_description', 'upload_business_related_documents',
            'business_related_photos', 'same_as_personal_phone_number', 'same_as_personal_email_id',
            'business_related_documents', 'business_related_photos', 'house_no_building_name', 
            'road_name_area_colony', 'country', 'state', 'city', 'pincode', 'bank_account_number', 
            'retype_bank_account_number', 'bank_name', 'ifsc_code', 'item_name', 'chosen_item_category', 
            'item_description', 'item_price', 'business_hours'
        ]

    def validate(self, data):
        if data.get('same_as_personal_phone_number') and not data.get('user'):
            raise ValidationError("User must be provided if 'same_as_personal_phone_number' is True.")

        if data.get('same_as_personal_email_id') and not data.get('user'):
            raise ValidationError("User must be provided if 'same_as_personal_email_id' is True.")
        return data


class VendorDetailSerializer(serializers.ModelSerializer):
    business_related_photos = serializers.ListField(
        child=serializers.CharField(), required=False, allow_empty=True
    )
    address = serializers.SerializerMethodField()
    services_provided = serializers.SerializerMethodField()

    class Meta:
        model = VendorKYC
        fields = [
            'full_name', 'business_email_id', 'phone_number', 'business_description',
            'business_related_photos', 'address', 'item_description', 
            'business_hours', 'services_provided'
        ]

    def get_address(self, obj):
        return {
            'house_no_building_name': obj.house_no_building_name,
            'road_name_area_colony': obj.road_name_area_colony,
            'country': obj.country,
            'state': obj.state,
            'city': obj.city,
            'pincode': obj.pincode
        }

    def get_services_provided(self, obj):
        return {
            'item_name': obj.item_name,
            'item_description': obj.item_description,
            'item_price': obj.item_price,
            'chosen_item_category': obj.chosen_item_category
        }
        


class VendorListSerializer(serializers.ModelSerializer):
    business_related_photos = serializers.ListField(child=serializers.CharField(), required=False, allow_empty=True)
    address = serializers.SerializerMethodField()
    services_provided = serializers.SerializerMethodField()
    

    class Meta:
        model = VendorKYC
        fields = [
            'business_related_photos', 'full_name', 'services_provided', 'address', 'latitude', 'longitude',
        ]

    def get_address(self, obj):
        return {
            'house_no_building_name': obj.house_no_building_name,
            'road_name_area_colony': obj.road_name_area_colony,
            'country': obj.country,
            'state': obj.state,
            'city': obj.city,
            'pincode': obj.pincode
        }

    def get_services_provided(self, obj):
        return {
            'item_name': obj.item_name,
            'item_description': obj.item_description,
            'item_price': obj.item_price,
            'chosen_item_category': obj.chosen_item_category
        }
        
        

class BusinessDocumentSerializer(serializers.ModelSerializer):
    class Meta:
        model = BusinessDocument
        fields = ['id', 'vendor_kyc', 'document', 'uploaded_at']


class BusinessPhotoSerializer(serializers.ModelSerializer):
    class Meta:
        model = BusinessPhoto
        fields = ['id', 'vendor_kyc', 'photo', 'uploaded_at']
        
class DealImageSerializer(serializers.ModelSerializer):
    """Serializer for the DealImage model."""
    class Meta:
        model = DealImage
        fields = ['id', 'create_deal', 'images', 'uploaded_at']


class CreateDealSerializer(serializers.ModelSerializer):
    vendor_name = serializers.CharField(source='vendor_kyc.full_name', read_only=True)
    vendor_uuid = serializers.UUIDField(source='vendor_kyc.vendor_id', read_only=True)
    actual_price = serializers.CharField(source='vendor_kyc.item_price')
    country = serializers.CharField(source='vendor_kyc.country', read_only=True)
    vendor_email = serializers.EmailField(source='vendor_kyc.business_email_id', read_only=True)
    vendor_number = serializers.CharField(source='vendor_kyc.phone_number', read_only=True)
    discount_percentage = serializers.SerializerMethodField()
    latitude = serializers.DecimalField(source='vendor_kyc.latitude', read_only=True, max_digits=9, decimal_places=6)
    longitude = serializers.DecimalField(source='vendor_kyc.longitude', read_only=True, max_digits=9, decimal_places=6)
    
    start_time = serializers.SerializerMethodField()  
    end_time = serializers.SerializerMethodField()

    class Meta:
        model = CreateDeal
        fields = [
            'deal_uuid', 'deal_title', 'deal_description', 'select_service',
            'upload_images', 'start_date', 'end_date', 'start_time', 'end_time',
            'start_now', 'actual_price', 'deal_price', 'available_deals',
            'location_house_no', 'location_road_name', 'location_country',
            'location_state', 'location_city', 'location_pincode', 'vendor_kyc',
            'vendor_name', 'vendor_uuid', 'country', 'vendor_email', 'vendor_number',
            'discount_percentage', 'latitude', 'longitude'
        ]
        read_only_fields = ['deal_uuid', 'discount_percentage']  # Prevent client from setting these fields

    def get_discount_percentage(self, obj):
        """Calculate and return the discount percentage."""
        if obj.actual_price and obj.deal_price:
            discount = ((obj.actual_price - obj.deal_price) / obj.actual_price) * 100
            return round(discount, 2)
        return 0
    
    def get_start_time(self, obj):
        """Return start_time in HH:MM:SS format."""
        return obj.start_time.strftime('%H:%M:%S') if obj.start_time else None

    def get_end_time(self, obj):
        """Return end_time in HH:MM:SS format."""
        return obj.end_time.strftime('%H:%M:%S') if obj.end_time else None

    def validate(self, data):
        # Ensure vendor KYC is provided
        vendor_kyc = data.get('vendor_kyc')
        if not vendor_kyc:
            raise serializers.ValidationError("Vendor KYC must be provided.")

        # Ensure vendor's KYC is approved
        if not vendor_kyc.is_approved:
            raise serializers.ValidationError("Cannot create a deal because Vendor KYC is not approved.")

        # Ensure the deal price is less than or equal to the actual price
        if data.get('deal_price') and data.get('actual_price'):
            if data['deal_price'] > data['actual_price']:
                raise serializers.ValidationError("Deal price must be less than or equal to the actual price.")

        # Validate date ranges if 'start_now' is not set
        if not data.get('start_now') and (data.get('start_date') or data.get('end_date')):
            if data['start_date'] and data['end_date'] and data['start_date'] >= data['end_date']:
                raise serializers.ValidationError("Start date must be earlier than end date.")

        return data

    def create(self, validated_data):
        
        # Fetch the actual_price from VendorKYC
        vendor_kyc = validated_data.get('vendor_kyc')
        validated_data['actual_price'] = vendor_kyc.item_price

        # Automatically set fields based on the VendorKYC instance
        validated_data['select_service'] = vendor_kyc.item_name
        validated_data['location_house_no'] = vendor_kyc.house_no_building_name or ''
        validated_data['location_road_name'] = vendor_kyc.road_name_area_colony or ''
        validated_data['location_country'] = vendor_kyc.country or ''
        validated_data['location_state'] = vendor_kyc.state or ''
        validated_data['location_city'] = vendor_kyc.city or ''
        validated_data['location_pincode'] = vendor_kyc.pincode or ''
        validated_data['latitude'] = vendor_kyc.latitude or None
        validated_data['longitude'] = vendor_kyc.longitude or None
        
        if validated_data.get('start_now'):
            now = timezone.now()
            validated_data['start_time'] = now.time().replace(microsecond=0)
            #validated_data['end_time'] = now.time().replace(microsecond=0)  
        else:
            validated_data['start_time'] = validated_data.get('start_time')  
            validated_data['end_time'] = validated_data.get('end_time')
        

        return super().create(validated_data)
    
    
class CreateDeallistSerializer(serializers.ModelSerializer):
    vendor_name = serializers.CharField(source='vendor_kyc.full_name', read_only=True)
    vendor_uuid = serializers.UUIDField(source='vendor_kyc.vendor_id', read_only=True)
    country = serializers.CharField(source='vendor_kyc.country', read_only=True)
    discount_percentage = serializers.SerializerMethodField()
    latitude = serializers.DecimalField(source='vendor_kyc.latitude', read_only=True, max_digits=9, decimal_places=6)
    longitude = serializers.DecimalField(source='vendor_kyc.longitude', read_only=True, max_digits=9, decimal_places=6)
    

    class Meta:
        model = CreateDeal
        fields = [
            'deal_uuid','deal_post_time', 'deal_title', 'select_service',
            'upload_images', 'start_date', 'end_date', 'start_time', 'end_time',
            'actual_price', 'deal_price', 'available_deals',
            'location_house_no', 'location_road_name', 'location_country',
            'location_state', 'location_city', 'location_pincode',
            'vendor_name', 'vendor_uuid', 'country',
            'discount_percentage', 'latitude', 'longitude'
        ]
        read_only_fields = ['deal_uuid', 'discount_percentage']  # Prevent client from setting these fields

    def get_discount_percentage(self, obj):
        """Calculate and return the discount percentage."""
        if obj.actual_price and obj.deal_price:
            discount = ((obj.actual_price - obj.deal_price) / obj.actual_price) * 100
            return round(discount, 2)
        return 0

    def create(self, validated_data):
        # Fetch the actual_price from VendorKYC
        vendor_kyc = validated_data.get('vendor_kyc')
        validated_data['actual_price'] = vendor_kyc.item_price

        # Automatically set fields based on the VendorKYC instance
        validated_data['location_house_no'] = vendor_kyc.house_no_building_name or ''
        validated_data['location_road_name'] = vendor_kyc.road_name_area_colony or ''
        validated_data['location_country'] = vendor_kyc.country or ''
        validated_data['location_state'] = vendor_kyc.state or ''
        validated_data['location_city'] = vendor_kyc.city or ''
        validated_data['location_pincode'] = vendor_kyc.pincode or ''
        validated_data['latitude'] = vendor_kyc.latitude or None
        validated_data['longitude'] = vendor_kyc.longitude or None
        

        return super().create(validated_data)    
    

class CreateDealImageUploadSerializer(serializers.ModelSerializer):
    """Serializer to upload images to a deal."""
    image = serializers.ImageField()
 
    class Meta:
        model = DealImage
        fields = ['image']        
        
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