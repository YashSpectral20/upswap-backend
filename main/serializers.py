from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from django.utils import timezone
from .models import (
    CustomUser, OTP, Activity, ChatRoom, ChatMessage,
    ChatRequest, VendorKYC, ActivityImage
)

User = get_user_model()

class CustomUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ['id', 'name', 'username', 'email', 'phone_number', 'date_of_birth', 'gender', 'password', 'confirm_password']

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
        return attrs

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        user = User(**validated_data)
        user.set_password(validated_data['password'])
        user.save()
        return user
    
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    access = serializers.CharField(read_only=True)
    refresh = serializers.CharField(read_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        user = authenticate(email=email, password=password)

        if user is None:
            raise serializers.ValidationError('Invalid email or password.')

        # Create tokens
        from rest_framework_simplejwt.tokens import RefreshToken
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        return {
            'user': user,
            'access': access_token,
            'refresh': str(refresh),
        }
        
class VerifyOTPSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6)

    def validate_otp(self, value):
        try:
            otp_record = OTP.objects.get(otp=value)
        except OTP.DoesNotExist:
            raise serializers.ValidationError("Invalid OTP")

        if otp_record.is_expired():
            raise serializers.ValidationError("OTP has expired")

        self.context['otp_record'] = otp_record
        return value

    def verify_otp(self):
        otp_record = self.context.get('otp_record')
        if otp_record:
            otp_record.delete()  # Delete the OTP once verified
            return True
        return False

class ActivitySerializer(serializers.ModelSerializer):
    images = serializers.SerializerMethodField()  # Use a method field to get the image URLs
    uploaded_images = serializers.ListField(
        child=serializers.CharField(),  # For storing static image paths
        write_only=True,
        required=False,
        allow_empty=True
    )
    maximum_participants = serializers.IntegerField()
    set_current_datetime = serializers.BooleanField(write_only=True, required=False, default=False)
    infinite_time = serializers.BooleanField(write_only=True, required=False, default=False)

    class Meta:
        model = Activity
        fields = [
            'activity_id', 'activity_title', 'activity_description', 
            'activity_type', 'user_participation', 'maximum_participants', 
            'start_date', 'end_date', 'start_time', 'end_time', 'created_at', 
            'created_by', 'set_current_datetime', 'infinite_time', 'images', 'uploaded_images'
        ]
        read_only_fields = ['created_by', 'created_at']

    def get_images(self, obj):
        return obj.images  # Get all image URLs stored in the Activity model's JSONField

    def validate(self, data):
        now = timezone.now().date()

        if data.get('start_date') and data['start_date'] < now:
            raise serializers.ValidationError({"start_date": "Start date cannot be in the past."})
        if data.get('end_date') and data['end_date'] < now:
            raise serializers.ValidationError({"end_date": "End date cannot be in the past."})
        if data.get('start_date') and data.get('end_date') and data['end_date'] < data['start_date']:
            raise serializers.ValidationError({"end_date": "End date must be after start date."})
        if data.get('start_time') and data.get('end_time') and data['end_time'] < data['start_time']:
            raise serializers.ValidationError({"end_time": "End time must be after start time."})

        if not data.get('user_participation', False):
            data['maximum_participants'] = 0

        return data

    def create(self, validated_data):
        uploaded_images = validated_data.pop('uploaded_images', [])
        validated_data['created_by'] = self.context['request'].user

        if validated_data.pop('set_current_datetime', False):
            current_datetime = timezone.now()
            validated_data['start_date'] = current_datetime.date()
            validated_data['start_time'] = current_datetime.time()

        if validated_data.pop('infinite_time', False):
            future_date = timezone.now() + timezone.timedelta(days=365 * 100)  # 100 years from now
            validated_data['end_date'] = future_date.date()
            validated_data['end_time'] = future_date.time()

        activity = super().create(validated_data)
        # Save uploaded image paths
        activity.images = uploaded_images
        activity.save()

        return activity

    def update(self, instance, validated_data):
        if validated_data.pop('set_current_datetime', False):
            current_datetime = timezone.now()
            validated_data['start_date'] = current_datetime.date()
            validated_data['start_time'] = current_datetime.time()

        if validated_data.pop('infinite_time', False):
            future_date = timezone.now() + timezone.timedelta(days=365 * 100)  # 100 years from now
            validated_data['end_date'] = future_date.date()
            validated_data['end_time'] = future_date.time()

        uploaded_images = validated_data.pop('uploaded_images', None)
        if uploaded_images is not None:
            instance.images = uploaded_images
            instance.save()

        return super().update(instance, validated_data)

class ActivityImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ActivityImage
        fields = '__all__'

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

class BusinessHourSerializer(serializers.Serializer):
    day = serializers.ChoiceField(
        choices=[
            ('Sunday', 'Sunday'), ('Monday', 'Monday'), ('Tuesday', 'Tuesday'),
            ('Wednesday', 'Wednesday'), ('Thursday', 'Thursday'),
            ('Friday', 'Friday'), ('Saturday', 'Saturday')
        ]
    )
    start_time = serializers.TimeField()
    end_time = serializers.TimeField()

    def validate(self, data):
        if data['start_time'] >= data['end_time']:
            raise serializers.ValidationError("End time must be after start time.")
        return data

class VendorKYCSerializer(serializers.ModelSerializer):
    profile_pic = serializers.ImageField(required=False, allow_null=True)
    upload_business_related_documents = serializers.FileField(required=False, allow_null=True)
    business_related_photos = serializers.ImageField(required=False, allow_null=True)
    same_as_personal_phone_number = serializers.BooleanField(write_only=True, required=False, default=False)
    same_as_personal_email_id = serializers.BooleanField(write_only=True, required=False, default=False)
    business_hours = BusinessHourSerializer(many=True)

    class Meta:
        model = VendorKYC
        fields = [
            'vendor_id', 'profile_pic', 'user', 'full_name', 'phone_number', 'business_email_id',
            'business_establishment_year', 'business_description',
            'upload_business_related_documents', 'business_related_photos',
            'same_as_personal_phone_number', 'same_as_personal_email_id',
            'bank_account_number', 'retype_bank_account_number', 'bank_name', 'ifsc_code',
            'item_name', 'chosen_item_category', 'item_description', 'item_price', 'business_hours', 'is_approved'
        ]

    def validate(self, data):
        if data['phone_number'] and data.get('same_as_personal_phone_number'):
            if data['phone_number'] != data.get('user').phone_number:
                raise serializers.ValidationError({"phone_number": "Phone number does not match with user's phone number."})
        
        if data['business_email_id'] and data.get('same_as_personal_email_id'):
            if data['business_email_id'] != data.get('user').email:
                raise serializers.ValidationError({"business_email_id": "Email ID does not match with user's email ID."})

        return data

    def create(self, validated_data):
        business_hours_data = validated_data.pop('business_hours', [])
        vendor_kyc = VendorKYC.objects.create(**validated_data)

        # Convert to string representation for storing in the model's business_hours field
        vendor_kyc.business_hours = [
            f"{hour_data['day']} {hour_data['start_time'].strftime('%I:%M %p')} - {hour_data['end_time'].strftime('%I:%M %p')}"
            for hour_data in business_hours_data
        ]
        vendor_kyc.save()

        return vendor_kyc

    def update(self, instance, validated_data):
        business_hours_data = validated_data.pop('business_hours', [])

        # Update the business hours field
        instance.business_hours = [
            f"{hour_data['day']} {hour_data['start_time'].strftime('%I:%M %p')} - {hour_data['end_time'].strftime('%I:%M %p')}"
            for hour_data in business_hours_data
        ]
        instance.save()

        return super().update(instance, validated_data)
