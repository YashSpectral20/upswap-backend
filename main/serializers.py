from rest_framework import serializers
from django.contrib.auth import get_user_model
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
        fields = ['id', 'name', 'email', 'phone_number', 'date_of_birth', 'gender', 'password', 'confirm_password']

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "Password fields didn't match."})
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

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            user = User.objects.filter(email=email).first()
            if not user or not user.check_password(password):
                raise serializers.ValidationError("Invalid login credentials.")
        else:
            raise serializers.ValidationError("Must include 'email' and 'password'.")

        return user

class OTPSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6)

    def validate(self, attrs):
        otp = attrs.get('otp')
        try:
            otp_instance = OTP.objects.get(otp=otp)
        except OTP.DoesNotExist:
            raise serializers.ValidationError({"otp": "Invalid OTP"})

        if otp_instance.is_expired():
            raise serializers.ValidationError({"otp": "OTP has expired"})

        attrs['user'] = otp_instance.user
        return attrs

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
            'item_name', 'chosen_item_category', 'item_description', 'item_price', 'business_hours'
        ]
        read_only_fields = ['full_name']

    def validate_business_hours(self, value):
        days_of_week = set(day[0] for day in BusinessHourSerializer().fields['day'].choices)
        provided_days = set(hour['day'] for hour in value)

        if not days_of_week.issubset(provided_days):
            missing_days = days_of_week - provided_days
            raise serializers.ValidationError(f"Business hours must be provided for all days. Missing: {', '.join(missing_days)}")

        return value

    def validate(self, data):
        if data.get('same_as_personal_phone_number'):
            data['phone_number'] = data['user'].phone_number
        if data.get('same_as_personal_email_id'):
            data['business_email_id'] = data['user'].email
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
