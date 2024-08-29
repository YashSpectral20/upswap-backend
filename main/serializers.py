from rest_framework import serializers
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from django.utils import timezone
from .models import (
    CustomUser, OTP, Activity, ActivityImage, ChatRoom, ChatMessage,
    ChatRequest, VendorKYC, BankDetails, ServicesProvide
)

User = get_user_model()

class CustomUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ['id', 'name', 'username', 'email', 'phone_number', 'date_of_birth', 'gender', 'password', 'confirm_password']

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
            user = authenticate(request=self.context.get('request'), email=email, password=password)
            if not user:
                raise serializers.ValidationError("Invalid login credentials.")
        else:
            raise serializers.ValidationError("Must include 'email' and 'password'.")

        attrs['user'] = user
        return attrs

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
    maximum_participants = serializers.IntegerField()
    set_current_datetime = serializers.BooleanField(write_only=True, required=False, default=False)
    infinite_time = serializers.BooleanField(write_only=True, required=False, default=False)

    class Meta:
        model = Activity
        fields = [
            'activity_id', 'activity_title', 'activity_description', 
            'activity_type', 'user_participation', 'maximum_participants', 
            'start_date', 'end_date', 'start_time', 'end_time', 'created_at', 
            'created_by', 'set_current_datetime', 'infinite_time'
        ]
        read_only_fields = ['created_by', 'created_at']

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
        validated_data['created_by'] = self.context['request'].user

        if validated_data.pop('set_current_datetime', False):
            current_datetime = timezone.now()
            validated_data['start_date'] = current_datetime.date()
            validated_data['start_time'] = current_datetime.time()

        if validated_data.pop('infinite_time', False):
            future_date = timezone.now() + timezone.timedelta(days=365 * 100)  # 100 years from now
            validated_data['end_date'] = future_date.date()
            validated_data['end_time'] = future_date.time()

        return super().create(validated_data)

    def update(self, instance, validated_data):
        if validated_data.pop('set_current_datetime', False):
            current_datetime = timezone.now()
            validated_data['start_date'] = current_datetime.date()
            validated_data['start_time'] = current_datetime.time()

        if validated_data.pop('infinite_time', False):
            future_date = timezone.now() + timezone.timedelta(days=365 * 100)  # 100 years from now
            validated_data['end_date'] = future_date.date()
            validated_data['end_time'] = future_date.time()

        return super().update(instance, validated_data)

class ActivityImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ActivityImage
        fields = ['id', 'activity', 'upload_image']

class ChatRoomSerializer(serializers.ModelSerializer):
    participants = serializers.SlugRelatedField(
        many=True,
        slug_field='username',
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
    upload_business_related_documents = serializers.FileField(required=False, allow_null=True)
    business_related_photos = serializers.ImageField(required=False, allow_null=True)
    same_as_personal_phone_number = serializers.BooleanField(write_only=True, required=False, default=False)
    same_as_personal_email_id = serializers.BooleanField(write_only=True, required=False, default=False)
    phone_number = serializers.CharField(required=False, allow_blank=True)
    business_email_id = serializers.EmailField(required=False, allow_blank=True)

    class Meta:
        model = VendorKYC
        fields = [
            'vendor_id', 'full_name', 'phone_number', 'business_email_id', 
            'business_establishment_year', 'business_description', 
            'upload_business_related_documents', 'business_related_photos', 
            'same_as_personal_phone_number', 'same_as_personal_email_id'
        ]
        read_only_fields = ['full_name']

    def validate(self, data):
        user = self.context['request'].user

        if data.get('same_as_personal_phone_number'):
            data['phone_number'] = user.phone_number or ""
        if data.get('same_as_personal_email_id'):
            data['business_email_id'] = user.email or ""

        if data.get('same_as_personal_phone_number') and not user.phone_number:
            raise serializers.ValidationError({"phone_number": "User's personal phone number is not available."})
        if data.get('same_as_personal_email_id') and not user.email:
            raise serializers.ValidationError({"business_email_id": "User's personal email is not available."})

        return data

    def create(self, validated_data):
        user = self.context['request'].user

        if validated_data.pop('same_as_personal_phone_number', False):
            validated_data['phone_number'] = user.phone_number

        if validated_data.pop('same_as_personal_email_id', False):
            validated_data['business_email_id'] = user.email

        validated_data['full_name'] = user.name

        return super().create(validated_data)

    def update(self, instance, validated_data):
        user = self.context['request'].user

        if validated_data.pop('same_as_personal_phone_number', False):
            validated_data['phone_number'] = user.phone_number

        if validated_data.pop('same_as_personal_email_id', False):
            validated_data['business_email_id'] = user.email

        validated_data['full_name'] = user.name

        return super().update(instance, validated_data)

class BankDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model = BankDetails
        fields = ['vendor_kyc', 'account_number', 'retype_account_number', 'bank_name', 'ifsc_code']
        extra_kwargs = {
            'retype_account_number': {'write_only': True}
        }

    def validate(self, attrs):
        if attrs.get('account_number') != attrs.get('retype_account_number'):
            raise serializers.ValidationError({"retype_account_number": "Account number fields didn't match."})
        return attrs

    def create(self, validated_data):
        validated_data.pop('retype_account_number')
        return super().create(validated_data)

class ServicesProvideSerializer(serializers.ModelSerializer):
    class Meta:
        model = ServicesProvide
        fields = '__all__'