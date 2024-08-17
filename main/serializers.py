from rest_framework import serializers
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from django.utils import timezone
from .models import CustomUser, OTP, Activity, ActivityImage, ChatRoom, ChatMessage
import uuid

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

        # Validate start_date and end_date
        if data.get('start_date') and data['start_date'] < now:
            raise serializers.ValidationError({"start_date": "Start date cannot be in the past."})
        if data.get('end_date') and data['end_date'] < now:
            raise serializers.ValidationError({"end_date": "End date cannot be in the past."})
        
        # Validate end_date is after start_date
        if data.get('start_date') and data.get('end_date') and data['end_date'] < data['start_date']:
            raise serializers.ValidationError({"end_date": "End date must be after start date."})
        
        # Validate end_time is after start_time
        if data.get('start_time') and data.get('end_time') and data['end_time'] < data['start_time']:
            raise serializers.ValidationError({"end_time": "End time must be after start time."})

        # Validate maximum_participants based on user_participation
        if not data.get('user_participation', False):
            data['maximum_participants'] = 0

        return data

    def create(self, validated_data):
        # Assign the logged-in user as the creator
        validated_data['created_by'] = self.context['request'].user

        # Handle the set_current_datetime and infinite_time flags
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
        # Handle the set_current_datetime and infinite_time flags
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
    
    def create(self, validated_data):
        # Automatically set the user_uuid based on the activity's creator
        activity = validated_data['activity']
        validated_data['user_uuid'] = activity.created_by.id
        return super().create(validated_data)

class ChatRoomSerializer(serializers.ModelSerializer):
    participants = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), many=True)
    activity = serializers.PrimaryKeyRelatedField(queryset=Activity.objects.all())

    class Meta:
        model = ChatRoom
        fields = ['id', 'activity', 'participants']

class ChatMessageSerializer(serializers.ModelSerializer):
    sender = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    chat_room = serializers.PrimaryKeyRelatedField(queryset=ChatRoom.objects.all())

    class Meta:
        model = ChatMessage
        fields = ['id', 'chat_room', 'sender', 'content', 'created_at']
