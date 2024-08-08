from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import authenticate, get_user_model
from .models import CustomUser, OTP, Activity, ActivityImage

User = get_user_model()

class CustomUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = CustomUser
        fields = ['name', 'username', 'email', 'phone_number', 'date_of_birth', 'gender', 'password', 'confirm_password']

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        user = CustomUser(**validated_data)
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


#Activity-Serializers:
class ActivitySerializer(serializers.ModelSerializer):
    maximum_participants = serializers.IntegerField()

    class Meta:
        model = Activity
        fields = [
            'activity_id', 'created_by', 'activity_title', 'activity_description', 
            'activity_type', 'user_participation', 'maximum_participants'
        ]

    def validate(self, data):
        if not data.get('user_participation', False):
            data['maximum_participants'] = 0
        return data

    def create(self, validated_data):
        if not validated_data.get('user_participation', False):
            validated_data['maximum_participants'] = 0
        return super().create(validated_data)

    def update(self, instance, validated_data):
        if not validated_data.get('user_participation', False):
            validated_data['maximum_participants'] = 0
        return super().update(instance, validated_data)

class ActivityImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ActivityImage
        fields = ['id', 'activity', 'upload_image']