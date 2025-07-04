from rest_framework import serializers
from .models import (
    Provider,
    Service,
    ServiceCategory,
    Appointment,
    TimeSlot,
)
from main.models import FavoriteService

class ServiceNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = Service
        fields = ['id', 'name']

class ProviderSerializer(serializers.ModelSerializer):
    services = ServiceNameSerializer(many=True, read_only=True)

    class Meta:
        model = Provider
        fields = '__all__'
        read_only_fields = ['id', 'profile_photo']

    # def get_services(self, obj):
    #     return list(obj.services.values_list('name', flat=True))


    def validate_work_hours(self, value):
        expected_days = {
            "monday", "tuesday", "wednesday", "thursday",
            "friday", "saturday", "sunday"
        }
        required_fields = {"start", "end", "closed"}

        if not isinstance(value, dict):
            raise serializers.ValidationError("work_hours must be a dictionary.")

        if set(value.keys()) != expected_days:
            raise serializers.ValidationError("work_hours must contain all 7 days (monday to sunday).")

        for day, entry in value.items():
            if not isinstance(entry, dict):
                raise serializers.ValidationError(f"{day} must be a dictionary.")
            if set(entry.keys()) != required_fields:
                raise serializers.ValidationError(f"{day} must contain keys: start, end, closed.")

        return value

    def update(self, instance, validated_data):
        image_data = self.context.get('profile_photo', None)
        if image_data:
            instance.profile_photo = image_data
        return super().update(instance, validated_data)

class ProviderNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = Provider
        fields = ['id', 'name']

class ServiceCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ServiceCategory
        fields = '__all__'

class ServiceSerializer(serializers.ModelSerializer):
    providers = ProviderNameSerializer(many=True, read_only=True)
    vendor_name = serializers.CharField(source='vendor.full_name', read_only=True)
    vendor_pic = serializers.CharField(source='vendor.profile_pic', read_only=True)
    is_favorite = serializers.SerializerMethodField()

    class Meta:
        model = Service
        fields = [
            'id', 'name', 'vendor', 'vendor_name', 'vendor_pic', 
            'description', 'category', 'duration',
            'buffer_time', 'price', 'color_code',
            'image', 'providers', 'is_favorite'
        ]

    def update(self, instance, validated_data):
        image_data = self.context.get('images', None)
        if image_data:
            instance.image = image_data
        return super().update(instance, validated_data)

    def get_is_favorite(self, obj):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return FavoriteService.objects.filter(user=request.user, service=obj).exists()
        return False

class AppointmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Appointment
        fields = [
            'id', 'customer', 'vendor', 'service',
            'status', 'notes', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class TimeSlotSerializer(serializers.ModelSerializer):
    provider = ProviderNameSerializer(read_only=True)

    class Meta:
        model = TimeSlot
        fields = [
            'id', 'provider', 'date', 'start_time', 
            'end_time', 'is_available'
        ]

class AppointmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Appointment
        fields = [
            'id', 'customer', 'vendor', 'provider',
            'service', 'time_slot', 'status', 'notes',
            'created_at', 'updated_at'
        ]