from rest_framework import serializers
from .models import (
    Provider,
    Service,
    ServiceCategory,
    Appointment,
)

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
    service_category = serializers.CharField(source='category.service_category', read_only=True)
    providers = ProviderNameSerializer(many=True, read_only=True)

    class Meta:
        model = Service
        fields = [
            'id', 'name', 'vendor', 'description', 'category', 'duration',
            'buffer_time', 'price', 'color_code',
            'image', 'service_category', 'providers'
        ]

    def update(self, instance, validated_data):
        image_data = self.context.get('images', None)
        if image_data:
            instance.image = image_data
        return super().update(instance, validated_data)

class AppointmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Appointment
        fields = [
            'id', 'customer', 'vendor', 'service',
            'status', 'notes', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
