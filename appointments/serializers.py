from rest_framework import serializers
from .models import (
    Provider,
    Service,
    ServiceCategory,
    Appointment,
    TimeSlot,
)
from main.models import FavoriteService, Address


class ServiceNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = Service
        fields = ['id', 'name', 'price', 'duration', 'image']

class ProviderSerializer(serializers.ModelSerializer):
    services = ServiceNameSerializer(many=True, read_only=True)
    latest_timeslot_end_date = serializers.SerializerMethodField()

    class Meta:
        model = Provider
        fields = '__all__'
        read_only_fields = ['id', 'profile_photo', 'latest_timeslot_end_date']

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

    def get_latest_timeslot_end_date(self, obj):
        latest_slot = TimeSlot.objects.filter(provider=obj).order_by('-date', '-start_time').first()
        if latest_slot:
            return latest_slot.date
        return None

    def update(self, instance, validated_data):
        image_data = self.context.get('profile_photo', None)
        if image_data:
            instance.profile_photo = image_data
        return super().update(instance, validated_data)

class ProviderNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = Provider
        fields = ['id', 'name', 'email', 'phone']

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
            'id', 'customer', 'vendor', 'service', 'time_slot',
            'status', 'notes', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

        # def update(self, instance, validated_data):
        #     print("Inside update, validated_data:", validated_data)

        #     time_slots = validated_data.pop('time_slot', None)

        #     for attr, value in validated_data.items():
        #         print(f"Setting {attr} = {value}")
        #         setattr(instance, attr, value)

        #     instance.save()

        #     if time_slots is not None:
        #         instance.time_slot.set(time_slots)

        #     return instance


class TimeSlotSerializer(serializers.ModelSerializer):
    provider = ProviderNameSerializer(read_only=True)

    class Meta:
        model = TimeSlot
        fields = [
            'id', 'provider', 'date', 'start_time', 
            'end_time', 'is_available'
        ]

class AddressSerializer2(serializers.ModelSerializer):
    class Meta:
        model = Address
        fields = [
            'uuid', 'house_no_building_name', 'road_name_area_colony', 'country', 
            'state', 'city', 'pincode', 'latitude', 'longitude'
        ]
        read_only_fields = ['uuid']

class GetAppointmentSerializer(serializers.ModelSerializer):

    provider = ProviderNameSerializer(read_only=True)
    time_slot = TimeSlotSerializer(read_only=True, many=True)
    service = ServiceNameSerializer(read_only=True)
    location = serializers.SerializerMethodField()
    booked_by_name = serializers.CharField(source='customer.name', read_only=True)
    booked_by_email = serializers.CharField(source='customer.email', read_only=True)
    booked_by_phone = serializers.CharField(source='customer.phone_number', read_only=True)
    class Meta:
        model = Appointment
        fields = [
            'id', 'customer', 'booked_by_name', 'booked_by_email',
            'booked_by_phone', 'vendor', 'provider',
            'service', 'time_slot', 'status', 'notes',
            'created_at', 'updated_at', 'location'
        ]   # 

    def get_location(self, obj):
        addresses = obj.vendor.addresses
        if addresses.exists():
            return AddressSerializer2(addresses, many=True).data
        return []

    