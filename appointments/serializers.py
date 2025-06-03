from rest_framework import serializers
from .models import (
    Provider
)

class ProviderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Provider
        exclude = ['vendor']

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

    # def validate(self, attrs):
    #     data = attrs.get('services')
    #     services = data.pop('services')