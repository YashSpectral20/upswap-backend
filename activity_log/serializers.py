from rest_framework.serializers import ModelSerializer

from .models import ActivityLog

class ActivityLogSerializer(ModelSerializer):
    class Meta:
        model = ActivityLog
        feilds = '__all__'