from rest_framework import serializers
from .models import ChatRoom, ChatRequest, ChatMessage
from django.utils.timezone import localtime

class ChatRequestSerializer(serializers.ModelSerializer):
    from_user_name = serializers.CharField(source='from_user.name', read_only=True)
    from_user_profile_pic = serializers.SerializerMethodField()
    chatroom_id = serializers.SerializerMethodField()
    activity_admin_profile_pic = serializers.SerializerMethodField()
    activity_admin_username = serializers.SerializerMethodField()
    last_admin_message = serializers.SerializerMethodField()
    created_at = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)

    class Meta:
        model = ChatRequest
        fields = '__all__' 
        extra_fields = ['from_user_name', 'from_user_profile_pic', 'chatroom_id', 'activity_admin_profile_pic', 'activity_admin_username', 'last_admin_message']
        
    def get_chatroom_id(self, obj):
        if obj.is_accepted:
            try:
                chatroom = ChatRoom.objects.filter(
                    activity=obj.activity,
                    participants=obj.from_user
                ).order_by('-created_at').first()
                if chatroom:
                    return str(chatroom.id)
            except:
                return None
        return None

    def get_from_user_profile_pic(self, obj):
        profile_pic = obj.from_user.profile_pic
        if profile_pic:
            return profile_pic.url if hasattr(profile_pic, 'url') else str(profile_pic)
        return None
    
    def get_activity_admin_profile_pic(self, obj):
        profile_pic = obj.activity.created_by.profile_pic
        if profile_pic:
            return profile_pic.url if hasattr(profile_pic, 'url') else str(profile_pic)
        return None
    
    def get_activity_admin_username(self, obj):
        return obj.activity.created_by.username if obj.activity and obj.activity.created_by else None
    
    def get_last_admin_message(self, obj):
        if obj.is_accepted:
            chatroom = ChatRoom.objects.filter(activity=obj.activity, participants=obj.from_user).first()
            if chatroom:
                last_message = ChatMessage.objects.filter(
                    chat_room=chatroom,
                    sender=obj.activity.created_by
                ).order_by('-created_at').first()
                if last_message:
                    return {
                        "content": last_message.content,
                        "created_at": last_message.created_at.strftime("%Y-%m-%d %H:%M:%S")
                    }
        return None

class ChatRoomSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatRoom
        fields = '__all__'

class ChatMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatMessage
        fields = '__all__'