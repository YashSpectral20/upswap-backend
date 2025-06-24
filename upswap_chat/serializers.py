from rest_framework import serializers
from .models import ChatRoom, ChatRequest, ChatMessage
from django.utils.timezone import localtime
from main.models import CustomUser

class ChatRequestSerializer(serializers.ModelSerializer):
    from_user_name = serializers.CharField(source='from_user.name', read_only=True)
    from_user_profile_pic = serializers.SerializerMethodField()
    chatroom_id = serializers.SerializerMethodField()
    activity_admin_profile_pic = serializers.SerializerMethodField()
    activity_admin_username = serializers.SerializerMethodField()
    last_admin_message = serializers.SerializerMethodField()
    last_user_message = serializers.SerializerMethodField()
    created_at = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    activity_title = serializers.SerializerMethodField()

    class Meta:
        model = ChatRequest
        fields = '__all__' 
        extra_fields = ['from_user_name', 'activity_title', 'from_user_profile_pic', 'chatroom_id', 'activity_admin_profile_pic', 'activity_admin_username', 'last_admin_message', 'last_user_message']
        
    def get_activity_title(self, obj):
        return obj.activity.activity_title
    
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
                        "id": last_message.id,
                        "content": last_message.content,
                        "created_at": last_message.created_at.strftime("%Y-%m-%d %H:%M:%S")
                    }
        return None
    
    def get_last_user_message(self, obj):
        if obj.is_accepted:
            chatroom = ChatRoom.objects.filter(activity=obj.activity, participants=obj.from_user).first()
            if chatroom:
                last_message = ChatMessage.objects.filter(
                    chat_room=chatroom,
                    sender=obj.from_user
                ).order_by('-created_at').first()
                if last_message:
                    return {
                        "id": last_message.id,
                        "content": last_message.content,
                        "created_at": last_message.created_at.strftime("%Y-%m-%d %H:%M:%S")
                    }
        return None

class CustomUserSerializer(serializers.ModelSerializer):
    profile_pic = serializers.SerializerMethodField()
    
    class Meta:
        model = CustomUser
        fields = ('id', 'name', 'profile_pic')

    def get_profile_pic(self, obj):
        if not obj.profile_pic:
            return ""
        return obj.profile_pic

class LastMessageSerializer(serializers.ModelSerializer):
    sender_id = serializers.UUIDField(source='sender.id')

    class Meta:
        model = ChatMessage
        fields = ('id', 'sender_id', 'content', 'created_at')

class GetChatRoomSerializer(serializers.ModelSerializer):
    participants = CustomUserSerializer(many=True, read_only=True)
    last_message = serializers.SerializerMethodField()

    class Meta:
        model = ChatRoom
        fields = ('id', 'activity', 'participants', 'created_at', 'last_message')

    def get_last_message(self, obj):
        last_msg = obj.messages.first()  # due to ordering = ('-created_at',)
        if last_msg:
            return LastMessageSerializer(last_msg).data
        return None


class ChatRoomSerializer(serializers.ModelSerializer):

    class Meta:
        model = ChatRoom
        fields = '__all__'

class ChatMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatMessage
        fields = '__all__'
        
class MyInterestedActivitySerializer(serializers.ModelSerializer):
    activity_id = serializers.UUIDField(source='activity.activity_id')
    activity_admin_uuid = serializers.UUIDField(source='activity.created_by.id')
    activity_title = serializers.CharField(source='activity.activity_title')
    activity_admin_name = serializers.CharField(source='activity.created_by.name')
    activity_admin_profile_pic = serializers.SerializerMethodField()
    user_uuid = serializers.UUIDField(source='from_user.id')
    last_message = serializers.SerializerMethodField()
    thumbnail_image = serializers.SerializerMethodField()
    chatroom_id = serializers.SerializerMethodField() 

    class Meta:
        model = ChatRequest
        fields = ['activity_id', 'activity_title', 'activity_admin_uuid', 'activity_admin_name', 'activity_admin_profile_pic', 'user_uuid', 'last_message', 'thumbnail_image', 'chatroom_id']

    def get_activity_admin_profile_pic(self, obj):
        pic = obj.activity.created_by.profile_pic
        return pic.url if pic and hasattr(pic, 'url') else str(pic) if pic else None
    
    def get_thumbnail_image(self, obj):
        imgs = obj.activity.uploaded_images
        if isinstance(imgs, list) and imgs:
            first = imgs[0]
            # agar dict ho to thumbnail key
            if isinstance(first, dict):
                return first.get('thumbnail')
            # agar direct string URL ho
            return first
        return None

    def get_last_message(self, obj):
        try:
            chatroom = ChatRoom.objects.filter(activity=obj.activity, participants=obj.from_user).first()
            if chatroom:
                last_msg = ChatMessage.objects.filter(chat_room=chatroom).order_by('-created_at').first()
                if last_msg:
                    return {
                        "sender": last_msg.sender.name,
                        "sender_id": str(last_msg.sender.id),
                        "content": last_msg.content,
                        "created_at": last_msg.created_at.strftime("%Y-%m-%d %H:%M:%S")
                    }
        except:
            pass
        return None
    
    def get_chatroom_id(self, obj):
        try:
            chatroom = ChatRoom.objects.filter(
                activity=obj.activity,
                participants=obj.from_user
            ).filter(
                participants=obj.activity.created_by
            ).first()

            if chatroom:
                return str(chatroom.id)
        except:
            pass
        return None