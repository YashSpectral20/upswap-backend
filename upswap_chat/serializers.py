from rest_framework import serializers
from .models import ChatRoom, ChatRequest, ChatMessage

class ChatRequestSerializer(serializers.ModelSerializer):
    from_user_name = serializers.CharField(source='from_user.name', read_only=True)
    from_user_profile_pic = serializers.SerializerMethodField()
    chatroom_id = serializers.SerializerMethodField()

    class Meta:
        model = ChatRequest
        fields = '__all__' 
        extra_fields = ['from_user_name', 'from_user_profile_pic']
        
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

class ChatRoomSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatRoom
        fields = '__all__'

class ChatMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatMessage
        fields = '__all__'