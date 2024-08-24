from django.contrib import admin
from .models import CustomUser, Activity, ActivityImage, ChatRoom, ChatMessage, ChatRequest

# Custom User Admin
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('id', 'username', 'email', 'phone_number', 'date_of_birth', 'gender', 'is_staff', 'is_active', 'otp_verified')
    list_filter = ('is_staff', 'is_active', 'otp_verified')
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('id', 'name', 'email', 'phone_number', 'date_of_birth', 'gender')}),
        ('Permissions', {'fields': ('is_staff', 'is_active', 'otp_verified')}),
    )
    readonly_fields = ('id',)
    search_fields = ('username', 'email', 'phone_number')
    ordering = ('username',)
    filter_horizontal = ()

admin.site.register(CustomUser, CustomUserAdmin)

# Activity Admin
@admin.register(Activity)
class ActivityAdmin(admin.ModelAdmin):
    list_display = ['activity_id', 'created_by', 'activity_title', 'activity_type', 'user_participation', 'max_participations_display', 'start_date', 'end_date', 'start_time', 'end_time', 'infinite_time', 'created_at']
    readonly_fields = ['activity_id', 'created_by']
    list_filter = ('activity_type', 'infinite_time')

    def created_by(self, obj):
        return obj.created_by.username  # Display the username of the creator
    created_by.short_description = 'Created By'

    def max_participations_display(self, obj):
        return obj.maximum_participants if obj.user_participation else 0
    max_participations_display.short_description = 'Max Participations'

# Activity Image Admin
@admin.register(ActivityImage)
class ActivityImageAdmin(admin.ModelAdmin):
    list_display = ('id', 'activity', 'upload_image', 'user_uuid_display')
    search_fields = ('activity__activity_title',)
    list_filter = ('activity__activity_type',)
    readonly_fields = ('id',)

    def user_uuid_display(self, obj):
        return obj.activity.created_by.username  # Display the username of the user who created the activity
    user_uuid_display.short_description = 'User UUID'

# ChatRoom Admin
@admin.register(ChatRoom)
class ChatRoomAdmin(admin.ModelAdmin):
    list_display = ('id', 'created_at', 'activity', 'participants_display')
    readonly_fields = ('id', 'created_at')

    def activity(self, obj):
        return obj.activity.activity_title  # Display the title of the activity
    activity.short_description = 'Activity'

    def participants_display(self, obj):
        return ', '.join([user.username for user in obj.participants.all()])
    participants_display.short_description = 'Participants'

# ChatMessage Admin
@admin.register(ChatMessage)
class ChatMessageAdmin(admin.ModelAdmin):
    list_display = ('chat_room', 'sender', 'message', 'created_at')
    readonly_fields = ('created_at',)

    def message(self, obj):
        return obj.content
    message.short_description = 'Message'

# ChatRequest Admin
@admin.register(ChatRequest)
class ChatRequestAdmin(admin.ModelAdmin):
    list_display = ('activity', 'from_user', 'to_user', 'is_accepted', 'is_rejected', 'interested')
    readonly_fields = ('activity', 'from_user', 'to_user')
    list_filter = ('is_accepted', 'is_rejected', 'interested')
    search_fields = ('from_user__username', 'to_user__username', 'activity__activity_title')

    def activity(self, obj):
        return obj.activity.activity_title  # Display the title of the activity
    activity.short_description = 'Activity'

    def from_user(self, obj):
        return obj.from_user.username  # Display the username of the from_user
    from_user.short_description = 'From User'

    def to_user(self, obj):
        return obj.to_user.username  # Display the username of the to_user
    to_user.short_description = 'To User'
