from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from .models import CustomUser, Activity, ActivityImage, ChatRoom, ChatMessage
from django.core.exceptions import ValidationError
from django.forms import ValidationError as FormValidationError

# Custom User Creation Form
class CustomUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = CustomUser
        fields = ('username', 'email', 'name', 'phone_number', 'date_of_birth', 'gender')

# Custom User Change Form
class CustomUserChangeForm(UserChangeForm):
    class Meta(UserChangeForm.Meta):
        model = CustomUser
        fields = ('username', 'email', 'name', 'phone_number', 'date_of_birth', 'gender', 'is_active', 'is_staff', 'is_superuser')

# CustomUser Admin
class CustomUserAdmin(BaseUserAdmin):
    form = CustomUserChangeForm
    add_form = CustomUserCreationForm

    model = CustomUser
    list_display = ('id', 'username', 'email', 'phone_number', 'date_of_birth', 'gender', 'is_staff', 'is_active', 'otp_verified')
    list_filter = ('is_staff', 'is_active', 'otp_verified')

    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('id', 'name', 'email', 'phone_number', 'date_of_birth', 'gender')}),
        ('Permissions', {'fields': ('is_staff', 'is_active', 'otp_verified')}),
    )
    readonly_fields = ('id',)  # Ensure id is read-only
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'phone_number', 'date_of_birth', 'gender', 'password1', 'password2', 'is_staff', 'is_active')}
        ),
    )
    search_fields = ('username', 'email', 'phone_number')
    ordering = ('username',)

admin.site.register(CustomUser, CustomUserAdmin)

# Activity Admin
@admin.register(Activity)
class ActivityAdmin(admin.ModelAdmin):
    list_display = ['activity_id', 'created_by_uuid', 'activity_title', 'activity_type', 'user_participation', 'max_participations_display', 'start_date', 'end_date', 'start_time', 'end_time', 'infinite_time', 'created_at']
    readonly_fields = ['activity_id', 'created_by_uuid']
    list_filter = ('activity_type', 'infinite_time')

    def created_by_uuid(self, obj):
        return obj.created_by.id  # This will return the UUID of the user
    created_by_uuid.short_description = 'Created By (User UUID)'

    def save_model(self, request, obj, form, change):
        try:
            obj.clean()  # Ensure model's clean method is called for validation
        except ValidationError as e:
            form._errors[FormValidationError.NON_FIELD_ERRORS] = form.error_class([str(e)])
            return
        super().save_model(request, obj, form, change)

    def max_participations_display(self, obj):
        return obj.maximum_participants if obj.user_participation else 0
    max_participations_display.short_description = 'Max Participations'

# Activity Image Admin
class ActivityImageAdmin(admin.ModelAdmin):
    list_display = ('id', 'activity', 'upload_image', 'user_uuid_display')
    search_fields = ('activity__activity_title',)
    list_filter = ('activity__activity_type',)
    readonly_fields = ('id',)

    def user_uuid_display(self, obj):
        # Display the UUID of the user who created the activity
        return obj.activity.created_by.id
    user_uuid_display.short_description = 'User UUID'

admin.site.register(ActivityImage, ActivityImageAdmin)

# ChatRoom Admin
@admin.register(ChatRoom)
class ChatRoomAdmin(admin.ModelAdmin):
    list_display = ('id', 'created_at', 'activity', 'participants_display')
    readonly_fields = ('id', 'created_at')

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
