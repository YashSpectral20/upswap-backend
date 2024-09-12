from django.contrib import admin
from .models import (
    CustomUser, Activity, ActivityImage, ChatRoom, ChatMessage,
    ChatRequest, VendorKYC, BusinessDocument, BusinessPhoto, ActivityImage, OTP, CreateDeal
)

# Custom User Admin
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('id', 'email', 'phone_number', 'date_of_birth', 'gender', 'is_staff', 'is_active', 'otp_verified', 'country_code', 'dial_code', 'country')
    list_filter = ('is_staff', 'is_active', 'otp_verified', 'country')
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('id', 'name', 'email', 'phone_number', 'date_of_birth', 'gender', 'country_code', 'dial_code', 'country')}),
        ('Permissions', {'fields': ('is_staff', 'is_active', 'otp_verified', 'is_superuser')}),
    )
    readonly_fields = ('id',)
    search_fields = ('username', 'email', 'phone_number', 'country_code', 'dial_code', 'country')
    ordering = ('email',)
    filter_horizontal = ()

admin.site.register(CustomUser, CustomUserAdmin)

# Activity Admin
@admin.register(Activity)
class ActivityAdmin(admin.ModelAdmin):
    list_display = [
        'activity_id', 'created_by_display', 'activity_title',
        'activity_type', 'user_participation', 'max_participations_display',
        'start_date', 'end_date', 'start_time', 'end_time', 'infinite_time', 'set_current_datetime',
        'location', 'latitude', 'longitude', 'created_at'
    ]
    readonly_fields = ['activity_id', 'created_by']
    list_filter = ('activity_type', 'infinite_time')

    def save_model(self, request, obj, form, change):
        # Set created_by to the current user if it's not already set
        if not obj.created_by_id:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)

    def created_by_display(self, obj):
        # Safely handle the case where created_by might be None
        return obj.created_by.username if obj.created_by_id else 'N/A'
    created_by_display.short_description = 'Created By'

    def max_participations_display(self, obj):
        return obj.maximum_participants if obj.user_participation else 0
    max_participations_display.short_description = 'Max Participations'

# ChatRoom Admin
@admin.register(ChatRoom)
class ChatRoomAdmin(admin.ModelAdmin):
    list_display = ('id', 'created_at', 'activity_display', 'participants_display')
    readonly_fields = ('id', 'created_at')

    def activity_display(self, obj):
        return obj.activity.activity_title if obj.activity else 'N/A'
    activity_display.short_description = 'Activity'

    def participants_display(self, obj):
        return ', '.join(user.username for user in obj.participants.all()) if obj.participants.exists() else 'No Participants'
    participants_display.short_description = 'Participants'

# ChatMessage Admin
@admin.register(ChatMessage)
class ChatMessageAdmin(admin.ModelAdmin):
    list_display = ('chat_room', 'sender', 'message_display', 'created_at')
    readonly_fields = ('created_at',)

    def message_display(self, obj):
        return obj.content
    message_display.short_description = 'Message'

# ChatRequest Admin
@admin.register(ChatRequest)
class ChatRequestAdmin(admin.ModelAdmin):
    list_display = (
        'activity_display', 'from_user_display', 'to_user_display',
        'is_accepted', 'is_rejected', 'interested'
    )
    readonly_fields = ('activity_display', 'from_user_display', 'to_user_display')
    list_filter = ('is_accepted', 'is_rejected', 'interested')
    search_fields = ('from_user__username', 'to_user__username', 'activity__activity_title')

    def activity_display(self, obj):
        return obj.activity.activity_title if obj.activity else 'N/A'
    activity_display.short_description = 'Activity'

    def from_user_display(self, obj):
        return obj.from_user.username if obj.from_user else 'N/A'
    from_user_display.short_description = 'From User'

    def to_user_display(self, obj):
        return obj.to_user.username if obj.to_user else 'N/A'
    to_user_display.short_description = 'To User'


# ActivityImage Admin
@admin.register(ActivityImage)
class ActivityImageAdmin(admin.ModelAdmin):
    list_display = ('image', 'activity')
    readonly_fields = ('image', 'activity')


class BusinessDocumentInline(admin.TabularInline):
    model = BusinessDocument
    extra = 1


class BusinessPhotoInline(admin.TabularInline):
    model = BusinessPhoto
    extra = 1


@admin.register(VendorKYC)
class VendorKYCAdmin(admin.ModelAdmin):
    list_display = ['full_name', 'phone_number', 'business_email_id', 'business_establishment_year']
    search_fields = ['full_name', 'business_email_id', 'phone_number']
    list_filter = ['chosen_item_category', 'state', 'city']
    inlines = [BusinessDocumentInline, BusinessPhotoInline]

    def formatted_business_hours(self, obj):
        return "\n".join([f"{day}: {hours}" for day, hours in obj.business_hours.items()])


@admin.register(BusinessDocument)
class BusinessDocumentAdmin(admin.ModelAdmin):
    list_display = ['vendor_kyc', 'document', 'uploaded_at']
    search_fields = ['vendor_kyc__full_name']


@admin.register(BusinessPhoto)
class BusinessPhotoAdmin(admin.ModelAdmin):
    list_display = ['vendor_kyc', 'photo', 'uploaded_at']
    search_fields = ['vendor_kyc__full_name']
    
@admin.register(CreateDeal)
class CreateDealAdmin(admin.ModelAdmin):
    list_display = ['deal_uuid', 'deal_title', 'vendor_kyc', 'actual_price', 'deal_price', 'deal_valid_till_start_time', 'deal_valid_till_end_time', 'vendor_kyc']
    search_fields = ['deal_title', 'vendor_kyc__full_name']