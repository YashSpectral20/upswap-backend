from django.contrib import admin
from .models import (
    CustomUser, Activity, ActivityImage, ChatRoom, ChatMessage, 
    ChatRequest, VendorKYC, BankDetails, ServicesProvide, ChooseBusinessHours
)

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
    list_display = [
        'activity_id', 'created_by_display', 'activity_title', 
        'activity_type', 'user_participation', 'max_participations_display', 
        'start_date', 'end_date', 'start_time', 'end_time', 'infinite_time', 'created_at'
    ]
    readonly_fields = ['activity_id', 'created_by']
    list_filter = ('activity_type', 'infinite_time')

    def created_by_display(self, obj):
        return obj.created_by.username if obj.created_by else 'N/A'
    created_by_display.short_description = 'Created By'

    def max_participations_display(self, obj):
        return obj.maximum_participants if obj.user_participation else 0
    max_participations_display.short_description = 'Max Participations'

# Activity Image Admin
@admin.register(ActivityImage)
class ActivityImageAdmin(admin.ModelAdmin):
    list_display = ('id', 'activity', 'upload_image', 'user_display')
    search_fields = ('activity__activity_title',)
    list_filter = ('activity__activity_type',)
    readonly_fields = ('id',)

    def user_display(self, obj):
        return obj.activity.created_by.username if obj.activity and obj.activity.created_by else 'N/A'
    user_display.short_description = 'User'

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

# VendorKYC Admin
@admin.register(VendorKYC)
class VendorKYCAdmin(admin.ModelAdmin):
    list_display = (
        'vendor_id', 'user', 'full_name', 'phone_number', 'business_email_id', 
        'business_establishment_year', 'business_description', 
        'upload_business_related_documents', 'business_related_photos', 
        'same_as_personal_phone_number', 'same_as_personal_email_id'
    )
    search_fields = ('full_name', 'phone_number', 'business_email_id')
    readonly_fields = ('vendor_id',)

# BankDetails Admin
@admin.register(BankDetails)
class BankDetailsAdmin(admin.ModelAdmin):
    list_display = ('id', 'vendor_kyc', 'account_number', 'retype_account_number', 'bank_name', 'ifsc_code')
    search_fields = ('vendor_kyc__full_name', 'account_number', 'bank_name', 'ifsc_code')
    readonly_fields = ('id',)

# ServicesProvide Admin
@admin.register(ServicesProvide)
class ServicesProvideAdmin(admin.ModelAdmin):
    list_display = ('item_name', 'chosen_item_category', 'item_description', 'item_price')
    search_fields = ('item_name', 'item_description')
    list_filter = ('chosen_item_category',)

# ChooseBusinessHours Admin
@admin.register(ChooseBusinessHours)
class ChooseBusinessHoursAdmin(admin.ModelAdmin):
    list_display = ('vendor_kyc', 'day', 'formatted_start_time', 'formatted_end_time')
    list_filter = ('day',)
    search_fields = ('vendor_kyc__user__username',)

    def formatted_start_time(self, obj):
        return obj.start_time.strftime('%I:%M %p')
    formatted_start_time.short_description = 'Start Time (AM/PM)'

    def formatted_end_time(self, obj):
        return obj.end_time.strftime('%I:%M %p')
    formatted_end_time.short_description = 'End Time (AM/PM)'
