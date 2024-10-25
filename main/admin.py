from django.contrib import admin
from .models import (
    CustomUser, Activity, ActivityImage, ChatRoom, ChatMessage,
    ChatRequest, VendorKYC, Address, Service, BusinessDocument, BusinessPhoto, ActivityImage, OTP, CreateDeal, DealImage, PlaceOrder
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

class AddressInline(admin.TabularInline):
    model = Address
    extra = 1

class ServiceInline(admin.TabularInline):
    model = Service
    extra = 1

@admin.register(VendorKYC)
class VendorKYCAdmin(admin.ModelAdmin):
    list_display = [
        'vendor_id', 'full_name', 'phone_number', 'business_email_id', 
        'business_establishment_year', 'country_code', 'dial_code', 'is_approved'
    ]
    search_fields = ['full_name', 'business_email_id', 'phone_number']
    list_filter = ['addresses__state', 'addresses__city', 'is_approved']  # Filter by addresses and approval status
    inlines = [BusinessDocumentInline, BusinessPhotoInline, AddressInline, ServiceInline]

    def formatted_business_hours(self, obj):
        """
        Formats the business hours in the admin panel display.
        """
        if obj.business_hours:
            return "\n".join(obj.business_hours)
        return "No business hours set"

    formatted_business_hours.short_description = 'Business Hours'

    def save_model(self, request, obj, form, change):
        # Custom logic before saving
        super().save_model(request, obj, form, change)

@admin.register(BusinessDocument)
class BusinessDocumentAdmin(admin.ModelAdmin):
    list_display = ['vendor_kyc', 'document', 'uploaded_at']
    search_fields = ['vendor_kyc__full_name']

@admin.register(BusinessPhoto)
class BusinessPhotoAdmin(admin.ModelAdmin):
    list_display = ['vendor_kyc', 'photo', 'uploaded_at']
    search_fields = ['vendor_kyc__full_name']

@admin.register(Address)
class AddressAdmin(admin.ModelAdmin):
    list_display = ['vendor', 'house_no_building_name', 'road_name_area_colony', 'city', 'state', 'pincode', 'country', 'latitude', 'longitude']
    search_fields = ['vendor__full_name', 'city', 'state']

@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ['vendor_kyc', 'item_name', 'item_description', 'item_price']
    search_fields = ['vendor_kyc__full_name', 'item_name']
    
class DealImageInline(admin.TabularInline):
    model = DealImage
    extra = 1
    
@admin.register(CreateDeal)
class CreateDealAdmin(admin.ModelAdmin):
    list_display = [
        'deal_uuid', 'deal_title', 'vendor_kyc', 'actual_price', 'deal_price', 
        'start_date', 'end_date', 'start_time', 'end_time', 'vendor_kyc', 
        'deal_post_time', 'get_discount_percentage'
    ]
    search_fields = ['deal_title', 'vendor_kyc__full_name']
    inlines = [DealImageInline]
    
    def get_discount_percentage(self, obj):
        return obj.discount_percentage  # Access the @property correctly
    get_discount_percentage.short_description = 'Discount (%)'

    
@admin.register(DealImage)
class DealImageAdmin(admin.ModelAdmin):
    list_display = ['create_deal', 'images', 'uploaded_at']
    search_fields = ['create_deal__deal_title', 'create_deal__vendor_kyc__full_name']
    
    
    
@admin.register(PlaceOrder)
class PlaceOrderAdmin(admin.ModelAdmin):
    # Fields to be displayed in the list view
    list_display = ('order_id', 'user', 'vendor', 'deal', 'quantity', 'total_amount', 'payment_status', 'payment_mode', 'created_at')

    # Fields to search in the admin
    search_fields = ('order_id', 'user__username', 'deal__deal_uuid', 'vendor__vendor_id', 'payment_status')

    # Filters to use in the admin list view
    list_filter = ('payment_status', 'payment_mode', 'created_at')

    # Fields to be read-only in the detail view (excluding transaction_id)
    readonly_fields = ('order_id', 'created_at', 'total_amount')

    # Fields to display in the form in the detail view
    fields = (
        'order_id', 'user', 'deal', 'vendor', 'quantity', 'country', 'latitude', 'longitude',
        'total_amount', 'transaction_id', 'payment_status', 'payment_mode', 'created_at'
    )

    # Ordering in the list view
    ordering = ('-created_at',)

    # Related models to show when managing PlaceOrder
    raw_id_fields = ('user', 'deal', 'vendor')

    # Add date hierarchy to filter by date in the admin
    date_hierarchy = 'created_at'
