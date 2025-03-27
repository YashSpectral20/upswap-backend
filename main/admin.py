from django.contrib import admin
from .models import (
    CustomUser, Activity, ChatRoom, ChatMessage,
    ChatRequest, PasswordResetOTP, VendorKYC, Address, Service, OTP, CreateDeal, PlaceOrder, VendorRating
)

# Custom User Admin
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('id', 'email', 'name', 'phone_number', 'date_of_birth', 'gender', 'is_staff', 'is_active', 'otp_verified', 'country_code', 'dial_code', 'country', 'social_id', 'type', 'bio', 'fcm_token', 'latitude', 'longitude')
    list_filter = ('is_staff', 'is_active', 'otp_verified', 'country', 'type')
    fieldsets = (
        (None, {'fields': ('username', 'password', 'email', 'social_id', 'type')}),
        ('Personal info', {'fields': ('id', 'name', 'phone_number', 'date_of_birth', 'gender', 'country_code', 'dial_code', 'country', 'bio', 'profile_pic', 'fcm_token', 'latitude', 'longitude')}),
        ('Permissions', {'fields': ('is_staff', 'is_active', 'otp_verified', 'is_superuser')}),
    )
    readonly_fields = ('id',)
    search_fields = ('username', 'email', 'phone_number', 'country_code', 'dial_code', 'country', 'social_id', 'type', 'bio', 'fcm_token')
    ordering = ('email',)
    filter_horizontal = ()

admin.site.register(CustomUser, CustomUserAdmin)



# Activity Admin
@admin.register(Activity)
class ActivityAdmin(admin.ModelAdmin):
    list_display = [
        'activity_id', 'created_by_display', 'activity_title',
        'activity_category_display', 'user_participation', 'max_participations_display',
        'start_date', 'end_date', 'start_time', 'end_time', 'infinite_time', 'set_current_datetime',
        'location', 'latitude', 'longitude', 'created_at'
    ]
    readonly_fields = ['activity_id', 'created_by']
    list_filter = ('activity_category', 'infinite_time')  # Use activity_category for filtering

    def activity_category_display(self, obj):
        return obj.activity_category.actv_category if obj.activity_category else 'N/A'
    activity_category_display.short_description = 'Activity Category'

    def created_by_display(self, obj):
        return obj.created_by.username if obj.created_by_id else 'N/A'
    created_by_display.short_description = 'Created By'

    def max_participations_display(self, obj):
        return obj.maximum_participants if obj.user_participation else 0
    max_participations_display.short_description = 'Max Participations'

    def save_model(self, request, obj, form, change):
        # Automatically set created_by to the current user if not already set
        if not obj.created_by_id:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)



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
        'business_establishment_year', 'country_code', 'dial_code', 
        'is_approved', 'fcm_token', 'latitude', 'longitude'
    ]
    search_fields = ['full_name', 'business_email_id', 'phone_number', 'fcm_token']
    list_filter = ['addresses__state', 'addresses__city', 'is_approved']
    inlines = [AddressInline, ServiceInline]

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



@admin.register(Address)
class AddressAdmin(admin.ModelAdmin):
    list_display = ['vendor', 'house_no_building_name', 'road_name_area_colony', 'city', 'state', 'pincode', 'country', 'latitude', 'longitude']
    search_fields = ['vendor__full_name', 'city', 'state']

@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ['vendor_kyc', 'item_name', 'item_description', 'item_price']
    search_fields = ['vendor_kyc__full_name', 'item_name']
    
    
@admin.register(CreateDeal)
class CreateDealAdmin(admin.ModelAdmin):
    list_display = [
        'deal_uuid', 'deal_title', 'vendor_kyc', 'actual_price', 'deal_price', 
        'start_date', 'end_date', 'start_time', 'end_time', 'buy_now', 'vendor_kyc', 
        'deal_post_time', 'get_discount_percentage', 'deal_post_time'
    ]
    search_fields = ['deal_title', 'vendor_kyc__full_name']
    inlines = []
    
    def get_discount_percentage(self, obj):
        return obj.discount_percentage  # Access the @property correctly
    get_discount_percentage.short_description = 'Discount (%)'

    
    
    
@admin.register(PlaceOrder)
class PlaceOrderAdmin(admin.ModelAdmin):
    # Fields to be displayed in the list view
    list_display = ('order_id', 'placeorder_id', 'user', 'vendor', 'deal', 'quantity', 'total_amount', 'payment_status', 'payment_mode', 'created_at')

    # Fields to search in the admin
    search_fields = ('order_id', 'placeorder_id', 'user__username', 'deal__deal_uuid', 'vendor__vendor_id', 'payment_status')

    # Filters to use in the admin list view
    list_filter = ('payment_status', 'payment_mode', 'created_at')

    # Fields to be read-only in the detail view (excluding transaction_id)
    readonly_fields = ('order_id', 'created_at', 'total_amount')

    # Fields to display in the form in the detail view
    fields = (
        'order_id', 'placeorder_id', 'user', 'deal', 'vendor', 'quantity', 'country', 'latitude', 'longitude',
        'total_amount', 'transaction_id', 'payment_status', 'payment_mode', 'created_at'
    )

    # Ordering in the list view
    ordering = ('-created_at',)

    # Related models to show when managing PlaceOrder
    raw_id_fields = ('user', 'deal', 'vendor')

    # Add date hierarchy to filter by date in the admin
    date_hierarchy = 'created_at'


@admin.register(PasswordResetOTP)
class PasswordResetOTPAdmin(admin.ModelAdmin):
    list_display = ('user', 'otp', 'used', 'created_at')
    search_fields = ('user__username', 'otp')
    
@admin.register(VendorRating)
class VendorRatingAdmin(admin.ModelAdmin):
    list_display = ('rating_id', 'user', 'vendor', 'order', 'rating', 'created_at')  # ✅ Admin panel me show hone wale columns
    list_filter = ('rating', 'created_at')  # ✅ Filter options rating aur created_at ke basis par
    search_fields = ('user__username', 'vendor__business_name', 'order__id')  # ✅ Search by username, vendor name, order ID
    ordering = ('-created_at',)  # ✅ Latest rating sabse upar dikhayega
    readonly_fields = ('rating_id', 'created_at')  # ✅ UUID aur created_at ko readonly rakhenge

    fieldsets = (
        ("User & Vendor Details", {
            'fields': ('user', 'vendor', 'order')
        }),
        ("Rating Details", {
            'fields': ('rating', 'created_at')
        }),
    )

    def vendor_name(self, obj):
        return obj.vendor.business_name  # ✅ Vendor ka naam show karega
    vendor_name.short_description = "Vendor Name"

    def user_email(self, obj):
        return obj.user.email  # ✅ User ka email show karega
    user_email.short_description = "User Email"