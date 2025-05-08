from PIL import Image
from io import BytesIO
from django.core.files.base import ContentFile
import os
import random
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
import json
import uuid
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.contrib.postgres.fields import JSONField
from datetime import datetime, timedelta
from django.conf import settings
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from django.utils.timezone import now
from decimal import Decimal
from datetime import timedelta

#from django.contrib.auth import get_user_model

#User = get_user_model()

# Custom User Models
class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, name, phone_number, date_of_birth, gender, country_code='', dial_code='', country='', password=None, fcm_token=None, latitude=None, longitude=None):
        if not email:
            raise ValueError('The Email field is required')
        if not username:
            raise ValueError('The Username field is required')

        user = self.model(
            email=self.normalize_email(email),
            username=username,
            name=name,
            phone_number=phone_number,
            date_of_birth=date_of_birth,
            gender=gender,
            country_code=country_code,
            dial_code=dial_code,
            country=country,
            fcm_token=fcm_token,
            latitude=latitude,
            longitude=longitude
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, name, phone_number, date_of_birth, gender, country_code='', dial_code='', country='', password=None, fcm_token=None, latitude=None, longitude=None):
        user = self.create_user(
            email=email,
            username=username,
            name=name,
            phone_number=phone_number,
            date_of_birth=date_of_birth,
            gender=gender,
            country_code=country_code,
            dial_code=dial_code,
            country=country,
            password=password,
            fcm_token=fcm_token,
            latitude=latitude,
            longitude=longitude
        )
        user.is_superuser = True
        user.is_staff = True
        user.is_admin = True
        user.save(using=self._db)
        return user

class CustomUser(AbstractBaseUser, PermissionsMixin):
    GENDER_CHOICES = [
        ('M', 'Male'),
        ('F', 'Female'),
        ('O', 'Other'),
    ]
    LOGIN_TYPE_CHOICES = [
        ('google', 'Google'),
        ('apple', 'Apple'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=15)
    country_code = models.CharField(max_length=10, blank=True, default='')
    dial_code = models.CharField(max_length=10, blank=True, default='')
    country = models.CharField(max_length=100, blank=True, default='')
    date_of_birth = models.DateField(null=True, blank=True)
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    otp_verified = models.BooleanField(default=False)
    
    social_id = models.CharField(max_length=255, blank=True, null=True, unique=True)
    type = models.CharField(max_length=10, choices=LOGIN_TYPE_CHOICES, blank=True, null=True)
    
    bio = models.TextField(blank=True, null=True)
    profile_pic = models.JSONField(default=list, blank=True, null=True)
    fcm_token = models.CharField(max_length=255, blank=True, null=True)
    latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True, verbose_name="Latitude")
    longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True, verbose_name="Longitude")

    
    objects = CustomUserManager()
    

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'name', 'phone_number', 'date_of_birth', 'gender']

    def __str__(self):
        return self.email

    def get_full_name(self):
        return self.name

    def get_short_name(self):
        return self.username
    
class OTP(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_verified = models.BooleanField(default=False)

    def is_expired(self):
        return timezone.now() > self.expires_at
    
class ActivityCategory(models.Model):
    actv_category = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.actv_category

class Activity(models.Model):
    activity_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    activity_title = models.CharField(max_length=50)
    activity_description = models.TextField()
    uploaded_images = models.JSONField(default=list, blank=True)
    activity_category = models.ForeignKey(ActivityCategory, on_delete=models.SET_NULL, null=True, blank=True)
    user_participation = models.BooleanField(default=True)
    maximum_participants = models.IntegerField(default=0)
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    start_time = models.TimeField(null=True, blank=True)
    end_time = models.TimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    infinite_time = models.BooleanField(default=False)  # Updated to False
    set_current_datetime = models.BooleanField(default=False)
    images = models.JSONField(default=list, blank=True, help_text="List of image paths")
    location = models.CharField(max_length=255, blank=True, null=True, help_text="Optional description of the location")
    latitude = models.DecimalField(max_digits=9, decimal_places=6, blank=True, null=True, help_text="Latitude of the location")
    longitude = models.DecimalField(max_digits=9, decimal_places=6, blank=True, null=True, help_text="Longitude of the location")

    def clean(self):
        now = timezone.now().date()
        if self.start_date and self.start_date < now:
            raise ValidationError("Start date cannot be in the past.")
        if self.end_date and self.end_date < now:
            raise ValidationError("End date cannot be in the past.")
        if self.start_date and self.end_date and self.end_date < self.start_date:
            raise ValidationError("End date must be after start date.")
        if self.start_date == self.end_date:
            if self.start_time and self.end_time and self.end_time <= self.start_time:
                raise ValidationError("End time must be after start time")
        
        if self.maximum_participants > 1000:
            raise ValidationError("Maximum participants cannot exceed 1000.")

    def save(self, *args, **kwargs):
        if self.infinite_time and not (self.start_date or self.start_time or self.end_date or self.end_time):
            future_date = timezone.now() + timezone.timedelta(days=365 * 999)  
            self.end_date = future_date.date()
            self.end_time = future_date.time()

        if self.set_current_datetime and not (self.start_date or self.start_time):
            current_datetime = timezone.now()
            self.start_date = current_datetime.date()
            self.start_time = current_datetime.time()

        if self.infinite_time and self.set_current_datetime and not (self.start_date or self.start_time or self.end_date or self.end_time):
            self.start_date = None
            self.start_time = None
            self.end_date = None
            self.end_time = None

        if not self.user_participation:
            self.maximum_participants = 0

        self.clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.activity_title




    
# class ChatRequest(models.Model):
#     activity = models.ForeignKey(Activity, on_delete=models.CASCADE)
#     from_user = models.ForeignKey(CustomUser, related_name='sent_requests', on_delete=models.CASCADE)
#     to_user = models.ForeignKey(CustomUser, related_name='received_requests', on_delete=models.CASCADE)
#     is_accepted = models.BooleanField(default=False)
#     is_rejected = models.BooleanField(default=False)
#     interested = models.BooleanField(default=False)
#     created_at = models.DateTimeField(default=timezone.now)
    
#     def accept(self):
#         if not self.is_rejected:
#             self.is_accepted = True
#             self.interested = True
#             chat_room, created = ChatRoom.objects.get_or_create(activity=self.activity)
#             chat_room.participants.add(self.from_user, self.to_user)
#             chat_room.save()
#             self.save()

#     def reject(self):
#         if not self.is_accepted:
#             self.is_rejected = True
#             self.save()

#     def __str__(self):
#         return f"Request from {self.from_user} to {self.to_user} for {self.activity}"

# class ChatRoom(models.Model):
#     id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
#     activity = models.ForeignKey(Activity, on_delete=models.CASCADE)
#     participants = models.ManyToManyField(CustomUser)
#     created_at = models.DateTimeField(auto_now_add=True)
    
#     def __str__(self):
#         return f"ChatRoom {self.id} for Activity {self.activity.activity_title}"

# class ChatMessage(models.Model):
#     chat_room = models.ForeignKey(ChatRoom, related_name='messages', on_delete=models.CASCADE)
#     sender = models.ForeignKey(CustomUser, related_name='sent_messages', on_delete=models.CASCADE)
#     content = models.TextField()
#     created_at = models.DateTimeField(auto_now_add=True)

#     def __str__(self):
#         return f"Message {self.id} from {self.sender.email}"


def validate_file_type(file):
    """
    Validator to ensure that uploaded files are either images or specific document types.
    """
    ext = os.path.splitext(file.name)[1]
    valid_extensions = ['.jpg', '.jpeg', '.png', '.pdf', '.doc', '.docx']

    if not ext.lower() in valid_extensions:
        raise ValidationError(f'Unsupported file extension. Allowed extensions are: {", ".join(valid_extensions)}')

class VendorKYC(models.Model):
    vendor_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    profile_pic = models.CharField(max_length=500, blank=True, default="")
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, default='')
    full_name = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=15, blank=True)
    business_email_id = models.EmailField(max_length=255, blank=True)
    business_establishment_year = models.IntegerField()
    business_description = models.TextField()
    uploaded_business_documents = models.JSONField(default=list, blank=True)
    uploaded_images = models.JSONField(default=list, blank=True)
    same_as_personal_phone_number = models.BooleanField(default=False)
    same_as_personal_email_id = models.BooleanField(default=False)
    
    country_code = models.CharField(max_length=10, blank=True)
    dial_code = models.CharField(max_length=10, blank=True)
    
    # Latitude and Longitude
    fcm_token = models.CharField(max_length=255, null=True, blank=True)
    latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True, verbose_name="Latitude")
    longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True, verbose_name="Longitude")

    # Bank Details
    bank_account_number = models.CharField(max_length=50, default='', blank=True)
    retype_bank_account_number = models.CharField(max_length=50, default='', blank=True)
    bank_name = models.CharField(max_length=100, default='', blank=True)
    ifsc_code = models.CharField(max_length=20, default='', blank=True)
    
    business_hours = models.JSONField(default=list, blank=True, null=True)
    
    def populate_contact_details(self):
        """
        Populates the phone_number and business_email_id fields based on the vendor's preferences.
        """
        if self.same_as_personal_phone_number:
            if not self.user.phone_number:
                raise ValidationError("Personal phone number is missing.")
            self.phone_number = self.user.phone_number

        if self.same_as_personal_email_id:
            if not self.user.email:
                raise ValidationError("Personal email is missing.")
            self.business_email_id = self.user.email

    def save(self, *args, **kwargs):
        # Ensure contact details are correctly populated before saving
        self.populate_contact_details()
        super().save(*args, **kwargs)
    
    def set_business_hours(self, hours):
        """
        Helper method to format and store business hours as strings.
        Expects hours to be a list of dicts like:
        [
            {"day": "Sunday", "time": "10:00 AM - 6:00 PM"},
            {"day": "Monday", "time": "10:00 AM - 6:00 PM"},
            ...
        ]
        """
        if isinstance(hours, list):
            self.business_hours = [
                f"{entry['day']}: {entry['time']}" for entry in hours
            ]
        else:
            raise ValueError("Invalid format for business hours.")

    def get_business_hours(self):
        """
        Returns business hours in the same format that was set.
        """
        return self.business_hours
    
    is_approved = models.BooleanField(default=False)

class ServiceCategory(models.Model):
    serv_category = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.serv_category
    
class Service(models.Model):
    vendor_kyc = models.ForeignKey(VendorKYC, related_name='services', on_delete=models.CASCADE)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    item_name = models.CharField(max_length=255)
    item_description = models.TextField()
    item_price = models.DecimalField(max_digits=10, decimal_places=2)
    service_category = models.ForeignKey(ServiceCategory, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.item_name

    def save(self, *args, **kwargs):

        super().save(*args, **kwargs)

class Address(models.Model):
    vendor = models.ForeignKey(VendorKYC, related_name='addresses', on_delete=models.CASCADE)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)
    house_no_building_name = models.CharField(max_length=255, blank=True)
    road_name_area_colony = models.CharField(max_length=255, blank=True)
    country = models.CharField(max_length=100, blank=True)
    state = models.CharField(max_length=100, blank=True)
    city = models.CharField(max_length=100, blank=True)
    pincode = models.CharField(max_length=10, blank=True)
    
    # Latitude and Longitude
    latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True, verbose_name="Latitude")
    longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True, verbose_name="Longitude")

    def __str__(self):
        return f"{self.house_no_building_name}, {self.road_name_area_colony}, {self.city}, {self.state}, {self.country}, {self.pincode}"


class CreateDeal(models.Model):
    vendor_kyc = models.ForeignKey('VendorKYC', on_delete=models.CASCADE, related_name='deal')
    
    deal_post_time = models.DateTimeField(default=timezone.now)
    deal_uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    deal_title = models.CharField(max_length=255)
    deal_description = models.TextField()

    select_service = models.CharField(max_length=255, blank=True)
    uploaded_images = models.JSONField(default=list, blank=True)

    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    start_time = models.TimeField(blank=True, null=True)
    end_time = models.TimeField(blank=True, null=True)
    start_now = models.BooleanField(default=False)
    buy_now = models.BooleanField(default=True)
    view_count = models.IntegerField(default=0)

    actual_price = models.DecimalField(max_digits=10, decimal_places=2)
    deal_price = models.DecimalField(max_digits=10, decimal_places=2)
    available_deals = models.PositiveIntegerField(default=0)

    location_house_no = models.CharField(max_length=255, blank=True)
    location_road_name = models.CharField(max_length=255, blank=True)
    location_country = models.CharField(max_length=255, blank=True)
    location_state = models.CharField(max_length=255, blank=True)
    location_city = models.CharField(max_length=255, blank=True)
    location_pincode = models.CharField(max_length=20, blank=True)
    latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True, verbose_name="Latitude")
    longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True, verbose_name="Longitude")

    def save(self, *args, **kwargs):
        if self.pk is None: 
            if not self.vendor_kyc.is_approved:
                raise ValidationError("Cannot create a deal because Vendor KYC is not approved.")

        # if self.select_service:
        #     try:
        #         service = self.vendor_kyc.services.get(item_name=self.select_service)
        #         self.actual_price = service.item_price
        #     except Service.DoesNotExist:
        #         raise ValidationError(f"The service '{self.select_service}' does not exist.")

        if self.start_now:
            now = timezone.now()
            self.start_date = now.date()
            self.start_time = now.time().replace(microsecond=0)
            
        if self.pk is None and self.available_deals < 1:
            raise ValidationError("You must provide at least 1 deal while creating a deal.")

        super().save(*args, **kwargs)

    def get_uploaded_images(self):
        return self.uploaded_images if self.uploaded_images else []

    def set_uploaded_images(self, image_metadata):
        """
        Save image metadata as a list of dictionaries in JSONField.
        """
        if not isinstance(image_metadata, list):
            raise ValueError("Image metadata must be a list of dictionaries.")
        self.uploaded_images = image_metadata

    @property
    def discount_percentage(self):
        """Calculate and return the discount percentage."""
        if self.actual_price > 0:  # Ensure no division by zero
            discount = ((self.actual_price - self.deal_price) / self.actual_price) * 100
            return round(discount, 2)
        return 0.0

def deal_image_upload_path(instance, filename):
    """Function to define the upload path dynamically."""
    # Using the original extension might be risky without checking the file type
    # You can enforce a conversion to a specific format like WEBP as you are doing
    extension = 'webp'
    deal_uuid = instance.create_deal.deal_uuid if instance.create_deal else 'unknown'
    filename = f"asset_{uuid.uuid4()}.{extension}"
    return f"upswap-assets/{filename}"

    
#PlacingOrders
class PlaceOrder(models.Model):
    order_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    placeorder_id = models.CharField(max_length=12, unique=True, blank=True, null=True)  # 12 digit ka random ID
    deal = models.ForeignKey('CreateDeal', on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    vendor = models.ForeignKey('VendorKYC', on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)
    country = models.CharField(max_length=100, blank=True)
    latitude = models.DecimalField(max_digits=9, decimal_places=6, blank=True, null=True)
    longitude = models.DecimalField(max_digits=9, decimal_places=6, blank=True, null=True)
    total_amount = models.DecimalField(max_digits=20, decimal_places=2, blank=True, null=True)
    transaction_id = models.CharField(max_length=50, blank=True, null=True)
    payment_status = models.CharField(max_length=50, blank=True, null=True)
    payment_mode = models.CharField(max_length=50, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.placeorder_id:
            self.placeorder_id = self.generate_placeorder_id()
        super().save(*args, **kwargs)

    def generate_placeorder_id(self):
        while True:
            random_number = str(random.randint(10**11, (10**12)-1))  # 12 digit ka random number
            if not PlaceOrder.objects.filter(placeorder_id=random_number).exists():
                return random_number

    def __str__(self):
        return f"Order {self.order_id} for {self.user.username}" if self.order_id else "Unsaved Order"

    

class PasswordResetOTP(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return now() > self.created_at + timedelta(minutes=10)
    
class FavoriteVendor(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='favorite_vendors')
    vendor = models.ForeignKey(VendorKYC, on_delete=models.CASCADE, related_name='favorited_by')
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'vendor')  # Same vendor ko ek user multiple baar favorite nahi kar sakta

    def __str__(self):
        return f"{self.user.email} favorited {self.vendor.full_name}"
    
class VendorRating(models.Model):
    rating_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)  # User jo rating de raha hai
    vendor = models.ForeignKey('VendorKYC', on_delete=models.CASCADE)  # Jisko rating mil rahi hai
    order = models.ForeignKey('PlaceOrder', on_delete=models.CASCADE)  # Kis order pe rating di ja rahi hai
    rating = models.DecimalField(max_digits=2, decimal_places=1, choices=[
        (Decimal('0.5'), '0.5'), (Decimal('1.0'), '1'), (Decimal('1.5'), '1.5'), 
        (Decimal('2.0'), '2'), (Decimal('2.5'), '2.5'), (Decimal('3.0'), '3'),
        (Decimal('3.5'), '3.5'), (Decimal('4.0'), '4'), (Decimal('4.5'), '4.5'), (Decimal('5.0'), '5')
    ])  # Allowed rating values
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'order')  # Ek user ek order pe ek hi rating de sakta hai

    def __str__(self):
        return f"Rating {self.rating} by {self.user.username} for {self.vendor}"
    
class RaiseAnIssueMyOrders(models.Model):
    issue_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey("CustomUser", on_delete=models.CASCADE)  # User raising the issue
    place_order = models.ForeignKey("PlaceOrder", on_delete=models.CASCADE, related_name="raised_issues")  # Related order
    subject = models.CharField(max_length=255)  # Issue title
    describe_your_issue = models.TextField()  # Issue description
    choose_files = models.JSONField(default=list, blank=True)  # Image metadata
    created_at = models.DateTimeField(default=timezone.now)  # Timestamp

    def __str__(self):
        return f"Issue: {self.subject} - Order: {self.place_order.order_id}"

class RaiseAnIssueVendors(models.Model):
    issue_uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="vendor_issues")
    vendor = models.ForeignKey('VendorKYC', on_delete=models.CASCADE, related_name="raised_issues")
    subject = models.CharField(max_length=255)
    describe_your_issue = models.TextField()
    choose_files = models.JSONField(default=list, blank=True, null=True)  # Stores image metadata
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"Issue {self.issue_uuid} - {self.subject}"
    
class RaiseAnIssueCustomUser(models.Model):
    issue_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    raised_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="issues_raised")
    against_user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="issues_against")
    activity = models.ForeignKey("Activity", on_delete=models.CASCADE)
    subject = models.CharField(max_length=255)
    describe_your_issue = models.TextField()
    choose_files = models.JSONField(default=list, blank=True, null=True)  # Multiple images JSON format
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Issue by {self.raised_by.username} against {self.against_user.username}"
    
    
class Notification(models.Model):
    NOTIFICATION_TYPES = [
        ('deal', 'CreateDeal'),
        ('order_update', 'Order Update'),
        ('activity', 'Activity'),
        ('general', 'General'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='notifications')
    notification_type = models.CharField(max_length=50, choices=NOTIFICATION_TYPES)
    title = models.CharField(max_length=255)
    body = models.TextField()
    reference_id = models.UUIDField(null=True, blank=True)
    reference_type = models.CharField(max_length=50, null=True, blank=True)
    data = models.JSONField(default=dict)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.notification_type} - {self.title}"

    class Meta:
        indexes = [
            models.Index(fields=['user', 'is_read', 'created_at']),
            models.Index(fields=['notification_type', 'reference_id', 'reference_type']),
        ]

class Device(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='devices')
    device_token = models.CharField(max_length=255)
    device_type = models.CharField(max_length=50, choices=[('android', 'Android'), ('ios', 'iOS'), ('web', 'Web')])
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.email} - {self.device_type}"