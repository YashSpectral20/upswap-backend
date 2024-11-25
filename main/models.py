from PIL import Image
from io import BytesIO
from django.core.files.base import ContentFile
import os
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

#from django.contrib.auth import get_user_model

#User = get_user_model()

# Custom User Models
class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, name, phone_number, date_of_birth, gender, country_code='', dial_code='', country='', password=None):
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
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, name, phone_number, date_of_birth, gender, country_code='', dial_code='', country='', password=None):
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

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=15, unique=True)
    country_code = models.CharField(max_length=10, blank=True, default='')
    dial_code = models.CharField(max_length=10, blank=True, default='')
    country = models.CharField(max_length=100, blank=True, default='')
    date_of_birth = models.DateField(null=True, blank=True)
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    otp_verified = models.BooleanField(default=False)
    
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
    activity_category = models.ForeignKey(ActivityCategory, on_delete=models.SET_NULL, null=True, blank=True)
    user_participation = models.BooleanField(default=True)
    maximum_participants = models.IntegerField(default=0)
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    start_time = models.TimeField(null=True, blank=True)
    end_time = models.TimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    infinite_time = models.BooleanField(default=True)
    set_current_datetime = models.BooleanField(default=False)
    images = models.JSONField(default=list, blank=True, help_text="List of image paths")
    location = models.CharField(max_length=255, blank=True, null=True, help_text="Optional description of the location")
    latitude = models.DecimalField(max_digits=9, decimal_places=6, blank=True, null=True, help_text="Latitude of the location")
    longitude = models.DecimalField(max_digits=9, decimal_places=6, blank=True, null=True, help_text="Longitude of the location")

    def clean(self):
        now = timezone.now().date()

        # Check date validations
        if self.start_date and self.start_date < now:
            raise ValidationError("Start date cannot be in the past.")
        if self.end_date and self.end_date < now:
            raise ValidationError("End date cannot be in the past.")
        if self.start_date and self.end_date and self.end_date < self.start_date:
            raise ValidationError("End date must be after start date.")
        if self.start_time and self.end_time and self.end_time < self.start_time:
            raise ValidationError("End time must be after start time.")
        
        # Check maximum participants limit
        if self.maximum_participants > 1000:
            raise ValidationError("Maximum participants cannot exceed 1000.")

    def save(self, *args, **kwargs):
        # Apply the special condition logic
        if self.infinite_time:
            future_date = timezone.now() + timezone.timedelta(days=365 * 999)  # 999 years from now
            self.end_date = future_date.date()
            self.end_time = future_date.time()
        if self.set_current_datetime:
            current_datetime = timezone.now()
            self.start_date = current_datetime.date()
            self.start_time = current_datetime.time()
        if self.infinite_time and self.set_current_datetime:
            self.start_date = None
            self.start_time = None
            self.end_date = None
            self.end_time = None

        if not self.user_participation:
            self.maximum_participants = 0

        # Perform the clean validation before saving
        self.clean()
        
        super().save(*args, **kwargs)

    def __str__(self):
        return self.activity_title

class ActivityImage(models.Model):
    image_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    activity = models.ForeignKey(Activity, on_delete=models.CASCADE, related_name='activity_images')
    image = models.ImageField()  # Leave upload_to blank; we will set it in the save method
    uploaded_at = models.DateTimeField(auto_now_add=True)

    @property
    def storage_url(self):
        activity_uuid = self.activity.activity_id
        return f"https://upswap-assets.storage.bunnycdn.com/activity_images/{activity_uuid}/{self.image.name}"

    def save(self, *args, **kwargs):
        # Dynamically set the upload path using activity_id
        self.image.field.upload_to = f'activity_images/{self.activity.activity_id}/'
        super().save(*args, **kwargs)
        
        # Update the Activity model with the new image path
        image_path = self.storage_url  # Use the storage_url property
        activity = self.activity
        if image_path not in activity.images:
            activity.images.append(image_path)
            activity.save()

    def __str__(self):
        return f"Image for {self.activity.activity_title}"



    
class ChatRequest(models.Model):
    activity = models.ForeignKey(Activity, on_delete=models.CASCADE)
    from_user = models.ForeignKey(CustomUser, related_name='sent_requests', on_delete=models.CASCADE)
    to_user = models.ForeignKey(CustomUser, related_name='received_requests', on_delete=models.CASCADE)
    is_accepted = models.BooleanField(default=False)
    is_rejected = models.BooleanField(default=False)
    interested = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)
    
    def accept(self):
        if not self.is_rejected:
            self.is_accepted = True
            self.interested = True
            chat_room, created = ChatRoom.objects.get_or_create(activity=self.activity)
            chat_room.participants.add(self.from_user, self.to_user)
            chat_room.save()
            self.save()

    def reject(self):
        if not self.is_accepted:
            self.is_rejected = True
            self.save()

    def __str__(self):
        return f"Request from {self.from_user} to {self.to_user} for {self.activity}"

class ChatRoom(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    activity = models.ForeignKey(Activity, on_delete=models.CASCADE)
    participants = models.ManyToManyField(CustomUser)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"ChatRoom {self.id} for Activity {self.activity.activity_title}"

class ChatMessage(models.Model):
    chat_room = models.ForeignKey(ChatRoom, related_name='messages', on_delete=models.CASCADE)
    sender = models.ForeignKey(CustomUser, related_name='sent_messages', on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Message {self.id} from {self.sender.email}"


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
    profile_pic = models.ImageField(upload_to='vendor_profile_pics/', null=True, blank=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, default='')
    full_name = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=15, blank=True)
    business_email_id = models.EmailField(max_length=255, blank=True)
    business_establishment_year = models.IntegerField()
    business_description = models.TextField()
    upload_business_related_documents = models.FileField(upload_to='business_documents/', null=True, blank=True)
    business_related_photos = models.ImageField(upload_to='business_photos/', null=True, blank=True)
    same_as_personal_phone_number = models.BooleanField(default=False)
    same_as_personal_email_id = models.BooleanField(default=False)

    business_related_documents = models.JSONField(default=list, blank=True, help_text="List of document paths")
    business_related_photos = models.JSONField(default=list, blank=True, help_text="List of photo paths")
    
    country_code = models.CharField(max_length=10, blank=True)
    dial_code = models.CharField(max_length=10, blank=True)
    
    # Latitude and Longitude
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

class BusinessDocument(models.Model):
    vendor_kyc = models.ForeignKey(VendorKYC, related_name='business_documents', on_delete=models.CASCADE)
    document = models.FileField(upload_to='business_documents/', validators=[validate_file_type])
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        # Update the VendorKYC model with the new document path
        document_path = self.document.url.replace('/media/', '')  # Remove media URL base
        vendor_kyc = self.vendor_kyc
        if document_path not in vendor_kyc.business_related_documents:
            vendor_kyc.business_related_documents.append(document_path)
            vendor_kyc.save()

    def __str__(self):
        return f"Document for {self.vendor_kyc.full_name}"

class BusinessPhoto(models.Model):
    vendor_kyc = models.ForeignKey(VendorKYC, related_name='business_photos', on_delete=models.CASCADE)
    photo = models.ImageField(upload_to='business_photos/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        # Update the VendorKYC model with the new photo path
        photo_path = self.photo.url.replace('/media/', '')  # Remove media URL base
        vendor_kyc = self.vendor_kyc
        if photo_path not in vendor_kyc.business_related_photos:
            vendor_kyc.business_related_photos.append(photo_path)
            vendor_kyc.save()

    def __str__(self):
        return f"Photo for {self.vendor_kyc.full_name}"


class CreateDeal(models.Model):
    vendor_kyc = models.ForeignKey('VendorKYC', on_delete=models.CASCADE, related_name='deal')
    
    deal_post_time = models.DateTimeField(default=timezone.now)
    deal_uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    deal_title = models.CharField(max_length=255)
    deal_description = models.TextField()

    select_service = models.CharField(max_length=255, blank=True)
    upload_images = models.JSONField(default=list, null=True, blank=True)

    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    start_time = models.TimeField(blank=True, null=True)
    end_time = models.TimeField(blank=True, null=True)
    start_now = models.BooleanField(default=False)

    actual_price = models.DecimalField(max_digits=10, decimal_places=2)
    deal_price = models.DecimalField(max_digits=10, decimal_places=2)
    available_deals = models.PositiveIntegerField()

    location_house_no = models.CharField(max_length=255, blank=True)
    location_road_name = models.CharField(max_length=255, blank=True)
    location_country = models.CharField(max_length=255, blank=True)
    location_state = models.CharField(max_length=255, blank=True)
    location_city = models.CharField(max_length=255, blank=True)
    location_pincode = models.CharField(max_length=20, blank=True)
    latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True, verbose_name="Latitude")
    longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True, verbose_name="Longitude")

    def save(self, *args, **kwargs):
        if not self.vendor_kyc.is_approved:
            raise ValidationError("Cannot create a deal because Vendor KYC is not approved.")

        if self.select_service:
            try:
                service = self.vendor_kyc.services.get(item_name=self.select_service)
                self.actual_price = service.item_price
            except Service.DoesNotExist:
                raise ValidationError(f"The service '{self.select_service}' does not exist.")

        if self.start_now:
            now = timezone.now()
            self.start_date = now.date()
            self.start_time = now.time().replace(microsecond=0)

        super().save(*args, **kwargs)

    def get_upload_images(self):
        return self.upload_images if self.upload_images else []

    def set_upload_images(self, image_metadata):
        """
        Save image metadata as a list of dictionaries in JSONField.
        """
        if not isinstance(image_metadata, list):
            raise ValueError("Image metadata must be a list of dictionaries.")
        self.upload_images = image_metadata

    @property
    def discount_percentage(self):
        """Calculate and return the discount percentage."""
        if self.actual_price > 0:  # Ensure no division by zero
            discount = ((self.actual_price - self.deal_price) / self.actual_price) * 100
            return round(discount, 2)
        return 0.0


# def deal_image_upload_path(instance, filename):
#     """
#     Function to define the upload path dynamically:
#     deal_images/deal_<deal_uuid>/images/asset_<asset_uuid>.webp
#     """
#     asset_uuid = str(uuid.uuid4())  # Generate a new UUID for each image
#     filename = f"asset_{asset_uuid}.webp"  # Set the generated filename
#     path = f"{filename}"
#     print(f"Generated path: {path}")  # For debugging
#     return path

# class DealsImage(models.Model):
#     # Unique identifier for each image
#     image_id = models.UUIDField(default=uuid.uuid4, primary_key=True, unique=True, editable=False)
    
#     # Foreign key linking to CreateDeal model
#     create_deal = models.ForeignKey(
#         'CreateDeal',
#         related_name='deals_assets',
#         on_delete=models.CASCADE,
#         null=True,
#         blank=True
#     )
    
#     # Image field to upload images with dynamic path
#     images = models.ImageField(upload_to=deal_image_upload_path)

#     # Timestamp for when the image was uploaded
#     uploaded_at = models.DateTimeField(auto_now_add=True)

#     def save(self, *args, **kwargs):
#         """
#         Overriding the save method to convert the image to WebP format.
#         """
#         if self.images:
#             # Open the uploaded image
#             image = Image.open(self.images)
#             output = BytesIO()
            
#             # Convert image to WebP format
#             image = image.convert('RGB')  # Ensure compatibility with WebP
#             image.save(output, format='WEBP', quality=85)  # Adjust quality as needed
#             output.seek(0)

#             # Replace the image file with the WebP version
#             webp_filename = f"asset_{self.image_id}.webp"  # Use image_id as the base for naming
#             self.images = ContentFile(output.read(), name=webp_filename)

#         super().save(*args, **kwargs)

#     def __str__(self):
#         return f"Asset ID: {self.image_id}"


def deal_image_upload_path(instance, filename):
    """Function to define the upload path dynamically."""
    # Using the original extension might be risky without checking the file type
    # You can enforce a conversion to a specific format like WEBP as you are doing
    extension = 'webp'
    filename = f"asset_{uuid.uuid4()}.{extension}"
    return f"deal_images/deal_{instance.create_deal_id}/images/{filename}"

class DealsImage(models.Model):
    image_id = models.UUIDField(default=uuid.uuid4, primary_key=True, unique=True, editable=False)
    create_deal = models.ForeignKey(
        'CreateDeal',
        related_name='deals_assets',
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )
    images = models.ImageField(upload_to=deal_image_upload_path)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        """Save image in WebP format."""
        if self.images and not self._state.adding:
            # Only convert on initial save to avoid recursion
            return super().save(*args, **kwargs)
        
        if self.images:
            # Convert image to WebP format before saving
            with Image.open(self.images) as image:
                output = BytesIO()
                image = image.convert('RGB')
                image.save(output, format='WEBP', quality=85)
                output.seek(0)
                
                # We save the file with a new filename in WEBP format
                self.images.save(
                    self.images.name,  # This should be the name generated by `upload_to`
                    ContentFile(output.getvalue()),  # Saving the actual image data
                    save=False  # We set save to False to avoid recursion
                )
        
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Asset ID: {self.image_id}"

    
#PlacingOrders
class PlaceOrder(models.Model):
    order_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    deal = models.ForeignKey('CreateDeal', on_delete=models.CASCADE)  # Replace 'CreateDeal' with the actual model name for deals
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)  # Fetches user from CustomUser table
    vendor = models.ForeignKey('VendorKYC', on_delete=models.CASCADE)  # Fetches vendor details from VendorKYC table
    quantity = models.PositiveIntegerField(default=1)
    country = models.CharField(max_length=100, blank=True)
    latitude = models.DecimalField(max_digits=9, decimal_places=6, blank=True, null=True)
    longitude = models.DecimalField(max_digits=9, decimal_places=6, blank=True, null=True)
    total_amount = models.DecimalField(max_digits=20, decimal_places=2, blank=True, null=True)
    transaction_id = models.CharField(max_length=50, blank=True, null=True)  # Generates a unique UUID for each transaction
    payment_status = models.CharField(max_length=50, blank=True, null=True)
    payment_mode = models.CharField(max_length=50, blank=True, null=True)  # Store payment mode like 'Credit Card', 'PayPal', etc.
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Order {self.order_id} by {self.user.username}"