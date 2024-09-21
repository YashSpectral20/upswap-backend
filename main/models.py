import os
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
import uuid
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.contrib.postgres.fields import JSONField
from datetime import datetime, timedelta
from django.conf import settings
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

class Activity(models.Model):
    activity_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    activity_title = models.CharField(max_length=50)
    activity_description = models.TextField()

    class ActivityType(models.TextChoices):
        TECH_GAMING = 'TECH_GAMING', 'Tech and Gaming'
        VOLUNTEER_OPPORTUNITIES = 'VOLUNTEER_OPPORTUNITIES', 'Volunteer Opportunities'
        CULTURAL_EXCHANGES = 'CULTURAL_EXCHANGES', 'Cultural Exchanges'
        INTELLECTUAL_PURSUITS = 'INTELLECTUAL_PURSUITS', 'Intellectual Pursuits'
        SPORTS_RECREATION = 'SPORTS_RECREATION', 'Sports and Recreation'
        ARTS_CRAFTS = 'ARTS_CRAFTS', 'Arts and Crafts'
        SOCIAL_GATHERINGS = 'SOCIAL_GATHERINGS', 'Social Gatherings'
        EDUCATIONAL_WORKSHOPS = 'EDUCATIONAL_WORKSHOPS', 'Educational Workshops'
        MUSIC_ENTERTAINMENT = 'MUSIC_ENTERTAINMENT', 'Music and Entertainment'
        OTHERS = 'OTHERS', 'Others'

    activity_type = models.CharField(max_length=50, choices=ActivityType.choices)
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
    image = models.ImageField(upload_to='activity_images/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        # Update the Activity model with the new image path
        image_path = self.image.url.replace('/media/', '')  # Remove media URL base
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
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, blank = True, default = '')
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

    # Address Information
    house_no_building_name = models.CharField(max_length=255, blank=True)
    road_name_area_colony = models.CharField(max_length=255, blank=True)
    country = models.CharField(max_length=100, blank=True)
    state = models.CharField(max_length=100, blank=True)
    city = models.CharField(max_length=100, blank=True)
    pincode = models.CharField(max_length=10, blank=True)

    # Bank Details
    bank_account_number = models.CharField(max_length=50, default='', blank=True)
    retype_bank_account_number = models.CharField(max_length=50, default='', blank=True)
    bank_name = models.CharField(max_length=100, default='', blank=True)
    ifsc_code = models.CharField(max_length=20, default='', blank=True)

    # Services
    item_name = models.CharField(max_length=255)

    class ItemCategory(models.TextChoices):
        RESTAURANTS = 'Restaurants'
        CONSULTANTS = 'Consultants'
        ESTATE_AGENTS = 'Estate Agents'
        RENT_HIRE = 'Rent & Hire'
        DENTIST = 'Dentist'
        PERSONAL_CARE = 'Personal Care'
        FOOD = 'Food'
        BAKERY = 'Bakery'
        GROCERIES = 'Groceries'
        OTHERS = 'Others'

    chosen_item_category = models.CharField(max_length=50, choices=ItemCategory.choices)
    item_description = models.TextField()
    item_price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)

    # Business Hours
    business_hours = models.JSONField(null=True, blank=True, default=dict)
    
    is_approved = models.BooleanField(default=False)

    def clean(self):
        # Validate that business_hours is a valid JSON list
        if not isinstance(self.business_hours, list):
            raise ValidationError("Business hours must be a list.")
        for entry in self.business_hours:
            if not isinstance(entry, str):
                raise ValidationError("Each business hour entry must be a string.")

    def save(self, *args, **kwargs):
        # Populate phone_number and business_email_id if flags are set
        if self.same_as_personal_phone_number:
            if self.user:
                self.phone_number = self.user.phone_number

        if self.same_as_personal_email_id:
            if self.user:
                self.business_email_id = self.user.email

        if not self.phone_number and not self.same_as_personal_phone_number:
            raise ValidationError("Phone number cannot be blank.")

        if not self.business_email_id and not self.same_as_personal_email_id:
            raise ValidationError("Business email ID cannot be blank.")

        super().save(*args, **kwargs)

    def __str__(self):
        return self.full_name

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
    
class DealImage(models.Model):
    """Model for storing images related to deals."""
    image = models.ImageField(upload_to='deal_images/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Image {self.id} for Deal"

    def get_image_path(self):
        """Return the image path as a string."""
        return self.image.url if self.image else ''


class CreateDeal(models.Model):
    vendor_kyc = models.OneToOneField('VendorKYC', on_delete=models.CASCADE, related_name='deal')

    deal_uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    deal_title = models.CharField(max_length=255)
    deal_description = models.TextField()

    select_service = models.CharField(max_length=255, blank=True)
    upload_images = models.TextField(blank=True)

    deal_valid_till_start_time = models.DateTimeField(blank=True, null=True)
    deal_valid_till_end_time = models.DateTimeField(blank=True, null=True)
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

    def save(self, *args, **kwargs):
        # Ensure that the vendor's KYC is approved before allowing the creation of a deal
        if not self.vendor_kyc.is_approved:
            raise ValidationError("Cannot create a deal because Vendor KYC is not approved.")

        # Automatically populate fields from VendorKYC
        if self.vendor_kyc:
            self.select_service = self.vendor_kyc.item_name
            self.actual_price = self.vendor_kyc.item_price or self.actual_price
            self.location_house_no = self.vendor_kyc.house_no_building_name or ''
            self.location_road_name = self.vendor_kyc.road_name_area_colony or ''
            self.location_country = self.vendor_kyc.country or ''
            self.location_state = self.vendor_kyc.state or ''
            self.location_city = self.vendor_kyc.city or ''
            self.location_pincode = self.vendor_kyc.pincode or ''

        # Set the start time if 'start_now' is True
        if self.start_now:
            self.deal_valid_till_start_time = timezone.now()

        super().save(*args, **kwargs)
        
        
