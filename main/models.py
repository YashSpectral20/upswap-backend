from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
import uuid
from django.utils import timezone
from django.core.exceptions import ValidationError
import mimetypes
from django.utils.translation import gettext_lazy as _

# Custom User Models
class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, name, phone_number, date_of_birth, gender, password=None):
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
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, name, phone_number, date_of_birth, gender, password=None):
        user = self.create_user(
            email=email,
            username=username,
            name=name,
            phone_number=phone_number,
            date_of_birth=date_of_birth,
            gender=gender,
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

class OTP(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

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
    user_participation = models.BooleanField(default=False)
    maximum_participants = models.IntegerField(default=0)
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    start_time = models.TimeField(null=True, blank=True)
    end_time = models.TimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    infinite_time = models.BooleanField(default=False)

    def clean(self):
        now = timezone.now().date()

        if self.start_date and self.start_date < now:
            raise ValidationError("Start date cannot be in the past.")
        if self.end_date and self.end_date < now:
            raise ValidationError("End date cannot be in the past.")
        if self.start_date and self.end_date and self.end_date < self.start_date:
            raise ValidationError("End date must be after start date.")
        if self.start_time and self.end_time and self.end_time < self.start_time:
            raise ValidationError("End time must be after start time.")
        
    def save(self, *args, **kwargs):
        if not self.user_participation:
            self.maximum_participants = 0
        if self.infinite_time:
            future_date = timezone.now() + timezone.timedelta(days=365 * 100)  # 100 years from now
            self.end_date = future_date.date()
            self.end_time = future_date.time()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.activity_title

class ActivityImage(models.Model):
    activity = models.ForeignKey(Activity, related_name='images', on_delete=models.CASCADE)
    upload_image = models.ImageField(upload_to='activity_images/')
    user_uuid = models.UUIDField(editable=False, null=True)

    def save(self, *args, **kwargs):
        if not self.user_uuid:
            self.user_uuid = self.activity.created_by.id
        super().save(*args, **kwargs)

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
            # Create a ChatRoom upon acceptance
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

class VendorKYC(models.Model):
    vendor_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    full_name = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=15)
    business_email_id = models.EmailField(max_length=255)
    business_establishment_year = models.IntegerField()
    business_description = models.TextField()
    upload_business_related_documents = models.FileField(upload_to='business_documents/', null=True, blank=True)
    business_related_photos = models.ImageField(upload_to='business_photos/', null=True, blank=True)
    same_as_personal_phone_number = models.BooleanField(default=False)
    same_as_personal_email_id = models.BooleanField(default=False)
    
    def validate_document(self, file):
        # Validate the MIME type of the file
        mime_type, _ = mimetypes.guess_type(file.name)
        allowed_types = [
            'application/pdf', 
            'application/msword', 
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        ]
        if mime_type not in allowed_types:
            raise ValidationError('Unsupported file type. Allowed types are PDF, DOC, and DOCX.')
    
    def save(self, *args, **kwargs):
        if self.same_as_personal_phone_number:
            self.phone_number = self.user.phone_number
        if self.same_as_personal_email_id:
            self.business_email_id = self.user.email
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Vendor KYC for {self.full_name}"

class BankDetails(models.Model):
    vendor_kyc = models.OneToOneField(VendorKYC, on_delete=models.CASCADE, related_name='bank_details')
    account_number = models.CharField(max_length=20)
    retype_account_number = models.CharField(max_length=20)
    bank_name = models.CharField(max_length=255)
    ifsc_code = models.CharField(max_length=11)

    def clean(self):
        if self.account_number != self.retype_account_number:
            raise ValidationError("Account numbers do not match.")

    def __str__(self):
        return f"Bank Details for Vendor {self.vendor_kyc.full_name}"

class ServicesProvide(models.Model):
    class ItemCategory(models.TextChoices):
        RESTAURANTS = 'RESTAURANTS', 'Restaurants'
        CONSULTANTS = 'CONSULTANTS', 'Consultants'
        ESTATE_AGENTS = 'ESTATE_AGENTS', 'Estate Agents'
        RENT_HIRE = 'RENT_HIRE', 'Rent & Hire'
        DENTIST = 'DENTIST', 'Dentist'
        PERSONAL_CARE = 'PERSONAL_CARE', 'Personal Care'
        FOOD = 'FOOD', 'Food'
        BAKERY = 'BAKERY', 'Bakery'
        GROCERIES = 'GROCERIES', 'Groceries'
        OTHERS = 'OTHERS', 'Others'

    vendor_kyc = models.ForeignKey(VendorKYC, on_delete=models.CASCADE, related_name='services_provide')
    item_name = models.CharField(max_length=255)
    chosen_item_category = models.CharField(
        max_length=20,
        choices=ItemCategory.choices,
        default=ItemCategory.OTHERS
    )
    item_description = models.TextField()
    item_price = models.DecimalField(max_digits=10, decimal_places=2)

    def __str__(self):
        return self.item_name
    
class ChooseBusinessHours(models.Model):
    vendor_kyc = models.ForeignKey(
        VendorKYC,
        on_delete=models.CASCADE,
        related_name='business_hours'  # Adjust related_name to avoid conflicts
    )

    class Days(models.TextChoices):
        SUNDAY = 'SUN', _('Sunday')
        MONDAY = 'MON', _('Monday')
        TUESDAY = 'TUE', _('Tuesday')
        WEDNESDAY = 'WED', _('Wednesday')
        THURSDAY = 'THU', _('Thursday')
        FRIDAY = 'FRI', _('Friday')
        SATURDAY = 'SAT', _('Saturday')

    day = models.CharField(max_length=3, choices=Days.choices)
    start_time = models.TimeField()
    end_time = models.TimeField()

    def __str__(self):
        return f"{self.get_day_display()}: {self.start_time.strftime('%I:%M %p')} - {self.end_time.strftime('%I:%M %p')}"
