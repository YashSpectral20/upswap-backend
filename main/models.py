from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
import uuid
from django.utils import timezone
from django.core.exceptions import ValidationError
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
    images = models.JSONField(default=list, blank=True, help_text="List of image paths")

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
    image_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    activity = models.ForeignKey(Activity, on_delete=models.CASCADE, related_name='activity_images')
    image = models.ImageField(upload_to='activity_images/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        # Update the Activity model with the new image path
        image_path = self.image.url.replace('/media/', '')  # Remove media URL base
        activity = self.activity
        existing_image_paths = activity.images
        if image_path not in existing_image_paths:
            existing_image_paths.append(image_path)
            activity.images = existing_image_paths
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

class VendorKYC(models.Model):
    vendor_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    profile_pic = models.ImageField(upload_to='vendor_profile_pics/', null=True, blank=True)
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
    bank_account_number = models.CharField(max_length=50, default='', blank=True)
    retype_bank_account_number = models.CharField(max_length=50, default='', blank=True)
    bank_name = models.CharField(max_length=100, default='', blank=True)
    ifsc_code = models.CharField(max_length=20, default='', blank=True)
    item_name = models.CharField(max_length=255)
    is_approved = models.BooleanField(default=False)
    
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

    class DayChoices(models.TextChoices):
        SUNDAY = 'Sunday'
        MONDAY = 'Monday'
        TUESDAY = 'Tuesday'
        WEDNESDAY = 'Wednesday'
        THURSDAY = 'Thursday'
        FRIDAY = 'Friday'
        SATURDAY = 'Saturday'
    
    business_hours = models.TextField(default='{}', help_text="Business hours stored as JSON string.")

    def get_business_hours(self):
        import json
        try:
            return json.loads(self.business_hours)
        except json.JSONDecodeError:
            return {}

    def set_business_hours(self, hours):
        import json
        self.business_hours = json.dumps(hours)

    def __str__(self):
        return f"{self.user.email} - {self.full_name}"
