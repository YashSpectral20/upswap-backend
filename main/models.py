from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
import uuid

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
        user.is_admin = True
        user.is_staff = True
        user.save(using=self._db)
        return user

class CustomUser(AbstractBaseUser, PermissionsMixin):
    GENDER_CHOICES = [
        ('M', 'Male'),
        ('F', 'Female'),
        ('O', 'Other'),
    ]

    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=15, unique=True)
    date_of_birth = models.DateField(null=True, blank=True)
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    otp_verified = models.BooleanField(default=False)  # Add this line

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

#Activity-Models:
class Activity(models.Model):
    activity_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_by = models.UUIDField(default=uuid.uuid4, editable=False)
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

    def save(self, *args, **kwargs):
        if not self.user_participation:
            self.maximum_participants = 0
        super().save(*args, **kwargs)


    def __str__(self):
        return self.activity_title
    

    
class ActivityImage(models.Model):
    activity = models.ForeignKey(Activity, related_name='images', on_delete=models.CASCADE)
    upload_image = models.ImageField(upload_to='activity_images/')