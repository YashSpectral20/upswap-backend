import random
import string
from datetime import timedelta
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from .models import OTP

def generate_otp(user):
    otp = ''.join(random.choices(string.digits, k=6))  # Generate a 6-digit OTP
    expires_at = timezone.now() + timedelta(minutes=10)  # OTP valid for 10 minutes

    # Save OTP to the database, create if not exists
    OTP.objects.update_or_create(
        user=user,
        defaults={'otp': otp, 'expires_at': expires_at}
    )

    # If using email, send OTP to the user
    send_mail(
        'Your OTP Code',
        f'Your OTP code is {otp}. It is valid for 10 minutes.',
        settings.EMAIL_HOST_USER,
        [user.email],
        fail_silently=False,
    )

    return otp
