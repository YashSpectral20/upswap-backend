import random
import string
import boto3
from PIL import Image
from io import BytesIO
import base64
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


def process_images_from_s3(image_paths):
    """
    Fetch, resize, and convert images to Base64 strings from S3 bucket.
    """
    s3_client = boto3.client(
        's3',
        aws_access_key_id='your_aws_access_key_id',
        aws_secret_access_key='your_aws_secret_access_key',
    )
    bucket_name = 'upswap-assets'
    base64_images = []

    for image_path in image_paths:
        try:
            # Download image from S3
            response = s3_client.get_object(Bucket=bucket_name, Key=image_path)
            image_data = response['Body'].read()
            
            # Open and resize the image
            with Image.open(BytesIO(image_data)) as img:
                img = img.convert('RGB')  # Ensure compatibility
                img = img.resize((600, 200), Image.ANTIALIAS)  # Resize to 600x200
                
                # Convert to Base64
                buffer = BytesIO()
                img.save(buffer, format="WEBP")
                base64_image = base64.b64encode(buffer.getvalue()).decode('utf-8')
                base64_images.append(base64_image)
        except Exception as e:
            print(f"Error processing image {image_path}: {e}")
            continue

    return base64_images