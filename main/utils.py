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
from botocore.exceptions import BotoCoreError, ClientError
import traceback
import requests

from pyfcm import FCMNotification #For push notification

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
    Fetch, resize, and convert images to Base64 strings from an S3 bucket.

    Args:
        image_paths (list): List of image paths in the S3 bucket.

    Returns:
        dict: A dictionary with successful results and error details.
    """
    # Initialize the S3 client
    s3_client = boto3.client(
        's3',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
    )
    bucket_name = 'upswap-assets'
    base64_images = []
    errors = []

    for image_path in image_paths:
        if not image_path or not isinstance(image_path, str):
            errors.append({
                "image_path": image_path,
                "error": "Invalid image path. Expected a non-empty string.",
                "traceback": traceback.format_exc()
            })
            continue

        try:
            # Fetch the image from S3
            response = s3_client.get_object(Bucket=bucket_name, Key=image_path)
            image_data = response['Body'].read()

            # Validate response data
            if not image_data:
                raise ValueError("The image data is empty or invalid.")

            # Process the image
            with Image.open(BytesIO(image_data)) as img:
                img = img.convert('RGB')  # Convert to RGB for consistent formatting
                img = img.resize((600, 200), Image.Resampling.LANCZOS)  # Resize to 600x200
                
                # Save the processed image to a buffer and encode it to Base64
                buffer = BytesIO()
                img.save(buffer, format="WEBP")
                buffer.seek(0)
                base64_image = base64.b64encode(buffer.read()).decode('utf-8')
                base64_images.append({"image_path": image_path, "base64": base64_image})

        except Exception as e:
            # Capture and format the traceback
            error_details = {
                "image_path": image_path,
                "error": str(e),
                "traceback": traceback.format_exc()
            }
            errors.append(error_details)

    return {"success": base64_images, "errors": errors}


def send_fcm_notification(device_token, title, message):
    FCM_SERVER_KEY = settings.FCM_SERVER_KEY  # .env se load karein
    headers = {
        "Authorization": f"key={FCM_SERVER_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "to": device_token,
        "notification": {
            "title": title,
            "body": message
        },
        "data": {
            "click_action": "FLUTTER_NOTIFICATION_CLICK",
            "title": title,
            "body": message
        }
    }

    response = requests.post("https://fcm.googleapis.com/fcm/send", json=payload, headers=headers)
    return response.json()