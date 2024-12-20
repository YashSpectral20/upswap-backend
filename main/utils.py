import io
import random
import string
import boto3
import uuid
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

def generate_asset_uuid():
    return str(uuid.uuid4())


def process_image(image_file, size):
    img = Image.open(image_file)
    img = img.convert("RGB")  # Ensure it's RGB
    img.thumbnail(size)  # Resize image
    img_io = BytesIO()
    img.save(img_io, format="WEBP", quality=85)
    img_io.seek(0)
    return img_io


def upload_to_s3(file_obj, folder_name, file_name):
    s3_client = boto3.client(
        's3',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_S3_REGION_NAME,
    )
    s3_path = f"{folder_name}/{file_name}"
    s3_client.upload_fileobj(
        file_obj,
        settings.AWS_STORAGE_BUCKET_NAME,
        s3_path,
        ExtraArgs={"ContentType": "image/webp"},
    )
    return f"{settings.MEDIA_URL}{s3_path}"



def upload_to_s3_documents(file, folder, file_type="document"):
    s3_client = boto3.client('s3', region_name=settings.AWS_S3_REGION_NAME,
                             aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                             aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY)
    
    # Generate unique file name
    file_extension = file.name.split('.')[-1].lower()
    asset_uuid = str(uuid.uuid4())
    
    if file_type == "image" and file_extension in ['jpg', 'jpeg', 'png']:
        # Convert image to webp
        image = Image.open(file)
        webp_file = io.BytesIO()
        image.save(webp_file, 'WEBP')
        webp_file.seek(0)
        file_key = f"{folder}/asset_{asset_uuid}.webp"
        s3_client.upload_fileobj(webp_file, settings.AWS_STORAGE_BUCKET_NAME, file_key, ExtraArgs={"ContentType": "image/webp"})
    else:
        # For documents and unsupported image formats, use the original file
        file_key = f"{folder}/asset_{asset_uuid}.{file_extension}"
        s3_client.upload_fileobj(file, settings.AWS_STORAGE_BUCKET_NAME, file_key)
    
    return f"{settings.MEDIA_URL}{file_key}"

def upload_to_s3_profile_image(file, folder, file_type="image"):
    s3_client = boto3.client('s3', region_name=settings.AWS_S3_REGION_NAME,
                             aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                             aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY)
    
    # Generate unique file name using UUID
    asset_uuid = str(uuid.uuid4())
    
    # Resize and convert the image to WebP format
    if file_type == "image":
        image = Image.open(file)
        # Resize the image to 160x130
        image = image.resize((160, 130))
        
        # Convert the image to WebP format
        webp_file = BytesIO()
        image.save(webp_file, 'WEBP')
        webp_file.seek(0)
        
        file_key = f"{folder}/asset_{asset_uuid}.webp"
        s3_client.upload_fileobj(webp_file, settings.AWS_STORAGE_BUCKET_NAME, file_key,
                                 ExtraArgs={"ContentType": "image/webp"})
    else:
        raise ValueError("Unsupported file type")

    return f"{settings.MEDIA_URL}{file_key}"


# def send_fcm_notification(device_token, title, message):
#     FCM_SERVER_KEY = settings.FCM_SERVER_KEY  # .env se load karein
#     headers = {
#         "Authorization": f"key={FCM_SERVER_KEY}",
#         "Content-Type": "application/json"
#     }

#     payload = {
#         "to": device_token,
#         "notification": {
#             "title": title,
#             "body": message
#         },
#         "data": {
#             "click_action": "FLUTTER_NOTIFICATION_CLICK",
#             "title": title,
#             "body": message
#         }
#     }

#     response = requests.post("https://fcm.googleapis.com/fcm/send", json=payload, headers=headers)
#     return response.json()