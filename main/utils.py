import io
import json
import os
import math
import random
import string
import time
import threading
import boto3
import uuid
import requests
from PIL import Image
from io import BytesIO
import base64
from datetime import timedelta, datetime
from zoneinfo import ZoneInfo
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from .models import OTP, Notification, Device
from botocore.exceptions import BotoCoreError, ClientError
import traceback
from math import radians, cos, sin, asin, sqrt 
from pyfcm import FCMNotification #For push notification
import sendgrid
from sendgrid.helpers.mail import Mail, Email, To, Content
from rest_framework.views import exception_handler
# from rest_framework.response import Response
# from rest_framework import status
from twilio.rest import Client
from dotenv import load_dotenv
from .firebase_utils import send_notification_to_user
from firebase_admin import messaging
from twilio.rest import Client

load_dotenv()

# Function to send an email
def send_email(from_email_address, to_email_address, subject, body, api_key=None):
    """
    Sends an email using SendGrid.

    Args:
        from_email_address (str): The sender's email address.
        to_email_address (str): The recipient's email address.
        subject (str): The email subject.
        body (str): The email content.
        api_key (str): The SendGrid API key (optional, defaults to environment variable).

    Returns:
        dict: A dictionary with status code, response body, and headers.
    """
    # try:
    # Use API key from argument or environment variable
    if not api_key:
        api_key = os.getenv("SENDGRID_API_KEY_UPSWAP")
    if not api_key:
        raise ValueError("SendGrid API key is missing. Please set it in the environment variables or pass it explicitly.")

    sg = sendgrid.SendGridAPIClient(api_key=api_key)
    from_email = Email(from_email_address)
    to_email = To(to_email_address)
    content = Content("text/plain", body)
    mail = Mail(from_email, to_email, subject, content)

    # Send the email
    response = sg.client.mail.send.post(request_body=mail.get())
    return {
        "status_code": response.status_code,
        "body": response.body.decode("utf-8") if response.body else None,
        "headers": dict(response.headers),
    }

def poll_twilio_message_status(phone, message_sid, client, max_tries=10, interval=10):
    """
    Polls the status of a Twilio message until it's delivered or until max tries.
    
    Args:
        message_sid (str): The SID of the Twilio message.
        max_tries (int): Maximum number of polling attempts.
        interval (int): Seconds to wait between each poll.

    Returns:
        str: Final message status.
    """
    # account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    # auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    # from_phone = os.getenv("FROM_PHONE_NUMBER")
    # app_hash = os.getenv("APP_HASH")
    # client = Client(account_sid, auth_token)
    for attempt in range(1, max_tries + 1):
        message = client.messages(message_sid).fetch()
        print(f"Attempt {attempt} for phone {phone}: Status = {message.status}")

        if message.status == 'delivered':
            print(f"Message was delivered successfully on {phone}.")
            return message.status

        time.sleep(interval)

    print("Max attempts reached. Final status:", message.status)
    return message.status

def send_otp_via_sms(dial_code, phone_number, otp):
    try:
        account_sid = os.getenv("TWILIO_ACCOUNT_SID")
        auth_token = os.getenv("TWILIO_AUTH_TOKEN")
        from_phone = os.getenv("FROM_PHONE_NUMBER")
        app_hash = os.getenv("APP_HASH")
        client = Client(account_sid, auth_token)

        message_body = f"Please verify your email/phone number with this OTP - {otp}\n{app_hash}"
        message = client.messages.create(
            body=message_body,
            from_=from_phone,
            to=f"{dial_code}{phone_number}"
        )
        err, err_code = message.error_message, message.error_code
        print(f"OTP {otp} sent: {phone_number} {message.sid}")
        # poll_twilio_message_status(phone=f"{dial_code}{phone_number}", message_sid=message.sid)
        threading.Thread(
            target=poll_twilio_message_status,
            args=(f"{dial_code}{phone_number}", message.sid, client), 
            daemon=True
        ).start()
        return err, err_code
    except Exception as e:
        print(f"Failed to send OTP: {str(e)}")
        return str(e), None

def generate_otp(user):
    otp = ''.join(random.choices(string.digits, k=6))  # 6-digit OTP
    expires_at = timezone.now() + timedelta(minutes=10)

    # Store OTP
    OTP.objects.update_or_create(
        user=user,
        defaults={'otp': otp, 'expires_at': expires_at}
    )

    # Send OTP via SMS instead of email
    send_otp_via_sms(user.dial_code, user.phone_number, otp)

    return otp

def generate_asset_uuid():
    return str(uuid.uuid4())


def process_image(image_file, size):
    img = Image.open(image_file)
    img = img.convert("RGB")  # Ensure it's RGB
    if size:
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

# def upload_to_s3_profile_image(file, folder, file_type="image"):
#     s3_client = boto3.client('s3', region_name=settings.AWS_S3_REGION_NAME,
#                              aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
#                              aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY)
    
#     # Generate unique file name using UUID
#     asset_uuid = str(uuid.uuid4())
    
#     # Resize and convert the image to WebP format
#     if file_type == "image":
#         image = Image.open(file)
#         # Resize the image to 160x130
#         image = image.resize((160, 130))
        
#         # Convert the image to WebP format
#         webp_file = BytesIO()
#         image.save(webp_file, 'WEBP')
#         webp_file.seek(0)
        
#         file_key = f"{folder}/asset_{asset_uuid}.webp"
#         s3_client.upload_fileobj(webp_file, settings.AWS_STORAGE_BUCKET_NAME, file_key,
#                                  ExtraArgs={"ContentType": "image/webp"})
#     else:
#         raise ValueError("Unsupported file type")

#     return f"{settings.MEDIA_URL}{file_key}"

def upload_to_s3_profile_image(file, folder, file_type="image"):
    """
    Uploads two versions of an image to S3: a compressed thumbnail and a full-size original.
    
    1. A resized (160x130) and compressed WebP image.
    2. The original size image, also converted to WebP, in an 'original/' subfolder.
    
    Returns the URL of the compressed thumbnail only.
    """
    if file_type != "image":
        raise ValueError("Unsupported file type")

    s3_client = boto3.client(
        's3', 
        region_name=settings.AWS_S3_REGION_NAME,
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY
    )
    
    asset_uuid = str(uuid.uuid4())
    image = Image.open(file)
    
    # --- 1. Process and Upload Resized (Compressed) Image ---
    # resized_image = image.resize((160, 130))
    webp_buffer = BytesIO()
    # Save with a standard quality for thumbnails
    image.save(webp_buffer, 'WEBP', quality=85)
    webp_buffer.seek(0)
    
    resized_file_key = f"{folder}/asset_{asset_uuid}.webp"
    s3_client.upload_fileobj(
        webp_buffer, 
        settings.AWS_STORAGE_BUCKET_NAME, 
        resized_file_key,
        ExtraArgs={"ContentType": "image/webp"}
    )
    
    # --- 2. Process and Upload Original Image (as WebP) ---
    original_webp_buffer = BytesIO()
    # Save the original image (no resize) with higher quality
    image.save(original_webp_buffer, 'WEBP', quality=95)
    original_webp_buffer.seek(0)

    # The key for the original image, placed in a subfolder as requested
    original_file_key = f"{folder}/original/asset_{asset_uuid}.webp"
    s3_client.upload_fileobj(
        original_webp_buffer, 
        settings.AWS_STORAGE_BUCKET_NAME, 
        original_file_key,
        ExtraArgs={"ContentType": "image/webp"}
    )
    
    # --- 3. Return only the URL of the compressed image as requested ---
    return f"{settings.MEDIA_URL}{resized_file_key}"

def create_notification(user, notification_type, title, body, reference_instance=None, data=None):
    reference_id = None

    if reference_instance:
        reference_id = getattr(reference_instance, 'id', None) or \
                       getattr(reference_instance, 'pk', None) or \
                       getattr(reference_instance, 'activity_id', None) or \
                       getattr(reference_instance, 'deal_id', None)

    notification = Notification.objects.create(
        user=user,
        notification_type=notification_type,
        title=title,
        body=body,
        reference_id=reference_id,
        reference_type=notification_type,
        data=data or {}
    )

    # Firebase notification bhejna
    send_notification_to_user(user, title, body, data)

    return notification

def send_whatsapp_message(to_phone):
    account_sid = os.getenv("TWILIO_ACCOUNT_SID", settings.TWILIO_ACCOUNT_SID)
    auth_token = os.getenv("TWILIO_AUTH_TOKEN", settings.TWILIO_AUTH_TOKEN)
    from_whatsapp_number = os.getenv("TWILIO_WHATSAPP_NUMBER", settings.TWILIO_WHATSAPP_NUMBER)
    content_sid = os.getenv("TWILIO_CONTENT_SID", settings.TWILIO_CONTENT_SID)

    client = Client(account_sid, auth_token)

    try:
        message = client.messages.create(
            from_=from_whatsapp_number,
            content_sid=content_sid,
            to=f'whatsapp:{to_phone}'
        )
        return {"status": "success", "sid": message.sid}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def send_email_via_mailgun(email, otp):
    response = requests.post(
        f"https://api.mailgun.net/v3/{os.getenv('MAILGUN_DOMAIN')}/messages",
        auth=("api", os.getenv("MAILGUN_API_KEY")),
        data={
            "from": "Upswap  <verify@upswap.app>",
            "to": [email], 
            "subject": "OTP verification",
            "text": f"Verify your email with this OTP - {otp}",
        },
    )

    if response.status_code == 200:
        return True
    else:
        print("OTP", otp, ' | ' ,response.text)
        return False


def convert_to_utc_date_time(date_str: str, time_str: str, timezone_str: str) -> tuple[str | None, str | None, str | None]:
    """
    Convert local date and time strings to UTC equivalents.

    Args:
        date_str (str): Date in 'YYYY-MM-DD' format.
        time_str (str): Time in 'HH:MM' or 'HH:MM:SS' format.
        timezone_str (str): IANA timezone string, e.g., 'Asia/Kolkata'.

    Returns:
        tuple: (UTC date str, UTC time str, error message or None)
    """
    try:
        # Try parsing time with or without seconds
        try:
            local_naive = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            local_naive = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M")

        # Validate and attach timezone
        try:
            tz = ZoneInfo(timezone_str)
        except ZoneInfoNotFoundError:
            return None, None, f"Invalid timezone: '{timezone_str}'"

        local_aware = local_naive.replace(tzinfo=tz)

        # Convert to UTC
        utc_dt = local_aware.astimezone(ZoneInfo("UTC"))

        # Return as strings
        return utc_dt.strftime("%Y-%m-%d"), utc_dt.strftime("%H:%M:%S"), None

    except ValueError as ve:
        return None, None, f"Invalid date or time format: {ve}"

    except Exception as e:
        return None, None, f"Unexpected error: {str(e)}"

import qrcode
import io
import json
import hmac
import hashlib
import base64
from datetime import datetime

SECRET_KEY = b'supersecretkey'

def generate_qr_data(deal):
    payload = {
        "deal_id": str(deal.id),
        "buyer_id": str(deal.buyer.id),
        "seller_id": str(deal.seller.id),
        "created_at": deal.created_at.isoformat()
    }

    # Create signature
    message = json.dumps(payload, sort_keys=True).encode()
    signature = hmac.new(SECRET_KEY, message, hashlib.sha256).hexdigest()
    payload["signature"] = signature

    return json.dumps(payload)

def generate_qr_image_in_memory(data: str) -> io.BytesIO:
    qr = qrcode.make(json.dumps(data))
    buffer = io.BytesIO()
    qr.save(buffer, format="webp")
    buffer.seek(0)
    return buffer

def generate_and_upload_qr_to_s3(deal):
    # data = generate_qr_data(deal)
    buffer = generate_qr_image_in_memory(deal)
    
    filename = f"collection-code/{deal.get('purchase_id')}.webp"
    folder = "qr_codes"

    s3_url = upload_to_s3(buffer, folder, filename)
    return s3_url

def get_error_messages(errors):
    messages = ""
    for field, field_errors in errors.items():
        for error in field_errors:
            messages = f"{field} {error}"
            break
        break
    if "non_field_errors" in messages :
        messages = messages.replace("non_field_errors","")
    return messages