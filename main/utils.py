import io
import os
import math
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
from math import radians, cos, sin, asin, sqrt 
from pyfcm import FCMNotification #For push notification
import sendgrid
from sendgrid.helpers.mail import Mail, Email, To, Content
from rest_framework.views import exception_handler

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

def generate_otp(user):
    otp = ''.join(random.choices(string.digits, k=6))  # Generate a 6-digit OTP
    expires_at = timezone.now() + timedelta(minutes=10)  # OTP valid for 10 minutes

    # Save OTP to the database, create if not exists
    OTP.objects.update_or_create(
        user=user,
        defaults={'otp': otp, 'expires_at': expires_at}
    )

    # If using email, send OTP to the user
    send_email(
        # 'Your OTP Code',
        # f'Your OTP code is {otp}. It is valid for 10 minutes.',
        # settings.EMAIL_HOST_USER,
        # [user.email],
        # fail_silently=False,
    from_email_address = "verify@upswap.app",
    to_email_address = user.email,
    subject = "Your UpSwap verification OTP is",
    body = f"Your upswap verification OTP is {otp} will be valid for 10 minutes"
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

def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)

    if response is not None:
        # Agar 'detail' key ho to usko 'message' bana do
        if 'detail' in response.data:
            response.data = {'message': response.data['detail']}
    else:
        # Agar koi unknown error ho
        return Response({'message': 'Something went wrong'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return response


    # except Exception as e:
    #     return {"error": str(e)}

# Example usage
# if __name__ == "__main__":
#     result = send_email(
#         from_email_address="verify@upswap.app",
#         to_email_address="<RECEIVER@EXAMPLE.COM>",
#         subject="Sending with SendGrid is Fun",
#         body="and easy to do anywhere, even with Python"
#     )
#     if "error" in result:
#         print(f"Error: {result['error']}")
#     else:
#         print(f"Status Code: {result['status_code']}")
#         print(f"Response Body: {result['body']}")
#         print(f"Headers: {result['headers']}")

####################################################################################

# def send_push_notification(device_tokens, title, message):
#     # Initialize the FCMNotification class with the API key
#     push_service = FCMNotification(api_key=settings.FCM_API_KEY)
    
#     if isinstance(device_tokens, list):
#         # Send to multiple devices
#         result = push_service.notify_multiple_devices(
#             registration_ids=device_tokens,
#             message_title=title,
#             message_body=message
#         )
#     else:
#         # Send to a single device
#         result = push_service.notify_single_device(
#             registration_id=device_tokens,
#             message_title=title,
#             message_body=message
#         )
#     return result

# def calculate_distance(lat1, lon1, lat2, lon2):
#     if None in [lat1, lon1, lat2, lon2]:
#         return float('inf')  # Return a very large distance if any coordinate is missing
    
#     # Convert decimal to float for calculations
#     lat1, lon1, lat2, lon2 = map(float, [lat1, lon1, lat2, lon2])
    
#     # Haversine Formula
#     dlon = radians(lon2 - lon1)
#     dlat = radians(lat2 - lat1)
#     a = sin(dlat / 2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2)**2
#     c = 2 * asin(sqrt(a))
    
#     r = 6371  # Radius of Earth in kilometers
#     return c * r



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