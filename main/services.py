# utils.py or services.py

import boto3
import base64
from django.conf import settings

# Initialize S3 client
s3 = boto3.client(
    's3',
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
    region_name=settings.AWS_S3_REGION_NAME
)

def get_image_from_s3(bucket_name, file_name):
    try:
        # Get the object from the S3 bucket
        s3_object = s3.get_object(Bucket=bucket_name, Key=file_name)
        
        # Get the image content
        image_content = s3_object['Body'].read()

        # Convert the image to Base64
        encoded_image = base64.b64encode(image_content).decode('utf-8')

        return encoded_image

    except Exception as e:
        return str(e)
