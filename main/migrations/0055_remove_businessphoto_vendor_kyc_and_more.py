# Generated by Django 5.0 on 2024-12-12 19:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0054_activity_uploaded_images_delete_activityimage'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='businessphoto',
            name='vendor_kyc',
        ),
        migrations.RemoveField(
            model_name='vendorkyc',
            name='business_related_documents',
        ),
        migrations.RemoveField(
            model_name='vendorkyc',
            name='upload_business_related_documents',
        ),
        migrations.AddField(
            model_name='vendorkyc',
            name='upload_business_documents',
            field=models.FileField(blank=True, default=list, upload_to=''),
        ),
        migrations.DeleteModel(
            name='BusinessDocument',
        ),
        migrations.DeleteModel(
            name='BusinessPhoto',
        ),
    ]
