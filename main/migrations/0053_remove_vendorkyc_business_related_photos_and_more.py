# Generated by Django 5.0 on 2024-12-10 17:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0052_delete_dealsimage'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='vendorkyc',
            name='business_related_photos',
        ),
        migrations.AddField(
            model_name='vendorkyc',
            name='uploaded_images',
            field=models.JSONField(blank=True, default=list),
        ),
    ]
