# Generated by Django 3.2.25 on 2024-08-31 07:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0012_activity_images'),
    ]

    operations = [
        migrations.AlterField(
            model_name='activity',
            name='images',
            field=models.JSONField(blank=True, default=list, help_text='List of image paths'),
        ),
    ]