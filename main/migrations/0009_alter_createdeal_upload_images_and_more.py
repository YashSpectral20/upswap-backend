# Generated by Django 5.0 on 2024-10-01 10:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0008_alter_createdeal_upload_images'),
    ]

    operations = [
        migrations.AlterField(
            model_name='createdeal',
            name='upload_images',
            field=models.TextField(blank=True, default='', help_text='List of deals images paths'),
        ),
        migrations.AlterField(
            model_name='dealimage',
            name='images',
            field=models.ImageField(upload_to='deal_images/'),
        ),
    ]