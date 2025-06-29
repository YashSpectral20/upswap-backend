# Generated by Django 5.0 on 2025-04-25 11:10

from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('upswap_chat', '0005_chatrequest_is_rejected'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='chatmessage',
            name='read_by',
            field=models.ManyToManyField(blank=True, related_name='read_messages', to=settings.AUTH_USER_MODEL),
        ),
    ]
