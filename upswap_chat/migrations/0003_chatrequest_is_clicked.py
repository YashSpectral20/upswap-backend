# Generated by Django 5.0 on 2025-04-12 07:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('upswap_chat', '0002_chatrequest_initial_message'),
    ]

    operations = [
        migrations.AddField(
            model_name='chatrequest',
            name='is_clicked',
            field=models.BooleanField(default=False, help_text='True if request was interacted with'),
        ),
    ]
