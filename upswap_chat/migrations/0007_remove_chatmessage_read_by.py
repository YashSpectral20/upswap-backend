# Generated by Django 5.0 on 2025-04-25 11:42

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('upswap_chat', '0006_chatmessage_read_by'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='chatmessage',
            name='read_by',
        ),
    ]
