# Generated by Django 5.0 on 2025-04-05 11:27

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0086_alter_notification_notification_type'),
    ]

    operations = [
        migrations.CreateModel(
            name='FCMDevice',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('registration_id', models.CharField(max_length=255)),
                ('name', models.CharField(blank=True, max_length=20, null=True)),
                ('active', models.BooleanField(default=True)),
                ('device_id', models.CharField(blank=True, max_length=100, null=True)),
                ('type', models.CharField(choices=[('android', 'Android'), ('ios', 'iOS'), ('web', 'Web')], max_length=50)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
