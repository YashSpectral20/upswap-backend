# Generated by Django 5.0 on 2024-10-03 07:11

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0012_createdeal_location_latitude_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='createdeal',
            old_name='location_latitude',
            new_name='latitude',
        ),
        migrations.RenameField(
            model_name='createdeal',
            old_name='location_longitude',
            new_name='longitude',
        ),
    ]
