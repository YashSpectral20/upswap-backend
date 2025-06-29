# Generated by Django 5.0 on 2024-10-10 06:49

import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0019_remove_vendorkyc_item_name'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='vendorkyc',
            name='city',
        ),
        migrations.RemoveField(
            model_name='vendorkyc',
            name='country',
        ),
        migrations.RemoveField(
            model_name='vendorkyc',
            name='house_no_building_name',
        ),
        migrations.RemoveField(
            model_name='vendorkyc',
            name='pincode',
        ),
        migrations.RemoveField(
            model_name='vendorkyc',
            name='road_name_area_colony',
        ),
        migrations.RemoveField(
            model_name='vendorkyc',
            name='state',
        ),
        migrations.CreateModel(
            name='Address',
            fields=[
                ('address_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('house_no_building_name', models.CharField(blank=True, max_length=255)),
                ('road_name_area_colony', models.CharField(blank=True, max_length=255)),
                ('country', models.CharField(blank=True, max_length=100)),
                ('state', models.CharField(blank=True, max_length=100)),
                ('city', models.CharField(blank=True, max_length=100)),
                ('pincode', models.CharField(blank=True, max_length=10)),
                ('latitude', models.DecimalField(blank=True, decimal_places=6, max_digits=9, null=True, verbose_name='Latitude')),
                ('longitude', models.DecimalField(blank=True, decimal_places=6, max_digits=9, null=True, verbose_name='Longitude')),
                ('vendor', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='addresses', to='main.vendorkyc')),
            ],
        ),
    ]
